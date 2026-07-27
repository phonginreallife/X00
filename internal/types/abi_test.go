package types

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// These tests guard the BPF/Go ABI. The structs in this package are read off a
// BPF ring buffer with encoding/binary, which lays fields out packed, so the C
// definitions in bpf/kernelseal_common.h must match field for field.
//
// A mismatch is silent at runtime: a policy map update with a wrong-but-
// same-sized struct still succeeds, it just writes to the wrong fields. That is
// exactly what happened when bpf/lsm_file_protect.bpf.c carried its own copy of
// struct ks_policy that was missing block_maps and audit_all, which silently
// disabled ptrace blocking. Hence the header-parsing test below.

const (
	execEventSize   = 316
	lsmEventSize    = 300
	policyConfigLen = 8
)

func bpfDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "bpf"))
	if err != nil {
		t.Fatalf("resolving bpf dir: %v", err)
	}
	return dir
}

func TestABI_StructSizes(t *testing.T) {
	tests := []struct {
		name string
		v    any
		want int
	}{
		{"ExecEvent", ExecEvent{}, execEventSize},
		{"LSMEvent", LSMEvent{}, lsmEventSize},
		{"PolicyConfig", PolicyConfig{}, policyConfigLen},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := binary.Size(tt.v); got != tt.want {
				t.Errorf("binary.Size(%s) = %d, want %d", tt.name, got, tt.want)
			}
		})
	}
}

// TestABI_FieldOffsets pins the packed byte offset of every field that carries
// meaning. The expected values are the offsets of the corresponding fields in
// the C structs, including C's alignment padding.
func TestABI_FieldOffsets(t *testing.T) {
	t.Run("ExecEvent", func(t *testing.T) {
		want := map[string]uintptr{
			"Timestamp": 0,
			"PID":       8,
			"TID":       12,
			"PPID":      16,
			"UID":       20,
			"GID":       24,
			"CgroupID":  32, // 4 bytes of pad at 28 so the u64 is 8-aligned
			"EventType": 40,
			"Comm":      44, // 3 bytes of reserved at 41
			"Filename":  60,
		}
		assertOffsets(t, reflect.TypeOf(ExecEvent{}), want)
	})

	t.Run("LSMEvent", func(t *testing.T) {
		want := map[string]uintptr{
			"Timestamp":  0,
			"PID":        8,
			"TID":        12,
			"UID":        16,
			"TargetPID":  20,
			"EventType":  24,
			"AccessType": 25,
			"Comm":       28, // 2 bytes of reserved at 26
			"Path":       44,
		}
		assertOffsets(t, reflect.TypeOf(LSMEvent{}), want)
	})

	t.Run("PolicyConfig", func(t *testing.T) {
		want := map[string]uintptr{
			"EnforceMode":   0,
			"BlockEnviron":  1,
			"BlockMem":      2,
			"BlockMaps":     3,
			"BlockPtrace":   4,
			"AllowSelfRead": 5,
			"AuditAll":      6,
			"Reserved":      7,
		}
		assertOffsets(t, reflect.TypeOf(PolicyConfig{}), want)
	})
}

// assertOffsets checks both the packed offset that encoding/binary will use and
// Go's own in-memory offset. Requiring the two to agree proves Go inserted no
// hidden alignment padding, which would make the wire read and the struct
// disagree.
func assertOffsets(t *testing.T, typ reflect.Type, want map[string]uintptr) {
	t.Helper()

	packed := uintptr(0)
	seen := make(map[string]bool, len(want))

	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if expect, ok := want[f.Name]; ok {
			seen[f.Name] = true
			if packed != expect {
				t.Errorf("%s.%s packed offset = %d, want %d", typ.Name(), f.Name, packed, expect)
			}
			if f.Offset != expect {
				t.Errorf("%s.%s Go offset = %d, want %d (hidden padding?)", typ.Name(), f.Name, f.Offset, expect)
			}
		}
		packed += uintptr(binary.Size(reflect.New(f.Type).Elem().Interface()))
	}

	for name := range want {
		if !seen[name] {
			t.Errorf("%s has no field %q", typ.Name(), name)
		}
	}

	// Sanity: Go's declared size must be at least the packed size.
	if got := typ.Size(); got < packed {
		t.Errorf("%s: Go size %d < packed size %d", typ.Name(), got, packed)
	}
}

// TestABI_HeaderMatchesGoStructs parses bpf/kernelseal_common.h, computes the C
// layout including the padding the compiler inserts implicitly, and checks every
// named field against its Go counterpart. This is the test that would have caught
// the ks_policy drift.
func TestABI_HeaderMatchesGoStructs(t *testing.T) {
	headerPath := filepath.Join(bpfDir(t), "kernelseal_common.h")
	src, err := os.ReadFile(headerPath)
	if err != nil {
		t.Fatalf("reading %s: %v", headerPath, err)
	}

	defines := parseCDefines(string(src))

	tests := []struct {
		cName  string
		goType reflect.Type
	}{
		{"ks_exec_event", reflect.TypeOf(ExecEvent{})},
		{"ks_lsm_event", reflect.TypeOf(LSMEvent{})},
		{"ks_policy_config", reflect.TypeOf(PolicyConfig{})},
	}

	for _, tt := range tests {
		t.Run(tt.cName, func(t *testing.T) {
			cFields, cPayload, err := parseCStructLayout(string(src), tt.cName, defines)
			if err != nil {
				t.Fatalf("parsing struct %s: %v", tt.cName, err)
			}

			// The payload the kernel writes must be exactly what Go reads.
			if goSize := binary.Size(reflect.New(tt.goType).Elem().Interface()); goSize != cPayload {
				t.Errorf("size mismatch: C %s payload = %d, Go %s = %d",
					tt.cName, cPayload, tt.goType.Name(), goSize)
			}

			goOffsets := make(map[string]uintptr)
			for i := 0; i < tt.goType.NumField(); i++ {
				f := tt.goType.Field(i)
				goOffsets[normalizeFieldName(f.Name)] = f.Offset
			}

			for _, cf := range cFields {
				key := normalizeFieldName(cf.name)
				got, ok := goOffsets[key]
				if !ok {
					// Padding fields are named differently on each side (C
					// "reserved" vs Go "Pad1"); the size check above proves
					// those bytes are accounted for.
					if isPaddingName(cf.name) {
						continue
					}
					t.Errorf("C field %s.%s has no Go counterpart", tt.cName, cf.name)
					continue
				}
				if got != uintptr(cf.offset) {
					t.Errorf("%s.%s: C offset %d, Go offset %d", tt.cName, cf.name, cf.offset, got)
				}
			}
		})
	}
}

func normalizeFieldName(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, "_", ""))
}

func isPaddingName(s string) bool {
	return strings.HasPrefix(s, "reserved") || strings.HasPrefix(s, "pad")
}

// TestABI_NoLocalStructRedefinition fails if any BPF source declares a struct
// that bpf/kernelseal_common.h already owns. Local copies compile fine and then
// drift, which is how the ptrace-blocking regression got in.
func TestABI_NoLocalStructRedefinition(t *testing.T) {
	dir := bpfDir(t)

	header, err := os.ReadFile(filepath.Join(dir, "kernelseal_common.h"))
	if err != nil {
		t.Fatalf("reading shared header: %v", err)
	}
	owned := make(map[string]bool)
	for _, name := range cStructNames(string(header)) {
		owned[name] = true
	}
	if len(owned) == 0 {
		t.Fatal("no structs found in kernelseal_common.h; parser is broken")
	}

	sources, err := filepath.Glob(filepath.Join(dir, "*.bpf.c"))
	if err != nil {
		t.Fatalf("globbing BPF sources: %v", err)
	}
	if len(sources) == 0 {
		t.Fatal("no *.bpf.c sources found")
	}

	for _, path := range sources {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		for _, name := range cStructNames(string(src)) {
			if owned[name] {
				t.Errorf("%s redefines struct %s, which kernelseal_common.h owns; include the header instead",
					filepath.Base(path), name)
			}
		}
	}
}

var (
	reDefine     = regexp.MustCompile(`(?m)^\s*#define\s+([A-Za-z_][A-Za-z0-9_]*)\s+(\d+)\s*$`)
	reStructOpen = regexp.MustCompile(`(?m)^\s*struct\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{`)
	reField      = regexp.MustCompile(`^(__u8|__u16|__u32|__u64|char)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(\[\s*([A-Za-z0-9_]+)\s*\])?\s*;`)
)

var cTypeWidths = map[string]int{
	"__u8":  1,
	"__u16": 2,
	"__u32": 4,
	"__u64": 8,
	"char":  1,
}

func parseCDefines(src string) map[string]int {
	out := make(map[string]int)
	for _, m := range reDefine.FindAllStringSubmatch(src, -1) {
		if v, err := strconv.Atoi(m[2]); err == nil {
			out[m[1]] = v
		}
	}
	return out
}

func cStructNames(src string) []string {
	matches := reStructOpen.FindAllStringSubmatch(src, -1)

	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m[1])
	}
	return out
}

type cField struct {
	name   string
	offset int
	width  int
}

// parseCStructLayout returns each field of a C struct with the offset the
// compiler would assign it, applying the natural-alignment rules that produce
// implicit padding, plus the total payload size (offset of the last field plus
// its width, without trailing struct padding).
func parseCStructLayout(src, name string, defines map[string]int) ([]cField, int, error) {
	marker := regexp.MustCompile(`(?m)^\s*struct\s+` + regexp.QuoteMeta(name) + `\s*\{`)
	loc := marker.FindStringIndex(src)
	if loc == nil {
		return nil, 0, fmt.Errorf("struct %s not found", name)
	}

	body := src[loc[1]:]
	if end := strings.Index(body, "};"); end >= 0 {
		body = body[:end]
	} else {
		return nil, 0, fmt.Errorf("unterminated struct %s", name)
	}

	lines := strings.Split(body, "\n")

	fields := make([]cField, 0, len(lines))
	offset := 0

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if idx := strings.Index(line, "//"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}

		m := reField.FindStringSubmatch(line)
		if m == nil {
			return nil, 0, fmt.Errorf("could not parse field %q in struct %s", line, name)
		}

		// For arrays the alignment is that of the element type.
		align, ok := cTypeWidths[m[1]]
		if !ok {
			return nil, 0, fmt.Errorf("unknown C type %q in struct %s", m[1], name)
		}
		width := align

		if m[4] != "" { // array
			count, err := strconv.Atoi(m[4])
			if err != nil {
				resolved, found := defines[m[4]]
				if !found {
					return nil, 0, fmt.Errorf("unresolved array length %q in struct %s", m[4], name)
				}
				count = resolved
			}
			width *= count
		}

		// Insert the implicit padding the compiler would add before this field.
		if rem := offset % align; rem != 0 {
			offset += align - rem
		}

		fields = append(fields, cField{name: m[2], offset: offset, width: width})
		offset += width
	}

	if len(fields) == 0 {
		return nil, 0, fmt.Errorf("struct %s has no parsable fields", name)
	}

	return fields, offset, nil
}
