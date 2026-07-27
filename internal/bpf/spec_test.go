package bpf

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
)

// These tests check that every program and map the Go loader asks for by name
// actually exists in the compiled BPF objects.
//
// LoadAndAssign resolves the `ebpf:"..."` struct tags below against the object
// file, and a name that does not exist fails at startup rather than at compile
// time. Renaming a BPF function or map without updating the tag has broken this
// project before, so it is asserted here.
//
// Parsing an object's ELF and BTF needs no privileges and no BPF support, so
// unlike actually loading the programs, this runs anywhere.

func objectPath(t *testing.T, name string) string {
	t.Helper()

	path, err := filepath.Abs(filepath.Join("..", "..", "bpf", name))
	if err != nil {
		t.Fatalf("resolving %s: %v", name, err)
	}
	return path
}

// taggedNames returns the ebpf tag of every field of a struct, paired with
// whether the field is a program or a map.
func taggedNames(t *testing.T, v any) (programs, maps []string) {
	t.Helper()

	typ := reflect.TypeOf(v)
	programType := reflect.TypeOf((*ebpf.Program)(nil))
	mapType := reflect.TypeOf((*ebpf.Map)(nil))

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)

		name, ok := field.Tag.Lookup("ebpf")
		if !ok {
			t.Errorf("%s.%s has no ebpf tag", typ.Name(), field.Name)
			continue
		}

		switch field.Type {
		case programType:
			programs = append(programs, name)
		case mapType:
			maps = append(maps, name)
		default:
			t.Errorf("%s.%s has unexpected type %s", typ.Name(), field.Name, field.Type)
		}
	}

	return programs, maps
}

func assertSpecContains(t *testing.T, objectFile string, v any) {
	t.Helper()

	path := objectPath(t, objectFile)

	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		t.Skipf("%s not available (run make bpf): %v", objectFile, err)
	}

	programs, maps := taggedNames(t, v)

	if len(programs) == 0 || len(maps) == 0 {
		t.Fatalf("no programs or maps discovered from tags; the test is broken")
	}

	for _, name := range programs {
		if _, ok := spec.Programs[name]; !ok {
			t.Errorf("%s has no program %q; the ebpf struct tag and the BPF source disagree",
				objectFile, name)
		}
	}

	for _, name := range maps {
		if _, ok := spec.Maps[name]; !ok {
			t.Errorf("%s has no map %q; the ebpf struct tag and the BPF source disagree",
				objectFile, name)
		}
	}
}

func TestSpec_ExecMonitorNamesMatch(t *testing.T) {
	assertSpecContains(t, "exec_monitor.bpf.o", execObjects{})
}

func TestSpec_LSMNamesMatch(t *testing.T) {
	assertSpecContains(t, "lsm_file_protect.bpf.o", lsmObjects{})
}

// The LSM policy map's value size must match the Go PolicyConfig that writes it.
// The map update succeeds regardless of field order, so a size check is the only
// thing the kernel itself would catch; internal/types pins the field offsets.
func TestSpec_PolicyMapValueSize(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpec(objectPath(t, "lsm_file_protect.bpf.o"))
	if err != nil {
		t.Skipf("LSM object not available (run make bpf): %v", err)
	}

	policyMap, ok := spec.Maps["policy_config"]
	if !ok {
		t.Fatal("lsm_file_protect.bpf.o has no policy_config map")
	}

	const wantSize = 8 // struct ks_policy_config
	if policyMap.ValueSize != wantSize {
		t.Errorf("policy_config value size = %d, want %d", policyMap.ValueSize, wantSize)
	}
}

// protected_pids and ks_allowed_pids are keyed by PID and hold a single flag byte.
// A mismatch here would silently fail to protect processes.
func TestSpec_PIDMapShapes(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpec(objectPath(t, "lsm_file_protect.bpf.o"))
	if err != nil {
		t.Skipf("LSM object not available (run make bpf): %v", err)
	}

	for _, name := range []string{"protected_pids", "ks_allowed_pids"} {
		t.Run(name, func(t *testing.T) {
			m, ok := spec.Maps[name]
			if !ok {
				t.Fatalf("lsm_file_protect.bpf.o has no map %q", name)
			}
			if m.KeySize != 4 {
				t.Errorf("%s key size = %d, want 4 (uint32 PID)", name, m.KeySize)
			}
			if m.ValueSize != 1 {
				t.Errorf("%s value size = %d, want 1 (uint8 flag)", name, m.ValueSize)
			}
		})
	}
}

// TrackPID writes a uint64 into seen_pids, so the map must agree.
func TestSpec_SeenPidsShape(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpec(objectPath(t, "exec_monitor.bpf.o"))
	if err != nil {
		t.Skipf("exec monitor object not available (run make bpf): %v", err)
	}

	m, ok := spec.Maps["seen_pids"]
	if !ok {
		t.Fatal("exec_monitor.bpf.o has no seen_pids map")
	}
	if m.KeySize != 4 {
		t.Errorf("seen_pids key size = %d, want 4 (uint32 PID)", m.KeySize)
	}
	if m.ValueSize != 8 {
		t.Errorf("seen_pids value size = %d, want 8 (uint64 timestamp)", m.ValueSize)
	}
}

// AddTargetBinary writes a 16-byte key, matching char[16] on the BPF side.
func TestSpec_TargetBinariesKeySize(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpec(objectPath(t, "exec_monitor.bpf.o"))
	if err != nil {
		t.Skipf("exec monitor object not available (run make bpf): %v", err)
	}

	m, ok := spec.Maps["target_binaries"]
	if !ok {
		t.Fatal("exec_monitor.bpf.o has no target_binaries map")
	}

	// AddTargetBinary builds a fixed 16-byte key; a mismatch would make every
	// lookup miss and silently disable filtering.
	if m.KeySize != 16 {
		t.Errorf("target_binaries key size = %d, want 16", m.KeySize)
	}
}
