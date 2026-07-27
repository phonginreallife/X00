package secrets

import (
	"sort"
	"sync"
	"testing"
)

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Fatal("NewRegistry returned nil")
	}
	if got := r.Lookup("anything", 0); len(got) != 0 {
		t.Errorf("fresh registry returned %d secrets, want 0", len(got))
	}
}

func TestRegistry_RegisterForBinary(t *testing.T) {
	r := NewRegistry()
	r.RegisterForBinary("myapp", []Secret{
		{Name: "DB_PASSWORD", Value: "secret123"},
		{Name: "API_KEY", Value: "key456"},
	})

	got := r.Lookup("myapp", 0)
	if len(got) != 2 {
		t.Fatalf("Lookup returned %d secrets, want 2", len(got))
	}
}

func TestRegistry_RegisterForCgroup(t *testing.T) {
	r := NewRegistry()
	r.RegisterForCgroup(12345, []Secret{{Name: "CGROUP_SECRET", Value: "cgvalue"}})

	got := r.Lookup("unknown", 12345)
	if len(got) != 1 {
		t.Fatalf("Lookup returned %d secrets, want 1", len(got))
	}
	if got[0].Name != "CGROUP_SECRET" {
		t.Errorf("secret name = %q, want CGROUP_SECRET", got[0].Name)
	}
}

func TestRegistry_Lookup_Combined(t *testing.T) {
	r := NewRegistry()
	r.RegisterForBinary("myapp", []Secret{{Name: "BINARY_SECRET", Value: "binaryval"}})
	r.RegisterForCgroup(12345, []Secret{{Name: "CGROUP_SECRET", Value: "cgroupval"}})

	tests := []struct {
		name     string
		binary   string
		cgroupID uint64
		want     []string
	}{
		{"both match", "myapp", 12345, []string{"BINARY_SECRET", "CGROUP_SECRET"}},
		{"binary only", "myapp", 99999, []string{"BINARY_SECRET"}},
		{"cgroup only", "otherapp", 12345, []string{"CGROUP_SECRET"}},
		{"neither", "otherapp", 99999, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.Lookup(tt.binary, tt.cgroupID)
			if len(got) != len(tt.want) {
				t.Fatalf("Lookup returned %d secrets, want %d", len(got), len(tt.want))
			}
			for i, name := range tt.want {
				if got[i].Name != name {
					t.Errorf("secret[%d] = %q, want %q", i, got[i].Name, name)
				}
			}
		})
	}
}

func TestRegistry_RegisterForBinary_Replaces(t *testing.T) {
	r := NewRegistry()
	r.RegisterForBinary("myapp", []Secret{{Name: "OLD_SECRET", Value: "old"}})
	r.RegisterForBinary("myapp", []Secret{{Name: "NEW_SECRET", Value: "new"}})

	got := r.Lookup("myapp", 0)
	if len(got) != 1 {
		t.Fatalf("Lookup returned %d secrets, want 1", len(got))
	}
	if got[0].Name != "NEW_SECRET" {
		t.Errorf("secret name = %q, want NEW_SECRET", got[0].Name)
	}
}

// Lookup returns a copy, so a caller holding the result must not be affected by
// a later re-registration.
func TestRegistry_Lookup_ResultIsolated(t *testing.T) {
	r := NewRegistry()
	r.RegisterForBinary("myapp", []Secret{{Name: "FIRST", Value: "1"}})

	held := r.Lookup("myapp", 0)
	r.RegisterForBinary("myapp", []Secret{{Name: "SECOND", Value: "2"}})

	if held[0].Name != "FIRST" {
		t.Errorf("previously returned slice mutated to %q", held[0].Name)
	}
}

func TestRegistry_TargetBinaries(t *testing.T) {
	r := NewRegistry()
	r.RegisterForBinary("alpha", []Secret{{Name: "A", Value: "1"}})
	r.RegisterForBinary("beta", []Secret{{Name: "B", Value: "2"}})
	r.RegisterForCgroup(7, []Secret{{Name: "C", Value: "3"}})

	got := r.TargetBinaries()
	sort.Strings(got)

	want := []string{"alpha", "beta"}
	if len(got) != len(want) {
		t.Fatalf("TargetBinaries = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("TargetBinaries = %v, want %v", got, want)
		}
	}
}

func TestRegistry_ConcurrentAccess(t *testing.T) {
	r := NewRegistry()

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			r.RegisterForBinary("app1", []Secret{{Name: "SECRET", Value: "value"}})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = r.Lookup("app1", 0)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = r.TargetBinaries()
		}
	}()

	wg.Wait()
}
