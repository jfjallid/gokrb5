package config

import (
	"sort"
	"sync"
	"testing"
)

func TestCanonicalRealm(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"CORP.EXAMPLE.COM", "CORP.EXAMPLE.COM"},
		{"corp.example.com", "CORP.EXAMPLE.COM"},
		{"Corp.Example.Com.", "CORP.EXAMPLE.COM"},
		{"corp", "CORP"},
		{".", ""},
	}
	for _, c := range cases {
		if got := CanonicalRealm(c.in); got != c.want {
			t.Errorf("CanonicalRealm(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestEqualRealm(t *testing.T) {
	t.Parallel()
	if !EqualRealm("CORP.EXAMPLE.COM", "corp.example.com.") {
		t.Error("case- and trailing-dot equivalent realms should compare equal")
	}
	if EqualRealm("CORP", "CORP.EXAMPLE.COM") {
		t.Error("short and long forms should NOT compare equal without an alias")
	}
	if !EqualRealm("", "") {
		t.Error("two empty realms should compare equal")
	}
}

func TestRealmAliases_AddAndResolve(t *testing.T) {
	t.Parallel()
	a := NewRealmAliases()

	// Empty input is a no-op.
	a.Add("", "CORP.EXAMPLE.COM")
	a.Add("CORP", "")
	if got := a.Resolve("CORP"); got != "CORP" {
		t.Errorf("after no-op Adds, Resolve(CORP) = %q, want CORP", got)
	}

	a.Add("CORP", "CORP.EXAMPLE.COM")
	if got := a.Resolve("corp"); got != "CORP.EXAMPLE.COM" {
		t.Errorf("Resolve(corp) = %q, want CORP.EXAMPLE.COM", got)
	}
	if got := a.Resolve("corp.example.com."); got != "CORP.EXAMPLE.COM" {
		t.Errorf("Resolve of the canonical form should return canonical, got %q", got)
	}
	if got := a.Resolve(""); got != "" {
		t.Errorf("Resolve(\"\") = %q, want empty", got)
	}
}

func TestRealmAliases_SameCanonicalIgnored(t *testing.T) {
	t.Parallel()
	a := NewRealmAliases()
	a.Add("corp.example.com", "CORP.EXAMPLE.COM.")
	if got := len(a.toCanon); got != 0 {
		t.Errorf("toCanon should be empty (both sides canonicalize to the same value), got %d entries", got)
	}
}

func TestRealmAliases_ChainCollapsing(t *testing.T) {
	t.Parallel()
	a := NewRealmAliases()
	// A -> B -> C should collapse so A points directly at C.
	a.Add("B", "C")
	a.Add("A", "B")
	if got := a.Resolve("A"); got != "C" {
		t.Errorf("Resolve(A) = %q, want C", got)
	}
	if got := a.toCanon["A"]; got != "C" {
		t.Errorf("after chain collapsing, toCanon[A] = %q, want C", got)
	}
}

func TestRealmAliases_Equivalents(t *testing.T) {
	t.Parallel()
	a := NewRealmAliases()
	a.Add("CORP", "CORP.EXAMPLE.COM")
	a.Add("corp.example.lan", "CORP.EXAMPLE.COM")

	got := a.Equivalents("corp")
	sort.Strings(got)
	want := []string{"CORP", "CORP.EXAMPLE.COM", "CORP.EXAMPLE.LAN"}
	if len(got) != len(want) {
		t.Fatalf("Equivalents = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("Equivalents[%d] = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}

func TestRealmAliases_AddAll(t *testing.T) {
	t.Parallel()
	src := NewRealmAliases()
	src.Add("CORP", "CORP.EXAMPLE.COM")
	src.Add("WEST", "WEST.EXAMPLE.COM")

	dst := NewRealmAliases()
	dst.AddAll(src)

	if got := dst.Resolve("corp"); got != "CORP.EXAMPLE.COM" {
		t.Errorf("dst.Resolve(corp) = %q, want CORP.EXAMPLE.COM", got)
	}
	if got := dst.Resolve("west"); got != "WEST.EXAMPLE.COM" {
		t.Errorf("dst.Resolve(west) = %q, want WEST.EXAMPLE.COM", got)
	}

	// Snapshot semantics: mutating src after AddAll must not affect dst.
	src.Add("EAST", "EAST.EXAMPLE.COM")
	if got := dst.Resolve("east"); got != "EAST" {
		t.Errorf("dst should not see post-AddAll additions to src, got Resolve(east) = %q", got)
	}

	// nil and self are no-ops, not crashes.
	dst.AddAll(nil)
	dst.AddAll(dst)
}

func TestRealmAliases_ParseLines(t *testing.T) {
	t.Parallel()
	a := NewRealmAliases()
	err := a.parseLines([]string{
		"CORP = CORP.EXAMPLE.COM",
		"  west  =  west.example.com  ; trailing comment",
		"# a pure comment line",
		"",
		"east= east.example.com",
	})
	if err != nil {
		t.Fatalf("parseLines returned error: %v", err)
	}
	cases := map[string]string{
		"corp": "CORP.EXAMPLE.COM",
		"WEST": "WEST.EXAMPLE.COM",
		"East": "EAST.EXAMPLE.COM",
	}
	for in, want := range cases {
		if got := a.Resolve(in); got != want {
			t.Errorf("Resolve(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRealmAliases_ParseLinesRejectsMalformed(t *testing.T) {
	t.Parallel()
	a := NewRealmAliases()
	err := a.parseLines([]string{"no equals sign here"})
	if err == nil {
		t.Error("expected error on line missing '=' separator")
	}
}

func TestRealmAliases_Concurrent(t *testing.T) {
	t.Parallel()
	a := NewRealmAliases()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); a.Add("CORP", "CORP.EXAMPLE.COM") }()
		go func() { defer wg.Done(); _ = a.Resolve("corp") }()
	}
	wg.Wait()
	if got := a.Resolve("CORP"); got != "CORP.EXAMPLE.COM" {
		t.Errorf("after concurrent Adds, Resolve = %q", got)
	}
}
