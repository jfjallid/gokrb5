package client

import (
	"testing"
	"time"

	"github.com/jfjallid/gokrb5/v8/config"
	"github.com/jfjallid/gokrb5/v8/credentials"
	"github.com/jfjallid/gokrb5/v8/iana/nametype"
	"github.com/jfjallid/gokrb5/v8/keytab"
	"github.com/jfjallid/gokrb5/v8/messages"
	"github.com/jfjallid/gokrb5/v8/types"
)

// dummyTicketBytes returns the ASN.1 marshalled form of a minimal valid
// Ticket. The cryptographic contents are placeholders — only the bytes need
// to round-trip through Ticket.Unmarshal, which is all the CCache-loading
// path in NewFromCCacheWithFallbacks requires of them.
func dummyTicketBytes() ([]byte, error) {
	t := messages.Ticket{
		TktVNO: 5,
		Realm:  "TEST.REALM",
		SName: types.PrincipalName{
			NameType:   nametype.KRB_NT_SRV_INST,
			NameString: []string{"krbtgt", "TEST.REALM"},
		},
	}
	return t.Marshal()
}

// newTestCCache constructs an in-memory CCache containing a single krbtgt
// credential, suitable for exercising NewFromCCacheWithFallbacks without
// touching the filesystem or a real KDC. The principalRealm is the realm
// the cache's default principal advertises; the krbtgtRealm is the realm
// recorded in the krbtgt server-principal entry — different values let a
// test cover the DNS / NetBIOS mismatch case.
func newTestCCache(principalRealm, krbtgtRealm string, ticketBytes []byte) *credentials.CCache {
	cc := credentials.NewV4CCache()
	cc.SetDefaultPrincipal(credentials.NewPrincipal(
		types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"u"}},
		principalRealm,
	))
	cc.AddCredential(&credentials.Credential{
		Client: credentials.NewPrincipal(
			types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"u"}},
			principalRealm,
		),
		Server: credentials.NewPrincipal(
			types.PrincipalName{NameType: nametype.KRB_NT_SRV_INST, NameString: []string{"krbtgt", krbtgtRealm}},
			principalRealm,
		),
		AuthTime:  time.Now().UTC(),
		StartTime: time.Now().UTC(),
		EndTime:   time.Now().UTC().Add(time.Hour),
		RenewTill: time.Now().UTC().Add(2 * time.Hour),
		Ticket:    ticketBytes,
	})
	return cc
}

func TestAssumePreauthentication(t *testing.T) {
	t.Parallel()

	cl, err := NewWithKeytab("username", "REALM", &keytab.Keytab{}, &config.Config{}, AssumePreAuthentication(true))
	if err != nil {
		t.Fatalf("unexpected error from NewWithKeytab: %v", err)
	}
	if !cl.settings.assumePreAuthentication {
		t.Fatal("assumePreAuthentication should be true")
	}
	if !cl.settings.AssumePreAuthentication() {
		t.Fatal("AssumePreAuthentication() should be true")
	}
}

// TestSessionLookupViaAlias verifies that a session stored under one realm
// form is found by sessions.get() under any equivalent form, via the alias
// table. This is the user-visible payoff of Step 2.
func TestSessionLookupViaAlias(t *testing.T) {
	t.Parallel()

	cl, err := NewWithKeytab("u", "CORP.EXAMPLE.COM", &keytab.Keytab{}, &config.Config{})
	if err != nil {
		t.Fatalf("unexpected error from NewWithKeytab: %v", err)
	}
	cl.AddRealmAlias("CORP", "CORP.EXAMPLE.COM")

	cl.sessions.update(&session{realm: "CORP.EXAMPLE.COM"})

	if _, ok := cl.sessions.get("CORP.EXAMPLE.COM"); !ok {
		t.Error("session not found under the form it was stored under")
	}
	if _, ok := cl.sessions.get("CORP"); !ok {
		t.Error("session not found under the NetBIOS short form after AddRealmAlias")
	}
	if _, ok := cl.sessions.get("corp.example.com."); !ok {
		t.Error("session not found under a case- and trailing-dot variant of the same realm")
	}
	if _, ok := cl.sessions.get("OTHER.EXAMPLE.COM"); ok {
		t.Error("unrelated realm should NOT resolve to the stored session")
	}
}

// TestSessionStoredUnderCanonicalKey verifies the keying invariant: two
// updates referring to the same realm by different name forms collapse to
// a single map entry.
func TestSessionStoredUnderCanonicalKey(t *testing.T) {
	t.Parallel()

	cl, err := NewWithKeytab("u", "CORP.EXAMPLE.COM", &keytab.Keytab{}, &config.Config{})
	if err != nil {
		t.Fatalf("unexpected error from NewWithKeytab: %v", err)
	}
	cl.AddRealmAlias("CORP", "CORP.EXAMPLE.COM")

	cl.sessions.update(&session{realm: "corp.example.com"})
	cl.sessions.update(&session{realm: "CORP"})

	cl.sessions.mux.RLock()
	defer cl.sessions.mux.RUnlock()
	if got := len(cl.sessions.Entries); got != 1 {
		t.Errorf("expected 1 session entry after two equivalent updates, got %d", got)
	}
}

// TestClientSeedsAliasesFromConfig verifies that aliases declared in the
// Config's [realm_aliases] section are available immediately on the new
// client without any further setup — the user-visible payoff of Step 3a.
func TestClientSeedsAliasesFromConfig(t *testing.T) {
	t.Parallel()

	cfg := config.New()
	cfg.RealmAliases.Add("CORP", "CORP.EXAMPLE.COM")

	cl, err := NewWithKeytab("u", "CORP.EXAMPLE.COM", &keytab.Keytab{}, cfg)
	if err != nil {
		t.Fatalf("unexpected error from NewWithKeytab: %v", err)
	}
	if !cl.IsSameRealm("CORP", "CORP.EXAMPLE.COM") {
		t.Error("client should inherit [realm_aliases] entry from Config")
	}

	// Snapshot semantics: post-construction Config additions are NOT visible.
	cfg.RealmAliases.Add("WEST", "WEST.EXAMPLE.COM")
	if cl.IsSameRealm("WEST", "WEST.EXAMPLE.COM") {
		t.Error("post-construction Config mutations must not leak into already-constructed clients")
	}
}

// TestNewFromCCacheRegistersShortFormAlias verifies that when the krbtgt
// entry in the CCache uses the NetBIOS short form and the principal's
// realm uses the DNS long form, NewFromCCacheWithFallbacks records the
// equivalence on the client's alias table.
func TestNewFromCCacheRegistersShortFormAlias(t *testing.T) {
	t.Parallel()

	ticketBytes, err := dummyTicketBytes()
	if err != nil {
		t.Fatalf("could not build dummy ticket: %v", err)
	}

	cc := newTestCCache("CORP.EXAMPLE.COM", "CORP", ticketBytes)

	cl, _, err := NewFromCCacheWithFallbacks(cc, nil, &config.Config{})
	if err != nil {
		t.Fatalf("unexpected error from NewFromCCacheWithFallbacks: %v", err)
	}

	if !cl.IsSameRealm("CORP", "CORP.EXAMPLE.COM") {
		t.Error("expected alias CORP <-> CORP.EXAMPLE.COM to be registered")
	}
	if _, ok := cl.sessions.get("CORP.EXAMPLE.COM"); !ok {
		t.Error("session lookup under DNS long form should succeed")
	}
	if _, ok := cl.sessions.get("CORP"); !ok {
		t.Error("session lookup under NetBIOS short form should succeed")
	}
}

// TestNewFromCCacheReverseFormMatch verifies the case Step 2 couldn't
// handle on its own: the default principal advertises the NetBIOS short
// form and the krbtgt in the cache uses the DNS long form. The match must
// succeed via the alias-aware scan and register the equivalence so later
// lookups under either form resolve to the same session.
func TestNewFromCCacheReverseFormMatch(t *testing.T) {
	t.Parallel()

	ticketBytes, err := dummyTicketBytes()
	if err != nil {
		t.Fatalf("could not build dummy ticket: %v", err)
	}
	cc := newTestCCache("CORP", "CORP.EXAMPLE.COM", ticketBytes)

	cl, _, err := NewFromCCacheWithFallbacks(cc, nil, &config.Config{})
	if err != nil {
		t.Fatalf("unexpected error from NewFromCCacheWithFallbacks: %v", err)
	}
	if !cl.IsSameRealm("CORP", "CORP.EXAMPLE.COM") {
		t.Error("expected alias CORP <-> CORP.EXAMPLE.COM to be registered from reverse-form match")
	}
	if _, ok := cl.sessions.get("CORP"); !ok {
		t.Error("session lookup under short form should succeed")
	}
	if _, ok := cl.sessions.get("CORP.EXAMPLE.COM"); !ok {
		t.Error("session lookup under long form should succeed (via alias)")
	}
}

// TestNewFromCCacheUsesConfigAlias verifies that an alias declared up front
// in the Config (via [realm_aliases]) lets the CCache loader find a TGT
// whose realm form differs from the default principal's, without falling
// back to the speculative short-form heuristic.
func TestNewFromCCacheUsesConfigAlias(t *testing.T) {
	t.Parallel()

	ticketBytes, err := dummyTicketBytes()
	if err != nil {
		t.Fatalf("could not build dummy ticket: %v", err)
	}
	// "PROD" is not the first DNS label of "CORP.EXAMPLE.COM", so the
	// short-form heuristic can't reach it. Only the config-declared alias can.
	cc := newTestCCache("CORP.EXAMPLE.COM", "PROD", ticketBytes)

	cfg := config.New()
	cfg.RealmAliases.Add("PROD", "CORP.EXAMPLE.COM")

	cl, _, err := NewFromCCacheWithFallbacks(cc, nil, cfg)
	if err != nil {
		t.Fatalf("unexpected error from NewFromCCacheWithFallbacks: %v", err)
	}
	if _, ok := cl.sessions.get("CORP.EXAMPLE.COM"); !ok {
		t.Error("session lookup under default principal's realm should succeed via config alias")
	}
	if _, ok := cl.sessions.get("PROD"); !ok {
		t.Error("session lookup under config-aliased form should succeed")
	}
}

// TestNewFromCCacheNoSpuriousAlias verifies that when the CCache's krbtgt
// entry matches the principal's own realm exactly, no alias is recorded —
// guarding against accidental same-realm aliases that would be no-ops at
// best and confusing in debug output at worst.
func TestNewFromCCacheNoSpuriousAlias(t *testing.T) {
	t.Parallel()

	ticketBytes, err := dummyTicketBytes()
	if err != nil {
		t.Fatalf("could not build dummy ticket: %v", err)
	}

	cc := newTestCCache("CORP.EXAMPLE.COM", "CORP.EXAMPLE.COM", ticketBytes)

	cl, _, err := NewFromCCacheWithFallbacks(cc, nil, &config.Config{})
	if err != nil {
		t.Fatalf("unexpected error from NewFromCCacheWithFallbacks: %v", err)
	}

	eq := cl.RealmAliases().Equivalents("CORP.EXAMPLE.COM")
	if len(eq) != 1 || eq[0] != "CORP.EXAMPLE.COM" {
		t.Errorf("expected no aliases recorded, got %v", eq)
	}
}
