package client

import (
	"testing"

	"github.com/jfjallid/gokrb5/v8/config"
	"github.com/jfjallid/gokrb5/v8/keytab"
)

func newClientForRealmTests(t *testing.T, clientRealm string, opts ...func(*Settings)) *Client {
	t.Helper()
	cl, err := NewWithKeytab("u", clientRealm, &keytab.Keytab{}, config.New(), opts...)
	if err != nil {
		t.Fatalf("NewWithKeytab: %v", err)
	}
	return cl
}

func TestResolveTargetRealm_DCDomainOverride(t *testing.T) {
	t.Parallel()
	cl := newClientForRealmTests(t, "HOME.REALM")
	if got := cl.resolveTargetRealm("cifs/server01.foo.example.com", "PROD.REALM"); got != "PROD.REALM" {
		t.Errorf("expected dcDomain override to win, got %q", got)
	}
}

func TestResolveTargetRealm_KrbtgtSPN(t *testing.T) {
	t.Parallel()
	cl := newClientForRealmTests(t, "HOME.REALM")
	if got := cl.resolveTargetRealm("krbtgt/foreign.example.com", ""); got != "FOREIGN.EXAMPLE.COM" {
		t.Errorf("krbtgt SPN realm should be the second component uppercased, got %q", got)
	}
}

func TestResolveTargetRealm_DomainRealmConfig(t *testing.T) {
	t.Parallel()
	cl := newClientForRealmTests(t, "HOME.REALM")
	cl.Config.DomainRealm[".foo.example.com"] = "FOO.EXAMPLE.COM"

	if got := cl.resolveTargetRealm("cifs/server01.foo.example.com", ""); got != "FOO.EXAMPLE.COM" {
		t.Errorf("expected [domain_realm] match, got %q", got)
	}
}

func TestResolveTargetRealm_SuffixHeuristic(t *testing.T) {
	t.Parallel()
	cl := newClientForRealmTests(t, "HOME.REALM")
	// Default suffix-strip heuristic is enabled.
	if got := cl.resolveTargetRealm("cifs/server01.foo.example.com", ""); got != "FOO.EXAMPLE.COM" {
		t.Errorf("expected suffix-strip to produce FOO.EXAMPLE.COM, got %q", got)
	}
}

func TestResolveTargetRealm_SuffixHeuristicDisabled(t *testing.T) {
	t.Parallel()
	cl := newClientForRealmTests(t, "HOME.REALM", AllowDomainSuffixRealmGuess(false))
	// With heuristic off and no [domain_realm] / DNS / alias hit, falls
	// through to the client's own realm.
	if got := cl.resolveTargetRealm("cifs/server01.foo.example.com", ""); got != "HOME.REALM" {
		t.Errorf("with heuristic disabled, expected fallback to client realm, got %q", got)
	}
}

func TestResolveTargetRealm_FallbackToClientRealm(t *testing.T) {
	t.Parallel()
	cl := newClientForRealmTests(t, "HOME.REALM")
	// Bare hostname with no dots — suffix-strip has nothing to do, no
	// other source matches. Should fall through to the client's realm.
	if got := cl.resolveTargetRealm("cifs/server01", ""); got != "HOME.REALM" {
		t.Errorf("expected fallback to client realm for bare hostname, got %q", got)
	}
}

func TestResolveTargetRealm_PriorityDomainRealmOverHeuristic(t *testing.T) {
	t.Parallel()
	cl := newClientForRealmTests(t, "HOME.REALM")
	// A [domain_realm] entry pointing at a DIFFERENT realm than the
	// suffix would produce. The config must win.
	cl.Config.DomainRealm[".foo.example.com"] = "OVERRIDE.REALM"
	if got := cl.resolveTargetRealm("cifs/server01.foo.example.com", ""); got != "OVERRIDE.REALM" {
		t.Errorf("expected [domain_realm] to win over suffix heuristic, got %q", got)
	}
}

func TestResolveTargetRealm_NoSPNSlash(t *testing.T) {
	t.Parallel()
	cl := newClientForRealmTests(t, "HOME.REALM")
	cl.Config.DomainRealm[".example.com"] = "EXAMPLE.COM"
	// SPN with no "/" — treat the whole string as a host.
	if got := cl.resolveTargetRealm("host.example.com", ""); got != "EXAMPLE.COM" {
		t.Errorf("expected slashless SPN to be treated as host, got %q", got)
	}
}

func TestResolveTargetRealm_DNSLookupDisabledByDefault(t *testing.T) {
	t.Parallel()
	cl := newClientForRealmTests(t, "HOME.REALM")
	// DNSLookupRealm defaults to false, so lookupRealmDNS must not be
	// called even if it would succeed. We can't intercept net.LookupTXT
	// from here, but we can confirm the flag gating: with the heuristic
	// also off and no config entry, the result must be the client realm,
	// regardless of what DNS would say.
	cl.settings.allowDomainSuffixRealmGuess = false
	if got := cl.resolveTargetRealm("cifs/server01.dns-only.example", ""); got != "HOME.REALM" {
		t.Errorf("with DNSLookupRealm off and no other source, expected client realm, got %q", got)
	}
}
