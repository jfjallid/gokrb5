package client

import (
	"testing"
	"time"

	"github.com/jfjallid/gokrb5/v9/config"
	"github.com/jfjallid/gokrb5/v9/credentials"
	"github.com/jfjallid/gokrb5/v9/iana/nametype"
	"github.com/jfjallid/gokrb5/v9/messages"
	"github.com/jfjallid/gokrb5/v9/types"
)

// serviceTicketBytes marshals a minimal service ticket with the given SName.
func serviceTicketBytes(t *testing.T, spn string) []byte {
	t.Helper()
	tkt := messages.Ticket{
		TktVNO: 5,
		Realm:  "TEST.REALM",
		SName:  types.NewPrincipalName(nametype.KRB_NT_SRV_INST, spn),
	}
	b, err := tkt.Marshal()
	if err != nil {
		t.Fatalf("marshalling service ticket: %v", err)
	}
	return b
}

// addServiceTicket appends a service-ticket credential whose server SName host
// is in canonical (lower-case) form, mirroring what AD writes into a ccache.
func addServiceTicket(cc *credentials.CCache, principalRealm, spn string, ticketBytes []byte) {
	cc.AddCredential(&credentials.Credential{
		Client: credentials.NewPrincipal(
			types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"u"}},
			principalRealm,
		),
		Server:    credentials.NewPrincipal(types.NewPrincipalName(nametype.KRB_NT_SRV_INST, spn), principalRealm),
		AuthTime:  time.Now().UTC(),
		StartTime: time.Now().UTC(),
		EndTime:   time.Now().UTC().Add(time.Hour),
		RenewTill: time.Now().UTC().Add(2 * time.Hour),
		Ticket:    ticketBytes,
	})
}

// A caller requesting "cifs/SRV01.TEST.REALM" must match a ccache entry the
// KDC wrote as "cifs/srv01.test.realm". Before the EqualFold change the
// byte-exact GetEntry would miss and matchedTarget would be nil.
func TestNewFromCCacheFallbackTargetCaseInsensitive(t *testing.T) {
	t.Parallel()
	tgtBytes, err := dummyTicketBytes()
	if err != nil {
		t.Fatalf("dummyTicketBytes: %v", err)
	}
	cc := newTestCCache("TEST.REALM", "TEST.REALM", tgtBytes)
	addServiceTicket(cc, "TEST.REALM", "cifs/srv01.test.realm",
		serviceTicketBytes(t, "cifs/srv01.test.realm"))

	// Request the same service with the host in upper case.
	targets := [][]string{{"cifs", "SRV01.TEST.REALM"}}
	_, matched, err := NewFromCCacheWithFallbacks(cc, targets, config.New())
	if err != nil {
		t.Fatalf("NewFromCCacheWithFallbacks: %v", err)
	}
	if matched == nil {
		t.Fatal("expected a matched target for mixed-case SPN, got nil")
	}
	if len(matched) != 2 || matched[1] != "SRV01.TEST.REALM" {
		t.Errorf("unexpected matched target: %v", matched)
	}
}

// The fallback service ("host") must also match case-insensitively against a
// ccache entry stored in canonical form.
func TestNewFromCCacheFallbackServiceCaseInsensitive(t *testing.T) {
	t.Parallel()
	tgtBytes, err := dummyTicketBytes()
	if err != nil {
		t.Fatalf("dummyTicketBytes: %v", err)
	}
	cc := newTestCCache("TEST.REALM", "TEST.REALM", tgtBytes)
	addServiceTicket(cc, "TEST.REALM", "host/srv01.test.realm",
		serviceTicketBytes(t, "host/srv01.test.realm"))

	// Primary target cifs (absent), fallback host (present, different case).
	targets := [][]string{
		{"cifs", "SRV01.TEST.REALM"},
		{"host", "SRV01.TEST.REALM"},
	}
	_, matched, err := NewFromCCacheWithFallbacks(cc, targets, config.New())
	if err != nil {
		t.Fatalf("NewFromCCacheWithFallbacks: %v", err)
	}
	if matched == nil || matched[0] != "host" {
		t.Errorf("expected fallback 'host' target to match, got %v", matched)
	}
}
