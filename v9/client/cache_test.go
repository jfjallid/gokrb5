package client

import (
	"testing"
	"time"

	"github.com/jfjallid/gofork/encoding/asn1"
	"github.com/jfjallid/gokrb5/v9/iana/nametype"
	"github.com/jfjallid/gokrb5/v9/messages"
	"github.com/jfjallid/gokrb5/v9/types"
)

// ticketForSPN builds a minimal ticket whose SName is the given (already
// KDC-canonical) SPN string. Only fields the cache reads are populated.
func ticketForSPN(spn string) messages.Ticket {
	return messages.Ticket{
		Realm: "EXAMPLE.COM",
		SName: types.NewPrincipalName(nametype.KRB_NT_SRV_INST, spn),
	}
}

// The KDC canonicalises the host of an SPN, so a ticket requested as
// "cifs/SRV01.example.com" is stored under the returned "cifs/srv01...".
// A later lookup with the original (mixed) casing must still hit the entry.
func TestCache_CaseInsensitiveLookup(t *testing.T) {
	t.Parallel()
	c := NewCache()
	now := time.Now().UTC()
	c.addEntry(
		ticketForSPN("cifs/srv01.example.com"), // KDC-canonical form
		now, now, now.Add(time.Hour), now.Add(2*time.Hour),
		types.EncryptionKey{}, asn1.BitString{},
	)

	for _, lookup := range []string{
		"cifs/srv01.example.com",
		"cifs/SRV01.example.com",
		"CIFS/SRV01.EXAMPLE.COM",
	} {
		if _, ok := c.getEntry(lookup); !ok {
			t.Errorf("getEntry(%q) missed; expected case-insensitive hit", lookup)
		}
	}

	// Only one entry should exist regardless of the casing used.
	if n := len(c.getEntries()); n != 1 {
		t.Errorf("expected exactly 1 cache entry, got %d", n)
	}
}

// The stored CacheEntry must preserve the KDC's canonical SPN, not the folded
// key, so anything saved to a ccache keeps the correct case.
func TestCache_PreservesCanonicalSPN(t *testing.T) {
	t.Parallel()
	c := NewCache()
	now := time.Now().UTC()
	e := c.addEntry(
		ticketForSPN("cifs/srv01.example.com"),
		now, now, now.Add(time.Hour), now.Add(2*time.Hour),
		types.EncryptionKey{}, asn1.BitString{},
	)
	if e.SPN != "cifs/srv01.example.com" {
		t.Errorf("CacheEntry.SPN = %q, want canonical KDC form", e.SPN)
	}
	got, _ := c.getEntry("cifs/SRV01.example.com")
	if got.SPN != "cifs/srv01.example.com" {
		t.Errorf("looked-up CacheEntry.SPN = %q, want canonical KDC form", got.SPN)
	}
}

// RemoveEntry must delete regardless of the casing supplied by the caller.
func TestCache_RemoveCaseInsensitive(t *testing.T) {
	t.Parallel()
	c := NewCache()
	now := time.Now().UTC()
	c.addEntry(
		ticketForSPN("cifs/srv01.example.com"),
		now, now, now.Add(time.Hour), now.Add(2*time.Hour),
		types.EncryptionKey{}, asn1.BitString{},
	)
	c.RemoveEntry("cifs/SRV01.EXAMPLE.COM")
	if _, ok := c.getEntry("cifs/srv01.example.com"); ok {
		t.Error("RemoveEntry with differing case did not remove the entry")
	}
}

// GetCachedTicket goes through the same folding and must return a valid,
// in-window ticket when asked with a different case than was stored.
func TestGetCachedTicket_CaseInsensitive(t *testing.T) {
	t.Parallel()
	cl := newClientForRealmTests(t, "EXAMPLE.COM")
	now := time.Now().UTC()
	cl.cache.addEntry(
		ticketForSPN("cifs/srv01.example.com"),
		now.Add(-time.Minute), now.Add(-time.Minute), now.Add(time.Hour), now.Add(2*time.Hour),
		types.EncryptionKey{}, asn1.BitString{},
	)
	if _, _, ok := cl.GetCachedTicket("cifs/SRV01.example.com"); !ok {
		t.Error("GetCachedTicket missed on mixed-case SPN; expected a hit")
	}
}
