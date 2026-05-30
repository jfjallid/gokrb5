package credentials

import (
	"testing"

	"github.com/jfjallid/gokrb5/v8/iana/nametype"
	"github.com/jfjallid/gokrb5/v8/types"
)

func ccacheWithServerSPN(spn, realm string) *CCache {
	c := NewV4CCache()
	c.AddCredential(&Credential{
		Server: NewPrincipal(types.NewPrincipalName(nametype.KRB_NT_SRV_INST, spn), realm),
	})
	return c
}

// A ccache produced by the KDC (or kinit/Rubeus/impacket) commonly holds the
// host in the canonical lower-case form. GetEntry/Contains must match it even
// when the caller asks with mixed/upper case.
func TestCCache_GetEntry_CaseInsensitive(t *testing.T) {
	t.Parallel()
	c := ccacheWithServerSPN("cifs/srv01.example.com", "EXAMPLE.COM")

	for _, q := range []string{
		"cifs/srv01.example.com",
		"cifs/SRV01.example.com",
		"CIFS/SRV01.EXAMPLE.COM",
	} {
		p := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, q)
		if _, ok := c.GetEntry(p); !ok {
			t.Errorf("GetEntry(%q) missed; expected case-insensitive hit", q)
		}
		if !c.Contains(p) {
			t.Errorf("Contains(%q) = false; expected case-insensitive hit", q)
		}
	}
}

func TestCCache_GetEntry_DistinctHostStillMisses(t *testing.T) {
	t.Parallel()
	c := ccacheWithServerSPN("cifs/srv01.example.com", "EXAMPLE.COM")
	p := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "cifs/srv02.example.com")
	if _, ok := c.GetEntry(p); ok {
		t.Error("GetEntry matched a genuinely different host")
	}
	if c.Contains(p) {
		t.Error("Contains matched a genuinely different host")
	}
}
