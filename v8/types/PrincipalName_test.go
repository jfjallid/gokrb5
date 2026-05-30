package types

import (
	"testing"

	"github.com/jfjallid/gokrb5/v8/iana/nametype"
)

func TestPrincipalName_Equal(t *testing.T) {
	t.Parallel()
	a := NewPrincipalName(nametype.KRB_NT_SRV_INST, "cifs/srv01.example.com")
	tests := []struct {
		name string
		b    PrincipalName
		want bool
	}{
		{"identical", NewPrincipalName(nametype.KRB_NT_SRV_INST, "cifs/srv01.example.com"), true},
		{"different name type still equal", NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "cifs/srv01.example.com"), true},
		{"case differs (host)", NewPrincipalName(nametype.KRB_NT_SRV_INST, "cifs/SRV01.example.com"), false},
		{"case differs (service)", NewPrincipalName(nametype.KRB_NT_SRV_INST, "CIFS/srv01.example.com"), false},
		{"length differs", NewPrincipalName(nametype.KRB_NT_SRV_INST, "cifs"), false},
		{"different host", NewPrincipalName(nametype.KRB_NT_SRV_INST, "cifs/srv02.example.com"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.Equal(tc.b); got != tc.want {
				t.Errorf("Equal(%v) = %v, want %v", tc.b.NameString, got, tc.want)
			}
		})
	}
}

func TestPrincipalName_EqualFold(t *testing.T) {
	t.Parallel()
	a := NewPrincipalName(nametype.KRB_NT_SRV_INST, "cifs/srv01.example.com")
	tests := []struct {
		name string
		b    PrincipalName
		want bool
	}{
		{"identical", NewPrincipalName(nametype.KRB_NT_SRV_INST, "cifs/srv01.example.com"), true},
		{"host case differs", NewPrincipalName(nametype.KRB_NT_SRV_INST, "cifs/SRV01.example.com"), true},
		{"service case differs", NewPrincipalName(nametype.KRB_NT_SRV_INST, "CIFS/srv01.example.com"), true},
		{"all upper", NewPrincipalName(nametype.KRB_NT_SRV_INST, "CIFS/SRV01.EXAMPLE.COM"), true},
		{"different name type, same string", NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "Cifs/Srv01.Example.Com"), true},
		{"different host", NewPrincipalName(nametype.KRB_NT_SRV_INST, "cifs/srv02.example.com"), false},
		{"different service", NewPrincipalName(nametype.KRB_NT_SRV_INST, "host/srv01.example.com"), false},
		{"length differs", NewPrincipalName(nametype.KRB_NT_SRV_INST, "cifs"), false},
		{"empty vs empty", NewPrincipalName(nametype.KRB_NT_UNKNOWN, ""), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.EqualFold(tc.b); got != tc.want {
				t.Errorf("EqualFold(%v) = %v, want %v", tc.b.NameString, got, tc.want)
			}
		})
	}
}

// EqualFold must remain symmetric.
func TestPrincipalName_EqualFold_Symmetric(t *testing.T) {
	t.Parallel()
	a := NewPrincipalName(nametype.KRB_NT_SRV_INST, "cifs/SRV01.Example.COM")
	b := NewPrincipalName(nametype.KRB_NT_SRV_INST, "CIFS/srv01.example.com")
	if a.EqualFold(b) != b.EqualFold(a) {
		t.Errorf("EqualFold not symmetric: a.EqualFold(b)=%v b.EqualFold(a)=%v", a.EqualFold(b), b.EqualFold(a))
	}
	if !a.EqualFold(b) {
		t.Errorf("expected case-insensitive match")
	}
}
