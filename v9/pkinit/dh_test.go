package pkinit

import (
	"math/big"
	"testing"
)

func TestValidateDHPublicKey(t *testing.T) {
	p := oakleyGroup2P
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))

	good := []*big.Int{
		big.NewInt(2),
		big.NewInt(42),
		new(big.Int).Sub(p, big.NewInt(2)), // p-2
	}
	for _, y := range good {
		if err := ValidateDHPublicKey(y, p); err != nil {
			t.Errorf("expected y=%s to be accepted, got: %v", y.String(), err)
		}
	}

	bad := map[string]*big.Int{
		"zero":  big.NewInt(0),
		"one":   big.NewInt(1),
		"p-1":   pMinus1,
		"p":     new(big.Int).Set(p),
		"p+1":   new(big.Int).Add(p, big.NewInt(1)),
		"neg":   big.NewInt(-5),
		"nil_y": nil,
	}
	for name, y := range bad {
		if err := ValidateDHPublicKey(y, p); err == nil {
			t.Errorf("expected y=%s (%s) to be rejected, but it was accepted", strOrNil(y), name)
		}
	}
}

func strOrNil(y *big.Int) string {
	if y == nil {
		return "<nil>"
	}
	return y.String()
}
