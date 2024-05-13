package mstypes

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/jfjallid/gokrb5/v8/imported/rpc/v2/ndr"
	"github.com/jfjallid/gokrb5/v8/imported/testify/assert"
)

type testSIDStruct struct {
	SID RPCSID `ndr:"pointer"`
}

func Test_RPCSIDDecode(t *testing.T) {
	var tests = []struct {
		Hex string
		SID string
	}{
		{"040000000104000000000005150000005951b81766725d2564633b0b", "S-1-5-21-397955417-626881126-188441444"},
		{"05000000010500000000000515000000b9301b2eb7414c6c8c3b351501020000", "S-1-5-21-773533881-1816936887-355810188-513"},
		{"050000000105000000000005150000005951b81766725d2564633b0b74542f00", "S-1-5-21-397955417-626881126-188441444-3101812"},
		{"050000000105000000000005150000005951b81766725d2564633b0be8383200", "S-1-5-21-397955417-626881126-188441444-3291368"},
		{"050000000105000000000005150000005951b81766725d2564633b0b5db43200", "S-1-5-21-397955417-626881126-188441444-3322973"},
		{"050000000105000000000005150000005951b81766725d2564633b0b41163500", "S-1-5-21-397955417-626881126-188441444-3479105"},
		{"050000000105000000000005150000005951b81766725d2564633b0be8ea3100", "S-1-5-21-397955417-626881126-188441444-3271400"},
		{"050000000105000000000005150000005951b81766725d2564633b0bc1193200", "S-1-5-21-397955417-626881126-188441444-3283393"},
		{"050000000105000000000005150000005951b81766725d2564633b0b29f13200", "S-1-5-21-397955417-626881126-188441444-3338537"},
		{"050000000105000000000005150000005951b81766725d2564633b0b0f5f2e00", "S-1-5-21-397955417-626881126-188441444-3038991"},
		{"050000000105000000000005150000005951b81766725d2564633b0b2f5b2e00", "S-1-5-21-397955417-626881126-188441444-3037999"},
		{"050000000105000000000005150000005951b81766725d2564633b0bef8f3100", "S-1-5-21-397955417-626881126-188441444-3248111"},
		{"050000000105000000000005150000005951b81766725d2564633b0b075f2e00", "S-1-5-21-397955417-626881126-188441444-3038983"},
		{"040000000104000000000005150000004c86cebca07160e63fdce887", "S-1-5-21-3167651404-3865080224-2280184895"},
		{"050000000105000000000005150000004c86cebca07160e63fdce8875a040000", "S-1-5-21-3167651404-3865080224-2280184895-1114"},
		{"050000000105000000000005150000004c86cebca07160e63fdce88757040000", "S-1-5-21-3167651404-3865080224-2280184895-1111"},
	}

	for i, test := range tests {
		a := new(testSIDStruct)
		hexStr := TestNDRHeader + "01020304" + test.Hex //The 01000000 is a dumby value for the pointer uint32
		b, _ := hex.DecodeString(hexStr)
		dec := ndr.NewDecoder(bytes.NewReader(b))
		err := dec.Decode(a)
		if err != nil {
			t.Fatalf("test %d: %v", i+1, err)
		}
		assert.Equal(t, test.SID, a.SID.String(), "SID not as expected for test %d", i+1)

	}
}
