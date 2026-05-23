package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/jfjallid/gokrb5/v8/crypto/common"
	"github.com/jfjallid/gokrb5/v8/crypto/rfc8009"
)

func TestAes256CtsHmacSha384192_StringToKey(t *testing.T) {
	t.Parallel()
	// Test vectors from RFC 8009 Appendix A
	// Random 16bytes in test vector as string
	r, _ := hex.DecodeString("10DF9DD783E5BC8ACEA1730E74355F61")
	s := string(r)
	var tests = []struct {
		iterations uint32
		phrase     string
		salt       string
		saltp      string
		key        string
	}{
		{32768, "password", s + "ATHENA.MIT.EDUraeburn", "6165733235362d6374732d686d61632d7368613338342d3139320010df9dd783e5bc8acea1730e74355f61415448454e412e4d49542e4544557261656275726e", "45bd806dbf6a833a9cffc1c94589a222367a79bc21c413718906e9f578a78467"},
	}
	var e Aes256CtsHmacSha384192
	for _, test := range tests {
		saltp := rfc8009.GetSaltP(test.salt, "aes256-cts-hmac-sha384-192")
		if got := hex.EncodeToString([]byte(saltp)); got != test.saltp {
			t.Errorf("SaltP not as expected: got %s, want %s", got, test.saltp)
		}

		k, err := e.StringToKey(test.phrase, test.salt, common.IterationsToS2Kparams(test.iterations))
		if err != nil {
			t.Fatalf("StringToKey error: %v", err)
		}
		if got := hex.EncodeToString(k); got != test.key {
			t.Errorf("String to Key not as expected: got %s, want %s", got, test.key)
		}
	}
}

func TestAes256CtsHmacSha384192_DeriveKey(t *testing.T) {
	t.Parallel()
	// Test vectors from RFC 8009 Appendix A
	protocolBaseKey, _ := hex.DecodeString("6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52")
	testUsage := uint32(2)
	var e Aes256CtsHmacSha384192
	k, err := e.DeriveKey(protocolBaseKey, common.GetUsageKc(testUsage))
	if err != nil {
		t.Fatalf("Error deriving checksum key: %v", err)
	}
	if got := hex.EncodeToString(k); got != "ef5718be86cc84963d8bbb5031e9f5c4ba41f28faf69e73d" {
		t.Errorf("Checksum derived key not as expected: got %s", got)
	}
	k, err = e.DeriveKey(protocolBaseKey, common.GetUsageKe(testUsage))
	if err != nil {
		t.Fatalf("Error deriving encryption key: %v", err)
	}
	if got := hex.EncodeToString(k); got != "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49" {
		t.Errorf("Encryption derived key not as expected: got %s", got)
	}
	k, err = e.DeriveKey(protocolBaseKey, common.GetUsageKi(testUsage))
	if err != nil {
		t.Fatalf("Error deriving integrity key: %v", err)
	}
	if got := hex.EncodeToString(k); got != "69b16514e3cd8e56b82010d5c73012b622c4d00ffc23ed1f" {
		t.Errorf("Integrity derived key not as expected: got %s", got)
	}
}

func TestAes256CtsHmacSha384192_Cypto(t *testing.T) {
	t.Parallel()
	protocolBaseKey, _ := hex.DecodeString("6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52")
	testUsage := uint32(2)
	var tests = []struct {
		plain      string
		confounder string
		ke         string
		ki         string
		encrypted  string // AESOutput
		hash       string // TruncatedHMACOutput
		cipher     string // Ciphertext(AESOutput|HMACOutput)
	}{
		// Test vectors from RFC 8009 Appendix A
		{"", "f764e9fa15c276478b2c7d0c4e5f58e4", "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49", "69b16514e3cd8e56b82010d5c73012b622c4d00ffc23ed1f", "41f53fa5bfe7026d91faf9be959195a0", "58707273a96a40f0a01960621ac612748b9bbfbe7eb4ce3c", "41f53fa5bfe7026d91faf9be959195a058707273a96a40f0a01960621ac612748b9bbfbe7eb4ce3c"},
		{"000102030405", "b80d3251c1f6471494256ffe712d0b9a", "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49", "69b16514e3cd8e56b82010d5c73012b622c4d00ffc23ed1f", "4ed7b37c2bcac8f74f23c1cf07e62bc7b75fb3f637b9", "f559c7f664f69eab7b6092237526ea0d1f61cb20d69d10f2", "4ed7b37c2bcac8f74f23c1cf07e62bc7b75fb3f637b9f559c7f664f69eab7b6092237526ea0d1f61cb20d69d10f2"},
		{"000102030405060708090a0b0c0d0e0f", "53bf8a0d105265d4e276428624ce5e63", "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49", "69b16514e3cd8e56b82010d5c73012b622c4d00ffc23ed1f", "bc47ffec7998eb91e8115cf8d19dac4bbbe2e163e87dd37f49beca92027764f6", "8cf51f14d798c2273f35df574d1f932e40c4ff255b36a266", "bc47ffec7998eb91e8115cf8d19dac4bbbe2e163e87dd37f49beca92027764f68cf51f14d798c2273f35df574d1f932e40c4ff255b36a266"},
		{"000102030405060708090a0b0c0d0e0f1011121314", "763e65367e864f02f55153c7e3b58af1", "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49", "69b16514e3cd8e56b82010d5c73012b622c4d00ffc23ed1f", "40013e2df58e8751957d2878bcd2d6fe101ccfd556cb1eae79db3c3ee86429f2b2a602ac86", "fef6ecb647d6295fae077a1feb517508d2c16b4192e01f62", "40013e2df58e8751957d2878bcd2d6fe101ccfd556cb1eae79db3c3ee86429f2b2a602ac86fef6ecb647d6295fae077a1feb517508d2c16b4192e01f62"},
	}
	var e Aes256CtsHmacSha384192
	for i, test := range tests {
		m, _ := hex.DecodeString(test.plain)
		b, _ := hex.DecodeString(test.encrypted)
		ke, _ := hex.DecodeString(test.ke)
		cf, _ := hex.DecodeString(test.confounder)
		ct, _ := hex.DecodeString(test.cipher)
		cfm := append(cf, m...)

		// Test encryption to raw encrypted bytes
		_, c, err := e.EncryptData(ke, cfm)
		if err != nil {
			t.Errorf("encryption failed for test %v: %v", i+1, err)
		}
		if got := hex.EncodeToString(c); got != test.encrypted {
			t.Errorf("Encrypted result not as expected - test %v: got %s, want %s", i, got, test.encrypted)
		}

		// Test decryption of raw encrypted bytes
		p, err := e.DecryptData(ke, b)
		if err != nil {
			t.Errorf("decryption failed for test %v: %v", i+1, err)
		}
		// Remove the confounder bytes
		p = p[e.GetConfounderByteSize():]
		if got := hex.EncodeToString(p); got != test.plain {
			t.Errorf("Decrypted result not as expected - test %v: got %s, want %s", i, got, test.plain)
		}

		// Test integrity check of complete ciphertext message
		if !e.VerifyIntegrity(protocolBaseKey, ct, ct, testUsage) {
			t.Errorf("Integrity check of cipher text failed - test %v", i)
		}

		// Test encrypting and decrypting a complete cipertext message (with confounder, integrity hash)
		_, cm, err := e.EncryptMessage(protocolBaseKey, m, testUsage)
		if err != nil {
			t.Errorf("encryption to message failed for test %v: %v", i+1, err)
		}
		dm, err := e.DecryptMessage(protocolBaseKey, cm, testUsage)
		if err != nil {
			t.Errorf("decrypting complete encrypted message failed for test %v: %v", i+1, err)
		}
		if !bytes.Equal(m, dm) {
			t.Errorf("Message not as expected after encrypting and decrypting for test %v: got %x, want %x", i+1, dm, m)
		}

		// Test the integrity hash
		ivz := make([]byte, e.GetConfounderByteSize())
		hm := append(ivz, b...)
		mac, _ := common.GetIntegrityHash(hm, protocolBaseKey, testUsage, e)
		if got := hex.EncodeToString(mac); got != test.hash {
			t.Errorf("HMAC result not as expected - test %v: got %s, want %s", i, got, test.hash)
		}
	}
}

func TestAes256CtsHmacSha384192_VerifyIntegrity(t *testing.T) {
	t.Parallel()
	// Test vectors from RFC 8009
	protocolBaseKey, _ := hex.DecodeString("6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52")
	testUsage := uint32(2)
	var e Aes256CtsHmacSha384192
	var tests = []struct {
		kc     string
		pt     string
		chksum string
	}{
		{"ef5718be86cc84963d8bbb5031e9f5c4ba41f28faf69e73d", "000102030405060708090a0b0c0d0e0f1011121314", "45ee791567eefca37f4ac1e0222de80d43c3bfa06699672a"},
	}
	for _, test := range tests {
		p, _ := hex.DecodeString(test.pt)
		b, err := e.GetChecksumHash(protocolBaseKey, p, testUsage)
		if err != nil {
			t.Errorf("error generating checksum: %v", err)
		}
		if got := hex.EncodeToString(b); got != test.chksum {
			t.Errorf("Checksum not as expected: got %s, want %s", got, test.chksum)
		}
	}
}
