package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/jfjallid/gokrb5/v8/crypto/common"
	"github.com/jfjallid/gokrb5/v8/crypto/rfc8009"
)

func TestAes128CtsHmacSha256128_StringToKey(t *testing.T) {
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
		{32768, "password", s + "ATHENA.MIT.EDUraeburn", "6165733132382d6374732d686d61632d7368613235362d3132380010df9dd783e5bc8acea1730e74355f61415448454e412e4d49542e4544557261656275726e", "089bca48b105ea6ea77ca5d2f39dc5e7"},
	}
	var e Aes128CtsHmacSha256128
	for _, test := range tests {
		saltp := rfc8009.GetSaltP(test.salt, "aes128-cts-hmac-sha256-128")
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

func TestAes128CtsHmacSha256128_DeriveKey(t *testing.T) {
	t.Parallel()
	// Test vectors from RFC 8009 Appendix A
	protocolBaseKey, _ := hex.DecodeString("3705d96080c17728a0e800eab6e0d23c")
	testUsage := uint32(2)
	var e Aes128CtsHmacSha256128
	k, err := e.DeriveKey(protocolBaseKey, common.GetUsageKc(testUsage))
	if err != nil {
		t.Fatalf("Error deriving checksum key: %v", err)
	}
	if got := hex.EncodeToString(k); got != "b31a018a48f54776f403e9a396325dc3" {
		t.Errorf("Checksum derived key not as expected: got %s", got)
	}
	k, err = e.DeriveKey(protocolBaseKey, common.GetUsageKe(testUsage))
	if err != nil {
		t.Fatalf("Error deriving encryption key: %v", err)
	}
	if got := hex.EncodeToString(k); got != "9b197dd1e8c5609d6e67c3e37c62c72e" {
		t.Errorf("Encryption derived key not as expected: got %s", got)
	}
	k, err = e.DeriveKey(protocolBaseKey, common.GetUsageKi(testUsage))
	if err != nil {
		t.Fatalf("Error deriving integrity key: %v", err)
	}
	if got := hex.EncodeToString(k); got != "9fda0e56ab2d85e1569a688696c26a6c" {
		t.Errorf("Integrity derived key not as expected: got %s", got)
	}
}

func TestAes128CtsHmacSha256128_VerifyIntegrity(t *testing.T) {
	t.Parallel()
	// Test vectors from RFC 8009
	protocolBaseKey, _ := hex.DecodeString("3705d96080c17728a0e800eab6e0d23c")
	testUsage := uint32(2)
	var e Aes128CtsHmacSha256128
	var tests = []struct {
		kc     string
		pt     string
		chksum string
	}{
		{"b31a018a48f54776f403e9a396325dc3", "000102030405060708090a0b0c0d0e0f1011121314", "d78367186643d67b411cba9139fc1dee"},
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

func TestAes128CtsHmacSha256128_Cypto(t *testing.T) {
	t.Parallel()
	protocolBaseKey, _ := hex.DecodeString("3705d96080c17728a0e800eab6e0d23c")
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
		{"", "7e5895eaf2672435bad817f545a37148", "9b197dd1e8c5609d6e67c3e37c62c72e", "9fda0e56ab2d85e1569a688696c26a6c", "ef85fb890bb8472f4dab20394dca781d", "ad877eda39d50c870c0d5a0a8e48c718", "ef85fb890bb8472f4dab20394dca781dad877eda39d50c870c0d5a0a8e48c718"},
		{"000102030405", "7bca285e2fd4130fb55b1a5c83bc5b24", "9b197dd1e8c5609d6e67c3e37c62c72e", "9fda0e56ab2d85e1569a688696c26a6c", "84d7f30754ed987bab0bf3506beb09cfb55402cef7e6", "877ce99e247e52d16ed4421dfdf8976c", "84d7f30754ed987bab0bf3506beb09cfb55402cef7e6877ce99e247e52d16ed4421dfdf8976c"},
		{"000102030405060708090a0b0c0d0e0f", "56ab21713ff62c0a1457200f6fa9948f", "9b197dd1e8c5609d6e67c3e37c62c72e", "9fda0e56ab2d85e1569a688696c26a6c", "3517d640f50ddc8ad3628722b3569d2ae07493fa8263254080ea65c1008e8fc2", "95fb4852e7d83e1e7c48c37eebe6b0d3", "3517d640f50ddc8ad3628722b3569d2ae07493fa8263254080ea65c1008e8fc295fb4852e7d83e1e7c48c37eebe6b0d3"},
		{"000102030405060708090a0b0c0d0e0f1011121314", "a7a4e29a4728ce10664fb64e49ad3fac", "9b197dd1e8c5609d6e67c3e37c62c72e", "9fda0e56ab2d85e1569a688696c26a6c", "720f73b18d9859cd6ccb4346115cd336c70f58edc0c4437c5573544c31c813bce1e6d072c1", "86b39a413c2f92ca9b8334a287ffcbfc", "720f73b18d9859cd6ccb4346115cd336c70f58edc0c4437c5573544c31c813bce1e6d072c186b39a413c2f92ca9b8334a287ffcbfc"},
	}
	var e Aes128CtsHmacSha256128
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
