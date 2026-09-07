package auditchain

import (
	"strings"
	"testing"
)

// hexSecret is a 32-byte key written as the 64 hex characters an operator
// configures. The digits vary so a test that mixes up two keys is visible.
const (
	hexSecretA = "1111111111111111111111111111111111111111111111111111111111111111"
	hexSecretB = "2222222222222222222222222222222222222222222222222222222222222222"
)

// TestParseKeyringEmptyIsUnkeyed asserts an unset variable is the unkeyed
// deployment rather than an error: keying is opt-in, and a deployment without a
// key must still start.
func TestParseKeyringEmptyIsUnkeyed(t *testing.T) {
	t.Parallel()
	for _, spec := range []string{"", "   ", "\n"} {
		kr, err := ParseKeyring(spec)
		if err != nil {
			t.Fatalf("ParseKeyring(%q) error = %v, want nil", spec, err)
		}
		if kr != nil {
			t.Fatalf("ParseKeyring(%q) = %v, want nil keyring", spec, kr)
		}
	}
}

// TestParseKeyringActiveIsFirst asserts the first key signs and the rest stay
// available to verify, which is what makes rotation additive.
func TestParseKeyringActiveIsFirst(t *testing.T) {
	t.Parallel()
	kr, err := ParseKeyring("v2:" + hexSecretB + ", v1:" + hexSecretA)
	if err != nil {
		t.Fatalf("ParseKeyring error = %v", err)
	}
	if got := kr.ActiveKeyID(); got != "v2" {
		t.Fatalf("ActiveKeyID = %q, want v2", got)
	}
	for _, id := range []string{"v1", "v2"} {
		if _, ok := kr.Secret(id); !ok {
			t.Errorf("Secret(%q) not found, want the retired key to stay verifiable", id)
		}
	}
	if _, ok := kr.Secret("v3"); ok {
		t.Error("Secret(\"v3\") resolved, want a key the ring does not hold to be absent")
	}
	// The empty id is the unkeyed hash and always resolves, so pre-keying
	// entries walk the same code path.
	if secret, ok := kr.Secret(""); !ok || secret != nil {
		t.Errorf("Secret(\"\") = %v, %v; want nil, true", secret, ok)
	}
}

// TestParseKeyringRejects asserts every shape that would leave the chain weaker
// than it claims is refused at load, not at the first append.
func TestParseKeyringRejects(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"no separator":     "v1" + hexSecretA,
		"secret not hex":   "v1:zzzz",
		"secret too short": "v1:1111",
		"secret all zeros": "v1:" + strings.Repeat("0", 64),
		"id uppercase":     "V1:" + hexSecretA,
		"id with colon":    "v:1:" + hexSecretA,
		"id empty":         ":" + hexSecretA,
		"id too long":      strings.Repeat("k", 33) + ":" + hexSecretA,
		"duplicate id":     "v1:" + hexSecretA + ",v1:" + hexSecretB,
		"only separators":  ",,",
	}
	for name, spec := range cases {
		if _, err := ParseKeyring(spec); err == nil {
			t.Errorf("ParseKeyring(%s) accepted %q, want an error", name, spec)
		}
	}
}

// TestNilKeyring asserts the unkeyed deployment answers safely: no active key,
// the unkeyed hash resolves, and a signed entry does not.
func TestNilKeyring(t *testing.T) {
	t.Parallel()
	var kr *Keyring
	if got := kr.ActiveKeyID(); got != "" {
		t.Fatalf("ActiveKeyID = %q, want empty", got)
	}
	if _, ok := kr.Secret(""); !ok {
		t.Error("Secret(\"\") did not resolve on a nil keyring")
	}
	if _, ok := kr.Secret("v1"); ok {
		t.Error("Secret(\"v1\") resolved on a nil keyring")
	}
}
