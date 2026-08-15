package pack

import "testing"

func TestDigestStrictRoundTrip(t *testing.T) {
	t.Parallel()
	text := "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	digest, err := ParseDigest(text)
	if err != nil {
		t.Fatal(err)
	}
	if got := digest.String(); got != text {
		t.Fatalf("String() = %q, want %q", got, text)
	}
	if digest != digest {
		t.Fatal("Digest is not comparable")
	}

	for _, invalid := range []string{
		"",
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"sha256:0123",
		"SHA256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"sha256:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",
		"sha512:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		text + "\n",
	} {
		if _, err := ParseDigest(invalid); err == nil {
			t.Fatalf("ParseDigest(%q) succeeded", invalid)
		}
	}
}
