package pack

import (
	"encoding/hex"
	"fmt"
)

const digestPrefix = "sha256:"

type Digest struct {
	sum [32]byte
}

func ParseDigest(text string) (Digest, error) {
	if len(text) != len(digestPrefix)+64 || text[:len(digestPrefix)] != digestPrefix {
		return Digest{}, fmt.Errorf("digest must be sha256 followed by 64 lowercase hexadecimal characters")
	}
	encoded := text[len(digestPrefix):]
	for _, character := range encoded {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return Digest{}, fmt.Errorf("digest must use lowercase hexadecimal")
		}
	}
	var digest Digest
	if _, err := hex.Decode(digest.sum[:], []byte(encoded)); err != nil {
		return Digest{}, fmt.Errorf("decode digest: %w", err)
	}
	return digest, nil
}

func (d Digest) String() string {
	return digestPrefix + hex.EncodeToString(d.sum[:])
}
