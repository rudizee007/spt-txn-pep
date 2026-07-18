package gate

import (
	"errors"
	"math/big"
)

// base58 (Bitcoin/Solana alphabet) is an ADDRESS ENCODING, not a cryptographic
// primitive; decoding it is plain radix conversion. Implemented inline so the
// gate carries no third-party dependency and a hackathon judge can reproduce the
// demo offline. This is not "custom crypto" — there is no crypto here.
const b58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var b58Index = func() [256]int8 {
	var idx [256]int8
	for i := range idx {
		idx[i] = -1
	}
	for i := 0; i < len(b58Alphabet); i++ {
		idx[b58Alphabet[i]] = int8(i)
	}
	return idx
}()

var errBadBase58 = errors.New("gate: invalid base58 string")

// decodeBase58 decodes a base58 string to big-endian bytes, preserving
// leading-'1' bytes as leading zero bytes.
func decodeBase58(s string) ([]byte, error) {
	n := new(big.Int)
	radix := big.NewInt(58)
	tmp := new(big.Int)
	for i := 0; i < len(s); i++ {
		v := b58Index[s[i]]
		if v < 0 {
			return nil, errBadBase58
		}
		n.Mul(n, radix)
		n.Add(n, tmp.SetInt64(int64(v)))
	}
	body := n.Bytes()
	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}
	out := make([]byte, zeros+len(body))
	copy(out[zeros:], body)
	return out, nil
}

// decodePubkey32 decodes a base58 Solana public key and requires exactly 32
// bytes; anything else is a hard error (fail closed).
func decodePubkey32(s string) ([32]byte, error) {
	var pk [32]byte
	raw, err := decodeBase58(s)
	if err != nil {
		return pk, err
	}
	if len(raw) != 32 {
		return pk, ErrBadPubkey
	}
	copy(pk[:], raw)
	return pk, nil
}

// EncodeBase58 is the inverse of decodeBase58, used to render pubkeys as the
// base58 strings an x402 PaymentRequirements carries. Still an encoding, not
// crypto. decodeBase58(EncodeBase58(b)) == b for all b.
func EncodeBase58(b []byte) string {
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	n := new(big.Int).SetBytes(b)
	radix := big.NewInt(58)
	mod := new(big.Int)
	var rev []byte
	for n.Sign() > 0 {
		n.DivMod(n, radix, mod)
		rev = append(rev, b58Alphabet[mod.Int64()])
	}
	for i := 0; i < zeros; i++ {
		rev = append(rev, '1')
	}
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return string(rev)
}
