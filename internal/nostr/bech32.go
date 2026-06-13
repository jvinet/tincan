package nostr

import (
	"fmt"
	"strings"
)

// This is a minimal BIP-173 bech32 codec, used only for NIP-19 bare "npub" and
// "nsec" entities (the simple key forms, not the TLV nprofile/nevent variants).
// It is hand-rolled to avoid a dependency for ~80 lines of well-specified code.

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var bech32Reverse = func() [256]int8 {
	var rev [256]int8
	for i := range rev {
		rev[i] = -1
	}
	for i, c := range bech32Charset {
		rev[byte(c)] = int8(i)
	}
	return rev
}()

func bech32Polymod(values []byte) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func bech32HRPExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&31)
	}
	return out
}

func bech32Checksum(hrp string, data []byte) []byte {
	values := append(bech32HRPExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	mod := bech32Polymod(values) ^ 1
	out := make([]byte, 6)
	for i := 0; i < 6; i++ {
		out[i] = byte((mod >> uint(5*(5-i))) & 31)
	}
	return out
}

// convertBits regroups data from fromBits-wide units into toBits-wide units,
// optionally padding the final unit. Used to move between 8-bit bytes and the
// 5-bit groups bech32 encodes.
func convertBits(data []byte, fromBits, toBits uint, pad bool) ([]byte, error) {
	var acc uint32
	var bits uint
	maxv := uint32(1)<<toBits - 1
	out := make([]byte, 0, len(data)*int(fromBits)/int(toBits)+1)
	for _, b := range data {
		acc = acc<<fromBits | uint32(b)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			out = append(out, byte(acc>>bits&maxv))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte(acc<<(toBits-bits)&maxv))
		}
	} else if bits >= fromBits || acc<<(toBits-bits)&maxv != 0 {
		return nil, fmt.Errorf("invalid padding bits")
	}
	return out, nil
}

// encodeBech32 encodes 8-bit data under hrp as a bech32 string.
func encodeBech32(hrp string, data8 []byte) (string, error) {
	data5, err := convertBits(data8, 8, 5, true)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, b := range append(data5, bech32Checksum(hrp, data5)...) {
		sb.WriteByte(bech32Charset[b])
	}
	return sb.String(), nil
}

// decodeBech32 decodes a bech32 string into its human-readable prefix and the
// underlying 8-bit data.
func decodeBech32(s string) (hrp string, data8 []byte, err error) {
	if len(s) < 8 || len(s) > 2048 {
		return "", nil, fmt.Errorf("bech32 string has invalid length %d", len(s))
	}
	if low, up := strings.ToLower(s), strings.ToUpper(s); s != low && s != up {
		return "", nil, fmt.Errorf("bech32 string has mixed case")
	}
	s = strings.ToLower(s)
	sep := strings.LastIndexByte(s, '1')
	if sep < 1 || sep+7 > len(s) {
		return "", nil, fmt.Errorf("bech32 separator misplaced")
	}
	hrp = s[:sep]
	data5 := make([]byte, 0, len(s)-sep-1)
	for i := sep + 1; i < len(s); i++ {
		v := bech32Reverse[s[i]]
		if v < 0 {
			return "", nil, fmt.Errorf("invalid bech32 character %q", s[i])
		}
		data5 = append(data5, byte(v))
	}
	if bech32Polymod(append(bech32HRPExpand(hrp), data5...)) != 1 {
		return "", nil, fmt.Errorf("bad bech32 checksum")
	}
	data8, err = convertBits(data5[:len(data5)-6], 5, 8, false)
	if err != nil {
		return "", nil, err
	}
	return hrp, data8, nil
}
