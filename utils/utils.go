package utils

import (
	"math/big"
)

func BytesToBigInt(d []byte) *big.Int {
	n := big.NewInt(0)
	n.SetBytes(d)
	return n
}

func Reverse(d []byte) {
	for i, j := 0, len(d)-1; i < j; i, j = i+1, j-1 {
		d[i], d[j] = d[j], d[i]
	}
}

func Pad(d []byte, size int) []byte {
	return append(make([]byte, size-len(d)), d...)
}
