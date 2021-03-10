package utils

import (
	"math/big"
)

func BytesToBigInt(d []byte) *big.Int {
	n := big.NewInt(0)
	n.SetBytes(d)
	return n
}

func Pad(d []byte, size int) []byte {
	return append(make([]byte, size-len(d)), d...)
}
