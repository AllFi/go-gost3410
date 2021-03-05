package gost3410

import (
	"math/big"

	"github.com/martinlindhe/gogost/gost34112012256"
)

func BytesToBigInt(d []byte) *big.Int {
	n := big.NewInt(0)
	n.SetBytes(d)
	return n
}

func reverse(d []byte) {
	for i, j := 0, len(d)-1; i < j; i, j = i+1, j-1 {
		d[i], d[j] = d[j], d[i]
	}
}

func Pad(d []byte, size int) []byte {
	return append(make([]byte, size-len(d)), d...)
}

func СalculateDigest(msg []byte, curve *Curve) *big.Int {
	hash := gost34112012256.New()
	_, _ = hash.Write(msg)
	digest := hash.Sum(nil)

	e := BytesToBigInt(digest)
	e.Mod(e, curve.Q)
	if e.Cmp(zero) == 0 {
		e = big.NewInt(1)
	}
	return e
}
