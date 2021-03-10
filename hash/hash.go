package hash

import (
	"crypto/elliptic"
	"crypto/sha256"
	"hash"
	"math/big"

	"github.com/AllFi/go-gost3410"
	"github.com/AllFi/go-gost3410/utils"
	"github.com/martinlindhe/gogost/gost34112012256"
)

var GOST34112012256 = &gost34112012256Alg{}
var SHA256 = &sha256Alg{}

type gost34112012256Alg struct{}

func (h *gost34112012256Alg) New() hash.Hash {
	return gost34112012256.New()
}

type sha256Alg struct{}

func (h *sha256Alg) New() hash.Hash {
	return sha256.New()
}

func HashToInt(msg []byte, ha gost3410.HashAlgorithm, ec elliptic.Curve) *big.Int {
	h := ha.New()
	h.Write(msg)
	digest := h.Sum(nil)

	e := utils.BytesToBigInt(digest)
	e.Mod(e, ec.Params().N)
	if e.Cmp(big.NewInt(0)) == 0 {
		e = big.NewInt(1)
	}
	return e
}
