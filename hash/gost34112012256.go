package hash

import (
	"crypto/elliptic"
	"math/big"

	"github.com/AllFi/go-gost3410/utils"
	"github.com/martinlindhe/gogost/gost34112012256"
)

func Calculate(msg []byte, curve elliptic.Curve) *big.Int {
	hash := gost34112012256.New()
	_, _ = hash.Write(msg)
	digest := hash.Sum(nil)

	e := utils.BytesToBigInt(digest)
	e.Mod(e, curve.Params().N)
	if e.Cmp(big.NewInt(0)) == 0 {
		e = big.NewInt(1)
	}
	return e
}
