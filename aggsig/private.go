package aggsig

import (
	"errors"
	"math/big"

	"github.com/AllFi/go-gost3410"
	"github.com/AllFi/go-gost3410/curve"
	"github.com/AllFi/go-gost3410/utils"
)

type PrivateKey struct {
	*big.Int
}

func NewPrivateKey(context *gost3410.Context, raw []byte) (privateKey *PrivateKey, err error) {
	mode := context.Curve.Params().BitSize / 8
	if len(raw) != int(mode) {
		err = errors.New("invalid private key length")
		return
	}

	k := utils.BytesToBigInt(raw)
	if k.Cmp(zero) == 0 {
		err = errors.New("zero private key")
		return
	}
	return &PrivateKey{k}, nil
}

func (prv *PrivateKey) PublicKey(context *gost3410.Context) (*PublicKey, error) {
	x, y := context.Curve.ScalarBaseMult(prv.Bytes())
	return &PublicKey{curve.Point{x, y}}, nil
}
