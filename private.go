package gost3410

import (
	"errors"
	"math/big"
)

type PrivateKey struct {
	Key *big.Int
}

func NewPrivateKey(context *Context, raw []byte) (privateKey *PrivateKey, err error) {
	if len(raw) != int(context.Mode) {
		err = errors.New("invalid private key length")
		return
	}

	k := BytesToBigInt(raw)
	if k.Cmp(zero) == 0 {
		err = errors.New("zero private key")
		return
	}
	return &PrivateKey{k}, nil
}

func (prv *PrivateKey) PublicKey(context *Context) (*PublicKey, error) {
	x, y, err := context.Curve.Mul(prv.Key, context.Curve.Bx, context.Curve.By)
	if err != nil {
		return nil, err
	}
	return &PublicKey{x, y}, nil
}
