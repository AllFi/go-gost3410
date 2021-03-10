package gost3410

import (
	"crypto/elliptic"
	"hash"
)

type HashAlgorithm interface {
	New() hash.Hash
}

type Context struct {
	Curve         elliptic.Curve
	HashAlgorithm HashAlgorithm
}

func NewContext(curve elliptic.Curve, hashAlg HashAlgorithm) (context *Context) {
	return &Context{Curve: curve, HashAlgorithm: hashAlg}
}
