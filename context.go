package gost3410

import (
	"crypto/elliptic"
)

type Context struct {
	Curve elliptic.Curve
}

func NewContext(curve elliptic.Curve) (context *Context, err error) {
	return &Context{Curve: curve}, nil
}
