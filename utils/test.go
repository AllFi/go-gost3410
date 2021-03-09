package utils

import (
	"crypto/rand"
)

func RandomBytes(count int) []byte {
	b := make([]byte, count)
	rand.Read(b)
	return b
}
