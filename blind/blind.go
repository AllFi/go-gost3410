package blind

import (
	"math/big"

	"github.com/AllFi/go-gost3410"
)

func Sum(context *gost3410.Context, positive [][]byte, negative [][]byte) []byte {
	result := big.NewInt(0)
	for _, blind := range positive {
		result.Add(result, new(big.Int).SetBytes(blind))
	}

	for _, blind := range negative {
		result.Sub(result, new(big.Int).SetBytes(blind))
	}
	return result.Bytes()
}
