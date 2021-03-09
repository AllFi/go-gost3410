package aggsig

import (
	"testing"

	"github.com/AllFi/go-gost3410"
	"github.com/AllFi/go-gost3410/curve"
	"github.com/AllFi/go-gost3410/utils"

	"github.com/stretchr/testify/assert"
)

// func TestDebug(t *testing.T) {
// 	p := []string{"p", "q", "a", "b", "Bx", "By"}
// 	for i := 0; i < len(CurveParamsGostR34102001CryptoProA); i++ {
// 		println(p[i], hex.EncodeToString(CurveParamsGostR34102001CryptoProA[i]))
// 	}
// }

func TestAggsig(t *testing.T) {
	n := 4
	context, err := gost3410.NewContext(curve.GOST34102001())
	mode := context.Curve.Params().BitSize / 8
	assert.NoError(t, err)

	privateKeys := make([][]byte, n)
	publicKeys := make([]*PublicKey, n)
	nonces := make([][]byte, n)
	publicNonces := make([]*PublicKey, n)
	for i := 0; i < n; i++ {
		privateKey := utils.RandomBytes(mode)
		publicKey, err := NewPublicKey(context, privateKey)
		assert.NoError(t, err)

		privateKeys[i] = privateKey
		publicKeys[i] = publicKey

		nonce := utils.RandomBytes(mode)
		publicNonce, err := NewPublicKey(context, nonce)
		assert.NoError(t, err)

		nonces[i] = nonce
		publicNonces[i] = publicNonce
	}

	sumPublicNonces, err := SumPublicKeys(context, publicNonces)
	assert.NoError(t, err)

	msg := []byte("Hello world!")
	partialSignatures := make([][]byte, n)
	for i := 0; i < n; i++ {
		partialSignature, err := SignPartial(context, privateKeys[i], nonces[i], sumPublicNonces, msg)
		assert.NoError(t, err)
		partialSignatures[i] = partialSignature

		correct, err := VerifyPartial(context, partialSignature, publicKeys[i], publicNonces[i], msg)
		assert.True(t, correct)
		assert.NoError(t, err)
	}

	signature, err := AggregatePartialSignatures(context, partialSignatures, sumPublicNonces)
	assert.NoError(t, err)

	sumPublicKeys, err := SumPublicKeys(context, publicKeys)
	assert.NoError(t, err)

	correct, err := Verify(context, signature, sumPublicKeys, msg)
	assert.True(t, correct)
	assert.NoError(t, err)
}
