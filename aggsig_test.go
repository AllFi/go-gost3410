package gost3410

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAggsig(t *testing.T) {
	n := 4
	mode := Mode2001
	curveParams := CurveParamsGostR34102001CryptoProA
	context, err := NewContext(mode, curveParams)
	assert.NoError(t, err)

	privateKeys := make([][]byte, n)
	publicKeys := make([]*PublicKey, n)
	nonces := make([][]byte, n)
	publicNonces := make([]*PublicKey, n)
	for i := 0; i < n; i++ {
		privateKey := randomBytes(int(context.Mode), context)
		publicKey, err := NewPublicKey(context, privateKey)
		assert.NoError(t, err)

		privateKeys[i] = privateKey
		publicKeys[i] = publicKey

		nonce := randomBytes(int(context.Mode), context)
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

func randomBytes(count int, context *Context) []byte {
	b := make([]byte, count)
	rand.Read(b)
	return b
}
