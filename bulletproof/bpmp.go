package bulletproofs

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"

	"github.com/AllFi/go-gost3410/curve"
	"github.com/ing-bank/zkrp/util/bn"
)

type MPCPContext struct {
	tau1              *big.Int
	tau2              *big.Int
	V                 *curve.Point
	A                 *curve.Point
	S                 *curve.Point
	T1                *curve.Point
	T2                *curve.Point
	Mu                *big.Int
	Tprime            *big.Int
	InnerProductProof InnerProductProof
	Commit            *curve.Point
}

func PartialPreProve(ec elliptic.Curve, params BulletProofSetupParams) (context *MPCPContext, publicTau1 *curve.Point, publicTau2 *curve.Point) {
	order := ec.Params().N
	tau1, _ := rand.Int(rand.Reader, order) // (52)
	tau2, _ := rand.Int(rand.Reader, order) // (52)
	publicTau1, _ = CommitG1(ec, big.NewInt(0), tau1, params.H)
	publicTau2, _ = CommitG1(ec, big.NewInt(0), tau2, params.H)
	context = &MPCPContext{tau1: tau1, tau2: tau2}
	return
}

func PartialProve(ec elliptic.Curve, secret *big.Int, gamma *big.Int, inContext *MPCPContext, publicTau1s []*curve.Point, publicTau2s []*curve.Point, params BulletProofSetupParams) (outContext *MPCPContext, taux *big.Int, err error) {
	order := ec.Params().N

	// ////////////////////////////////////////////////////////////////////////////
	// First phase: page 19
	// ////////////////////////////////////////////////////////////////////////////

	// commitment to v and gamma
	V, _ := CommitG1(ec, secret, gamma, params.H)

	// aL, aR and commitment: (A, alpha)
	aL, _ := Decompose(secret, 2, params.N)                                        // (41)
	aR, _ := computeAR(aL)                                                         // (42)
	alpha, _ := rand.Int(rand.Reader, order)                                       // (43)
	A := commitVector(ec, aL, aR, alpha, params.H, params.Gg, params.Hh, params.N) // (44)

	// sL, sR and commitment: (S, rho)                                     // (45)
	sL := sampleRandomVector(ec, params.N)
	sR := sampleRandomVector(ec, params.N)
	rho, _ := rand.Int(rand.Reader, order)                                          // (46)
	S := commitVectorBig(ec, sL, sR, rho, params.H, params.Gg, params.Hh, params.N) // (47)

	// Fiat-Shamir heuristic to compute challenges y and z, corresponds to    (49)
	y, z, _ := HashBP(A, S)

	// ////////////////////////////////////////////////////////////////////////////
	// Second phase: page 20
	// ////////////////////////////////////////////////////////////////////////////

	/*
	   The paper does not describe how to compute t1 and t2.
	*/
	// compute t1: < aL - z.1^n, y^n . sR > + < sL, y^n . (aR + z . 1^n) >
	vz, _ := VectorCopy(z, params.N)
	vy := powerOf(ec, y, params.N)

	// aL - z.1^n
	naL, _ := VectorConvertToBig(aL, params.N)
	aLmvz, _ := VectorSub(ec, naL, vz)

	// y^n .sR
	ynsR, _ := VectorMul(ec, vy, sR)

	// scalar prod: < aL - z.1^n, y^n . sR >
	sp1, _ := ScalarProduct(ec, aLmvz, ynsR)

	// scalar prod: < sL, y^n . (aR + z . 1^n) >
	naR, _ := VectorConvertToBig(aR, params.N)
	aRzn, _ := VectorAdd(ec, naR, vz)
	ynaRzn, _ := VectorMul(ec, vy, aRzn)

	// Add z^2.2^n to the result
	// z^2 . 2^n
	p2n := powerOf(ec, new(big.Int).SetInt64(2), params.N)
	zsquared := bn.Multiply(z, z)
	z22n, _ := VectorScalarMul(ec, p2n, zsquared)
	ynaRzn, _ = VectorAdd(ec, ynaRzn, z22n)
	sp2, _ := ScalarProduct(ec, sL, ynaRzn)

	// sp1 + sp2
	t1 := big.NewInt(0).Add(sp1, sp2)
	t1 = big.NewInt(0).Mod(t1, order)

	// compute t2: < sL, y^n . sR >
	t2, _ := ScalarProduct(ec, sL, ynsR)
	t2 = big.NewInt(0).Mod(t2, order)

	// compute T1
	T1, _ := CommitG1(ec, t1, big.NewInt(0), params.H) // (53)
	for _, publicTau1 := range publicTau1s {
		T1 = T1.Add(ec, T1, publicTau1)
	}

	// compute T2
	T2, _ := CommitG1(ec, t2, big.NewInt(0), params.H) // (53)
	for _, publicTau2 := range publicTau2s {
		T2 = T2.Add(ec, T1, publicTau2)
	}

	// Fiat-Shamir heuristic to compute 'random' challenge x
	x, _, _ := HashBP(T1, T2)

	// compute bl                                                          // (58)
	sLx, _ := VectorScalarMul(ec, sL, x)
	bl, _ := VectorAdd(ec, aLmvz, sLx)

	// compute br                                                          // (59)
	// y^n . ( aR + z.1^n + sR.x )
	sRx, _ := VectorScalarMul(ec, sR, x)
	aRzn, _ = VectorAdd(ec, aRzn, sRx)
	ynaRzn, _ = VectorMul(ec, vy, aRzn)
	// y^n . ( aR + z.1^n sR.x ) + z^2 . 2^n
	br, _ := VectorAdd(ec, ynaRzn, z22n)

	// Compute t` = < bl, br >                                             // (60)
	tprime, _ := ScalarProduct(ec, bl, br)

	// Compute taux = tau2 . x^2 + tau1 . x + z^2 . gamma                  // (61)
	taux = bn.Multiply(inContext.tau2, bn.Multiply(x, x))
	taux = bn.Add(taux, bn.Multiply(inContext.tau1, x))
	taux = bn.Add(taux, bn.Multiply(bn.Multiply(z, z), gamma))
	taux = bn.Mod(taux, order)

	// Compute mu = alpha + rho.x                                          // (62)
	mu := bn.Multiply(rho, x)
	mu = bn.Add(mu, alpha)
	mu = bn.Mod(mu, order)

	// Inner Product over (g, h', P.h^-mu, tprime)
	hprime := updateGenerators(ec, params.Hh, y, params.N)

	// SetupInnerProduct Inner Product (Section 4.2)
	var setupErr error
	params.InnerProductParams, setupErr = setupInnerProduct(ec, params.H, params.Gg, hprime, tprime, params.N)
	if setupErr != nil {
		return nil, nil, setupErr
	}
	commit := commitInnerProduct(ec, params.Gg, hprime, bl, br)
	proofip, _ := proveInnerProduct(ec, bl, br, commit, params.InnerProductParams)

	outContext = &MPCPContext{
		V:                 V,
		A:                 A,
		S:                 S,
		T1:                T1,
		T2:                T2,
		Mu:                mu,
		Tprime:            tprime,
		InnerProductProof: proofip,
		Commit:            commit,
	}
	return
}

func AggregateProofs(inContext *MPCPContext, tauxs []*big.Int, params BulletProofSetupParams) (BulletProof, error) {
	// Aggregate taux
	taux := big.NewInt(0)
	for _, partialTaux := range tauxs {
		taux = taux.Add(taux, partialTaux)
	}

	var proof BulletProof
	proof.V = inContext.V
	proof.A = inContext.A
	proof.S = inContext.S
	proof.T1 = inContext.T1
	proof.T2 = inContext.T2
	proof.Taux = taux
	proof.Mu = inContext.Mu
	proof.Tprime = inContext.Tprime
	proof.InnerProductProof = inContext.InnerProductProof
	proof.Commit = inContext.Commit
	return proof, nil
}
