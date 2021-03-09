/*
 * Copyright (C) 2019 ING BANK N.V.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package bulletproofs

import (
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"math/big"
	"strconv"

	"github.com/AllFi/go-gost3410/curve"
	"github.com/ing-bank/zkrp/util/bn"
	"github.com/ing-bank/zkrp/util/byteconversion"
)

var SEEDU = "BulletproofsDoesNotNeedTrustedSetupU"

/*
InnerProductParams contains elliptic curve generators used to compute Pedersen
commitments.
*/
type InnerProductParams struct {
	N  int64
	Cc *big.Int
	Uu *curve.Point
	H  *curve.Point
	Gg []*curve.Point
	Hh []*curve.Point
	P  *curve.Point
}

/*
InnerProductProof contains the elements used to verify the Inner Product Proof.
*/
type InnerProductProof struct {
	N      int64
	Ls     []*curve.Point
	Rs     []*curve.Point
	U      *curve.Point
	P      *curve.Point
	Gg     *curve.Point
	Hh     *curve.Point
	A      *big.Int
	B      *big.Int
	Params InnerProductParams
}

/*
SetupInnerProduct is responsible for computing the inner product basic parameters that are common to both
ProveInnerProduct and Verify algorithms.
*/
func setupInnerProduct(ec elliptic.Curve, H *curve.Point, g, h []*curve.Point, c *big.Int, N int64) (InnerProductParams, error) {
	var params InnerProductParams

	if N <= 0 {
		return params, errors.New("N must be greater than zero")
	} else {
		params.N = N
	}
	if H == nil {
		params.H, _ = curve.MapToGroup(ec, SEEDH)
	} else {
		params.H = H
	}
	if g == nil {
		params.Gg = make([]*curve.Point, params.N)
		for i := int64(0); i < params.N; i++ {
			params.Gg[i], _ = curve.MapToGroup(ec, SEEDH+"g"+strconv.Itoa(int(i)))
		}
	} else {
		params.Gg = g
	}
	if h == nil {
		params.Hh = make([]*curve.Point, params.N)
		for i := int64(0); i < params.N; i++ {
			params.Hh[i], _ = curve.MapToGroup(ec, SEEDH+"h"+strconv.Itoa(int(i)))
		}
	} else {
		params.Hh = h
	}
	params.Cc = c
	params.Uu, _ = curve.MapToGroup(ec, SEEDU)
	params.P = new(curve.Point).SetInfinity()

	return params, nil
}

/*
proveInnerProduct calculates the Zero Knowledge Proof for the Inner Product argument.
*/
func proveInnerProduct(ec elliptic.Curve, a, b []*big.Int, P *curve.Point, params InnerProductParams) (InnerProductProof, error) {
	var (
		proof InnerProductProof
		n, m  int64
		Ls    []*curve.Point
		Rs    []*curve.Point
	)

	n = int64(len(a))
	m = int64(len(b))

	if n != m {
		return proof, errors.New("size of first array argument must be equal to the second")
	}

	// Fiat-Shamir:
	// x = Hash(g,h,P,c)
	x, _ := hashIP(ec, params.Gg, params.Hh, P, params.Cc, params.N)
	// Pprime = P.u^(x.c)
	ux := new(curve.Point).ScalarMult(ec, params.Uu, x)
	uxc := new(curve.Point).ScalarMult(ec, ux, params.Cc)
	PP := new(curve.Point).Add(ec, P, uxc)
	// Execute Protocol 2 recursively
	proof = computeBipRecursive(ec, a, b, params.Gg, params.Hh, ux, PP, n, Ls, Rs)
	proof.Params = params
	proof.Params.P = PP
	return proof, nil
}

/*
computeBipRecursive is the main recursive function that will be used to compute the inner product argument.
*/
func computeBipRecursive(ec elliptic.Curve, a, b []*big.Int, g, h []*curve.Point, u, P *curve.Point, n int64, Ls, Rs []*curve.Point) InnerProductProof {
	var (
		proof                            InnerProductProof
		cL, cR, x, xinv, x2, x2inv       *big.Int
		L, R, Lh, Rh, Pprime             *curve.Point
		gprime, hprime, gprime2, hprime2 []*curve.Point
		aprime, bprime, aprime2, bprime2 []*big.Int
	)
	order := ec.Params().N

	if n == 1 {
		// recursion end
		proof.A = a[0]
		proof.B = b[0]
		proof.Gg = g[0]
		proof.Hh = h[0]
		proof.P = P
		proof.U = u
		proof.Ls = Ls
		proof.Rs = Rs

	} else {
		// recursion

		// nprime := n / 2
		nprime := n / 2 // (20)

		// Compute cL = < a[:n'], b[n':] >                                    // (21)
		cL, _ = ScalarProduct(ec, a[:nprime], b[nprime:])
		// Compute cR = < a[n':], b[:n'] >                                    // (22)
		cR, _ = ScalarProduct(ec, a[nprime:], b[:nprime])
		// Compute L = g[n':]^(a[:n']).h[:n']^(b[n':]).u^cL                   // (23)
		L, _ = VectorExp(ec, g[nprime:], a[:nprime])
		Lh, _ = VectorExp(ec, h[:nprime], b[nprime:])
		L.Add(ec, L, Lh)
		L.Add(ec, L, new(curve.Point).ScalarMult(ec, u, cL))

		// Compute R = g[:n']^(a[n':]).h[n':]^(b[:n']).u^cR                   // (24)
		R, _ = VectorExp(ec, g[:nprime], a[nprime:])
		Rh, _ = VectorExp(ec, h[nprime:], b[:nprime])
		R.Add(ec, R, Rh)
		R.Add(ec, R, new(curve.Point).ScalarMult(ec, u, cR))

		// Fiat-Shamir:                                                       // (26)
		x, _, _ = HashBP(L, R)
		xinv = bn.ModInverse(x, order)

		// Compute g' = g[:n']^(x^-1) * g[n':]^(x)                            // (29)
		gprime = vectorScalarExp(ec, g[:nprime], xinv)
		gprime2 = vectorScalarExp(ec, g[nprime:], x)
		gprime, _ = VectorECAdd(ec, gprime, gprime2)
		// Compute h' = h[:n']^(x)    * h[n':]^(x^-1)                         // (30)
		hprime = vectorScalarExp(ec, h[:nprime], x)
		hprime2 = vectorScalarExp(ec, h[nprime:], xinv)
		hprime, _ = VectorECAdd(ec, hprime, hprime2)

		// Compute P' = L^(x^2).P.R^(x^-2)                                    // (31)
		x2 = bn.Mod(bn.Multiply(x, x), order)
		x2inv = bn.ModInverse(x2, order)
		Pprime = new(curve.Point).ScalarMult(ec, L, x2)
		Pprime.Add(ec, Pprime, P)
		Pprime.Add(ec, Pprime, new(curve.Point).ScalarMult(ec, R, x2inv))

		// Compute a' = a[:n'].x      + a[n':].x^(-1)                         // (33)
		aprime, _ = VectorScalarMul(ec, a[:nprime], x)
		aprime2, _ = VectorScalarMul(ec, a[nprime:], xinv)
		aprime, _ = VectorAdd(ec, aprime, aprime2)
		// Compute b' = b[:n'].x^(-1) + b[n':].x                              // (34)
		bprime, _ = VectorScalarMul(ec, b[:nprime], xinv)
		bprime2, _ = VectorScalarMul(ec, b[nprime:], x)
		bprime, _ = VectorAdd(ec, bprime, bprime2)

		Ls = append(Ls, L)
		Rs = append(Rs, R)
		// recursion computeBipRecursive(g',h',u,P'; a', b')                  // (35)
		proof = computeBipRecursive(ec, aprime, bprime, gprime, hprime, u, Pprime, nprime, Ls, Rs)
	}
	proof.N = n
	return proof
}

/*
Verify is responsible for the verification of the Inner Product Proof.
*/
func (proof InnerProductProof) Verify(ec elliptic.Curve) (bool, error) {
	order := ec.Params().N

	logn := len(proof.Ls)
	var (
		x, xinv, x2, x2inv                   *big.Int
		ngprime, nhprime, ngprime2, nhprime2 []*curve.Point
	)

	gprime := proof.Params.Gg
	hprime := proof.Params.Hh
	Pprime := proof.Params.P
	nprime := proof.N
	for i := int64(0); i < int64(logn); i++ {
		nprime = nprime / 2                        // (20)
		x, _, _ = HashBP(proof.Ls[i], proof.Rs[i]) // (26)
		xinv = bn.ModInverse(x, order)
		// Compute g' = g[:n']^(x^-1) * g[n':]^(x)                            // (29)
		ngprime = vectorScalarExp(ec, gprime[:nprime], xinv)
		ngprime2 = vectorScalarExp(ec, gprime[nprime:], x)
		gprime, _ = VectorECAdd(ec, ngprime, ngprime2)
		// Compute h' = h[:n']^(x)    * h[n':]^(x^-1)                         // (30)
		nhprime = vectorScalarExp(ec, hprime[:nprime], x)
		nhprime2 = vectorScalarExp(ec, hprime[nprime:], xinv)
		hprime, _ = VectorECAdd(ec, nhprime, nhprime2)
		// Compute P' = L^(x^2).P.R^(x^-2)                                    // (31)
		x2 = bn.Mod(bn.Multiply(x, x), order)
		x2inv = bn.ModInverse(x2, order)
		Pprime.Add(ec, Pprime, new(curve.Point).ScalarMult(ec, proof.Ls[i], x2))
		Pprime.Add(ec, Pprime, new(curve.Point).ScalarMult(ec, proof.Rs[i], x2inv))
	}

	// c == a*b and checks if P = g^a.h^b.u^c                                     // (16)
	ab := bn.Multiply(proof.A, proof.B)
	ab = bn.Mod(ab, order)
	// Compute right hand side
	rhs := new(curve.Point).ScalarMult(ec, gprime[0], proof.A)
	hb := new(curve.Point).ScalarMult(ec, hprime[0], proof.B)
	rhs.Add(ec, rhs, hb)
	rhs.Add(ec, rhs, new(curve.Point).ScalarMult(ec, proof.U, ab))
	// Compute inverse of left hand side
	nP := Pprime.Neg(ec, Pprime)
	nP.Add(ec, nP, rhs)
	// If both sides are equal then nP must be zero                               // (17)
	c := nP.IsZero()

	return c, nil
}

/*
hashIP is responsible for the computing a Zp element given elements from GT and G1.
*/
func hashIP(ec elliptic.Curve, g, h []*curve.Point, P *curve.Point, c *big.Int, n int64) (*big.Int, error) {
	digest := sha256.New()
	digest.Write(P.Bytes(ec))

	for i := int64(0); i < n; i++ {
		digest.Write(g[i].Bytes(ec))
		digest.Write(h[i].Bytes(ec))
	}

	digest.Write([]byte(c.String()))
	output := digest.Sum(nil)
	tmp := output[0:]
	result, err := byteconversion.FromByteArray(tmp)

	return result, err
}

/*
commitInnerProduct is responsible for calculating g^a.h^b.
*/
func commitInnerProduct(ec elliptic.Curve, g, h []*curve.Point, a, b []*big.Int) *curve.Point {
	var (
		result *curve.Point
	)

	ga, _ := VectorExp(ec, g, a)
	hb, _ := VectorExp(ec, h, b)
	result = new(curve.Point).Add(ec, ga, hb)
	return result
}

/*
VectorScalarExp computes a[i]^b for each i.
*/
func vectorScalarExp(ec elliptic.Curve, a []*curve.Point, b *big.Int) []*curve.Point {
	var (
		result []*curve.Point
		n      int64
	)
	n = int64(len(a))
	result = make([]*curve.Point, n)
	for i := int64(0); i < n; i++ {
		result[i] = new(curve.Point).ScalarMult(ec, a[i], b)
	}
	return result
}
