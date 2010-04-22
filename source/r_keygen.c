/*
	R_KEYGEN.C - key-pair generation for RSAEURO

    Copyright (c) J.S.A.Kapp 1994 - 1996.

	RSAEURO - RSA Library compatible with RSAREF(tm) 2.0.

	All functions prototypes are the Same as for RSAREF(tm).
	To aid compatiblity the source and the files follow the
	same naming comventions that RSAREF(tm) uses.  This should aid
	direct importing to you applications.

	This library is legal everywhere outside the US.  And should
	NOT be imported to the US and used there.

	All Trademarks Acknowledged.

	Revision history
		0.90 First revision, produced to perform just like the
		RSAREF(tm) version.

		0.91 Second revision, minor modifications to RSAFilter routine
		and method.  Result minor speed increase.
*/

#include "rsaeuro.h"
#include "r_random.h"
#include "nn.h"
#include "prime.h"

static int RSAFilter PROTO_LIST
	((NN_DIGIT *, unsigned int, NN_DIGIT *, unsigned int));

/* Generates an RSA key pair with a given length and public exponent. */

int R_GeneratePEMKeys(publicKey, privateKey, protoKey, randomStruct)
R_RSA_PUBLIC_KEY *publicKey;    /* new RSA public key */
R_RSA_PRIVATE_KEY *privateKey;  /* new RSA private key */
R_RSA_PROTO_KEY *protoKey;      /* RSA prototype key */
R_RANDOM_STRUCT *randomStruct;  /* random structure */
{
	NN_DIGIT d[MAX_NN_DIGITS], dP[MAX_NN_DIGITS], dQ[MAX_NN_DIGITS],
		e[MAX_NN_DIGITS], n[MAX_NN_DIGITS], p[MAX_NN_DIGITS], phiN[MAX_NN_DIGITS],
		pMinus1[MAX_NN_DIGITS], q[MAX_NN_DIGITS], qInv[MAX_NN_DIGITS],
		qMinus1[MAX_NN_DIGITS], t[MAX_NN_DIGITS], u[MAX_NN_DIGITS],
		v[MAX_NN_DIGITS];
	int status;
	unsigned int nDigits, pBits, pDigits, qBits;

	if((protoKey->bits < MIN_RSA_MODULUS_BITS) || (protoKey->bits > MAX_RSA_MODULUS_BITS))
		return(RE_MODULUS_LEN);

	nDigits = (protoKey->bits + NN_DIGIT_BITS - 1) / NN_DIGIT_BITS;
	pDigits = (nDigits + 1) / 2;
	pBits = (protoKey->bits + 1) / 2;
	qBits = protoKey->bits - pBits;

	/* NB: for 65537, this means that NN_DIGIT is at least 17 bits
		 in length. */

	NN_ASSIGN_DIGIT(e, protoKey->useFermat4 ? (NN_DIGIT)65537 : (NN_DIGIT)3, nDigits);

	/* Generate prime p between 3*2^(pBits-2) and 2^pBits-1, searching
		 in steps of 2, until one satisfies gcd (p-1, e) = 1. */

	NN_Assign2Exp(t, pBits-1, pDigits);
	NN_Assign2Exp(u, pBits-2, pDigits);
	NN_Add(t, t, u, pDigits);
	NN_ASSIGN_DIGIT(v, 1, pDigits);
	NN_Sub(v, t, v, pDigits);
	NN_Add(u, u, v, pDigits);
	NN_ASSIGN_DIGIT(v, 2, pDigits);

	do {
		if(status = GeneratePrime(p, t, u, v, pDigits, randomStruct))
			return(status);
	}while(!RSAFilter(p, pDigits, e, 1));

	/* Generate prime q between 3*2^(qBits-2) and 2^qBits-1, searching
		 in steps of 2, until one satisfies gcd (q-1, e) = 1. */

	NN_Assign2Exp(t, qBits-1, pDigits);
	NN_Assign2Exp(u, qBits-2, pDigits);
	NN_Add(t, t, u, pDigits);
	NN_ASSIGN_DIGIT(v, 1, pDigits);
	NN_Sub(v, t, v, pDigits);
	NN_Add(u, u, v, pDigits);
	NN_ASSIGN_DIGIT(v, 2, pDigits);

	do {
		if(status = GeneratePrime(q, t, u, v, pDigits, randomStruct))
			return(status);
	}while(!RSAFilter(q, pDigits, e, 1));

	/* Sort so that p > q. (p = q case is extremely unlikely. */

	if(NN_Cmp(p, q, pDigits) < 0) {
		NN_Assign(t, p, pDigits);
		NN_Assign(p, q, pDigits);
		NN_Assign(q, t, pDigits);
	}

	/* Compute n = pq, qInv = q^{-1} mod p, d = e^{-1} mod (p-1)(q-1),
		 dP = d mod p-1, dQ = d mod q-1. */

	NN_Mult(n, p, q, pDigits);
	NN_ModInv(qInv, q, p, pDigits);

	NN_ASSIGN_DIGIT(t, 1, pDigits);
	NN_Sub(pMinus1, p, t, pDigits);
	NN_Sub(qMinus1, q, t, pDigits);
	NN_Mult(phiN, pMinus1, qMinus1, pDigits);

	NN_ModInv(d, e, phiN, nDigits);
	NN_Mod(dP, d, nDigits, pMinus1, pDigits);
	NN_Mod(dQ, d, nDigits, qMinus1, pDigits);

	publicKey->bits = privateKey->bits = protoKey->bits;
	NN_Encode(publicKey->modulus, MAX_RSA_MODULUS_LEN, n, nDigits);
	NN_Encode(publicKey->exponent, MAX_RSA_MODULUS_LEN, e, 1);
	R_memcpy((POINTER)privateKey->modulus, (POINTER)publicKey->modulus, MAX_RSA_MODULUS_LEN);
	R_memcpy((POINTER)privateKey->publicExponent, (POINTER)publicKey->exponent, MAX_RSA_MODULUS_LEN);
	NN_Encode(privateKey->exponent, MAX_RSA_MODULUS_LEN, d, nDigits);
	NN_Encode(privateKey->prime[0], MAX_RSA_PRIME_LEN, p, pDigits);
	NN_Encode(privateKey->prime[1], MAX_RSA_PRIME_LEN, q, pDigits);
	NN_Encode(privateKey->primeExponent[0], MAX_RSA_PRIME_LEN, dP, pDigits);
	NN_Encode(privateKey->primeExponent[1], MAX_RSA_PRIME_LEN, dQ, pDigits);
	NN_Encode(privateKey->coefficient, MAX_RSA_PRIME_LEN, qInv, pDigits);

	/* Clear sensitive information. */

	R_memset((POINTER)d, 0, sizeof(d));
	R_memset((POINTER)dP, 0, sizeof(dP));
	R_memset((POINTER)dQ, 0, sizeof(dQ));
	R_memset((POINTER)p, 0, sizeof(p));
	R_memset((POINTER)phiN, 0, sizeof(phiN));
	R_memset((POINTER)pMinus1, 0, sizeof(pMinus1));
	R_memset((POINTER)q, 0, sizeof(q));
	R_memset((POINTER)qInv, 0, sizeof(qInv));
	R_memset((POINTER)qMinus1, 0, sizeof(qMinus1));
	R_memset((POINTER)t, 0, sizeof(t));

	return (0);
}

/* Returns nonzero iff GCD (a-1, b) = 1.
	 Assumes aDigits < MAX_NN_DIGITS, bDigits < MAX_NN_DIGITS. */

static int RSAFilter(a, aDigits, b, bDigits)
NN_DIGIT *a, *b;
unsigned int aDigits, bDigits;
{
	int status = 0;
	NN_DIGIT aMinus1[MAX_NN_DIGITS], t[MAX_NN_DIGITS];
	NN_DIGIT u[MAX_NN_DIGITS];

	NN_ASSIGN_DIGIT(t, 1, aDigits);
	NN_Sub(aMinus1, a, t, aDigits);

	NN_Gcd(u, aMinus1, b, aDigits);

	status = NN_EQUAL(t, u, aDigits);

	R_memset((POINTER)aMinus1, 0, sizeof(aMinus1));

	return(status);
}
