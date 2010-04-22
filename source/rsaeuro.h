/*
	RSAEURO.H - header file for RSAEURO cryptographic toolkit

	Copyright (c) J.S.A.Kapp 1994 - 1995.

	RSAEURO - RSA Library compatible with RSAREF(tm) 2.0.

	All functions prototypes are the Same as for RSAREF(tm).
	To aid compatiblity the source and the files follow the
	same naming comventions that RSAREF(tm) uses.  This should aid
				direct importing to your applications.

	This library is legal everywhere outside the US.  And should
	NOT be imported to the US and used there.

	This header file contains prototypes, and other definitions used
	in and by RSAEURO.

	Revision history
	0.90 First revision, implements all of RSAREF.H plus some minor
	changes.

	0.91 Second revision, Fixed a couple of problems.  SHS support
	added to header file, digest contexts altered.

	0.92 Third revision, add support at this level for the assembler
	routines and the implementation of some routines using the ANSI C
	equivalent.

	0.93 Fourth revision, Library details section added, MD4 details
	added to header file, digest contexts altered.
*/

#ifndef _RSAEURO_H_
#define _RSAEURO_H_

#include <string.h>

#include "global.h"
#include "md2.h"                               /* allow access to others */
#include "md4.h"
#include "md5.h"
#include "shs.h"
#include "nn.h"
#include "des.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Message-digest algorithms. */

#define DA_MD2 2
#define DA_MD4 4
#define DA_MD5 5
#define DA_SHS 3

/* Encryption algorithms to be ored with digest algorithm in Seal and Open. */

#define EA_DES_CBC 1
#define EA_DES_EDE2_CBC 2
#define EA_DES_EDE3_CBC 3
#define EA_DESX_CBC 4

/* RSA key lengths. */

#define MIN_RSA_MODULUS_BITS 508
/* 
	 PGP 2.6.2 Now allows 2048-bit keys changing below will allow this.
     It does lengthen key generation slightly if the value is increased.
*/
#define MAX_RSA_MODULUS_BITS 1024
#define MAX_RSA_MODULUS_LEN ((MAX_RSA_MODULUS_BITS + 7) / 8)
#define MAX_RSA_PRIME_BITS ((MAX_RSA_MODULUS_BITS + 1) / 2)
#define MAX_RSA_PRIME_LEN ((MAX_RSA_PRIME_BITS + 7) / 8)

/* Maximum lengths of encoded and encrypted content, as a function of
	 content length len. Also, inverse functions. */

#define ENCODED_CONTENT_LEN(len) (4*(len)/3 + 3)
#define ENCRYPTED_CONTENT_LEN(len) ENCODED_CONTENT_LEN ((len)+8)
#define DECODED_CONTENT_LEN(len) (3*(len)/4 + 1)
#define DECRYPTED_CONTENT_LEN(len) (DECODED_CONTENT_LEN (len) - 1)

/* Maximum lengths of signatures, encrypted keys, encrypted
	 signatures, and message digests. */

#define MAX_SIGNATURE_LEN MAX_RSA_MODULUS_LEN
#define MAX_PEM_SIGNATURE_LEN ENCODED_CONTENT_LEN(MAX_SIGNATURE_LEN)
#define MAX_ENCRYPTED_KEY_LEN MAX_RSA_MODULUS_LEN
#define MAX_PEM_ENCRYPTED_KEY_LEN ENCODED_CONTENT_LEN(MAX_ENCRYPTED_KEY_LEN)
#define MAX_PEM_ENCRYPTED_SIGNATURE_LEN ENCRYPTED_CONTENT_LEN(MAX_SIGNATURE_LEN)
#define MAX_DIGEST_LEN 20

/* Maximum length of Diffie-Hellman parameters. */

#define DH_PRIME_LEN(bits) (((bits) + 7) / 8)

/* Error codes. */

#define RE_CONTENT_ENCODING 0x0400
#define RE_DATA 0x0401
#define RE_DIGEST_ALGORITHM 0x0402
#define RE_ENCODING 0x0403
#define RE_KEY 0x0404
#define RE_KEY_ENCODING 0x0405
#define RE_LEN 0x0406
#define RE_MODULUS_LEN 0x0407
#define RE_NEED_RANDOM 0x0408
#define RE_PRIVATE_KEY 0x0409
#define RE_PUBLIC_KEY 0x040a
#define RE_SIGNATURE 0x040b
#define RE_SIGNATURE_ENCODING 0x040c
#define RE_ENCRYPTION_ALGORITHM 0x040d

/* Library details. */

#define RSAEURO_VER_MAJ 1
#define RSAEURO_VER_MIN 02
#define RSAEURO_IDENT "RSAEURO"
#define RSAEURO_DATE "21/08/94"

/* Internal Error Codes */

#define IDOK    0
#define IDERROR 1

/* Internal defs. */

#define TRUE    1
#define FALSE   0

/* Random structure. */

typedef struct {
  unsigned int bytesNeeded;                    /* seed bytes required */
  unsigned char state[16];                     /* state of object */
  unsigned int outputAvailable;                /* number byte available */
  unsigned char output[16];                    /* output bytes */
} R_RANDOM_STRUCT;

/* RSA public and private key. */

typedef struct {
  unsigned short int bits;                     /* length in bits of modulus */
  unsigned char modulus[MAX_RSA_MODULUS_LEN];  /* modulus */
  unsigned char exponent[MAX_RSA_MODULUS_LEN]; /* public exponent */
} R_RSA_PUBLIC_KEY;

typedef struct {
  unsigned short int bits;                     /* length in bits of modulus */
  unsigned char modulus[MAX_RSA_MODULUS_LEN];  /* modulus */
  unsigned char publicExponent[MAX_RSA_MODULUS_LEN];     /* public exponent */
  unsigned char exponent[MAX_RSA_MODULUS_LEN]; /* private exponent */
  unsigned char prime[2][MAX_RSA_PRIME_LEN];   /* prime factors */
  unsigned char primeExponent[2][MAX_RSA_PRIME_LEN];     /* exponents for CRT */
  unsigned char coefficient[MAX_RSA_PRIME_LEN];          /* CRT coefficient */
} R_RSA_PRIVATE_KEY;

/* RSA prototype key. */

typedef struct {
  unsigned int bits;                           /* length in bits of modulus */
  int useFermat4;                              /* public exponent (1 = F4, 0 = 3) */
} R_RSA_PROTO_KEY;

/* Diffie-Hellman parameters. */

typedef struct {
  unsigned char *prime;                        /* prime */
  unsigned int primeLen;                       /* length of prime */
  unsigned char *generator;                    /* generator */
  unsigned int generatorLen;                   /* length of generator */
} R_DH_PARAMS;

/* digest algorithm context */

typedef struct {
  int digestAlgorithm;                         /* digest type */
  union {                                      /* digest sub-context */
		MD2_CTX md2;
		MD4_CTX md4;
		MD5_CTX md5;
		SHS_CTX shs;
	} context;
} R_DIGEST_CTX;

/* signature context */

typedef struct {
	R_DIGEST_CTX digestContext;
} R_SIGNATURE_CTX;

/* envelope context */

typedef struct {
  int encryptionAlgorithm;                       /* encryption type */
  union {                                      /* encryption sub-context */
		DES_CBC_CTX des;
		DES3_CBC_CTX des3;
		DESX_CBC_CTX desx;
  } cipherContext;

  unsigned char buffer[8];                       /* data buffer */
  unsigned int bufferLen;                      /* buffer length */
} R_ENVELOPE_CTX;

/* Random Structures Routines. */

int R_RandomInit PROTO_LIST ((R_RANDOM_STRUCT *));
int R_RandomUpdate PROTO_LIST ((R_RANDOM_STRUCT *, unsigned char *, unsigned int));
int R_GetRandomBytesNeeded PROTO_LIST ((unsigned int *, R_RANDOM_STRUCT *));
void R_RandomFinal PROTO_LIST ((R_RANDOM_STRUCT *));
void R_RandomCreate PROTO_LIST ((R_RANDOM_STRUCT *random));
void R_RandomMix PROTO_LIST ((R_RANDOM_STRUCT *random));
int R_GenerateBytes(unsigned char *block, unsigned int len,
	R_RANDOM_STRUCT *random);

/* Cryptographic procedures. */

int R_DigestInit PROTO_LIST ((R_DIGEST_CTX *, int));
int R_DigestUpdate PROTO_LIST ((R_DIGEST_CTX *, unsigned char *,
	unsigned int));
int R_DigestFinal PROTO_LIST ((R_DIGEST_CTX *, unsigned char *,
	unsigned int *));
int R_SignInit PROTO_LIST ((R_SIGNATURE_CTX *, int));
int R_SignUpdate PROTO_LIST ((R_SIGNATURE_CTX *, unsigned char *,
	unsigned int));
int R_SignFinal PROTO_LIST ((R_SIGNATURE_CTX *, unsigned char *,
	unsigned int *, R_RSA_PRIVATE_KEY *));
int R_VerifyInit PROTO_LIST ((R_SIGNATURE_CTX *, int));
int R_VerifyUpdate PROTO_LIST ((R_SIGNATURE_CTX *, unsigned char *,
	unsigned int));
int R_VerifyFinal PROTO_LIST ((R_SIGNATURE_CTX *, unsigned char *,
	unsigned int, R_RSA_PUBLIC_KEY *));
int R_SealInit PROTO_LIST ((R_ENVELOPE_CTX *, unsigned char **, unsigned int *, unsigned char [8],
	unsigned int, R_RSA_PUBLIC_KEY **, int, R_RANDOM_STRUCT *));
int R_SealUpdate PROTO_LIST ((R_ENVELOPE_CTX *, unsigned char *,
	unsigned int *, unsigned char *, unsigned int));
int R_SealFinal PROTO_LIST ((R_ENVELOPE_CTX *, unsigned char *,
	unsigned int *));
int R_OpenInit PROTO_LIST ((R_ENVELOPE_CTX *, int, unsigned char *,
	unsigned int, unsigned char [8], R_RSA_PRIVATE_KEY *));
int R_OpenUpdate PROTO_LIST ((R_ENVELOPE_CTX *, unsigned char *,
	unsigned int *, unsigned char *, unsigned int));
int R_OpenFinal PROTO_LIST ((R_ENVELOPE_CTX *, unsigned char *,
	unsigned int *));

/* Cryptographic enhancements. */

int R_SignPEMBlock PROTO_LIST ((unsigned char *, unsigned int *, unsigned char *, unsigned int *,
	unsigned char *, unsigned int, int, int, R_RSA_PRIVATE_KEY *));
int R_SignBlock PROTO_LIST ((unsigned char *, unsigned int *, unsigned char *, unsigned int, int,
	R_RSA_PRIVATE_KEY *));
int R_VerifyPEMSignature PROTO_LIST ((unsigned char *, unsigned int *, unsigned char *, unsigned int,
	unsigned char *, unsigned int, int, int, R_RSA_PUBLIC_KEY *));
int R_VerifyBlockSignature PROTO_LIST ((unsigned char *, unsigned int,
	unsigned char *, unsigned int, int, R_RSA_PUBLIC_KEY *));
int R_SealPEMBlock PROTO_LIST ((unsigned char *, unsigned int *, unsigned char *, unsigned int *,
	unsigned char *, unsigned int *, unsigned char [8], unsigned char *,
	unsigned int, int, R_RSA_PUBLIC_KEY *, R_RSA_PRIVATE_KEY *,
	R_RANDOM_STRUCT *));
int R_OpenPEMBlock PROTO_LIST ((unsigned char *, unsigned int *, unsigned char *, unsigned int,
	unsigned char *, unsigned int, unsigned char *, unsigned int,
	unsigned char [8], int, R_RSA_PRIVATE_KEY *, R_RSA_PUBLIC_KEY *));
int R_DigestBlock PROTO_LIST ((unsigned char *, unsigned int *,
	unsigned char *, unsigned int, int));

int R_DecryptOpenPEMBlock PROTO_LIST ((R_ENVELOPE_CTX *, unsigned char *,
	unsigned int *, unsigned char *, unsigned int));
int R_EncryptOpenPEMBlock PROTO_LIST ((R_ENVELOPE_CTX *, unsigned char *,
	unsigned int *, unsigned char *, unsigned int));

/* Printable ASCII encoding and decoding. */

int R_EncodePEMBlock PROTO_LIST ((unsigned char *, unsigned int *,
	unsigned char *, unsigned int));
int R_DecodePEMBlock PROTO_LIST ((unsigned char *, unsigned int *,
	unsigned char *, unsigned int));

/* Key-pair generation. */

int R_GeneratePEMKeys PROTO_LIST ((R_RSA_PUBLIC_KEY *, R_RSA_PRIVATE_KEY *,
	R_RSA_PROTO_KEY *, R_RANDOM_STRUCT *));

/* Diffie-Hellman key agreement. */

int R_GenerateDHParams PROTO_LIST ((R_DH_PARAMS *, unsigned int,
	unsigned int, R_RANDOM_STRUCT *));
int R_SetupDHAgreement PROTO_LIST ((unsigned char *, unsigned char *,
	unsigned int, R_DH_PARAMS *, R_RANDOM_STRUCT *));
int R_ComputeDHAgreedKey PROTO_LIST ((unsigned char *, unsigned char *,
	unsigned char *, unsigned int, R_DH_PARAMS *));

/* Standard library routines. */

#ifdef USE_ANSI
#define R_memset(x, y, z) memset(x, y, z)
#define R_memcpy(x, y, z) memcpy(x, y, z)
#define R_memcmp(x, y, z) memcmp(x, y, z)
#else
void R_memset PROTO_LIST ((POINTER, int, unsigned int));
void R_memcpy PROTO_LIST ((POINTER, POINTER, unsigned int));
int R_memcmp PROTO_LIST ((POINTER, POINTER, unsigned int));
#endif

#ifdef __cplusplus
}
#endif

#endif /* _RSAEURO_H_ */
