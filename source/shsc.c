/*
	SHSC.C - Secure Hash Standard Code

    Copyright (c) J.S.A.Kapp 1994 - 1996.

	RSAEURO - RSA Library compatible with RSAREF(tm) 2.0.

	All functions prototypes are the Same as for RSAREF(tm).
	To aid compatiblity the source and the files follow the
	same naming comventions that RSAREF(tm) uses.  This should aid
	direct importing to your applications.

	This library is legal everywhere outside the US.  And should
	NOT be imported to the US and used there.

	All Trademarks Acknowledged.

	Revision history
		0.90 first revision, initial implementation of the secure
		hash standard FIPS PUB 180.

        1.03 second revision, SHSFinal modified to output to a char
        array specified by the user.
*/


#include "rsaeuro.h"
#include "shs.h"

/* The SHS Mysterious Constants */

#define K1  0x5A827999L 	/* Rounds  0-19 */
#define K2  0x6ED9EBA1L 	/* Rounds 20-39 */
#define K3  0x8F1BBCDCL 	/* Rounds 40-59 */
#define K4  0xCA62C1D6L     /* Rounds 60-79 */

/* SHS initial values */

#define Ainit 0x67452301L
#define Binit 0xEFCDAB89L
#define Cinit 0x98BADCFEL
#define Dinit 0x10325476L
#define Einit 0xC3D2E1F0L

/* The SHS f()-functions */

#define f1(x,y,z)   (( x & y ) | ( ~x & z ))              /* Rounds  0-19 */
#define f2(x,y,z)   ( x ^ y ^ z )                         /* Rounds 20-39 */
#define f3(x,y,z)   (( x & y ) | ( x & z ) | ( y & z ))   /* Rounds 40-59 */
#define f4(x,y,z)   ( x ^ y ^ z )                         /* Rounds 60-79 */

/* 32-bit rotate - kludged with shifts */

#define S(n,X)	((X << n) | (X >> (32 - n)))

/* The initial expanding function */

#define expand(count)	W[count] = W[count - 3] ^ W[count - 8] ^ W[count - 14] ^ W[count - 16]

/* The four SHS sub-rounds */

#define subRound1(count)    \
	{ \
		temp = S(5, A) + f1(B, C, D) + E + W[count] + K1; \
		E = D; \
		D = C; \
		C = S(30, B); \
		B = A; \
		A = temp; \
	}

#define subRound2(count)    \
	{ \
		temp = S(5, A) + f2(B, C, D) + E + W[count] + K2; \
		E = D; \
		D = C; \
		C = S(30, B); \
		B = A; \
		A = temp; \
	}

#define subRound3(count)    \
	{ \
		temp = S(5, A) + f3(B, C, D) + E + W[count] + K3; \
		E = D; \
		D = C; \
		C = S(30, B); \
		B = A; \
		A = temp; \
	}

#define subRound4(count)    \
	{ \
		temp = S(5, A) + f4(B, C, D) + E + W[count] + K4; \
		E = D; \
		D = C; \
		C = S(30, B); \
		B = A; \
		A = temp; \
	}

/* The two buffers of 5 32-bit words */

UINT4 h0, h1, h2, h3, h4;
UINT4 A, B, C, D, E;

static void byteReverse PROTO_LIST ((UINT4 *, int ));
static void SHSTransform PROTO_LIST ((SHS_CTX *));
static void Encode PROTO_LIST((unsigned char *, UINT4 *, unsigned int));

/* Initialize the SHS values */

void SHSInit(context)
SHS_CTX *context;               /* context */
{
	/* Set the h-vars to their initial values */
	context->digest[0] = Ainit;
	context->digest[1] = Binit;
	context->digest[2] = Cinit;
	context->digest[3] = Dinit;
	context->digest[4] = Einit;

	/* Initialise bit count */
	context->countLo = context->countHi = 0L;
}

/* Update SHS for a block of data.

   This code assumes that the buffer size is a multiple of
   SHS_BLOCKSIZE bytes long.
*/

void SHSUpdate(context, buffer, count)
SHS_CTX *context;               /* context */
BYTE *buffer;										/* input block */
int count;                      /* length of input block */
{
	/* Update bitcount */
	if((context->countLo + ((UINT4) count << 3)) < context->countLo)
		 context->countHi++;	/* Carry from low to high bitCount */

	context->countLo += ((UINT4) count << 3);
	context->countHi += ((UINT4) count >> 29);

	/* Process data in SHS_BLOCKSIZE chunks */
	while(count >= SHS_BLOCKSIZE) {
		R_memcpy((POINTER)context->data, buffer, SHS_BLOCKSIZE);
		byteReverse(context->data, SHS_BLOCKSIZE);
		SHSTransform(context);
		buffer += SHS_BLOCKSIZE;
		count -= SHS_BLOCKSIZE;
	}

	/* Handle any remaining bytes of data. */
	R_memcpy((POINTER)context->data, buffer, count);
}

/* Finalize SHS hash, outputs to a unsigned char array.
   array must be > 20 bytes in length.
*/

void SHSFinal(digest, context)
BYTE *digest;
SHS_CTX *context;               /* context */
{
	int count;
	UINT4 lowBitcount = context->countLo, highBitcount = context->countHi;

	/* Compute number of bytes mod 64 */
	count = (int) ((context->countLo >> 3) & 0x3F);

	/* Set the first char of padding to 0x80. */
	((BYTE *) context->data)[count++] = 0x80;

	/* Pad out to 56 mod 64 */
	if(count > 56) {
		/* Two lots of padding:  Pad the first block to 64 bytes */
		R_memset((BYTE *) context->data + count, 0, 64 - count);
		byteReverse(context->data, SHS_BLOCKSIZE);
		SHSTransform(context);

		/* Now fill the next block with 56 bytes */
		R_memset((POINTER)context->data, 0, 56);
	} else
		/* Pad block to 56 bytes */
		R_memset((BYTE *) context->data + count, 0, 56 - count);

	byteReverse(context->data, SHS_BLOCKSIZE);

	/* Append length in bits and transform */
	context->data[14] = highBitcount;
	context->data[15] = lowBitcount;

	SHSTransform(context);
	byteReverse(context->data, SHS_DIGESTSIZE);

    Encode(digest, context->digest, 20);

    R_memset((POINTER)context, 0, sizeof(SHS_CTX));
}

static void byteReverse(buffer, byteCount)
UINT4 *buffer;
int byteCount;
{
	UINT4 value;
	int count;

	/* Find out what the byte order is on this machine.
		 Big endian is for machines that place the most significant byte
		 first (eg. Sun SPARC). Little endian is for machines that place
		 the least significant byte first (eg. VAX). */


	if((*(unsigned short *) ("#P") >> 8) == '#')
		return;

	byteCount /= sizeof(UINT4);
	for(count = 0; count < byteCount; count++) {
		value = (buffer[count] << 16) | (buffer[count] >> 16);
		buffer[count] = ((value & 0xFF00FF00L) >> 8) | ((value & 0x00FF00FFL) << 8);
	}
}

/* Perform the SHS transformation. */

static void SHSTransform(context)
SHS_CTX *context;
{
	UINT4 W[80], temp;
	int i;

	/* Step 1.	Copy the data buffer into the local work buffer */
	for(i = 0; i < 16; i++)
		W[i] = context->data[i];

	/* Step 2.	Expand the 16 words into 64 temporary data words */
	expand(16); expand(17); expand(18); expand(19); expand(20);
	expand(21); expand(22); expand(23); expand(24); expand(25);
	expand(26); expand(27); expand(28); expand(29); expand(30);
	expand(31); expand(32); expand(33); expand(34); expand(35);
	expand(36); expand(37); expand(38); expand(39); expand(40);
	expand(41); expand(42); expand(43); expand(44); expand(45);
	expand(46); expand(47); expand(48); expand(49); expand(50);
	expand(51); expand(52); expand(53); expand(54); expand(55);
	expand(56); expand(57); expand(58); expand(59); expand(60);
	expand(61); expand(62); expand(63); expand(64); expand(65);
	expand(66); expand(67); expand(68); expand(69); expand(70);
	expand(71); expand(72); expand(73); expand(74); expand(75);
	expand(76); expand(77); expand(78); expand(79);

	/* Step 3.	Set up first buffer */
	A = context->digest[0];
	B = context->digest[1];
	C = context->digest[2];
	D = context->digest[3];
	E = context->digest[4];

	/* Step 4.	Serious mangling, divided into four sub-rounds */
	subRound1(0); subRound1(1); subRound1(2); subRound1(3);
	subRound1(4); subRound1(5); subRound1(6); subRound1(7);
	subRound1(8); subRound1(9); subRound1(10); subRound1(11);
	subRound1(12); subRound1(13); subRound1(14); subRound1(15);
	subRound1(16); subRound1(17); subRound1(18); subRound1(19);

	subRound2(20); subRound2(21); subRound2(22); subRound2(23);
	subRound2(24); subRound2(25); subRound2(26); subRound2(27);
	subRound2(28); subRound2(29); subRound2(30); subRound2(31);
	subRound2(32); subRound2(33); subRound2(34); subRound2(35);
	subRound2(36); subRound2(37); subRound2(38); subRound2(39);

	subRound3(40); subRound3(41); subRound3(42); subRound3(43);
	subRound3(44); subRound3(45); subRound3(46); subRound3(47);
	subRound3(48); subRound3(49); subRound3(50); subRound3(51);
	subRound3(52); subRound3(53); subRound3(54); subRound3(55);
	subRound3(56); subRound3(57); subRound3(58); subRound3(59);

	subRound4(60); subRound4(61); subRound4(62); subRound4(63);
	subRound4(64); subRound4(65); subRound4(66); subRound4(67);
	subRound4(68); subRound4(69); subRound4(70); subRound4(71);
	subRound4(72); subRound4(73); subRound4(74); subRound4(75);
	subRound4(76); subRound4(77); subRound4(78); subRound4(79);

	/* Step 5.	Build message digest */
	context->digest[0] += A;
	context->digest[1] += B;
	context->digest[2] += C;
	context->digest[3] += D;
	context->digest[4] += E;

    /* Clear sensitive information */

	R_memset((POINTER) W, 0, sizeof(W));
}

/* Encode SHS output in char array */

static void Encode(output, input, len)
unsigned char *output;
UINT4 *input;
unsigned int len;
{
	unsigned int i, j;

	for(i = 0, j = 0; j < len; i++, j += 4) {
        output[j+3] = (unsigned char)(input[i] & 0xff);
        output[j+2] = (unsigned char)((input[i] >> 8) & 0xff);
        output[j+1] = (unsigned char)((input[i] >> 16) & 0xff);
        output[j] = (unsigned char)((input[i] >> 24) & 0xff);
	}
}
