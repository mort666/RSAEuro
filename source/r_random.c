/*
	R_RANDOM.C - random objects for RSAEURO

	Copyright (c) J.S.A.Kapp 1994 - 1995.

	RSAEURO - RSA Library compatible with RSAREF(tm) 2.0.

	All functions prototypes are the Same as for RSAREF(tm).
	To aid compatiblity the source and the files follow the
	same naming comventions that RSAREF(tm) uses.  This should aid
	direct importing to your applications.

	This library is legal everywhere outside the US.  And should
	NOT be imported to the US and used there.

	Random Objects routines, based heavily on RSAREF(tm) random objects
	code.

	All Trademarks Acknowledged.

	Revisions History.
		0.90 First revision, initial version relied heavily
		on RSAREF(tm) compatible code.

		0.91 Current revision, minor improvements to original
		version.  New routines added.
			R_RandomCreate, R_RandomMix
		Compiler must has ANSI standard time routines for new routines
		to operate fully.

		1.00 23/6/95, Final Release Version
*/

#include <stdlib.h>
#include <time.h>

#ifdef MSDOS
	#include <sys\types.h>
#endif

#include "rsaeuro.h"
#include "r_random.h"

#define RANDOM_BYTES_RQ 256
#define RANDOM_BYTES_RQINT 512

#define MIX_CNT 16

/* Set up, random object ready for seeding. */

int R_RandomInit(random)
R_RANDOM_STRUCT *random;        /* new random structure */
{
			/* clear and setup object for seeding */
	R_memset((POINTER)random->state, 0, sizeof(random->state));
	random->outputAvailable = 0;
	random->bytesNeeded = RANDOM_BYTES_RQ;

	return(IDOK);
}



int R_RandomUpdate(random, block, len)
R_RANDOM_STRUCT *random;        /* random structure */
unsigned char *block;           /* block of values to mix in */
unsigned int len;               /* length of block */
{
	MD5_CTX context;
	BYTE digest[16];
	unsigned int i, j;

	MD5Init(&context);
	MD5Update(&context, block, len);
	MD5Final(digest, &context);

	/* add digest to state */

	for(j = 0, i = 16; i > 0; i--) {
		j += random->state[i-1] + digest[i-1];
		random->state[i-1] = (BYTE)j;
		j >>= 8;
	}

	if(random->bytesNeeded < len)
		random->bytesNeeded = 0;
	else
		random->bytesNeeded -= len;

	/* Clear sensitive information. */

	R_memset((POINTER)digest, 0, sizeof (digest));
	j = 0;

	return(IDOK);
}

/* Get the number of seed byte still required by the object */

int R_GetRandomBytesNeeded(bytesNeeded, random)
unsigned int *bytesNeeded;      /* number of mix-in bytes needed */
R_RANDOM_STRUCT *random;        /* random structure */
{
	*bytesNeeded = random->bytesNeeded;

	return(IDOK);
}

int R_GenerateBytes(block, len, random)
unsigned char *block;                             /* block */
unsigned int len;                                 /* length of block */
R_RANDOM_STRUCT *random;                          /* random structure */
{
	MD5_CTX context;
	unsigned int avail, i;

	if(random->bytesNeeded)
		return(RE_NEED_RANDOM);

	avail = random->outputAvailable;

	while(avail < len) {
		R_memcpy((POINTER)block, (POINTER)&random->output[16-avail], avail);
		len -= avail;
		block += avail;

		/* generate new output */

		MD5Init(&context);
		MD5Update(&context, random->state, 16);
		MD5Final(random->output, &context);
		avail = 16;

		/* increment state */
		for(i = 16; i > 0; i--)
			if(random->state[i-1]++)
				break;
	}

	R_memcpy((POINTER)block, (POINTER)&random->output[16-avail], len);
	random->outputAvailable = avail - len;

	return(IDOK);
}

/* Clear Random object when finished. */

void R_RandomFinal(random)
R_RANDOM_STRUCT *random;        /* random structure */
{
	R_memset((POINTER)random, 0, sizeof(R_RANDOM_STRUCT));
}

/* Create Random object, seed ready for use.
	 Requires ANSI Standard time routines to provide seed data.
*/

void R_RandomCreate(random)
R_RANDOM_STRUCT *random;                                /* random structure */
{
	unsigned int bytes;
	clock_t cnow;
	time_t t;
	struct tm *gmt;

			/* clear and setup object for seeding */
	R_memset((POINTER)random->state, 0, sizeof(random->state));
	random->outputAvailable = 0;
	random->bytesNeeded = RANDOM_BYTES_RQINT;  /* using internal value */

	t = time(NULL);                 /* use for seed data */
	gmt = gmtime(&t);

	while(random->bytesNeeded)
		R_RandomUpdate(random, (POINTER)gmt, sizeof(struct tm));

	R_memset((POINTER)gmt, 0, sizeof(struct tm));
	t = 0;
}

/* Mix up state of the current random structure.
	 Again requires both clock functions this just adds something
	 extra to the state.
*/

void R_RandomMix(random)
R_RANDOM_STRUCT *random;
{
	unsigned int i;

	for(i = 0; i < 16; i++) {
		random->state[i] ^= clock();
		random->state[15-i] ^= time(NULL);
	}
}



