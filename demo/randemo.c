/*
	RANDEMO.C - RANDOM Objects Demo.

	Copyright (c) J.S.A.Kapp 1994.

	RSAEURO - RSA Library compatible with RSAREF(tm) 2.0.

	This is a Demo program, which is part of RSAEURO

	Uses, rsaeuro.h also requires link with rsaeuro
	library file.

	This file is use to demonstrate the process of
	programming with RSAEURO.
*/

#include <stdio.h>
#include <stdlib.h>

/* This includes are used for obtaining and displaying the last modified
	 time for the file. */

#include "rsaeuro.h"    /* include rsaeuro function header file */

static void printbuff PROTO_LIST((unsigned char *out, int len));

void main(void)
{
	unsigned char freshout[20], seedbyte = 1;
	unsigned int bytesneeded;
	R_RANDOM_STRUCT randomstruct;

	fprintf(stderr, "RANDEMO - Random Object Demo Using %s.\n", RSAEURO_IDENT);

	R_RandomCreate(&randomstruct);

	R_GenerateBytes(freshout, sizeof(freshout), &randomstruct);

	printf("\n        Random Output 1 - ");
	printbuff(freshout, sizeof(freshout));

	R_RandomMix(&randomstruct);

	R_GenerateBytes(freshout, sizeof(freshout), &randomstruct);
	printf("        Mixed Random Output 1 - ");
	printbuff(freshout, sizeof(freshout));

	R_RandomFinal(&randomstruct);

	R_RandomInit(&randomstruct);

	while(1) {
		R_GetRandomBytesNeeded(&bytesneeded, &randomstruct);
		if(bytesneeded == 0)
			break;

		R_RandomUpdate(&randomstruct, &seedbyte, 1);
	}

	R_GenerateBytes(freshout, sizeof(freshout), &randomstruct);

	printf("        Random Output 2 - ");
	printbuff(freshout, sizeof(freshout));

	R_RandomMix(&randomstruct);

	R_GenerateBytes(freshout, sizeof(freshout), &randomstruct);
	printf("        Mixed Random Output 2 - ");
	printbuff(freshout, sizeof(freshout));

	R_GenerateBytes(freshout, sizeof(freshout), &randomstruct);
	printf("        Mixed Random Output 2 - ");
	printbuff(freshout, sizeof(freshout));

	R_RandomFinal(&randomstruct);
}

static void printbuff(unsigned char *out, int len)
{
	int i;

	for(i = 0; i < len; i++)
		printf("%02X", *(out+i));

	printf("\n");
}

