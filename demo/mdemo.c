/*
	MDEMO.C - MD2/MD4/MD5 Hash Demo Application.

	Copyright (c) J.S.A.Kapp 1994.

	RSAEURO - RSA Library compatible with RSAREF(tm) 2.0.

	This is a Demo program, which is part of RSAEURO

	Uses, rsaeuro.h also requires link with rsaeuro
	library file.

	This file is use to demonstrate the process of
	programming with RSAEURO.

	Requires RSAEURO.
*/

#include <stdio.h>
#include <stdlib.h>

/* This includes are used for obtaining and displaying the last modified
	 time for the file. */

#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "rsaeuro.h"    /* include rsaeuro function header file */

#define SIZE 1024000

static void printdigest PROTO_LIST((char *out, unsigned int len));

void main(int argc, char *argv[])
{
	unsigned len, files;
	unsigned long byte_cnt;
	unsigned char *buff, md2out[20], md4out[20], md5out[20];
	unsigned int md2len, md4len, md5len;
	struct stat statbuf;
	R_DIGEST_CTX md2ctxt, md5ctxt, md4ctxt;
	FILE *fp;


	fprintf(stderr, "MDEMO - MD2/MD4/MD5 Demo Application Using %s.\n", RSAEURO_IDENT);
	fprintf(stderr, "MD2/MD4/MD5 RSA Data Security, Inc. Message Digest Algorithms.\n");

	/* We expect 1 or more arguments */
	if(argc < 2) {
		fprintf(stderr, "This program prints the validation information for a file.\n");
		fprintf(stderr, "Examples:\n");
		fprintf(stderr, "          MDEMO SCAN.EXE\n");
		fprintf(stderr, "          MDEMO SCANRES.EXE\n");
		exit(1);
	}

	if((buff = (unsigned char *) calloc(SIZE, 1)) == NULL) {
		fprintf(stderr, "Memory Allocation Error.");
		exit(1);
	}

	/* Loop through each filename on the invocation line */

	for(files = 1; files < argc; files++) {
		printf("\n\tFile Name:  %s\n", argv[files]);
		fp = fopen(argv[files],"rb");
		if(!fp) {
			fprintf(stderr, "\n Sorry, I cannot open the input file.\n");
			continue;
		}

		/* Byte count and hash contexts to initial values */
		byte_cnt = 0;
		R_DigestInit(&md2ctxt, DA_MD2);
		R_DigestInit(&md4ctxt, DA_MD4);
		R_DigestInit(&md5ctxt, DA_MD5);

		/* Read the file in chunks until done */
		while((len = fread(buff, 1, sizeof(buff), fp)) != 0)
		{
			/* hash next part of file */
			R_DigestUpdate(&md2ctxt, buff, len);
			R_DigestUpdate(&md4ctxt, buff, len);
			R_DigestUpdate(&md5ctxt, buff, len);
			/* Byte count of file */
			byte_cnt += len;
		}

		/* finalise hash contexts */
		R_DigestFinal(&md2ctxt, md2out, &md2len);
		R_DigestFinal(&md4ctxt, md4out, &md4len);
		R_DigestFinal(&md5ctxt, md5out, &md5len);

		/* Get file info so we can print last modified time for file */
		fstat(fileno(fp), &statbuf);

		/* Give the user the results */
		printf("               Size:  %ld\n", byte_cnt);
		printf("               Date:  %s", ctime(&statbuf.st_mtime));
		printf("File Authentication:\n");
		printf("               MD2 Output - ");
		printdigest(md2out, md2len); 
		printf("               MD4 Output - ");
		printdigest(md4out, md4len); 
		printf("               MD5 Output - ");
		printdigest(md5out, md5len);
		fclose(fp);
	}

	exit(0);
}

static void printdigest(unsigned char *out, unsigned int len)
{
	int i;

	for(i = 0; i < len; i++)
		printf("%02X", *(out+i));

	printf("\n");
}

