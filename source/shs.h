/*
	SHS.H - header file for Secure Hash Standard Code

    Copyright (c) J.S.A.Kapp 1994 - 1996.

	RSAEURO - RSA Library compatible with RSAREF 2.0.

	All functions prototypes are the Same as for RSAREF.
	To aid compatiblity the source and the files follow the
	same naming comventions that RSAREF uses.  This should aid
				direct importing to your applications.

	This library is legal everywhere outside the US.  And should
	NOT be imported to the US and used there.

	Secure Hash Standard Code header file.

	Revision 1.00. - JSAK

    Revision 1.03. - JSAK
*/

#ifndef _SHS_H_
#define _SHS_H_

#include "global.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The SHS block size and message digest sizes, in bytes */

#define SHS_BLOCKSIZE   64
#define SHS_DIGESTSIZE  20

/* The structure for storing SHS info */

typedef struct {
	UINT4 digest [5];             /* Message digest */
	UINT4 countLo, countHi;       /* 64-bit bit count */
	UINT4 data [16];              /* SHS data buffer */
} SHS_CTX;

void SHSInit PROTO_LIST ((SHS_CTX *));
void SHSUpdate PROTO_LIST ((SHS_CTX *, unsigned char *, int ));
void SHSFinal PROTO_LIST ((unsigned char *, SHS_CTX *));

#ifdef __cplusplus
}
#endif

#endif /* _SHS_H_ */
