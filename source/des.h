/*
	DES.H - header file for DESC.C

	Copyright (c) J.S.A.Kapp 1994 - 1995.

	RSAEURO - RSA Library compatible with RSAREF(tm) 2.0.

	All functions prototypes are the Same as for RSAREF(tm).
	To aid compatiblity the source and the files follow the
	same naming comventions that RSAREF(tm) uses.  This should aid
	direct importing to your applications.

	This library is legal everywhere outside the US.  And should
	NOT be imported to the US and used there.

	All Trademarks Acknowledged.

	DES Code header file.

	Revision 1.00 - JSAK 23/6/95, Final Release Version
*/

#ifndef _DES_H_
#define _DES_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  UINT4 subkeys[32];                                             /* subkeys */
  UINT4 iv[2];                                       /* initializing vector */
  UINT4 originalIV[2];                        /* for restarting the context */
  int encrypt;                                               /* encrypt flag */
} DES_CBC_CTX;

typedef struct {
  UINT4 subkeys[32];                                             /* subkeys */
  UINT4 iv[2];                                       /* initializing vector */
  UINT4 inputWhitener[2];                                 /* input whitener */
  UINT4 outputWhitener[2];                               /* output whitener */
  UINT4 originalIV[2];                        /* for restarting the context */
  int encrypt;                                              /* encrypt flag */
} DESX_CBC_CTX;

typedef struct {
  UINT4 subkeys[3][32];                     /* subkeys for three operations */
  UINT4 iv[2];                                       /* initializing vector */
  UINT4 originalIV[2];                        /* for restarting the context */
  int encrypt;                                              /* encrypt flag */
} DES3_CBC_CTX;

void DES_CBCInit PROTO_LIST 
  ((DES_CBC_CTX *, unsigned char *, unsigned char *, int));
int DES_CBCUpdate PROTO_LIST
  ((DES_CBC_CTX *, unsigned char *, unsigned char *, unsigned int));
void DES_CBCRestart PROTO_LIST ((DES_CBC_CTX *));

void DESX_CBCInit PROTO_LIST
  ((DESX_CBC_CTX *, unsigned char *, unsigned char *, int));
int DESX_CBCUpdate PROTO_LIST
  ((DESX_CBC_CTX *, unsigned char *, unsigned char *, unsigned int));
void DESX_CBCRestart PROTO_LIST ((DESX_CBC_CTX *));

void DES3_CBCInit PROTO_LIST 
  ((DES3_CBC_CTX *, unsigned char *, unsigned char *, int));
int DES3_CBCUpdate PROTO_LIST
  ((DES3_CBC_CTX *, unsigned char *, unsigned char *, unsigned int));
void DES3_CBCRestart PROTO_LIST ((DES3_CBC_CTX *));

#ifdef __cplusplus
}
#endif
#endif /* _DES_H_ */
