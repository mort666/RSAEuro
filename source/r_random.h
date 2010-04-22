/*
	R_RANDOM.H - header file for R_RANDOM.C

	Copyright (c) J.S.A.Kapp 1994 - 1995.

	RSAEURO - RSA Library compatible with RSAREF(tm) 2.0.

	All functions prototypes are the Same as for RSAREF(tm).
	To aid compatiblity the source and the files follow the
	same naming comventions that RSAREF(tm) uses.  This should aid
	direct importing to your applications.

	This library is legal everywhere outside the US.  And should
	NOT be imported to the US and used there.

	All Trademarks Acknowledged.

	Random Number Routines Header File.

	Revision 1.00 - JSAK 23/6/95, Final Release Version
*/

int R_GenerateBytes PROTO_LIST
  ((unsigned char *, unsigned int, R_RANDOM_STRUCT *));
