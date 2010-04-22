/*
	RSA68K.S - processor-specific C library routines for RSAEURO

        Copyright (c) J.S.A.Kapp 1994 - 1996.

	RSAEURO - RSA Library compatible with RSAREF 2.0.

	All functions prototypes are the Same as for RSAREF.
	To aid compatiblity the source and the files follow the
	same naming comventions that RSAREF uses.  This should aid
	direct importing to your applications.

	This library is legal everywhere outside the US.  And should
	NOT be imported to the US and used there.

	Secure Standard Library Routines, MC68000 assembler versions.
	These are only applicable if NN_DIGIT equal to a 32-bit word.

	Requires the 'as' assembler to assemble.  Should work on all
	680x0 family processors.  The 'as' assembler comes with GNU
	gcc and is included with 'cc' that comes with UNIX boxes.

	Revision history
		0.90 First revision, this is code designed to run on a M68k
		processor when compiled using gcc. Support for R_STDLIB.C
		functions. Also added code for a selection of NN.C functions
		to improve the speed on the multi-precision math routines.
		Functions added:
			_R_memset, _R_memcpy, _R_memcmp,
			_NN_Digits, _NN_Assign,
			_NN_Add, _NN_Decode,
			_NN_Encode, _NN_AssignZero,
			_NN_Zero, _NN_Cmp.

		Some speed increases where noticed with the addition of
		these functions.
*/

	/* R_STDLIB Routines */

	.even
	.globl _R_memset

_R_memset:
	link a6, #0
  movel a6@(16), d1
	tstl d1
	jeq set1

	movel a6@(8), a0
	moveb a6@(15), d0

set2:
	moveb d0, a0@
	addql #1, a0

	subql #1, d1
	tstl d1
	jne set2

set1:
	unlk a6
	rts

	.even
	.globl _R_memcpy

/*
Alternative _R_memcpy routine, should work exactly the same as the other.

_R_memcpy:
	link a6,#0
	tstl a6@(16)
	jeq cpy1

cpy2:
	movel a6@(8),a0
	movel a6@(12),a1
	moveb a1@,a0@
	addql #1,a6@(12)
	addql #1,a6@(8)
	subql #1,a6@(16)
	tstl a6@(16)
	jne cpy2

cpy1:
	unlk a6
	rts
*/
_R_memcpy:
	link a6, #0
	movel a6@(16), d1
	tstl    d1
	jeq cpy1

	movel a6@(8), a1
	movel a6@(12), a0
	clrl d0
cpy2:
	moveb a0@(d0:l), a1@(d0:l)
	addql #1,d0
	cmpl d0, d1
	jhi cpy2
cpy1:
	unlk a6
	rts


	.even
	.globl _R_memcmp

_R_memcmp:
	link a6, #0
	movel d2, sp@-
	tstl a6@(16)
	jeq cmp1

	movel a6@(8), a0
	movel a6@(12), a1

cmp4:
	moveb a1@, d0
	addqw #1, a1
	moveb a0@, d1
	addqw #1, a0
	cmpb d1, d0
	jeq cmp2
	subqw #1, a0
	clrl d0
	moveb a0@, d0
	subqw #1, a1
	clrl d1
	moveb a1@, d1
	movel d0, d2
	subl d1, d2
	movel d2, d1
	movel d1, d0
	jra cmp3

cmp2:
	subql #1, a6@(16)
	tstl a6@(16)
	jne cmp4

cmp1:
	clrl d0

cmp3:
	movel a6@(-4), d2
	unlk a6
	rts

	/* Multipresecion Math Routines */

	.even
	.globl _NN_Digits

_NN_Digits:
	link a6,#0
	movel a6@(8), a0
	movel a6@(12), d0
	jra digit1

digit2:
	tstl a0@(d0:l:4)
	jne digitexit
digit1:
	subql #1, d0
	jpl digit2
digitexit:
	addql #1, d0
	unlk a6
	rts

	.even
	.globl _NN_Decode

_NN_Decode:
	link a6,#0
	moveml #0x3e20, sp@-
	movel a6@(8), a2
	movel a6@(12), d5
	movel a6@(16), a1
	subl a0, a0
	movel a6@(20), d1
	subql #1, d1
	jmi dec1
dec4:
	clrl d4
	clrl d2
	tstl d1
	jlt dec2
	clrl d3
dec3:
	moveb a1@(d1:l), d3
	movel d3, d0
	lsll d2, d0
	orl d0, d4
	subql #1, d1
	addql #8, d2
	tstl d1
	jlt dec2
	moveq #31, d6
	cmpl d2, d6
	jcc dec3
dec2:
	movel d4, a2@(a0:l:4)
	addqw #1, a0
	tstl d1
	jge dec4
	jra dec1
dec5:
	clrl a2@(a0:l:4)
	addqw #1, a0
dec1:
	cmpl a0, d5
	jhi dec5
	moveml a6@(-24), #0x47c
	unlk a6
	rts

	.even
	.globl _NN_Encode

_NN_Encode:
	link a6,#0
	moveml #0x3c20, sp@-
	movel a6@(8), a1
	movel a6@(16), a2
	movel a6@(20), d4
	subl a0, a0
	movel a6@(12), d1
	subql #1, d1
	clrl d5
	cmpl d5, d4
	jls enc1
enc4:
	movel a2@(a0:l:4), d3
	clrl d2
	tstl d1
	jlt enc2
enc3:
	movel d3, d0
	lsrl d2, d0
	moveb d0, a1@(d1:l)
	subql #1, d1
	addql #8, d2
	tstl d1
	jlt enc2
	moveq #31, d5
	cmpl d2, d5
	jcc enc3
enc2:
	addqw #1, a0
	cmpl a0, d4
	jhi enc4
	jra enc1
enc5:
	clrb a1@(d1:l)
	subql #1, d1
enc1:
	tstl d1
	jge enc5
	moveml a6@(-20), #0x43c
	unlk a6
	rts

	.even
	.globl _NN_Assign

_NN_Assign:
	link a6,#0
	movel d2,sp@-
	movel a6@(16), d1
	tstl    d1
	jeq ass1

	movel a6@(8), a1
	movel a6@(12), a0
	clrl d0
ass2:
	movel a0@(d0:l:4), a1@(d0:l:4)
	addql #1, d0
	cmpl d0, d1
	jhi ass2
ass1:
	movel a6@(-4), d2
	unlk a6
	rts

	.even
	.globl _NN_AssignZero

_NN_AssignZero:
	link a6,#0
	movel d2,sp@-
	movel a6@(12), d1
	tstl    d1
	jeq ass1

	movel a6@(8), a0
	clrl d0
	clrl d2
ass2:
	movel d2, a0@(d0:l:4)
	addql #1, d0
	cmpl d0, d1
	jhi ass2
ass1:
	movel a6@(-4), d2
	unlk a6
	rts

	.even
	.globl _NN_Add

_NN_Add:
	link a6,#0
	moveml #0x3030, sp@-
	movel a6@(20), d2
	tstl d2
	jeq add1

	movel a6@(8), a3
	movel a6@(12), a2
	movel a6@(16), a1
	clrl d0
	clrl d1

add4:
	movel d0, a0
	addl a2@(d1:l:4), a0
	cmpl a0, d0
	jls add2
	movel a1@(d1:l:4), a0
	jra add3
add2:
	addl a1@(d1:l:4), a0
	cmpl a1@(d1:l:4), a0
	scs d0
	extbl d0
	negl d0
add3:
	movel a0,a3@(d1:l:4)
	addql #1, d1
	cmpl d1, d2
	jhi add4

add1:
	moveml a6@(-16), #0xc0c
	unlk a6
	rts

	.even
	.globl _NN_Cmp

_NN_Cmp:
	link a6, #0
	movel a6@(8), a1
	movel a6@(12), a0
	movel a6@(16), d0

ncmp4:
	tstl d0
	jeq ncmp1

	subql #1, d0
	movel a1@(d0:l:4), d1
	cmpl a0@(d0:l:4), d1
	jls ncmp2
	movel #1, d0
	jra ncmp3
ncmp2:
	jcc ncmp4
	movel #-1, d0
	jra ncmp3

ncmp1:
	clrl d0

ncmp3:
	unlk a6
	rts

	.even
	.globl _NN_Zero

_NN_Zero:
	link a6, #0
	movel a6@(8), a0
	movel a6@(12), d0
	jeq nzero1

nzero2:
	tstl a0@+
	jne nzero3
	subql #1, d0
	jne nzero2
nzero3:
	clrl d0
	jra nzero4

nzero1:
	movel #1, d0

nzero4:
	unlk a6
	rts



