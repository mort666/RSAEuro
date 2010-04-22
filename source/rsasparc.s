/*
	RSASPARC.S - processor-specific C library routines for RSAEURO

        Copyright (c) J.S.A.Kapp 1994 - 1996.

	RSAEURO - RSA Library compatible with RSAREF 2.0.

	All functions prototypes are the Same as for RSAREF.
	To aid compatiblity the source and the files follow the
	same naming comventions that RSAREF uses.  This should aid
	direct importing to your applications.

	This library is legal everywhere outside the US.  And should
	NOT be imported to the US and used there.

	Secure Standard Library Routines, Sparc assembler versions.
	These are only applicable if NN_DIGIT equal to a 32-bit word.

	Requires the 'as' assembler to assemble.  The 'as' assembler
	comes with GNU gcc and is included with 'cc' that comes
	with UNIX boxes.

	Revision history
		0.90 First revision this version should work with most SPARC
		processors.
		Functions added:
			_R_memset, _R_memcpy, _R_memcmp,
			_NN_Digits, _NN_Assign,
			_NN_Add, _NN_Decode,
			_NN_Encode, _NN_AssignZero,
			_NN_Zero, _NN_Cmp.


*/
	/* Math Routines */

	.align 4
	.global _NN_Decode
	.proc 1
_NN_Decode:
	!#PROLOGUE# 0
	save %sp,-112,%sp
	!#PROLOGUE# 1
	mov 0,%i4
	b dec1
	add %i3,-1,%i3
dec5:
	bl dec2
	mov 0,%g3
	ldub [%i2+%i3],%g2
dec3:
	sll %g2,%g3,%g2
	or %i5,%g2,%i5
	addcc %i3,-1,%i3
	bneg dec2
	add %g3,8,%g3
	cmp %g3,31
	bleu,a dec3
	ldub [%i2+%i3],%g2
dec2:
	sll %i4,2,%g2
	st %i5,[%i0+%g2]
	add %i4,1,%i4
dec1:
	cmp %i4,%i1
	bgeu dec4
	cmp %i3,0
	bge dec5
	mov 0,%i5
	b dec6
	cmp %i4,%i1
dec7:
	st %g0,[%i0+%g2]
	add %i4,1,%i4
dec4:
	cmp %i4,%i1
dec6:
	blu dec7
	sll %i4,2,%g2
	ret
	restore

	.align 4
	.global _NN_Encode
	.proc 1
_NN_Encode:
	!#PROLOGUE# 0
	save %sp,-112,%sp
	!#PROLOGUE# 1
	mov 0,%i4
	b enc1
	add %i1,-1,%i1
enc5:
	ld [%i2+%g2],%i5
	cmp %i1,0
	bl enc2
	mov 0,%g3
	srl %i5,%g3,%g2
enc3:
	stb %g2,[%i0+%i1]
	addcc %i1,-1,%i1
	bneg enc2
	add %g3,8,%g3
	cmp %g3,31
	bleu enc3
	srl %i5,%g3,%g2
enc2:
	add %i4,1,%i4
enc1:
	cmp %i4,%i3
	bgeu enc4
	cmp %i1,0
	bge enc5
	sll %i4,2,%g2
enc4:
	cmp %i1,0
	bl enc6
	nop
	stb %g0,[%i0+%i1]
enc7:
	addcc %i1,-1,%i1
	bpos,a enc7
	stb %g0,[%i0+%i1]
enc6:
	ret
	restore

	.align 4
	.global _NN_AssignZero
	.proc 1
_NN_AssignZero:
	!#PROLOGUE# 0
	save %sp,-112,%sp
	!#PROLOGUE# 1
	cmp %i1,0
	be azr1
	nop
azr2:
	st %g0,[%i0]
	addcc %i1,-1,%i1
	bne azr2
	add %i0,4,%i0
azr1:
	ret
	restore

	.align 4
	.global _NN_Cmp
	.proc 1
_NN_Cmp:
	!#PROLOGUE# 0
	save %sp,-112,%sp
	!#PROLOGUE# 1
	cmp %i2,0
ncmp4:
	be ncmp1
	add %i2,-1,%i2
	sll %i2,2,%g2
	ld [%i0+%g2],%g3
	ld [%i1+%g2],%g2
	cmp %g3,%g2
	bleu ncmp2
	sll %i2,2,%g2
	b ncmp3
	mov 1,%i0
ncmp2:
	ld [%i0+%g2],%g3
	ld [%i1+%g2],%g2
	cmp %g3,%g2
	bgeu ncmp4
	cmp %i2,0
	b ncmp3
	mov -1,%i0
ncmp1:
	mov 0,%i0
ncmp3:
	ret
	restore

	.align 4
	.global _NN_Zero
	.proc 1
_NN_Zero:
	!#PROLOGUE# 0
	save %sp,-112,%sp
	!#PROLOGUE# 1
	cmp %i1,0
	be,a nzer1
	mov 1,%i0
	ld [%i0],%g2
nzer3:
	cmp %g2,0
	be nzer2
	add %i0,4,%i0
	b nzer1
	mov 0,%i0
nzer2:
	addcc %i1,-1,%i1
	bne,a nzer3
	ld [%i0],%g2
	mov 1,%i0
nzer1:
	ret
	restore

	.align 4
	.global _NN_Assign
	.proc 1
_NN_Assign:
	!#PROLOGUE# 0
	save %sp,-112,%sp
	!#PROLOGUE# 1
	cmp %i2,0
	be nass1
	nop
nass2:
	ld [%i1],%g2
	st %g2,[%i0]
	add %i1,4,%i1
	addcc %i2,-1,%i2
	bne nass2
	add %i0,4,%i0
nass1:
	ret
	restore

	.align 4
	.global _NN_Digits
	.proc 1
_NN_Digits:
	!#PROLOGUE# 0
	save %sp,-112,%sp
	!#PROLOGUE# 1
	mov %i0,%g3
	orcc %i1,%g0,%i0
	be ndig1
	nop
	add %i0,-1,%i0
	sll %i0,2,%g2
ndig2:
	ld [%g3+%g2],%g2
	cmp %g2,0
	bne,a ndig1
	add %i0,1,%i0
	add %i0,-1,%i0
	cmp %i0,-1
	bne ndig2
	sll %i0,2,%g2
	add %i0,1,%i0
ndig1:
	ret
	restore

	.align 4
	.global _NN_Add
	.proc 1
_NN_Add:
	!#PROLOGUE# 0
	save %sp,-112,%sp
	!#PROLOGUE# 1
	mov %i0,%i4
	cmp %i3,0
	be nadd1
	mov 0,%i0
nadd4:
	ld [%i1],%g2
	add %i0,%g2,%g3
	cmp %g3,%i0
	bgeu nadd2
	add %i1,4,%i1
	ld [%i2],%g3
	b nadd3
	add %i2,4,%i2
nadd2:
	ld [%i2],%g2
	add %g3,%g2,%g3
	add %i2,4,%i2
	cmp %g3,%g2
	addx %g0,0,%i0
nadd3:
	st %g3,[%i4]
	addcc %i3,-1,%i3
	bne nadd4
	add %i4,4,%i4
nadd1:
	ret
	restore


	/* R_STDLIB Routines */

	.align 4
	.global _R_memset
	.proc 1

_R_memset:
	!#PROLOGUE# 0
	save %sp,-112,%sp
	!#PROLOGUE# 1
	cmp %i2,0
	be set1
	nop
set2:
	stb %i1,[%i0]
	addcc %i2,-1,%i2
	bne set2
	add %i0,1,%i0
set1:
	ret
	restore

	.align 4
	.global _R_memcpy
	.proc 1

_R_memcpy:
	!#PROLOGUE# 0
	save %sp,-112,%sp
	!#PROLOGUE# 1
	cmp %i2,0
	be cpy1
	nop
cpy2:
	ldub [%i1],%g2
	stb %g2,[%i0]
	add %i1,1,%i1
	addcc %i2,-1,%i2
	bne cpy2
	add %i0,1,%i0
cpy1:
	ret
	restore

	.align 4
	.global _R_memcmp
	.proc 1

_R_memcmp:
	!#PROLOGUE# 0
	save %sp,-112,%sp
	!#PROLOGUE# 1
	cmp %i2,0
	be,a cmp1
	mov 0,%i0
	ldub [%i0],%g3
cmp3:
	ldub [%i1],%g2
	add %i1,1,%i1
	cmp %g3,%g2
	be cmp2
	add %i0,1,%i0
	ldub [%i0-1],%i0
	ldub [%i1-1],%g2
	b cmp1
	sub %i0,%g2,%i0
cmp2:
	addcc %i2,-1,%i2
	bne,a cmp3
	ldub [%i0],%g3
	mov 0,%i0
cmp1:
	ret
	restore

