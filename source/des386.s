/*
	DES386.S - Data Encryption Standard routines for RSAEURO

        Copyright (c) J.S.A.Kapp 1994 - 1996.

	RSAEURO - RSA Library compatible with RSAREF(tm) 2.0.

	All functions prototypes are the Same as for RSAREF(tm).
	To aid compatiblity the source and the files follow the
	same naming comventions that RSAREF(tm) uses.  This should aid
	direct importing to your applications.

	This library is legal everywhere outside the US.  And should
	NOT be imported to the US and used there.

	Based on Outerbridge's D3DES (V5.09) 1992 Vintage.

	Needs to be passed through 'cpp' be for 'as' assembles it.

	All Trademarks Acknowledged.

	Revision history
		0.90 First revision of this assembler version of the
		desfunc used in DESC.C.  The keys are altered to ease
		the S box look up.  S boxes are modified for 386 use.

		0.91 Current revision some minor bug fixes to original
		code.  Comments revised to reflect original C code.
*/

	/* Crafty DES Function */
#define	F(l,r,key) 	movl r,%eax ;\
	rorl $4,%eax ;\
	xorl key(%esi),%eax ;\
	andl $0xfcfcfcfc,%eax ;\
\
	movb %al,%bl ;\
	xorl _Spbox+6*256(%ebx),l ;\
	movb %ah,%bl ;\
	rorl $16,%eax ;\
	xorl _Spbox+4*256(%ebx),l ;\
	movb %al,%bl ;\
	xorl _Spbox+2*256(%ebx),l ;\
	movb %ah,%bl ;\
	xorl _Spbox(%ebx),l ;\
\
	movl 4+key(%esi),%eax ;\
	xorl r,%eax ;\
	andl $0xfcfcfcfc,%eax ;\
\
	movb %al,%bl ;\
	xorl _Spbox+7*256(%ebx),l ;\
	movb %ah,%bl ;\
	rorl $16,%eax ;\
	xorl _Spbox+5*256(%ebx),l ;\
	movb %al,%bl ;\
	xorl _Spbox+3*256(%ebx),l ;\
	movb %ah,%bl ;\
	xorl _Spbox+256(%ebx),l


	.align 2
.globl _desfunc

_desfunc:
	pushl %ebp
	movl %esp,%ebp
	pushl %esi
	pushl %ebx

	/* Get users data to encrypt from block buffer */
	movl 8(%ebp),%esi	/* esi = block */
	movl (%esi),%ecx	/* ecx = ((long *)block)[0] */
	movl 4(%esi),%edx	/* edx = ((long *)block)[1] */

	/* We use slightly modified S-boxes here */

	/* work = ((left >> 4) ^ right) & 0x0f0f0f0f */
	movl %ecx,%eax
	shrl $4,%eax
	xorl %edx,%eax
	andl $0x0f0f0f0f,%eax

	xorl %eax,%edx		/* right ^= work */

	/* left ^= work << 4 */
	shll $4,%eax
	xorl %eax,%ecx

	/* work = ((left >> 16) ^ right) & 0xffff */
	movl %ecx,%eax
	shrl $16,%eax
	xorl %edx,%eax
	andl $0xffff,%eax

	xorl %eax,%edx		/* right ^= work */

	/* left ^= work << 16 */
	shll $16,%eax
	xorl %eax,%ecx

	/* work = ((right >> 2) ^ left) & 0x33333333 */
	movl %edx,%eax
	shrl $2,%eax
	xorl %ecx,%eax
	andl $0x33333333,%eax

	/* left ^= work */
	xorl %eax,%ecx
	shll $2,%eax

	xorl %eax,%edx		/* right ^= (work << 2) */

	/* work = ((right >> 8) ^ left) & 0xff00ff */
	movl %edx,%eax
	shrl $8,%eax
	xorl %ecx,%eax
	andl $0x00ff00ff,%eax

	xorl %eax,%ecx		/* left ^= work */

	/* right ^= (work << 8) */
	shll $8,%eax
	xorl %eax,%edx

	roll $1,%edx		/* right <<<= 1 */

	/* work = (left ^ right) & 0xaaaaaaaa */
	movl %ecx,%eax
	xorl %edx,%eax
	andl $0xaaaaaaaa,%eax

	xorl %eax,%ecx		/* left ^= work */
	xorl %eax,%edx		/* right ^= work */

	roll $3,%ecx		/* left <<<= 3 */
	roll $2,%edx		/* right <<<= 2 */

	/* Set up for the rounds */
	movl 12(%ebp),%esi	/* esi = key schedule */
	xorl %ebx,%ebx		/* Upper 3 bytes must be zero */

	/* Do the rounds */
	F(%ecx,%edx,0)
	F(%edx,%ecx,8)
	F(%ecx,%edx,16)
	F(%edx,%ecx,24)
	F(%ecx,%edx,32)
	F(%edx,%ecx,40)
	F(%ecx,%edx,48)
	F(%edx,%ecx,56)
	F(%ecx,%edx,64)
	F(%edx,%ecx,72)
	F(%ecx,%edx,80)
	F(%edx,%ecx,88)
	F(%ecx,%edx,96)
	F(%edx,%ecx,104)
	F(%ecx,%edx,112)
	F(%edx,%ecx,120)

	/* Inverse permutation */
	rorl $2,%ecx	/* left >>>= 2 */
	rorl $3,%edx	/* right >>>= 3 */

	/* work = (left ^ right) & 0xaaaaaaaa */
	movl %ecx,%eax
	xorl %edx,%eax
	andl $0xaaaaaaaa,%eax

	xorl %eax,%ecx	/* left ^= work */
	xorl %eax,%edx	/* right ^= work */
	rorl $1,%ecx    /* left >>>= 1 */

	/* work = (left >> 8) ^ right) & 0xff00ff */
	movl %ecx,%eax
	shrl $8,%eax
	xorl %edx,%eax
	andl $0x00ff00ff,%eax

	xorl %eax,%edx	/* right ^= work */

	/* left ^= work << 8 */
	shll $8,%eax
	xorl %eax,%ecx

	/* work = ((left >> 2) ^ right) & 0x33333333 */
	movl %ecx,%eax
	shrl $2,%eax
	xorl %edx,%eax
	andl $0x33333333,%eax

	xorl %eax,%edx	/* right ^= work */

	/* left ^= work << 2 */
	shll $2,%eax
	xorl %eax,%ecx

	/* work = ((right >> 16) ^ left) & 0xffff */
	movl %edx,%eax
	shrl $16,%eax
	xorl %ecx,%eax
	andl $0xffff,%eax

	xorl %eax,%ecx	/* left ^= work */

	/* right ^= work << 16 */
	shll $16,%eax
	xorl %eax,%edx

	/* work = ((right >> 4) ^ left) & 0x0f0f0f0f */
	movl %edx,%eax
	shrl $4,%eax
	xorl %ecx,%eax
	andl $0x0f0f0f0f,%eax

	xorl %eax,%ecx	/* left ^= work */

	/* right ^= work << 4 */
	shll $4,%eax
	xorl %eax,%edx

	/* write output to users block buffer */
	movl 8(%ebp),%esi
	movl %edx,(%esi)
	mov %ecx,4(%esi)

	popl %ebx
	popl %esi
	leave
	ret
