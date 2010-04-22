/*
	RSA386.s - processor-specific C library routines for RSAEURO

        Copyright (c) J.S.A.Kapp 1994 - 1996.

	RSAEURO - RSA Library compatible with RSAREF 2.0.

	All functions prototypes are the Same as for RSAREF.
	To aid compatiblity the source and the files follow the
	same naming comventions that RSAREF uses.  This should aid
	direct importing to your applications.

	This library is legal everywhere outside the US.  And should
	NOT be imported to the US and used there.

	Secure Standard Library Routines, i386 assembler versions.
	These are only applicable if NN_DIGIT equal to a 32-bit word.

	Revision history
		0.90 First revision, this is code designed to run on a i386
		processor when compiled using gcc. Support for R_STDLIB.C
		functions.

		0.91 Next revision, this added code for a selection of NN.C
		functions to improve the speed on the multi-precision math
		routines. Functions added:
			_NN_Digits, _NN_Assign,
			_NN_Add, _NN_Decode,
			_NN_Encode, _NN_Sub,
			_NN_Cmp

		Some speed increases where noticed with the addition of
		these functions.
*/

/*      Multipresecion Math Routines */

	.align 2
	.globl _NN_Cmp

_NN_Cmp:
	pushl %ebp
	movl %esp,%ebp
	pushl %ebx
	movl 16(%ebp), %ecx
	testl %ecx, %ecx
	je ncmp1
ncmp5:
	decl %ecx
	leal 0(,%ecx,4),%eax
	movl 8(%ebp),%edx
	movl (%edx,%eax),%eax
	leal 0(,%ecx,4),%edx
	movl 12(%ebp),%ebx
	cmpl %eax,(%ebx,%edx)
	jae ncmp2
	movl $1,%eax
	jmp ncmp3
	.align 2, 0x90
ncmp2:
	jbe ncmp4
	movl $-1,%eax
	jmp ncmp3
	.align 2, 0x90
ncmp4:
	cmpl $0, %ecx
	jne ncmp5
ncmp1:
	xorl %eax,%eax
ncmp3:
	movl -4(%ebp),%ebx
	leave
	ret

	.align 2
	.globl _NN_Zero

_NN_Zero:
	pushl %ebp
	movl %esp,%ebp
	pushl %esi
	movl 12(%ebp), %ecx
	testl %ecx,%ecx
	je nzero1
	movl 8(%ebp), %esi
	xorl %eax,%eax

nzero3:
	cmpl $0, (%esi)
	jne nzero2
	addl $4, %esi
	loop nzero3

nzero1:
	inc %eax

nzero2:
	popl %esi
	leave
	ret

	.align 2
	.globl _NN_Digits

_NN_Digits:
	pushl   %ebp
	movl    %esp, %ebp
	movl    12(%ebp), %ecx
	testl %ecx,%ecx
	je   digit1
	movl    8(%ebp), %edx

digit3:
	dec     %ecx
	cmpl    $0, (%edx, %ecx, 4)
	jnz     digit2
	cmp     $-1, %ecx
	jnz     digit3
digit2:
	movl    %ecx, %eax
	inc     %eax
digit1:
	leave
	ret

	.align 2
	.globl _NN_Assign

_NN_Assign:
	pushl   %ebp
	movl    %esp, %ebp
	movl    16(%ebp), %ecx
	testl %ecx,%ecx
	je   assign1
	pushl   %esi
	pushl   %edi
	movl    8(%ebp), %edi
	movl    12(%ebp), %esi

	cld
	rep
	movsl

	popl    %edi
	popl    %esi
assign1:
	leave
	ret

	.align 2
	.globl _NN_AssignZero

_NN_AssignZero:
	pushl   %ebp
	movl    %esp, %ebp
	movl    12(%ebp), %ecx
	testl %ecx,%ecx
	je   zero1
	pushl   %edi
	movl    8(%ebp), %edi

	xorl    %eax, %eax
	rep
	stosl

	popl    %edi
zero1:
	leave
	ret

	.align 2
	.globl _NN_Add

_NN_Add:
	pushl   %ebp
	movl    %esp,%ebp
	pushl   %edi
	pushl   %esi
	pushl   %ebx
	xorl    %eax,%eax
	movl    20(%ebp),%edx
	cmpl    %edx,%eax
	jae     add1
	movl    8(%ebp),%ebx
	movl    16(%ebp),%ecx
	movl    12(%ebp),%esi
	leal    (%ebx,%edx,4),%edi
add4:
	movl    %eax,%edx
	addl    (%esi),%edx
	cmpl    %eax,%edx
	jae     add2
	movl     (%ecx),%edx
	jmp     add3

add2:
	addl    (%ecx),%edx
	cmpl    %edx,(%ecx)
	seta    %al
	andl    $255,%eax
add3:
	movl    %edx,(%ebx)
	addl    $4,%ebx
	addl    $4,%ecx
	addl    $4,%esi
	cmpl    %edi,%ebx
	jb      add4
add1:
	leal    -12(%ebp),%esp
	popl    %ebx
	popl    %esi
	popl    %edi
	leave
	ret

	.align 2
	.globl _NN_Decode

_NN_Decode:
	pushl %ebp
	movl %esp,%ebp
	subl $8,%esp
	pushl %edi
	pushl %esi
	pushl %ebx
	movl $0,-8(%ebp)
	movl 20(%ebp),%edx
	decl %edx
	js dec1
	movl 8(%ebp),%edi
	movl %edi,-4(%ebp)
dec4:
	xorl %ebx,%ebx
	xorl %ecx,%ecx
	testl %edx,%edx
	jl dec2
dec3:
	movl 16(%ebp),%esi
	movzbl (%edx,%esi),%eax
	sall %cl,%eax
	orl %eax,%ebx
	decl %edx
	addl $8,%ecx
	testl %edx,%edx
	jl dec2
	cmpl $31,%ecx
	jbe dec3
dec2:
	movl -4(%ebp),%edi
	movl %ebx,(%edi)
	addl $4,-4(%ebp)
	incl -8(%ebp)
	testl %edx,%edx
	jge dec4
dec1:
	movl 12(%ebp),%esi
	cmpl %esi,-8(%ebp)
	jae dec5
	movl -8(%ebp),%edi
	movl 8(%ebp),%esi
	leal (%esi,%edi,4),%eax
	movl 12(%ebp),%edi
	leal (%esi,%edi,4),%edx
dec6:
	movl $0,(%eax)
	addl $4,%eax
	cmpl %edx,%eax
	jb dec6
dec5:
	leal -20(%ebp),%esp
	popl %ebx
	popl %esi
	popl %edi
	leave
	ret

	.align 2
	.globl _NN_Encode

_NN_Encode:
	pushl %ebp
	movl %esp,%ebp
	subl $4,%esp
	pushl %edi
	pushl %esi
	pushl %ebx
	movl 8(%ebp),%edi
	movl 20(%ebp),%eax
	movl 12(%ebp),%edx
	decl %edx
	testl %eax,%eax
	je enc1
	movl 16(%ebp),%ebx
	leal (%ebx,%eax,4),%eax
	movl %eax,-4(%ebp)
enc4:
	movl (%ebx),%esi
	xorl %ecx,%ecx
	testl %edx,%edx
	jl enc2
enc3:
	movl %esi,%eax
	shrl %cl,%eax
	movb %al,(%edx,%edi)
	decl %edx
	addl $8,%ecx
	testl %edx,%edx
	jl enc2
	cmpl $31,%ecx
	jbe enc3
enc2:
	addl $4,%ebx
	cmpl %ebx,-4(%ebp)
	ja enc4
	jmp enc1
enc5:
	movb $0,(%edx,%edi)
	decl %edx
enc1:
	testl %edx,%edx
	jge enc5
	leal -16(%ebp),%esp
	popl %ebx
	popl %esi
	popl %edi
	leave
	ret


/* R_STDLIB Assembler Routines */

	.align 2
	.globl _R_memcpy

_R_memcpy:
	pushl   %ebp
	movl    %esp, %ebp
	movl    16(%ebp), %ecx
	testl   %ecx,%ecx
	je   cpyexit
	pushl   %esi
	pushl   %edi
	movl    8(%ebp), %edi
	movl    12(%ebp), %esi

	cld
	rep
	movsb

	cld
	popl    %edi
	popl    %esi
cpyexit:
	leave
	ret

	.align 2
	.globl _R_memcmp

_R_memcmp:
	pushl   %ebp
	movl    %esp, %ebp
	movl    16(%ebp), %ecx
	testl %ecx,%ecx
	je   cmpexit
	pushl   %esi
	pushl   %edi
	movl    8(%ebp), %edi
	movl    12(%ebp), %esi

	cld
	rep
	cmpsb

	xor             %eax, %eax
	cwtl
	movb    -1(%esi), %al
	movb    -1(%edi), %dl
	subb    %dl, %al

	popl    %edi
	popl    %esi
cmpexit:
	leave
	ret

	.align 2
	.globl _R_memset

_R_memset:
	pushl   %ebp
	movl    %esp, %ebp
	movl    16(%ebp), %ecx
	testl %ecx,%ecx
	je   setexit
	pushl   %edi
	movl    8(%ebp), %edi
	movl    12(%ebp), %eax

	rep
	stosb

	popl    %edi
setexit:
	leave
	ret
