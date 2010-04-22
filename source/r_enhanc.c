/*
	R_ENHANC.C - cryptographic enhancements for RSAEURO

    Copyright (c) J.S.A.Kapp 1994 - 1996.

	RSAEURO - RSA Library compatible with RSAREF(tm) 2.0.

	All functions prototypes are the Same as for RSAREF(tm).
	To aid compatiblity the source and the files follow the
	same naming comventions that RSAREF(tm) uses.  This should aid
	direct importing to your applications.

	This library is legal everywhere outside the US.  And should
	NOT be imported to the US and used there.

	All Trademarks Acknowledged.

	Cryptographic Enhancements.

	Revision history
		0.90 First revision, initial production of file.

		0.91 Second revision, altered to incorporate the addition of
		the SHS hashing algorithm to the toolkit. Waiting for OBJ ID
		for SHS Signature.

		0.92 Third revision, modified Digest, Signing and Verifying
		routines with improved error checking, to prevent SHS digest
		being used for signing data.  R_VerifyFinal altered to check
		that same digest used in original signature was used in verify
		doesn't verify signature if they don't match.

        1.02 Fourth revision, R_SealUpdate Bug fixed, Bug Reported by
        Anders Heerfordt <i3683@dc.dk>.  PADDING problem array incorrectly
        setup, reported by Anders Heerfordt <i3683@dc.dk>.

        1.04 Fifth revision, PADDING problem fixed again, reported by 
        Jonathan Ruano <jonah@encomix.es>.  R_RSAEuroInfo routine added
        to give basic info on toolkit.


*/

#include "rsaeuro.h"
#include "r_random.h"
#include "rsa.h"

/* DigestInfo encoding is DIGEST_INFO_A, then 2 or 5 or 4 (for MD2/MD5/MD4),
	 then DIGEST_INFO_B, then 16-byte message digest. */

/* Using the Original RSAREF/PKCS Object Indentifier, for signatures */

static unsigned char DIGEST_INFO_A[] = {
	0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7,
	0x0d, 0x02
};

#define DIGEST_INFO_A_LEN sizeof (DIGEST_INFO_A)

static unsigned char DIGEST_INFO_B[] = { 0x05, 0x00, 0x04, 0x10 };

#define DIGEST_INFO_B_LEN sizeof (DIGEST_INFO_B)

#define DIGEST_INFO_LEN (DIGEST_INFO_A_LEN + 1 + DIGEST_INFO_B_LEN + 16)

static unsigned char *PADDING[] = {
    (unsigned char *)"", (unsigned char *)"\01", (unsigned char *)"\02\02",
    (unsigned char *)"\03\03\03", (unsigned char *)"\04\04\04\04",
    (unsigned char *)"\05\05\05\05\05",
    (unsigned char *)"\06\06\06\06\06\06",
    (unsigned char *)"\07\07\07\07\07\07\07",
    (unsigned char *)"\010\010\010\010\010\010\010\010"
};

#define MAX_ENCRYPTED_KEY_LEN MAX_RSA_MODULUS_LEN

static void R_EncodeDigestInfo PROTO_LIST((unsigned char *, int, unsigned char *));
static int R_CheckDigestInfo PROTO_LIST ((unsigned char *, unsigned char *));

		/* encrypt prototypes */

static int CipherInit PROTO_LIST((R_ENVELOPE_CTX *, int, unsigned char *, int, unsigned char *, int));
static void EncryptBlk PROTO_LIST((R_ENVELOPE_CTX *, unsigned char *, unsigned char *, unsigned int));
static void RestartCipher PROTO_LIST((R_ENVELOPE_CTX *));

/*
    Return RSAEuro version information including Algorithms
    supported by this version of RSAEuro.

    Also Version number, flags and Ident of Toolkit.

    New to version 1.04
*/

void R_RSAEuroInfo(info)
RSAEUROINFO *info;              /* info structure */
{
    /* Blank structure before use */
    R_memset(info, 0x00, sizeof(RSAEUROINFO));

    info->Version = (RSAEURO_VER_MAJ << 8) | RSAEURO_VER_MIN;

    /* setup flags and algorithms supported */
    info->Algorithms = IA_FLAGS;
    info->flags = 0;

    /* Copy toolkit ID to info structure */
    R_memcpy(info->ManufacturerID, RSAEURO_IDENT, sizeof(RSAEURO_IDENT));
}

int R_DigestInit(context, digesttype)
R_DIGEST_CTX *context;          /* new context */
int digesttype;                 /* message-digest algorithm */
{
	context->digestAlgorithm = digesttype;

	switch(digesttype) {
	case DA_SHS:
		SHSInit(&context->context.shs);
		break;

	case DA_MD2:
		MD2Init(&context->context.md2);
		break;

	case DA_MD4:
		MD4Init(&context->context.md4);
		break;

	case DA_MD5:
		MD5Init(&context->context.md5);
		break;

	default:
		return(RE_DIGEST_ALGORITHM);
	}

	return(ID_OK);
}

int R_DigestUpdate(context, partIn, partInLen)
R_DIGEST_CTX *context;          /* context */
unsigned char *partIn;          /* next data part */
unsigned int partInLen;         /* length of next data part */
{
	switch(context->digestAlgorithm) {
	case DA_SHS:
		SHSUpdate(&context->context.shs, partIn, partInLen);
		break;

	case DA_MD2:
		MD2Update(&context->context.md2, partIn, partInLen);
		break;

	case DA_MD4:
		MD4Update(&context->context.md4, partIn, partInLen);
		break;

	case DA_MD5:
		MD5Update(&context->context.md5, partIn, partInLen);
		break;

	default:
		return(RE_DIGEST_ALGORITHM);
	}

	return(ID_OK);
}

int R_DigestFinal(context, digest, digestLen)
R_DIGEST_CTX *context;          /* context */
unsigned char *digest;          /* message digest */
unsigned int *digestLen;        /* length of message digest */
{
	*digestLen = context->digestAlgorithm == DA_SHS ? 20 : 16;

	switch(context->digestAlgorithm) {
	case DA_SHS:
        SHSFinal(digest, &context->context.shs); /* doesn't output as chars */
		break;

	case DA_MD2:
		MD2Final(digest, &context->context.md2);
		break;

	case DA_MD4:
		MD4Final(digest, &context->context.md4);
		break;

	case DA_MD5:
		MD5Final(digest, &context->context.md5);
		break;

	default:
		return(RE_DIGEST_ALGORITHM);
	}

	return(ID_OK);
}

/* Signing a file using SHS is not allowed for now */

int R_SignInit(context, digesttype)
R_SIGNATURE_CTX *context;       /* new context */
int digesttype;                 /* message-digest algorithm */
{
	return((digesttype == DA_SHS) ? RE_DIGEST_ALGORITHM : R_DigestInit(&context->digestContext, digesttype));
}

int R_SignUpdate(context, partIn, partInLen)
R_SIGNATURE_CTX *context;       /* context */
unsigned char *partIn;          /* next data part */
unsigned int partInLen;         /* length of next data part */
{
	return((context->digestContext.digestAlgorithm == DA_SHS) ? RE_DIGEST_ALGORITHM : R_DigestUpdate(&context->digestContext, partIn, partInLen));
}

int R_SignFinal(context, signature, signatureLen, privateKey)
R_SIGNATURE_CTX *context;       /* context */
unsigned char *signature;       /* signature */
unsigned int *signatureLen;     /* length of signature */
R_RSA_PRIVATE_KEY *privateKey;  /* signer's RSA private key */
{
	int status;
	unsigned char digest[MAX_DIGEST_LEN], digestInfo[DIGEST_INFO_LEN];
	unsigned int digestLen;

	if(context->digestContext.digestAlgorithm == DA_SHS)
		status = RE_DIGEST_ALGORITHM;
	else {
		if((status = R_DigestFinal(&context->digestContext, digest, &digestLen)) == 0) {
			R_EncodeDigestInfo(digestInfo, context->digestContext.digestAlgorithm, digest);

			if(RSAPrivateEncrypt(signature, signatureLen, digestInfo, DIGEST_INFO_LEN, privateKey) != 0) {
				status = RE_PRIVATE_KEY;
			}else{
						/* Reset for another verification. */
				R_DigestInit(&context->digestContext, context->digestContext.digestAlgorithm);
			}
		}
		/* Clear sensitive information. */
		R_memset(digest, 0, sizeof(digest));
		R_memset(digestInfo, 0, sizeof(digestInfo));
	}

	return(status);
}

int R_VerifyInit(context, digestAlgorithm)
R_SIGNATURE_CTX *context;       /* new context */
int digestAlgorithm;            /* message-digest algorithm */
{
	return((digestAlgorithm == DA_SHS) ? RE_DIGEST_ALGORITHM : R_DigestInit(&context->digestContext, digestAlgorithm));
}

int R_VerifyUpdate(context, partIn, partInLen)
R_SIGNATURE_CTX *context;       /* context */
unsigned char *partIn;          /* next data part */
unsigned int partInLen;         /* length of next data part */
{
	return((context->digestContext.digestAlgorithm == DA_SHS) ? RE_DIGEST_ALGORITHM : R_DigestUpdate(&context->digestContext, partIn, partInLen));
}

int R_VerifyFinal(context, signature, signatureLen, publicKey)
R_SIGNATURE_CTX *context;       /* context */
unsigned char *signature;       /* signature */
unsigned int signatureLen;      /* length of signature */
R_RSA_PUBLIC_KEY *publicKey;    /* signer's RSA public key */
{
	int status;
	unsigned char digest[MAX_DIGEST_LEN], digestInfo[DIGEST_INFO_LEN],
		originalDigestInfo[MAX_SIGNATURE_LEN];
	unsigned int originalDigestInfoLen, digestLen;

	status = 0;
	if(signatureLen > MAX_SIGNATURE_LEN)
		status = RE_LEN;

	if(context->digestContext.digestAlgorithm == DA_SHS)
		status = RE_DIGEST_ALGORITHM;

	if(!status) {
		if((status = R_DigestFinal (&context->digestContext, digest, &digestLen)) == 0) {
			R_EncodeDigestInfo(digestInfo, context->digestContext.digestAlgorithm, digest);

			if(RSAPublicDecrypt(originalDigestInfo, &originalDigestInfoLen, signature, signatureLen, publicKey) != 0) {
				status = RE_PUBLIC_KEY;
			}else{		/* Check the digest out */
				if((originalDigestInfoLen != DIGEST_INFO_LEN) || R_CheckDigestInfo(originalDigestInfo, digestInfo) || (R_memcmp((POINTER)originalDigestInfo, (POINTER)digestInfo, DIGEST_INFO_LEN)))
					status = RE_SIGNATURE;
				else
								/* Reset for another verification. */
					R_DigestInit(&context->digestContext, context->digestContext.digestAlgorithm);
			}
		}

		/* Clear sensitive information. */
		R_memset(digest, 0, sizeof(digest));
		R_memset(digestInfo, 0, sizeof(digestInfo));
		R_memset(originalDigestInfo, 0, sizeof(originalDigestInfo));
	}

	return(status);
}

/* Caller must ASCII encode the encrypted keys if required. */

int R_SealInit(context, encryptedKeys, encryptedKeyLens, iv, publicKeyCount, publicKeys,
		 encryptionAlgorithm, randomStruct)
R_ENVELOPE_CTX *context;        /* new context */
unsigned char **encryptedKeys;  /* encrypted keys */
unsigned int *encryptedKeyLens; /* lengths of encrypted keys */
unsigned char iv[8];            /* initialization vector */
unsigned int publicKeyCount;    /* number of public keys */
R_RSA_PUBLIC_KEY **publicKeys;  /* public keys */
int encryptionAlgorithm;        /* data encryption algorithm */
R_RANDOM_STRUCT *randomStruct;  /* random structure */
{
	int status;
	unsigned char key[24];
	unsigned int keyLen, i;

	context->encryptionAlgorithm = encryptionAlgorithm;

	keyLen = (encryptionAlgorithm == EA_DES_CBC) ? 8 : 24;

	if((status = R_GenerateBytes (key, keyLen, randomStruct)) == 0) {
		if((status = R_GenerateBytes (iv, 8, randomStruct)) == 0) {
			if(encryptionAlgorithm == EA_DES_EDE2_CBC)
					/* Make both E keys the same */
				R_memcpy ((POINTER)(key + 16), (POINTER)key, 8);

			if((status = CipherInit (context, encryptionAlgorithm, key, keyLen, iv, 1)) == 0) {
				for(i = 0; i < publicKeyCount; ++i) {
					if(RSAPublicEncrypt(encryptedKeys[i], &encryptedKeyLens[i], key, keyLen,
							 publicKeys[i], randomStruct)) {
						status = RE_PUBLIC_KEY;
						break;
					}
				}
			}
			if(status == 0)
				context->bufferLen = 0;
		}
	}

	/* Clear sensitive information. */

	R_memset(key, 0, sizeof(key));

	return(status);
}

/* partOut buffer should be at least partInLen + 7 */

int R_SealUpdate (context, partOut, partOutLen, partIn, partInLen)
R_ENVELOPE_CTX *context;        /* context */
unsigned char *partOut;         /* next encrypted data part */
unsigned int *partOutLen;       /* length of next encrypted data part */
unsigned char *partIn;          /* next data part */
unsigned int partInLen;         /* length of next data part */
{
	unsigned int temp;

	temp = 8 - context->bufferLen;
	if(partInLen < temp) {
						/* Just accumulate into buffer. */
		*partOutLen = 0;
		R_memcpy((POINTER)(context->buffer + context->bufferLen), (POINTER)partIn, partInLen);
        context->bufferLen += partInLen;    /* Bug Fix - 02/09/95, SK */
		return(ID_OK);
	}

	/* Fill the buffer and encrypt. */

	R_memcpy((POINTER)(context->buffer + context->bufferLen), (POINTER)partIn, temp);
	EncryptBlk(context, partOut, context->buffer, 8);
	partOut += 8;
	*partOutLen = 8;
	partIn += temp;
	partInLen -= temp;

	/* Encrypt as many 8-byte blocks as possible. */

	temp = 8 * (partInLen / 8);
	EncryptBlk(context, partOut, partIn, temp);
	*partOutLen += temp;
	partIn += temp;
	partInLen -= temp;


	/* Length now less than 8, so copy remainder to buffer for next time. */
	R_memcpy((POINTER)context->buffer, partIn, context->bufferLen = partInLen);

	return(ID_OK);
}

/* Assume partOut buffer is at least 8 bytes. */

int R_SealFinal(context, partOut, partOutLen)
R_ENVELOPE_CTX *context;        /* context */
unsigned char *partOut;         /* last encrypted data part */
unsigned int *partOutLen;       /* length of last encrypted data part */
{
	unsigned int padLen;

	/* Pad and encrypt final block. */

	padLen = 8 - context->bufferLen;                        /* little trick to pad the block */
	R_memset((POINTER)(context->buffer + context->bufferLen), (int)padLen, padLen);
	EncryptBlk(context, partOut, context->buffer, 8);
	*partOutLen = 8;

	/* Restart the context. */

	RestartCipher(context);
	context->bufferLen = 0;

	return(ID_OK);
}

/* Assume caller has already ASCII decoded the encryptedKey if necessary. */

int R_OpenInit(context, encryptionAlgorithm, encryptedKey, encryptedKeyLen, iv, privateKey)
R_ENVELOPE_CTX *context;        /* new context */
int encryptionAlgorithm;        /* data encryption algorithm */
unsigned char *encryptedKey;    /* encrypted data encryption key */
unsigned int encryptedKeyLen;   /* length of encrypted key */
unsigned char iv[8];            /* initialization vector */
R_RSA_PRIVATE_KEY *privateKey;  /* recipient's RSA private key */
{
	int status;
	unsigned char key[MAX_ENCRYPTED_KEY_LEN];
	unsigned int keyLen;

	if(encryptedKeyLen > MAX_ENCRYPTED_KEY_LEN)
		return(RE_LEN);

	context->encryptionAlgorithm = encryptionAlgorithm;

	if(RSAPrivateDecrypt(key, &keyLen, encryptedKey, encryptedKeyLen, privateKey)) {
		status = RE_PRIVATE_KEY;
	}else{
		if(encryptionAlgorithm == EA_DES_CBC) {
			if(keyLen != 8) status = RE_PRIVATE_KEY;
			else{
				if((status = CipherInit (context, encryptionAlgorithm, key, keyLen, iv, 0)) == 0)
					context->bufferLen = 0;
			}
		}else{
			if(keyLen != 24) status = RE_PRIVATE_KEY;
			else {
				if((status = CipherInit (context, encryptionAlgorithm, key, keyLen, iv, 0)) == 0)
					context->bufferLen = 0;
			}
		}
	}

	/* Clear sensitive information. */

	R_memset(key, 0, sizeof(key));

	return(status);
}

/* Assume partOut buffer is at least partInLen + 7.
	 Always leaves at least one byte in buffer. */

int R_OpenUpdate(context, partOut, partOutLen, partIn, partInLen)
R_ENVELOPE_CTX *context;        /* context */
unsigned char *partOut;         /* next recovered data part */
unsigned int *partOutLen;       /* length of next recovered data part */
unsigned char *partIn;          /* next encrypted data part */
unsigned int partInLen;         /* length of next encrypted data part */
{
	unsigned int tempLen;

	tempLen = 8 - context->bufferLen;
	if (partInLen <= tempLen) {
		/* Just accumulate into buffer. */
		*partOutLen = 0;
		R_memcpy((POINTER)(context->buffer + context->bufferLen), partIn, partInLen);
		context->bufferLen += partInLen;
		return(ID_OK);
	}

	/* Fill the buffer and decrypt.  We know that there will be more left
		 in partIn after decrypting the buffer. */

	R_memcpy((POINTER)(context->buffer + context->bufferLen), partIn, tempLen);

	EncryptBlk (context, partOut, context->buffer, 8);
	partOut += 8;
	*partOutLen = 8;
	partIn += tempLen;
	partInLen -= tempLen;

	/* Decrypt as many 8 byte blocks as possible, leaving at least one byte
		 in partIn.      */

	tempLen = 8 * ((partInLen - 1) / 8);
	EncryptBlk (context, partOut, partIn, tempLen);
	partIn += tempLen;
	*partOutLen += tempLen;
	partInLen -= tempLen;

			/* Length is between 1 and 8, so copy into buffer. */

	R_memcpy((POINTER)context->buffer, partIn, context->bufferLen = partInLen);

	return (ID_OK);
}

/* Assume partOut buffer is at least 7 bytes. */

int R_OpenFinal(context, partOut, partOutLen)
R_ENVELOPE_CTX *context;        /* context */
unsigned char *partOut;         /* last recovered data part */
unsigned int *partOutLen;       /* length of last recovered data part */
{
	int status;
	unsigned char lastPart[8];
	unsigned int padLen;

	status = 0;

	if(context->bufferLen == 0)
			/* There was no input data to decrypt */
		*partOutLen = 0;
	else {
		if(context->bufferLen != 8) {
			status = RE_KEY;
		}else{

			/* Decrypt and strip any padding from the final block. */

			EncryptBlk (context, lastPart, context->buffer, 8);

			padLen = lastPart[7];

			if(padLen == 0 || padLen > 8)
				status = RE_KEY;
			else{
				if(R_memcmp((POINTER)&lastPart[8 - padLen], PADDING[padLen], padLen) != 0)
					status = RE_KEY;
				else
					R_memcpy (partOut, lastPart, *partOutLen = 8 - padLen);
			}
				/* Restart the context. */
			if(status == 0) {
				RestartCipher(context);
				context->bufferLen = 0;
			}
		}
	}

	/* Clear sensitive information. */

	R_memset(lastPart, 0, sizeof(lastPart));

	return (status);
}

/**/

int R_SignPEMBlock(encodedContent, encodedContentLen, encodedSignature, encodedSignatureLen,
	 content, contentLen, recode, digestAlgorithm, privateKey)
unsigned char *encodedContent;         /* encoded content */
unsigned int *encodedContentLen;       /* length of encoded content */
unsigned char *encodedSignature;       /* encoded signature */
unsigned int *encodedSignatureLen;     /* length of encoded signature */
unsigned char *content;                /* content */
unsigned int contentLen;               /* length of content */
int recode;                            /* recoding flag */
int digestAlgorithm;                   /* message-digest algorithm */
R_RSA_PRIVATE_KEY *privateKey;         /* signer's RSA private key */
{
	int status;
	unsigned char signature[MAX_SIGNATURE_LEN];
	unsigned int signatureLen;

	if((status = R_SignBlock(signature, &signatureLen, content, contentLen, digestAlgorithm, privateKey)) != 0)
		return(status);

	if(recode)
		R_EncodePEMBlock(encodedContent, encodedContentLen, content, contentLen);

	R_EncodePEMBlock(encodedSignature, encodedSignatureLen, signature, signatureLen);

	return(ID_OK);
}

int R_SignBlock(signature, signatureLen, block, blockLen, digestAlgorithm, privateKey)
unsigned char *signature;       /* signature */
unsigned int *signatureLen;     /* length of signature */
unsigned char *block;           /* block */
unsigned int blockLen;          /* length of block */
int digestAlgorithm;            /* message-digest algorithm */
R_RSA_PRIVATE_KEY *privateKey;  /* signer's RSA private key */
{
	R_SIGNATURE_CTX context;
	int status;

	if((status = R_SignInit(&context, digestAlgorithm)) == 0)
		if((status = R_SignUpdate(&context, block, blockLen)) == 0)
			status = R_SignFinal(&context, signature, signatureLen, privateKey);

	/* Clear sensitive information. */
	R_memset((POINTER)&context, 0, sizeof(context));

	return(status);
}

int R_VerifyPEMSignature(content, contentLen, encodedContent, encodedContentLen, encodedSignature,
	 encodedSignatureLen, recode, digestAlgorithm, publicKey)
unsigned char *content;           /* content */
unsigned int *contentLen;         /* length of content */
unsigned char *encodedContent;    /* (possibly) encoded content */
unsigned int encodedContentLen;   /* length of encoded content */
unsigned char *encodedSignature;  /* encoded signature */
unsigned int encodedSignatureLen; /* length of encoded signature */
int recode;                       /* recoding flag */
int digestAlgorithm;              /* message-digest algorithm */
R_RSA_PUBLIC_KEY *publicKey;      /* signer's RSA public key */
{
	unsigned char signature[MAX_SIGNATURE_LEN];
	unsigned int signatureLen;

	if(encodedSignatureLen > MAX_PEM_SIGNATURE_LEN)
		return(RE_SIGNATURE_ENCODING);

	if(recode) {
		if(R_DecodePEMBlock(content, contentLen, encodedContent, encodedContentLen))
			return(RE_CONTENT_ENCODING);
	}else{
		*contentLen = encodedContentLen;
		content = encodedContent;
	}

	if(R_DecodePEMBlock(signature, &signatureLen, encodedSignature, encodedSignatureLen))
		return (RE_SIGNATURE_ENCODING);

	return(R_VerifyBlockSignature(content, *contentLen, signature, signatureLen, digestAlgorithm, publicKey));
}

int R_VerifyBlockSignature(block, blockLen, signature, signatureLen, digestAlgorithm, publicKey)
unsigned char *block;            /* block */
unsigned int blockLen;           /* length of block */
unsigned char *signature;        /* signature */
unsigned int signatureLen;       /* length of signature */
int digestAlgorithm;             /* message-digest algorithm */
R_RSA_PUBLIC_KEY *publicKey;     /* signer's RSA public key */
{
	R_SIGNATURE_CTX context;
	int status;

	if((status = R_VerifyInit(&context, digestAlgorithm)) == 0)
		if((status = R_VerifyUpdate(&context, block, blockLen)) == 0)
			status = R_VerifyFinal(&context, signature, signatureLen, publicKey);

	/* Clear sensitive information. */
	R_memset((POINTER)&context, 0, sizeof(context));

	return(status);
}

int R_SealPEMBlock(encryptedContent, encryptedContentLen, encryptedKey, encryptedKeyLen,
	 encryptedSignature, encryptedSignatureLen, iv, content, contentLen,
	 digestAlgorithm, publicKey, privateKey, randomStruct)
unsigned char *encryptedContent;            /* encoded, encrypted content */
unsigned int *encryptedContentLen;          /* length */
unsigned char *encryptedKey;                /* encoded, encrypted key */
unsigned int *encryptedKeyLen;              /* length */
unsigned char *encryptedSignature;          /* encoded, encrypted signature */
unsigned int *encryptedSignatureLen;        /* length */
unsigned char iv[8];                        /* DES initialization vector */
unsigned char *content;                     /* content */
unsigned int contentLen;                    /* length of content */
int digestAlgorithm;                        /* message-digest algorithms */
R_RSA_PUBLIC_KEY *publicKey;                /* recipient's RSA public key */
R_RSA_PRIVATE_KEY *privateKey;              /* signer's RSA private key */
R_RANDOM_STRUCT *randomStruct;              /* random structure */
{
	R_ENVELOPE_CTX context;
	R_RSA_PUBLIC_KEY *publicKeys[1];
	int status;
	unsigned char encryptedKeyBlock[MAX_ENCRYPTED_KEY_LEN],
		signature[MAX_SIGNATURE_LEN], *encryptedKeys[1];
	unsigned int signatureLen, encryptedKeyBlockLen;

	if((status = R_SignBlock(signature, &signatureLen, content, contentLen,
														digestAlgorithm, privateKey)) == 0) {

		encryptedKeys[0] = encryptedKeyBlock;
		publicKeys[0] = publicKey;

		if((status = R_SealInit(&context, encryptedKeys, &encryptedKeyBlockLen, iv, 1, publicKeys, EA_DES_CBC, randomStruct)) == 0) {

			R_EncodePEMBlock(encryptedKey, encryptedKeyLen, encryptedKeyBlock,
												encryptedKeyBlockLen);

			R_EncryptOpenPEMBlock(&context, encryptedContent, encryptedContentLen,
														 content,       contentLen);

			R_EncryptOpenPEMBlock(&context, encryptedSignature, encryptedSignatureLen,
														 signature,     signatureLen);
		}
	}

	/* Clear sensitive information. */
	R_memset((POINTER)&context, 0, sizeof(context));
	R_memset(signature, 0, sizeof(signature));

	return (status);
}

int R_OpenPEMBlock(content, contentLen, encryptedContent, encryptedContentLen, encryptedKey,
	 encryptedKeyLen, encryptedSignature, encryptedSignatureLen,
	 iv, digestAlgorithm, privateKey, publicKey)
unsigned char *content;                     /* content */
unsigned int *contentLen;                   /* length of content */
unsigned char *encryptedContent;            /* encoded, encrypted content */
unsigned int encryptedContentLen;           /* length */
unsigned char *encryptedKey;                /* encoded, encrypted key */
unsigned int encryptedKeyLen;               /* length */
unsigned char *encryptedSignature;          /* encoded, encrypted signature */
unsigned int encryptedSignatureLen;         /* length */
unsigned char iv[8];                        /* DES initialization vector */
int digestAlgorithm;                        /* message-digest algorithms */
R_RSA_PRIVATE_KEY *privateKey;              /* recipient's RSA private key */
R_RSA_PUBLIC_KEY *publicKey;                /* signer's RSA public key */
{
	R_ENVELOPE_CTX context;
	int status;
	unsigned char encryptedKeyBlock[MAX_ENCRYPTED_KEY_LEN],
		signature[MAX_SIGNATURE_LEN];
	unsigned int encryptedKeyBlockLen, signatureLen;

	if(encryptedSignatureLen > MAX_PEM_ENCRYPTED_SIGNATURE_LEN)
		return(RE_SIGNATURE_ENCODING);

	if(encryptedKeyLen > MAX_PEM_ENCRYPTED_KEY_LEN)
		return(RE_KEY_ENCODING);

	if(R_DecodePEMBlock(encryptedKeyBlock, &encryptedKeyBlockLen, encryptedKey, encryptedKeyLen) != 0) {
			status = RE_KEY_ENCODING;
	}else{
		if((status = R_OpenInit(&context, EA_DES_CBC, encryptedKeyBlock, encryptedKeyBlockLen, iv, privateKey)) == 0) {

			if((status = R_DecryptOpenPEMBlock(&context, content, contentLen, encryptedContent, encryptedContentLen)) != 0) {
				if((status == RE_LEN || status == RE_ENCODING))
					status = RE_CONTENT_ENCODING;
				else
					status = RE_KEY;
			}else{

				status = R_DecryptOpenPEMBlock(&context, signature, &signatureLen, encryptedSignature, encryptedSignatureLen);

				if(status) {
					if((status == RE_LEN || status == RE_ENCODING))
						status = RE_SIGNATURE_ENCODING;
					else
						status = RE_KEY;
				}else
					status = R_VerifyBlockSignature(content, *contentLen, signature, signatureLen, digestAlgorithm, publicKey);
			}
		}
	}
	/* Clear sensitive information. */

	R_memset((POINTER)&context, 0, sizeof(context));
	R_memset(signature, 0, sizeof(signature));

	return(status);
}

int R_DigestBlock(digest, digestLen, block, blockLen, digestAlgorithm)
unsigned char *digest;           /* message digest */
unsigned int *digestLen;         /* length of message digest */
unsigned char *block;            /* block */
unsigned int blockLen;           /* length of block */
int digestAlgorithm;             /* message-digest algorithm */
{
	R_DIGEST_CTX context;
	int status;

	if((status = R_DigestInit(&context, digestAlgorithm)) == 0)
		if((status = R_DigestUpdate(&context, block, blockLen)) == 0)
			status = R_DigestFinal(&context, digest, digestLen);

	/* Clear sensitive information. */

	R_memset((POINTER)&context, 0, sizeof(context));

	return(status);
}

int R_DecryptOpenPEMBlock(context, output, outputLen, input, inputLen)
R_ENVELOPE_CTX *context;          /* context */
unsigned char *output;            /* decoded, decrypted block */
unsigned int *outputLen;          /* length of output */
unsigned char *input;             /* encrypted, encoded block */
unsigned int inputLen;            /* length */
{
	int status;
	unsigned char encryptedPart[24];
	unsigned int i, len;

	*outputLen = 0;

	for (i = 0; i < inputLen/32; i++) {
			/* len is always 24 */
		if ((status = R_DecodePEMBlock(encryptedPart, &len, &input[32*i], 32)) != 0)
			break;

		R_OpenUpdate (context, output, &len, encryptedPart, 24);
		*outputLen += len;
		output += len;
	}

	if(!status)                     /* Decode the last block. */
		if((status = R_DecodePEMBlock(encryptedPart, &len, &input[32*i], inputLen - 32*i)) == 0) {
									/* Decrypt the last block. */
			R_OpenUpdate (context, output, &len, encryptedPart, len);
			output += len;
			*outputLen += len;
			if((status = R_OpenFinal (context, output, &len)) == 0)
				*outputLen += len;
		}

	/* Clear sensitive information. */

	R_memset((POINTER)&context, 0, sizeof(context));
	R_memset(encryptedPart, 0, sizeof(encryptedPart));

	return(status);
}

int R_EncryptOpenPEMBlock(context, output, outputLen, input, inputLen)
R_ENVELOPE_CTX *context;          /* context */
unsigned char *output;            /* encrypted, encoded block */
unsigned int *outputLen;          /* length of output */
unsigned char *input;             /* block to encrypt */
unsigned int inputLen;            /* length */
{
	unsigned char encryptedPart[24];
	unsigned int i, lastPartLen, tempLen, len;

	/* Encrypt and encode as many 24-byte blocks as possible. */

	for (i = 0; i < inputLen / 24; ++i) {
		/* Assume part out length will equal part in length since it is
			 a multiple of 8.  Also assume no error output. */
		R_SealUpdate (context, encryptedPart, &tempLen, &input[24*i], 24);

		/* len will always be 32 */
		R_EncodePEMBlock (&output[32*i], &tempLen, encryptedPart, 24);
	}

	/* Encrypt the last part into encryptedPart. */

	R_SealUpdate(context, encryptedPart, &lastPartLen, &input[24*i], inputLen - 24*i);
	R_SealFinal(context, encryptedPart + lastPartLen, &len);
	lastPartLen += len;

	R_EncodePEMBlock(&output[32*i], &len, encryptedPart, lastPartLen);
	*outputLen = 32*i + len;

	/* Clear sensitive information. */

	R_memset(encryptedPart, 0, sizeof(encryptedPart));

	return(ID_OK);
}

/* Assumes that digestAlgorithm is DA_MD2, DA_MD4 or DA_MD5 and
	 the digest length must be 16.  SHS Not supported here. */

static void R_EncodeDigestInfo(digestInfo, digestAlgorithm, digest)
unsigned char *digestInfo;
int digestAlgorithm;
unsigned char *digest;
{
	if(!(digestAlgorithm == DA_SHS)) {
		digestInfo[DIGEST_INFO_A_LEN] = digestAlgorithm;

		R_memcpy((POINTER)&digestInfo[DIGEST_INFO_A_LEN + 1], (POINTER)DIGEST_INFO_B, DIGEST_INFO_B_LEN);
		R_memcpy((POINTER)digestInfo, (POINTER)DIGEST_INFO_A, DIGEST_INFO_A_LEN);
		R_memcpy((POINTER)&digestInfo[DIGEST_INFO_A_LEN + 1 + DIGEST_INFO_B_LEN], (POINTER)digest, 16);
	}
}

/* Quick check to correct digest was used to verify */

static int R_CheckDigestInfo(originaldigestInfo, digestInfo)
unsigned char *originaldigestInfo;
unsigned char *digestInfo;
{
	return((originaldigestInfo[DIGEST_INFO_A_LEN] ==
		digestInfo[DIGEST_INFO_A_LEN]) ? ID_OK : RE_SIGNATURE);
}

/*
    Blowfish uses a keyLen value during startup, this was added to this routine
    for version 1.10 of RSAEuro.
*/

static int CipherInit(context, encryptionAlgorithm, key, keyLen, iv, encrypt)
R_ENVELOPE_CTX *context;
int encryptionAlgorithm;
unsigned char *key;
int keyLen;
unsigned char *iv;
int encrypt;
{
	switch(encryptionAlgorithm) {
	case EA_DES_CBC:
		DES_CBCInit (&context->cipherContext.des, key, iv, encrypt);
		break;
	case EA_DESX_CBC:
		DESX_CBCInit (&context->cipherContext.desx, key, iv, encrypt);
		break;
	case EA_DES_EDE2_CBC:
	case EA_DES_EDE3_CBC:
		DES3_CBCInit (&context->cipherContext.des3, key, iv, encrypt);
		break;
	default:
		return (RE_ENCRYPTION_ALGORITHM);
	}
	return(ID_OK);
}

/* Assume len is a multiple of 8.
 */
static void EncryptBlk(context, output, input, len)
R_ENVELOPE_CTX *context;
unsigned char *output;
unsigned char *input;
unsigned int len;
{
	switch(context->encryptionAlgorithm) {
	case EA_DES_CBC:
		DES_CBCUpdate (&context->cipherContext.des, output, input, len);
		break;
	case EA_DESX_CBC:
		DESX_CBCUpdate (&context->cipherContext.desx, output, input, len);
		break;
	case EA_DES_EDE2_CBC:
	case EA_DES_EDE3_CBC:
		DES3_CBCUpdate (&context->cipherContext.des3, output, input, len);
        break;
	}
}

static void RestartCipher(context)
R_ENVELOPE_CTX *context;
{
	switch(context->encryptionAlgorithm) {
	case EA_DES_CBC:
		DES_CBCRestart (&context->cipherContext.des);
		break;
	case EA_DESX_CBC:
		DESX_CBCRestart (&context->cipherContext.desx);
		break;
	case EA_DES_EDE2_CBC:
	case EA_DES_EDE3_CBC:
		DES3_CBCRestart (&context->cipherContext.des3);
	}
}
