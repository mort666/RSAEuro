/*
	REDEMO.C - Demo Application using RSAEURO cryptographic toolkit

	Copyright (c) J.S.A.Kapp 1994.

	RSAEURO - RSA Library compatible with RSAREF(tm) 2.0.

	All functions prototypes are the Same as for RSAREF(tm).
	To aid compatiblity the source and the files follow the
	same naming comventions that RSAREF(tm) uses.  This should aid
	direct importing to your applications.

	This library is legal everywhere outside the US.  And should
	NOT be imported to the US and used there.

	This application shows how to use RSAEURO routines in your
	applications.
*/


#include <stdio.h>
#include <string.h>
#include "rsaeuro.h"		/* Required Prototypes */

/* Implement these simple routines as macros */

#define ReadClose(file) \
{               \
	fclose (file);\
}


#define WriteClose(file) \
{                   \
	if(file != stdout)\
		fclose(file);   \
}

#define PrintMessage(message) \
{                 \
	puts(message);  \
	fflush(stdout); \
}

/* Internal function prototypes */

static R_RANDOM_STRUCT *InitRandomStruct PROTO_LIST((void));
static void DoSignFile PROTO_LIST((void));
static void DoVerifyFile PROTO_LIST((void));
static void DoSealFile PROTO_LIST((R_RANDOM_STRUCT *));
static void DoOpenFile PROTO_LIST((void));
static void DoGenerateKeys PROTO_LIST((R_RANDOM_STRUCT *));
static void DoOpenkeys PROTO_LIST((void));
static void WriteKeypair2 PROTO_LIST((void));
static void WriteBigInteger PROTO_LIST
	((FILE *, unsigned char *, unsigned int));
static int ReadInit PROTO_LIST((FILE **, char *));
static int ReadUpdate PROTO_LIST
	((FILE *, unsigned char *, unsigned int *, unsigned int));
static void ReadFinal PROTO_LIST((FILE *));
static int ReadBlock PROTO_LIST
	((unsigned char *, unsigned int *, unsigned int, char *));
static int WriteInit PROTO_LIST((FILE **, char *));
static int WriteUpdate PROTO_LIST((FILE *, unsigned char *, unsigned int));
static void WriteFinal PROTO_LIST((FILE *));
static int WriteBlock PROTO_LIST((unsigned char *, unsigned int, char *));
static int GetPublicKey PROTO_LIST((R_RSA_PUBLIC_KEY **));
static int GetPrivateKey PROTO_LIST((R_RSA_PRIVATE_KEY **));
static int GetDigestAlgorithm PROTO_LIST((int *));
static int GetEncryptionAlgorithm PROTO_LIST((int *));
static void PrintMessage PROTO_LIST((char *));
static void PrintError PROTO_LIST((char *, int));
static int GetCommand PROTO_LIST((char *, unsigned int, char *));
static char *upr PROTO_LIST ((char *s));

/* Use one key from RSADSI's RSAREF(tm) RDEMO for comptiblity testing.
	 This ensures that both RSAEURO and RSAREF(tm) code is compatible.
*/

static R_RSA_PUBLIC_KEY PUBLIC_KEY1 = {
	512,
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0xc0, 0x76, 0x47, 0x97, 0xb8, 0xbe, 0xc8, 0x97,
	 0x2a, 0x0e, 0xd8, 0xc9, 0x0a, 0x8c, 0x33, 0x4d, 0xd0, 0x49, 0xad, 0xd0,
	 0x22, 0x2c, 0x09, 0xd2, 0x0b, 0xe0, 0xa7, 0x9e, 0x33, 0x89, 0x10, 0xbc,
	 0xae, 0x42, 0x20, 0x60, 0x90, 0x6a, 0xe0, 0x22, 0x1d, 0xe3, 0xf3, 0xfc,
	 0x74, 0x7c, 0xcf, 0x98, 0xae, 0xcc, 0x85, 0xd6, 0xed, 0xc5, 0x2d, 0x93,
	 0xd5, 0xb7, 0x39, 0x67, 0x76, 0x16, 0x05, 0x25},
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01}
};

static R_RSA_PRIVATE_KEY PRIVATE_KEY1 = {
	512,
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0xc0, 0x76, 0x47, 0x97, 0xb8, 0xbe, 0xc8, 0x97,
	 0x2a, 0x0e, 0xd8, 0xc9, 0x0a, 0x8c, 0x33, 0x4d, 0xd0, 0x49, 0xad, 0xd0,
	 0x22, 0x2c, 0x09, 0xd2, 0x0b, 0xe0, 0xa7, 0x9e, 0x33, 0x89, 0x10, 0xbc,
   0xae, 0x42, 0x20, 0x60, 0x90, 0x6a, 0xe0, 0x22, 0x1d, 0xe3, 0xf3, 0xfc,
	 0x74, 0x7c, 0xcf, 0x98, 0xae, 0xcc, 0x85, 0xd6, 0xed, 0xc5, 0x2d, 0x93,
   0xd5, 0xb7, 0x39, 0x67, 0x76, 0x16, 0x05, 0x25},
  {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01},
  {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x1a, 0xe3, 0x6b, 0x75, 0x22, 0xf6, 0x64, 0x87,
	 0xd9, 0xf4, 0x61, 0x0d, 0x15, 0x50, 0x29, 0x0a, 0xc2, 0x02, 0xc9, 0x29,
   0xbe, 0xdc, 0x70, 0x32, 0xcc, 0x3e, 0x02, 0xac, 0xf3, 0x7e, 0x3e, 0xbc,
	 0x1f, 0x86, 0x6e, 0xe7, 0xef, 0x7a, 0x08, 0x68, 0xd2, 0x3a, 0xe2, 0xb1,
   0x84, 0xc1, 0xab, 0xd6, 0xd4, 0xdb, 0x8e, 0xa9, 0xbe, 0xc0, 0x46, 0xbd,
	 0x82, 0x80, 0x37, 0x27, 0xf2, 0x88, 0x87, 0x01},
	{{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdf, 0x02, 0xb6, 0x15,
		0xfe, 0x15, 0x92, 0x8f, 0x41, 0xb0, 0x2b, 0x58, 0x6b, 0x51, 0xc2, 0xc0,
		0x22, 0x60, 0xca, 0x39, 0x68, 0x18, 0xca, 0x4c, 0xba, 0x60, 0xbb, 0x89,
		0x24, 0x65, 0xbe, 0x35},
	 {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdc, 0xee, 0xb6, 0x0d,
		0x54, 0x35, 0x18, 0xb4, 0xac, 0x74, 0x83, 0x4a, 0x05, 0x46, 0xc5, 0x07,
		0xf2, 0xe9, 0x1e, 0x38, 0x9a, 0x87, 0xe2, 0xf2, 0xbe, 0xcc, 0x6f, 0x8c,
		0x67, 0xd1, 0xc9, 0x31}},
	{{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x59, 0x48, 0x7e, 0x99,
		0xe3, 0x75, 0xc3, 0x8d, 0x73, 0x21, 0x12, 0xd9, 0x7d, 0x6d, 0xe8, 0x68,
		0x7f, 0xda, 0xfc, 0x5b, 0x6b, 0x5f, 0xb1, 0x6e, 0x72, 0x97, 0xd3, 0xbd,
		0x1e, 0x43, 0x55, 0x99},
	 {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x61, 0xb5, 0x50, 0xde,
		0x64, 0x37, 0x77, 0x4d, 0xb0, 0x57, 0x77, 0x18, 0xed, 0x6c, 0x77, 0x07,
		0x24, 0xee, 0xe4, 0x66, 0xb4, 0x31, 0x14, 0xb5, 0xb6, 0x9c, 0x43, 0x59,
		0x1d, 0x31, 0x32, 0x81}},
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0x4c, 0x79, 0xc4,
	 0xb9, 0xbe, 0xa9, 0x7c, 0x25, 0xe5, 0x63, 0xc9, 0x40, 0x7a, 0x2d, 0x09,
	 0xb5, 0x73, 0x58, 0xaf, 0xe0, 0x9a, 0xf6, 0x7d, 0x71, 0xf8, 0x19, 0x8c,
	 0xb7, 0xc9, 0x56, 0xb8}
};

R_RSA_PUBLIC_KEY PUBLIC_KEY2;
R_RSA_PRIVATE_KEY PRIVATE_KEY2;
int KEYPAIR2_READY = 0;

void main(void)
{
	char command[80];
	int done = 0;
	R_RANDOM_STRUCT *randomStruct;

	randomStruct = InitRandomStruct();		/* setup random object */

	PrintMessage("REDEMO - Demo Application Using "RSAEURO_IDENT".");
	PrintMessage("NOTE: When saving to a file, a filename of \"-\" will output to the screen.");

	while(!done) {
		PrintMessage("");
		PrintMessage("[S] - Sign a file");
		PrintMessage("[V] - Verify a signed file");
		PrintMessage("[E] - sEal a file");
		PrintMessage("[O] - Open a sealed file");
		PrintMessage("[G] - Generate a keypair (may take a long time)");
		PrintMessage("[L] - Load keypair");
		PrintMessage("[Q] - Quit");
		GetCommand(command, sizeof (command), "  Enter choice");

		upr(command);
		switch(*command) {
		case '#':
			/* entered a comment */
			break;

		case 'S':
			DoSignFile();
			break;

		case 'V':
			DoVerifyFile();
			break;

		case 'E':
			DoSealFile(randomStruct);
			break;

		case 'O':
			DoOpenFile();
			break;

		case 'G':
			DoGenerateKeys(randomStruct);
			break;

		case 'L':
			DoOpenkeys();
			break;

		case '\0':
		case 'Q':
			done = 1;
			break;

		default:
			PrintError("ERROR: Unrecognized command.  Try again.", 0);
			break;
		}
	}

	R_RandomFinal(randomStruct);
	R_memset((POINTER)&PRIVATE_KEY2, 0, sizeof(PRIVATE_KEY2));
}

/*
	Initialize the random structure with all NULL seed bytes for
	test purposes.  This will NOT produce a random stream, for a
	random stream one needs a random seed.

	See: R_RandomCreate
*/

static R_RANDOM_STRUCT *InitRandomStruct(void)
{
	static unsigned char seedByte = 0;
	unsigned int bytesNeeded;
	static R_RANDOM_STRUCT randomStruct;

	R_RandomInit(&randomStruct);

	/* Initialize with all zero seed bytes, which will not yield an actual
			 random number output. */

	while (1) {
		R_GetRandomBytesNeeded(&bytesNeeded, &randomStruct);
		if(bytesNeeded == 0)
			break;

		R_RandomUpdate(&randomStruct, &seedByte, 1);
	}

	return(&randomStruct);
}

/*
	Signs user specified file using chosen private key and
	Digestalgorithm.
*/

static void DoSignFile(void)
{
	FILE *file;
	R_RSA_PRIVATE_KEY *privateKey;
	R_SIGNATURE_CTX context;
	int digestAlgorithm, status;
	unsigned char partIn[24], signature[MAX_SIGNATURE_LEN];
	unsigned int partInLen, signatureLen;

	status = 0;

	if(ReadInit(&file, "  Enter filename of content to sign"))
		return;

	if(GetPrivateKey(&privateKey) && GetDigestAlgorithm(&digestAlgorithm))
		if((status = R_SignInit(&context, digestAlgorithm)) == 0) {
			while(!ReadUpdate(file, partIn, &partInLen, sizeof (partIn)))
				if((status = R_SignUpdate(&context, partIn, partInLen)) != 0)
					break;
			if(!status)
				if((status = R_SignFinal(&context, signature, &signatureLen, privateKey)) == 0)
					WriteBlock(signature, signatureLen, "  Enter filename to save the signature");
		}

	ReadClose(file);

	if(status)
		PrintError ("Signing File", status);

	R_memset((POINTER)&context, 0, sizeof(context));
	R_memset((POINTER)partIn, 0, sizeof(partIn));
}

static void DoVerifyFile(void)
{
	FILE *file;
	R_RSA_PUBLIC_KEY *publicKey;
	R_SIGNATURE_CTX context;
	int digestAlgorithm, status;
	unsigned char partIn[16], signature[MAX_SIGNATURE_LEN];
	unsigned int partInLen, signatureLen;

	status = 0;

	if(ReadInit(&file, "  Enter name of file to verify"))
		return;

	if(GetPublicKey (&publicKey) && GetDigestAlgorithm (&digestAlgorithm))
		if(!ReadBlock(signature, &signatureLen, sizeof (signature), "  Enter filename of signature")) {
			if((status = R_VerifyInit(&context, digestAlgorithm)) == 0)
				while(!ReadUpdate(file, partIn, &partInLen, sizeof (partIn)))
					if ((status = R_VerifyUpdate(&context, partIn, partInLen)) != 0)
						break;
			if(!status)
				if((status = R_VerifyFinal(&context, signature, signatureLen, publicKey)) == 0)
					PrintMessage ("Signature verified.");
		}

	ReadClose (file);

	if(status)
		PrintError("Verifying File", status);

	R_memset((POINTER)&context, 0, sizeof(context));
	R_memset((POINTER)partIn, 0, sizeof(partIn));
}

static void DoSealFile(randomStruct)
R_RANDOM_STRUCT *randomStruct;
{
	FILE *inFile, *outFile;
	R_ENVELOPE_CTX context;
	R_RSA_PUBLIC_KEY *publicKey;
	int encryptionAlgorithm, status;
	unsigned char encryptedKey[MAX_ENCRYPTED_KEY_LEN], *encryptedKeys[1],
		iv[8], partIn[24], partOut[31];
	unsigned int encryptedKeyLen, partInLen, partOutLen;

	status = 0;

	if(ReadInit(&inFile, "  Enter filename of content to seal"))
		return;

	if(WriteInit(&outFile, "  Enter filename to save the encrypted content")) {
		ReadClose(inFile);
		return;
	}

	if(GetPublicKey(&publicKey) && GetEncryptionAlgorithm (&encryptionAlgorithm)) {

		encryptedKeys[0] = encryptedKey;

		if((status = R_SealInit(&context, encryptedKeys, &encryptedKeyLen, iv, 1, &publicKey,
					encryptionAlgorithm, randomStruct)) == 0) {
			while(!ReadUpdate (inFile, partIn, &partInLen, sizeof (partIn))) {
				if ((status = R_SealUpdate(&context, partOut, &partOutLen, partIn, partInLen)) != 0)
					break;
				WriteUpdate (outFile, partOut, partOutLen);
			}
			if(!status) {
				if((status = R_SealFinal (&context, partOut, &partOutLen)) == 0)
					WriteUpdate(outFile, partOut, partOutLen);

				if(!WriteBlock(encryptedKey, encryptedKeyLen, "  Enter filename to save the encrypted key"))
					WriteBlock(iv, 8, "  Enter filename to save the initializing vector");
			}
		}
	}

	ReadClose(inFile);
	WriteClose(outFile);

	if(status)
		PrintError ("sealing file", status);

	R_memset((POINTER)&context, 0, sizeof(context));
	R_memset((POINTER)partIn, 0, sizeof(partIn));
}

static void DoOpenFile(void)
{
	FILE *inFile, *outFile;
	R_ENVELOPE_CTX context;
	R_RSA_PRIVATE_KEY *privateKey;
	int encryptionAlgorithm, status;
	unsigned char encryptedKey[MAX_ENCRYPTED_KEY_LEN], iv[8], partIn[24],
		partOut[31];
	unsigned int encryptedKeyLen, ivLen, partInLen, partOutLen;

	status = 0;

	if (ReadInit(&inFile, "  Enter filename of encrypted content to open"))
		return;

	if (WriteInit(&outFile, "  Enter filename to save the recovered content")) {
		ReadClose(inFile);
		return;
	}

	if(GetPrivateKey(&privateKey) && GetEncryptionAlgorithm(&encryptionAlgorithm))
		if(!ReadBlock(encryptedKey, &encryptedKeyLen, sizeof (encryptedKey), "  Enter filename of the encrypted key"))
			if(!ReadBlock(iv, &ivLen, 8, "  Enter filename of the initializing vector"))
				if((status = R_OpenInit(&context, encryptionAlgorithm, encryptedKey, encryptedKeyLen, iv,
					privateKey)) == 0) {
					while (!ReadUpdate(inFile, partIn, &partInLen, sizeof (partIn))) {
						if((status = R_OpenUpdate(&context, partOut, &partOutLen, partIn, partInLen)) != 0)
							break;
						WriteUpdate(outFile, partOut, partOutLen);
					}
					if(!status)
						if((status = R_OpenFinal(&context, partOut, &partOutLen)) == 0)
							WriteUpdate(outFile, partOut, partOutLen);
				}

	ReadClose(inFile);
	WriteClose(outFile);

	if(status)
		PrintError("Opening File", status);

	R_memset((POINTER)&context, 0, sizeof(context));
	R_memset((POINTER)partOut, 0, sizeof(partOut));
}

static void DoGenerateKeys(randomStruct)
R_RANDOM_STRUCT *randomStruct;
{
	R_RSA_PROTO_KEY protoKey;
	char command[80];
	int status, keySize;

	if(GetCommand(command, sizeof(command), "  Enter Key Size in bits (508 - 1024)")) {
		sscanf(command, "%d", &protoKey.bits);

		protoKey.useFermat4 = 1;

		status = R_GeneratePEMKeys(&PUBLIC_KEY2, &PRIVATE_KEY2, &protoKey, randomStruct);
		if(status) {
			PrintError("Key Generation", status);
			return;
		}

		PrintMessage("  Public key 2 and private key 2 are now ready to use.");
		KEYPAIR2_READY = 1;

		WriteKeypair2();
	}
}

static void DoOpenkeys(void)
{
	FILE *file;
	char filename[256];

	while(1) {
		if(!GetCommand(filename, sizeof (filename), "  Enter filename of file for the keypair"))
			return;

		if (filename[0] == '-' && filename[1] == '\0') {
			/* use stdout */
			return;
		}

		if((file = fopen (filename, "rb")) != NULL)
				/* successfully opened */
			break;

		PrintError("ERROR: Cannot open a file with that name.  Try again.", 0);
	}

	if((fread(&PUBLIC_KEY2, sizeof(PUBLIC_KEY2), 1, file)) != 1) {
		PrintMessage("ERROR: Cannot Read Public Key from File.");
	} else {
		if((fread(&PRIVATE_KEY2, sizeof(PRIVATE_KEY2), 1, file)) != 1)
			PrintMessage("ERROR: Cannot Read Private Key from File.");
  }

	PrintMessage("  Public key 2 and private key 2 are now ready to use.");
	KEYPAIR2_READY = 1;

	ReadClose(file);
}

static void WriteKeypair2(void)
{
	FILE *file;
	char filename[256];

	while(1) {
		if(!GetCommand(filename, sizeof (filename), "  Enter filename to save the keypair"))
			return;

		if (filename[0] == '-' && filename[1] == '\0') {
			/* use stdout */
			return;
		}

		if((file = fopen (filename, "wb")) != NULL)
				/* successfully opened */
			break;

		PrintError("ERROR: Cannot open a file with that name.  Try again.", 0);
	}

	if((fwrite(&PUBLIC_KEY2, sizeof(PUBLIC_KEY2), 1, file)) != 1) {
		PrintMessage("ERROR: Cannot Write Public Key to File.");
	} else {
		if((fwrite(&PRIVATE_KEY2, sizeof(PRIVATE_KEY2), 1, file)) != 1)
			PrintMessage("ERROR: Cannot Write Private Key to File.");
	}

	WriteClose(file);
}

/* Write the byte string 'integer' to 'file', skipping over leading zeros.
 */
static void WriteBigInteger(file, integer, integerLen)
FILE *file;
unsigned char *integer;
unsigned int integerLen;
{
	while (*integer == 0 && integerLen > 0) {
		integer++;
		integerLen--;
	}

	if (integerLen == 0) {
		/* Special case, just print a zero. */
		fprintf (file, "00\n");
    return;
	}
  
  for (; integerLen > 0; integerLen--)
		fprintf (file, "%02x ", (unsigned int)(*integer++));

  fprintf (file, "\n");
}

/* Ask the user to use public key 1, 2 or 3 and point publicKey to
		 the answer.
	 Return 0 on success or 1 if user cancels by entering a blank.
 */
static int GetPublicKey (publicKey)
R_RSA_PUBLIC_KEY **publicKey;
{
	char command[80];

	while (1) {
		if(KEYPAIR2_READY)
			GetCommand(command, sizeof (command), "  Public key 1 or 2?");
		else
			*command = '1';

		switch (*command) {
		case '\0':
			return (0);

		case '1':
			*publicKey = &PUBLIC_KEY1;
			return (1);

		case '2':
			if (!KEYPAIR2_READY)
				break;
			*publicKey = &PUBLIC_KEY2;
			return (1);

		default:
			if (KEYPAIR2_READY)
				PrintError ("ERROR: Please enter 1 or 2.  Try again.", 0);
			break;
		}
	}
}

/* Ask the user to use private key 1, 2 or 3 and point privateKey to
		 the answer.
	 Return 0 on success or 1 if user cancels by entering a blank.
 */
static int GetPrivateKey(privateKey)
R_RSA_PRIVATE_KEY **privateKey;
{
	char command[80];

	while (1) {
		if (KEYPAIR2_READY)
			GetCommand(command, sizeof (command), "  Public key 1 or 2?");
		else
			*command = '1';

		switch (*command) {
		case '\0':
			return (0);

		case '1':
			*privateKey = &PRIVATE_KEY1;
			return (1);

		case '2':
			if (!KEYPAIR2_READY)
				break;
			*privateKey = &PRIVATE_KEY2;
			return (1);

		default:
			if (KEYPAIR2_READY)
				PrintError ("ERROR: Please enter 1 or 2.  Try again.", 0);
			break;
		}
	}
}

/* Ask the user to use MD2 or MD5 and point digestAlgorithm to the
		 answer.
	 Return 0 on success or 1 if user cancels by entering a blank.
 */
static int GetDigestAlgorithm (digestAlgorithm)
int *digestAlgorithm;
{
	char command[80];

	while (1) {
		GetCommand (command, sizeof (command), "  MD2 or MD5 (2 or 5)?");

		switch (*command) {
		case '\0':
			return (0);

    case '2':
      *digestAlgorithm = DA_MD2;
			return (1);

		case '5':
			*digestAlgorithm = DA_MD5;
			return (1);

		default:
			PrintError ("ERROR: Please enter 2 or 5.  Try again.", 0);
			break;
		}
	}
}

/* Ask the user to use DES, DESX, DES-EDE2, or DES-EDE3, and point
		 encryptionAlgorithm to the answer.
	 Return 0 on success or 1 if user cancels by entering a blank.
 */
static int GetEncryptionAlgorithm (encryptionAlgorithm)
int *encryptionAlgorithm;
{
	char command[80];

	while (1) {
		GetCommand(command, sizeof (command), "  DES, DESX, DES-EDE2 or DES-EDE3 (1, X, 2 or 3)?");

		upr(command);
		switch(*command) {
		case '\0':
			return (0);

		case '1':
			*encryptionAlgorithm = EA_DES_CBC;
			return (1);

		case 'X':
			*encryptionAlgorithm = EA_DESX_CBC;
			return (1);

		case '2':
			*encryptionAlgorithm = EA_DES_EDE2_CBC;
			return (1);

		case '3':
			*encryptionAlgorithm = EA_DES_EDE3_CBC;
			return (1);

		default:
			PrintError ("ERROR: Please enter 1, X, 2 or 3.  Please Try again.", 0);
			break;
		}
	}
}

/* Ask for the filename using the given prompt string and open it
		 for reading.
	 Return 0 on success or 1 if error or if user cancels by entering a blank.
 */
static int ReadInit (file, prompt)
FILE **file;
char *prompt;
{
	char filename[256];

	while (1) {
		if(!GetCommand (filename, sizeof (filename), prompt))
			return (1);
    
    if ((*file = fopen (filename, "rb")) != NULL)
      /* successfully opened */
			break;
    
		PrintError ("ERROR: Cannot open a file with that name.  Try again.", 0);
  }

  return (0);
}

/* Read a block of up to length maxPartOutLen bytes from file, storing
		 it in partOut and returning its length in partOutLen.
   Return 0 on success or 1 if error or end of file.
 */
static int ReadUpdate (file, partOut, partOutLen, maxPartOutLen)
FILE *file;
unsigned char *partOut;
unsigned int *partOutLen;
unsigned int maxPartOutLen;
{
  int status;
  
	/* fread () returns the number of items read in.
	 */
	*partOutLen = fread (partOut, 1, maxPartOutLen, file);

  status = 0;
  if (ferror (file)) {
		PrintError ("ERROR: Cannot read file.", 0);
    status = 1;
  }
  if (*partOutLen == 0 && feof (file))
		status = 1;

	return (status);
}

/* Read a file of up to length maxBlockLen bytes, storing it in
		 block and returning its length in blockLen.
	 Ask for the filename using the given prompt string.
	 Return 0 on success or 1 if error or if user cancels by entering a blank.
 */
static int ReadBlock (block, blockLen, maxBlockLen, prompt)
unsigned char *block;
unsigned int *blockLen;
unsigned int maxBlockLen;
char *prompt;
{
  FILE *file;
	int status;
	unsigned char *dummy;
  unsigned int dummyLen;

  if (ReadInit (&file, prompt))
		return (1);

	if ((status = ReadUpdate (file, block, blockLen, maxBlockLen)) == 0) {
		if (*blockLen == maxBlockLen)
			/* Read exactly maxBlockLen bytes, so reading one more will set
					 end of file if there were exactly maxBlockLen bytes in the file.
			 */
      if (!ReadUpdate (file, dummy, &dummyLen, 1)) {
				PrintError ("ERROR: File is too large.", 0);
				status = 1;
			}
	}

	ReadClose(file);

	return (status);
}

/* Ask for the filename using the given prompt string and open it
	 for writing.
	 Return 0 on success or 1 if error or if user cancels by entering a blank.
*/

static int WriteInit (file, prompt)
FILE **file;
char *prompt;
{
	char filename[256];

	while (1) {
		if(!GetCommand (filename, sizeof (filename), prompt))
			return(1);

		if(filename[0] == '-' && filename[1] == '\0') {
			/* use stdout */
			*file = stdout;
			break;
		}
		if((*file = fopen (filename, "wb")) != NULL)
			/* successfully opened */
			break;

		PrintError("ERROR: Cannot open a file with that name.  Try again.", 0);
	}

	return(0);
}

/* Write block of length partOutLen to a file.
	 Return 0 on success or 1 if error.
 */
static int WriteUpdate(file, partOut, partOutLen)
FILE *file;
unsigned char *partOut;
unsigned int partOutLen;
{
	int status;

	status = 0;
	if(fwrite(partOut, 1, partOutLen, file) < partOutLen) {
		PrintError("ERROR: Cannot write file.", 0);
		status = 1;
	}

	return(status);
}

/* Write block of length blockLen to a file.
	 Ask for the filename using the given prompt string.
	 Return 0 on success or 1 if error or if user cancels by entering a blank.
 */
static int WriteBlock (block, blockLen, prompt)
unsigned char *block;
unsigned int blockLen;
char *prompt;
{
	FILE *file;
	int status;

	if(WriteInit(&file, prompt))
		return (1);

	do{
		if((status = WriteUpdate (file, block, blockLen)) != 0)
			break;

		if(file == stdout)
			/* Printing to screen, so print a new line. */
			printf("\n");
	}while(0);

	WriteClose(file);

	return(status);
}

/* If type is zero, simply print the task string, otherwise convert the
		 type to a string and print task and type.
 */
static void PrintError(task, type)
char *task;
int type;
{
	char *typeString, *msg[] = {
						"Recovered DES key cannot decrypt encrypted content",
						"Encrypted key length or signature length is out of range",
						"Modulus length is out of range",
						"Private key cannot encrypt message digest, or cannot decrypt encrypted key",
						"Public key cannot encrypt data encryption key, or cannot decrypt signature",
						"Signature is incorrect",
						"Unknown Error",
						NULL };

	if(type == 0) {		/* Non RSAEURO Related Error */
		puts(task);			/* Internal Deal with it */
		return;
	}

	/* Convert the type to a string if it is recognized.	 */
	switch(type) {
	case RE_KEY:
		typeString = msg[0];
		break;
	case RE_LEN:
		typeString = msg[1];
		break;
	case RE_MODULUS_LEN:
		typeString = msg[2];
		break;
	case RE_PRIVATE_KEY:
		typeString = msg[3];
		break;
	case RE_PUBLIC_KEY:
		typeString = msg[4];
		break;
	case RE_SIGNATURE:
		typeString = msg[5];
		break;

	default:
		printf("ERROR: Code 0x%04x, %s", type, msg[6]);
		fflush(stdout);
		return;
	}

	printf("ERROR: %s while %s\n", typeString, task);
	fflush(stdout);
}

static int GetCommand(command, maxCommandSize, prompt)
char *command;
unsigned int maxCommandSize;
char *prompt;
{
	unsigned int i;

	printf("%s (blank to cancel): \n", prompt);
	fflush(stdout);

	fgets(command, maxCommandSize, stdin);

	/* Replace the line terminator with a '\0'.	 */

	for (i = 0; command[i] != '\0'; i++) {
		if (command[i] == '\012' || command[i] == '\015' ||	i == (maxCommandSize - 1)) {
			command[i] = '\0';
			break;
		}
	}
	return(strlen(command));
}

static char *upr(char *s)
{
	char *p = s;

	while(*s) {
		if((*s >= 'a') && (*s <= 'z'))
			*s += 'A'-'a';
		s++;
	}

	return p;
}
