#include <gcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sendfile.h>
#include <sys/socket.h>

#define GCRY_CIPHER GCRY_CIPHER_AES128


int main (int argc, char const *argv[])
{
	/*
		Parse arguments
	*/
	
	/*
		Read in password
	*/
	char *pass = NULL;
	size_t passLen = 0;
	ssize_t passRead;
		
	printf("Password: ");

	passRead = getline(&pass, &passLen, stdin);
	
	/*
		Initializing the libgcrypt library by following the instruction
		in the libgcrypt documentation:
		http://www.gnupg.org/documentation/manuals/gcrypt/Initializing-the-library.html#Initializing-the-library
	*/
	if (!gcry_check_version(GCRYPT_VERSION)) {
		fputs ("libgcrypt version mismatch\n", stderr);
		exit (2);
	}

	gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
	gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
	gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

	/*
		Key Generation
	*/
	char key[16] = {0};
	size_t keyLength = gcry_cipher_get_algo_keylen(GCRY_CIPHER);
	const char *salt = "NaCl";
	size_t saltlen = sizeof(salt);
	
	gcry_kdf_derive(pass, passLen, GCRY_KDF_PBKDF2, GCRY_MD_SHA512, salt, saltlen, 4096, keyLength, key);
	
	/*
		Cipher Setup
	*/
	printf("Key: ");
	printf(key);
	printf("\n");
	const int IV[16] = {5844};
	printf("IV: ");
	printf(IV);
	printf("\n");
	const char *name = "aes128";
	int algorithm = gcry_cipher_map_name(name);
	size_t blockLength = gcry_cipher_get_algo_blklen(GCRY_CIPHER);
	gcry_cipher_hd_t hand;

	gcry_cipher_open(&hand, algorithm, GCRY_CIPHER_MODE_CBC, 0);
	gcry_cipher_setkey(hand, key, keyLength);
	gcry_cipher_setiv(hand, IV, blockLength);
	
	/* 
		Open the file for reading and then copy to a buffer
	*/	
	FILE *ifp;
	long len;
	char *buffer;
	
	ifp = fopen("techrypt.c", "r");
				
	fseek(ifp, 0L, SEEK_END);
	len = ftell(ifp);
	rewind(ifp);
	
	buffer = gcry_calloc_secure(1, len+1);
	
	fread(buffer, len+1, 1, ifp);
	
	fclose(ifp);
	
	/*
		Encrypt the buffer
	*/
	gcry_cipher_encrypt(hand, buffer, len, NULL, 0);
	
	/*
		Write the buffer to a file
	*/
	FILE *ofp;
	ofp = fopen("test.gt", "w");
	
	fprintf(ofp, buffer);
	
	fclose(ofp);
	
	/*
		Send the buffer to remote computer
	*/
	
	return 0;
}