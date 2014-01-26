#include <gcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include "optparse.h"

#define GCRY_CIPHER GCRY_CIPHER_AES128

int local = 0;
struct opt_str ip = {NULL, 0};

struct opt_spec options[] = {
	{opt_text, OPT_NO_SF, "FILE", OPT_NO_METAVAR, "input file to encrypt", OPT_NO_DATA},
    {opt_help, "h", "--help", OPT_NO_METAVAR, OPT_NO_HELP, OPT_NO_DATA},
	{opt_store_str, "d", OPT_NO_LF, " < IP-addr:port >", 
	 "The IP address and port to which to send the encrypted file", &ip},
    {opt_store_1, "l", "--local", OPT_NO_METAVAR,
     "Encrypt file locally", &local},
    {OPT_NO_ACTION}
};

int main (int argc, char **argv) {
	/*
		Parse arguments
	*/
	if(opt_parse("usage: %s < input file > [options]", options, argv) == 0) {
		opt_help(0, NULL);
	}
	
	if (ip.s) {
		ip.s[0] = ip.s0;
	}
	
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
	char key[16] = "";
	size_t keyLength = gcry_cipher_get_algo_keylen(GCRY_CIPHER);

	const char *salt = "NaCl";
	size_t saltLen = sizeof(salt);
	unsigned long iterations = 4096;
	gpg_error_t errStatus; 
	
	printf("gcry_kdf_derive(%s, %u, %d, %s, %u, %d, %d, key)\n", pass, strlen(pass), GCRY_KDF_PBKDF2, salt, strlen(salt), iterations, keyLength);
	
	errStatus = gcry_kdf_derive(pass, passLen, GCRY_KDF_PBKDF2, GCRY_MD_SHA512, salt, saltLen, iterations, keyLength, key);
	
	if(errStatus != 0) {
		printf("Error generating key from password!\n");
		printf("Error no: %d and message: %s\n ", errStatus, gcry_strerror(errStatus)); 
	}
		
	/*
		Cipher Setup
	*/
	printf("Key: %X\n", key);

	const int IV[16] = {5844}; // const int IV = 5844;
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
	FILE *ifp = fopen(argv[1], "r");
	if(ifp == 0) {
		printf("%s", "Could not open file");
		return 1;
	}
	
	long len;
	
//	ifp = fopen("techrypt.c", "r");
	fread(stdout, sizeof(ifp), 1, ifp);
	fseek(ifp, 0L, SEEK_END);
	len = ftell(ifp);
	rewind(ifp);
	
	char *buffer = gcry_calloc_secure(1, len);
	
	fread(buffer, len, 1, ifp);
		
	fclose(ifp);
	
	/*
		Encrypt the buffer
	*/
	gcry_cipher_encrypt(hand, buffer, len, NULL, 0);
	gcry_cipher_decrypt(hand, buffer, len, NULL, 0);

	/*
		If the local flag is set then we encrypt the file locally
		instead of sending it over the network
		Otherwise we send the file over the network
	*/
	if (local == 1) {
		/*
			Write the buffer to a file
		*/
		FILE *ofp;
		ofp = fopen(strcat(argv[1], ".gt"), "w");
	
		fprintf(ofp, buffer);
	
		fclose(ofp);
		
	} else {
		/*
			Send the buffer to remote computer
		*/
		int port = 60888;
		int sock;
	
		sock = socket(AF_INET, SOCK_STREAM, 0);

		if (sock == -1) {
			fprintf(stderr, "unable to create socket: %s\n", strerror(errno));
			exit(1);
		}
	
	//	ssize_t sent = sendfile(sock, ofp, NULL, len+1);
		
	}	
	
	return 0;
}