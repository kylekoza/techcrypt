#include <gcrypt.h>
#include <stdio.h>
#include <stdlib.h>
//#include <sys/sendfile.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include "optparse.h"

#define GCRY_CIPHER GCRY_CIPHER_AES128

int local = 0;
int port = 8888; // Use 8888 as default

struct opt_spec options[] = {
	{opt_text, OPT_NO_SF, "FILE", OPT_NO_METAVAR, "If specified with -l then decrypts FILE otherwise decrypts to FILE", OPT_NO_DATA},
    {opt_help, "h", "--help", OPT_NO_METAVAR, OPT_NO_HELP, OPT_NO_DATA},
	{opt_store_int, "d", OPT_NO_LF, " < port >", 
	 "The port from which to receive the encrypted file", &port},
    {opt_store_1, "l", "--local", OPT_NO_METAVAR,
     "Encrypt file locally", &local},
    {OPT_NO_ACTION}
};

int main (int argc, char **argv) {
	/*
		Parse arguments
	*/
	if(opt_parse("usage: %s < filename > [options]", options, argv) == 0) {
		opt_help(0, NULL);
	}
		
	/*
		Read in password
	*/
	char *pass = NULL;
	size_t passLen = 0;
	ssize_t passRead;
	
	char *fileName;
		
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
	gcry_control(GCRYCTL_INIT_SECMEM, 65536, 0);
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
		
	errStatus = gcry_kdf_derive(pass, passLen, GCRY_KDF_PBKDF2, GCRY_MD_SHA512, salt, saltLen, iterations, keyLength, key);
			
	/*
		Cipher Setup
	*/
//	printf("Key: %X\n", key);
	puts(key);
	
	const char* IV = "5844"; // const int IV = 5844;
	const char *name = "aes128";
	int algorithm = gcry_cipher_map_name(name);
	size_t blockLength = gcry_cipher_get_algo_blklen(GCRY_CIPHER);
	gcry_cipher_hd_t hand;

	gcry_cipher_open(&hand, algorithm, GCRY_CIPHER_MODE_CBC, 0);
	gcry_cipher_setkey(hand, key, keyLength);
	gcry_cipher_setiv(hand, IV, blockLength);
	
	char *buffer;
	long len;
	
	/*
		If the local flag is set then we encrypt the file locally
		instead of sending it over the network
		Otherwise we send the file over the network
	*/
	if (local == 1) {
	
		/* 
			Open the file for reading and then copy to a buffer
		*/	
		FILE *ifp = fopen(argv[1], "rb");
		if(ifp == 0) {
			printf("%s", "Could not open file");
			return 1;
		}
		
//		ifp = fopen("techrypt.c.gt", "r");
//		fread(stdout, sizeof(ifp), 1, ifp);
		fseek(ifp, 0L, SEEK_END);
		len = ftell(ifp);
		rewind(ifp);
		
		buffer = gcry_calloc_secure(len+(16-(len%16)), sizeof(char));

		fread(buffer, 1, len, ifp);
		
		fileName = argv[1];
		size_t inLen = strlen(fileName);
		fileName[inLen-3] = '\0';
	
		fclose(ifp);
		
	} else {
		/*
			Retrieve file from remote computer
		*/
		int sock;
		int localSock;
		struct sockaddr_in inPort;
		inPort.sin_family = AF_INET;
		inPort.sin_addr.s_addr = INADDR_ANY;
		inPort.sin_port = htons(port);
	
		sock = socket(AF_INET, SOCK_STREAM, 0);

		if (sock == -1) {
			printf("%s", "Could not open socket");
			exit(1);
		}
		
		bind(sock, (struct sockaddr *) &inPort, sizeof(inPort));
		listen(sock, 0);
		
		printf("%s", "Waiting for connection...\n");
		
		localSock = accept(sock, NULL, NULL);
		printf("%s", "Inbound file...\n");
		
		FILE *contents = fdopen(localSock, "rb");
		fseek(contents, 0L, SEEK_END);
		len = ftell(contents);
		fseek(contents, 0L, SEEK_SET);
		
		char *buffer = gcry_calloc_secure(len+(16-(len%16)), sizeof(char));

		fread(buffer, 1, len, contents);

		fileName = argv[1];
	
		fclose(contents);
		
		close(sock);
						
	}	
	

	/*
		Decrypt the buffer
	*/
	gcry_cipher_decrypt(hand, buffer, len+(16-(len%16)), NULL, 0);

	/*
		Write the buffer to a file
	*/
	FILE *ofp = fopen(fileName, "wb");
	fwrite(buffer, 1, len, ofp);
	
	fclose(ofp);
		
	return 0;
}