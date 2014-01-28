#include <gcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include "optparse.h"

#define GCRY_CIPHER GCRY_CIPHER_AES128

int local = 0; // Feax-Boolean for whether we are being run in local mode
struct opt_str ip = {NULL, 0}; // Structure to store the ip and port

// Structure for command line options
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
    gcry_error_t errorVal;

    errorVal = gcry_cipher_open(&hand, algorithm, GCRY_CIPHER_MODE_CBC, 0);
//    printf("ErrorVal = %u \n", errorVal);
    errorVal = gcry_cipher_setkey(hand, key, keyLength);
//    printf("ErrorVal = %u \n", errorVal);
    errorVal = gcry_cipher_setiv(hand, IV, blockLength);
//    printf("ErrorVal = %u \n", errorVal);	
	
	/*
		Open the file for reading and then copy to a buffer
	*/	
	FILE *ifp = fopen(argv[1], "rb");
	if(ifp == 0) {
		printf("%s", "Could not open file");
		return 1;
	}
	
	long len;
	
//	fread(stdout, sizeof(ifp), 1, ifp);
	
	// Lets figure out how big the file is
	fseek(ifp, 0, SEEK_END);
	len = ftell(ifp);
	rewind(ifp);
	
	// This is the buffer where we'll store the plaintext
	// and convert to ciphertext
	// We're allocating len+(16-(len%16)) bytes because
	// the block cipher needs to be divisible by the blocklength
	// which is 16 bytes. The use of calloc makes sure the extra
	// memory will consist of NULLs so that we can strip them off later
    char *buffer = gcry_calloc_secure(len+(16-(len%16)), sizeof(char));

	// Copy the input file to the buffer
    fread(buffer, 1, len, ifp);

    fclose(ifp);
		
	/*
		Encrypt the buffer
	*/
    errorVal = gcry_cipher_encrypt(hand, buffer, len+(16-(len%16)), NULL, 0);	
	
	/*
		If the local flag is set then we encrypt the file locally
		instead of sending it over the network
		Otherwise we send the file over the network
	*/
	if (local == 1) {
		/*
			Write the buffer to a file
		*/
		FILE *ofp = fopen(strcat(argv[1], ".gt"), "wb");

		fwrite(buffer, 1, len+(16-(len%16)), ofp);
	
		fclose(ofp);
		
	} else {
		/*
			Parse the IP options
		*/
		if (ip.s) {
			ip.s[0] = ip.s0;
		}
		
		// Getting the IP address from the argument
		char *ipAddr = strtok(ip.s, ":");
		
		// Getting the port from the argument
		char *port = strtok(NULL, ":");
		// Convert the port char* to an int
		int portNo = atoi(port);
		
		/*
			Calculate the HMAC
		*/
		gcry_md_hd_t macHand;
	
		size_t macLen = gcry_md_get_algo_dlen(GCRY_MD_SHA512);
		char *mac = gcry_calloc_secure(macLen, sizeof(char));
		
		errorVal = gcry_md_open(&macHand, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC);
		errorVal = gcry_md_setkey(macHand, key, keyLength);
		
		gcry_md_write(macHand, buffer, len+(16-(len%16)));
		mac = gcry_md_read(macHand, 0);
		
		/*
			Send the buffer to remote computer
		*/
		// Allocating a buffer big enought to hold 
		// the ciphertext with the MAC added on at the end
		char *sendBuffer = gcry_calloc_secure(len+(16-(len%16)+macLen), sizeof(char));
		
		// Figured this out the hard way...
		// Sometimes ciphertext includes NULLs, which 
		// was causing strcpy to fail here...
		//
		// Instead I'm now using memcpy to copy the ciphertext
		// and the MAC into the buffer
        memcpy(sendBuffer, buffer, len+(16-(len%16)));
        memcpy(sendBuffer+len+(16-(len%16)), mac, macLen);

        int sock;
        sock = socket(AF_INET, SOCK_STREAM, 0);

        if (sock == -1) {
                printf("%s", "Could not open socket");
                exit(1);
        }

		// localAddr is the socket we are going to use to communicate
		// servAddr is the remote socket we will connect to
        struct sockaddr_in localAddr;
        struct sockaddr_in servAddr;
        localAddr.sin_family = AF_INET;
        localAddr.sin_addr.s_addr = INADDR_ANY;
        localAddr.sin_port = htons(0);

        bind(sock, (struct sockaddr *)&localAddr, sizeof(localAddr));

        servAddr.sin_family = AF_INET;
        servAddr.sin_port = htons(portNo);  // Set the port to the port number
        servAddr.sin_addr.s_addr = inet_addr(ipAddr); // The IP specified in the argument
		
		// Connect to the socket
        connect(sock, (struct sockaddr *)&servAddr, sizeof(servAddr));
		
		// Send the data, woooo
        write(sock, sendBuffer, len+(16-(len%16)+macLen));
				
	}	
	
	return 0;
}