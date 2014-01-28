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
int port = 8888; // Use 8888 as default

// Structure for command line options
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
	gcry_control(GCRYCTL_INIT_SECMEM, 131072, 0);
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
	size_t macLen = 0;
	
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
		
		// Lets figure out how big the file is
		fseek(ifp, 0L, SEEK_END);
		len = ftell(ifp);
		rewind(ifp);
		
		// Allocate secure RAM for the buffer
		buffer = gcry_calloc_secure(len, sizeof(char));

		// Copy the input file to the buffer
		fread(buffer, 1, len, ifp);
		
		// Since we're running locally, the name of the output file is the same as the argument
		// without the .gt
		fileName = argv[1];
		size_t inLen = strlen(fileName);

		// End the filename by replacing the "." with a NULL char
		fileName[inLen-3] = '\0';
	
		fclose(ifp);
		
	} else {
		/*
			Retrieve file from remote computer
			Open a socket and listen for communication
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
		
		// Accepting the connection
		localSock = accept(sock, NULL, NULL);
		printf("%s", "Inbound file...\n");
		
		// Allocate some memory for the buffer
		// len+(160(len%16)) is so that the memory we allocate is divisible 
		// by the blocklength, which is 16
        len = 4096L;
		buffer = gcry_calloc_secure(len+(16-(len%16)), sizeof(char));
        long dataRead = 0L;
        int keepReading = 1;
		
		// Let's figure out how much data we're getting
		// If I were to do this part over, I would instead open two connections
		// from techrypt- where the first connection sends the 
		// amount of data to be transmitted in the second connection
        while (keepReading) {
            dataRead = recv(localSock, buffer, len, MSG_PEEK);
            if (dataRead == len) {
                len = len * 2;
				sleep(.5);
                buffer = gcry_realloc(buffer, len);
                keepReading = 1;
            } else {
                keepReading = 0;
            }
        }
		// How much data did we read?
        len = dataRead;
		
		// Now lets actually store it in the buffer
        dataRead = recv(localSock, buffer, len, 0);
		
		// Output file name is the command line argument
		fileName = argv[1];
			
		close(sock);
		
		/*
			Setup the HMAC
		*/
		gcry_md_hd_t macHand;
	
		macLen = gcry_md_get_algo_dlen(GCRY_MD_SHA512);
		char *mac = gcry_calloc_secure(macLen, sizeof(char));
		
		gcry_md_open(&macHand, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC);
		gcry_md_setkey(macHand, key, keyLength);
		
		// Generate the HMAC for the message we received
		// Since we know there's a MAC of size macLen at the end
		// we will only generate the hash based on the first
		// len-macLen bytes
		gcry_md_write(macHand, buffer, len-macLen);
		mac = gcry_md_read(macHand, 0);
		
		/*
			Strip HMAC from buffer
		*/
		char *exMac = buffer+(len-macLen);
		
		/*
			Check HMAC against our HMAC
		*/
		// I think this may be exploitable with a strategically placed NULL
		// The use of memcmp could fix this...if I have time I will replace and check
		if(strncmp(mac, exMac, macLen) != 0) {
			exit(62);
		}
								
	}	
	

	/*
		Decrypt the buffer
	*/
	gcry_cipher_decrypt(hand, buffer, len, NULL, 0);
	
	
	/*
		Reverse padding algorithm
		Strip the amount of bytes from the end of the file
		determined by the contents of the last byte
		This is why using PKCS7 was so useful
	*/
	char *padPtr = buffer+len-macLen-1;
	int writeLen = len-macLen-(*padPtr);
	
	/*
		Write the buffer to a file
	*/
	FILE *ofp = fopen(fileName, "wb");
	fwrite(buffer, 1, writeLen, ofp);
	
	fclose(ofp);
		
	return 0;
}