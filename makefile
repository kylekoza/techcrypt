CC=gcc
CFLAGS=`libgcrypt-config --cflags --libs`

all: techrypt techdec

techrypt: techrypt.c
	$(CC) $(CFLAGS) techrypt.c -o techrypt

techdec: techdec.c
	$(CC) $(CFLAGS) techdec.c -o techdec
	
clean:
	rm techrypt techdec test.gt test