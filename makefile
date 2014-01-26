CC=gcc
CFLAGS=`libgcrypt-config --cflags --libs`

all: techrypt techdec

techrypt: techrypt.c optparse.c
	$(CC) $(CFLAGS) techrypt.c optparse.c -ggdb -o techrypt

techdec: techdec.c
	$(CC) $(CFLAGS) techdec.c optparse.c -ggdb -o techdec
	
optparse: optparse.c
	$(CC) optparse.c -ggdb -o optparse
	
clean:
	rm techrypt techdec test.gt test encrypt techcrypt.c.gt