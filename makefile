CC=gcc
CFLAGS=`libgcrypt-config --cflags --libs`

all: techrypt techdec encrypt

techrypt: techrypt.c optparse.c
	$(CC) $(CFLAGS) techrypt.c optparse.c -ggdb -o techrypt

techdec: techdec.c
	$(CC) $(CFLAGS) techdec.c optparse.c -ggdb -o techdec
	
encrypt: encrypt.c
	$(CC) $(CFLAGS) encrypt.c -ggdb -o encrypt

optparse: optparse.c
	$(CC) optparse.c -ggdb -o optparse

adam: techrypt-adam.c
	$(CC) $(CFLAGS) techrypt-adam.c -ggdb -o adam
	
clean:
	rm techrypt techdec test.gt test encrypt techcrypt.c.gt