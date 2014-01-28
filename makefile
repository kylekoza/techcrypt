# Set the variable CC to refer to GCC
# this is kind of unnecessary, but it's nice
# to have if you ever need to change compilers
CC=gcc

# We needs to compile with libgcrypt
# so lets make a variable for it
CFLAGS=`libgcrypt-config --cflags --libs`

# Default option for make
# will compile techrypt and techdec
all: techrypt techdec

# Compile techrypt with optparse
# the ggdb flag is for debugging
# output file as techrypt
techrypt: techrypt.c optparse.c
	$(CC) $(CFLAGS) techrypt.c optparse.c -ggdb -o techrypt

# Compile techdec with optparse
# the ggdb flag is for debugging
# output file as techdec
techdec: techdec.c
	$(CC) $(CFLAGS) techdec.c optparse.c -ggdb -o techdec

# Just compile optparse
optparse: optparse.c
	$(CC) optparse.c -ggdb -o optparse

# Remove the compiled executables	
clean:
	rm techrypt techdec