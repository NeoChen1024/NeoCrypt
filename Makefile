CC	= cc
CFLAGS	= -O3 -finline -g3 -Wall -pipe -fPIE -fPIC -ansi -std=c99
EXE	= arc4

all: ${EXE}
arc4:
	$(CC) $(CFLAGS) -o $@ $@.c
countline:
	wc -l *.c
clean:
	-rm -f ${EXE}
