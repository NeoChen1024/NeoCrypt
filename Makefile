CC	= cc
CFLAGS	= -O3 -finline -g3 -Wall -pipe -fPIE -fPIC -ansi -pedantic $(OPT)
EXE	= rc4

.PHONY:	all countline clean
all: ${EXE}
rc4:
	$(CC) $(CFLAGS) -o $@ $@.c
countline:
	wc -l *.c
clean:
	-rm -f ${EXE}
