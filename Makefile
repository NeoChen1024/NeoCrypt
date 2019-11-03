CC	= cc
CFLAGS	= -O3 -finline -g3 -Wall -Wextra -pipe -fPIE -fPIC -std=c89 -pedantic $(OPT)
EXE	= rc4

.PHONY:	all countline clean
all: ${EXE}
rc4:
	$(CC) $(CFLAGS) -o $@ $@.c
countline:
	wc -l *.c
clean:
	-rm -f ${EXE}
