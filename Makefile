CC	=	cc
# use xorswap
#OPT	+=	-DXORSWAP
# use loop unroll
OPT	+=	-DUNROLL
CFLAGS	=	-Ofast -g3 -Wall -Wextra -pipe -fPIE -std=c99 -pedantic $(OPT)
EXE	=	rc4crypt

.PHONY:	all countline clean
all: ${EXE}
countline:
	wc -l *.c
clean:
	-rm -f ${EXE}
