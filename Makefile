CC	=	cc
# use loop unroll
OPT	+=	-DUNROLL
CFLAGS	=	-Ofast -g3 -Wall -Wextra -pipe -fPIE -std=c99 -pedantic $(OPT)
EXE	=	rc4crypt

.PHONY:	all loc clean test
all: ${EXE}
test:
	@./test.sh
loc:
	wc -l *.c *.h
clean:
	-rm -f ${EXE}
