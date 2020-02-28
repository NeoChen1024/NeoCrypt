CC	=	cc
# use loop unroll
OPT	+=	-DUNROLL
CFLAGS	=	-O2 -g -Wall -Wextra -pipe -std=c99 -pedantic $(OPT)
EXE	=	rc4crypt

.PHONY:	all loc clean test
all: ${EXE}
test:
	@./test.sh
loc:
	wc -l *.c *.h
clean:
	-rm -f ${EXE}
