CC	=	cc
# use inline
OPT	+=	-DINLINE -DLE
CFLAGS	=	-O2 -g -Wall -Wextra -pipe -std=c99 -pedantic $(OPT)
EXE	=	neocrypt

.PHONY:	all loc clean test
all: ${EXE}
test:
	@./test.sh
loc:
	wc -l *.c
clean:
	-rm -f ${EXE}
