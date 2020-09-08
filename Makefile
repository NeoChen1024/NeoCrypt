CC	=	cc
# use inline
OPT	+=	-DINLINE -DLE -DEXPECT_MACRO
CFLAGS	=	-O2 -g -Wall -Wextra -pipe -static -std=c99 -pedantic $(OPT)
EXE	=	neocrypt

.PHONY:	all loc clean test
all: ${EXE}
test:
	@./test.sh
loc:
	wc -l *.c
clean:
	-rm -f ${EXE}
