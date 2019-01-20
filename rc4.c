/* ========================================================================== *\
||                          RC4 Implementation in C                           ||
||                                 Neo_Chen                                   ||
\* ========================================================================== */

/* ========================================================================== *\
||   This is free and unencumbered software released into the public domain.  ||
||									      ||
||   Anyone is free to copy, modify, publish, use, compile, sell, or	      ||
||   distribute this software, either in source code form or as a compiled    ||
||   binary, for any purpose, commercial or non-commercial, and by any	      ||
||   means.								      ||
||									      ||
||   In jurisdictions that recognize copyright laws, the author or authors    ||
||   of this software dedicate any and all copyright interest in the	      ||
||   software to the public domain. We make this dedication for the benefit   ||
||   of the public at large and to the detriment of our heirs and	      ||
||   successors. We intend this dedication to be an overt act of	      ||
||   relinquishment in perpetuity of all present and future rights to this    ||
||   software under copyright law.					      ||
||									      ||
||   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,	      ||
||   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF       ||
||   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.   ||
||   IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR        ||
||   OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,    ||
||   ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR    ||
||   OTHER DEALINGS IN THE SOFTWARE.					      ||
||									      ||
||   For more information, please refer to <http://unlicense.org/>            ||
\* ========================================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <termios.h>

#define KEYSIZE	256
FILE *infile;
FILE *outfile;
FILE *pwfile;
uint8_t sbox[256];
uint8_t key[KEYSIZE];
char *str;
size_t strlength=0;
size_t keylength=0;
int i=0, j=0;

uint8_t status=0;
#define ST_KEY_MASK	0x01
#define ST_IN_MASK	0x02
#define ST_INSTR_MASK	0x04
#define ST_OUT_MASK	0x08

#define ST_KEY		(status & ST_KEY_MASK)
#define ST_IN		(status & ST_IN_MASK)
#define ST_INSTR	(status & ST_INSTR_MASK)
#define ST_OUT		(status & ST_OUT_MASK)

#ifdef XORSWAP
void swap(uint8_t *a, uint8_t *b)
{
	(*a) ^= (*b);
	(*b) ^= (*a);
	(*a) ^= (*b);
}
#else
void swap(uint8_t *a, uint8_t *b)
{
	uint8_t temp=0;
	temp = *a;
	*a = *b;
	*b = temp;
}
#endif

void ksa(uint8_t *sbox, uint8_t *key, size_t keylength)
{
	int i=0, j=0;
	for(i=0; i < (1<<8); ++i)
		sbox[i]=i;
	for(i=0; i < (1<<8); ++i)
	{
		j = (j + sbox[i] + key[i % keylength]) & 0xFF;
		swap(sbox + i, sbox +j);
	}
}

uint8_t prga(uint8_t *sbox)
{
	i = (i + 1) & 0xFF;
	j = (j + sbox[i]) & 0xFF;
	swap(sbox + i, sbox + j);
	return sbox[(sbox[i] + sbox[j]) & 0xFF];
}

/* Hexdecimal string to byte array */
size_t readbyte(uint8_t *dst, size_t limit, FILE *fd)
{
	size_t size=0;
	int input=0;
	while(size < limit && input != EOF)
	{
		dst[size++] = input = getc(fd);
	}
	return size;
}

int main(int argc, char **argv)
{
	int input=0;
	int ret=0;
	size_t ptr=0;
	int opt;
	while((opt = getopt(argc, argv, "hs:i:o:k:p:")) != -1)
	{
		switch(opt)
		{
			case 'i':	/* Input from fd */
				if(strcmp(optarg, "-"))
				{
					if((infile = fopen(optarg, "r")) == NULL)
					{
						perror(optarg);
						exit(8);
					}
				}
				else
					infile=stdin;
				status |= ST_IN_MASK;
				break;
			case 's':	/* Input from argument */
				strlength = strlen(optarg);
				if(strlength == 0)
				{
					fputs("?STR\n", stderr);
					exit(2);
				}
				str = calloc(strlength, sizeof(char));
				strncpy(str, optarg, strlength);
				status |= ST_INSTR_MASK;
				break;
			case 'o':	/* Output */
				if(strcmp(optarg, "-"))
				{
					if((outfile = fopen(optarg, "w")) == NULL)
					{
						perror(optarg);
						exit(8);
					}
				}
				else
					outfile=stdout;
				status |= ST_OUT_MASK;
				break;
			case 'k':	/* Key from argument */
				strncpy((char*)key, optarg, KEYSIZE);
				keylength = strnlen((char*)key, KEYSIZE);
				if(keylength == 0)
				{
					fputs("?KEY\n", stderr);
					exit(4);
				}
				status |= ST_KEY_MASK;
				break;
			case 'p':	/* Key from fd */
				if(strcmp(optarg, "-"))
				{
					if((pwfile = fopen(optarg, "r")) == NULL)
					{
						perror(optarg);
						exit(8);
					}
					keylength = readbyte(key, KEYSIZE, pwfile);
				}
				else
				{
					pwfile=stdin;
					if(infile == stdin)
					{
						fputs("?PWDIN\n", stderr);
						exit(4);
					}
					fputs("?PW=", stdout);
					keylength = readbyte(key, KEYSIZE, stdin);
				}
				status |= ST_KEY_MASK;
				break;
			case 'h': /* Help */
				printf("Usage: %s [-h] [-i infile] [-s instr] [-o outfile] [-k key] [-p keyfile]\n", argv[0]);
				exit(0);
			default:
				fputs("?INVARG\n", stderr);
				exit(1);

		}
	}

	if(! (ST_KEY && (ST_IN || ST_INSTR) && ST_OUT))
	{
		fputs("?ARG\n", stderr);
		exit(8);
	}

	ksa(sbox, key, keylength);

	if(ST_IN)
	{
		while((input = getc(infile)) != EOF && ret != EOF)
		{
			ret = putc(prga(sbox) ^ input, outfile);
		}
		fclose(infile);
	}
	else if(ST_INSTR)
	{
		while(ptr < strlength && ret != EOF)
		{
			ret = putc(prga(sbox) ^ str[ptr++], outfile);
		}
	}
	fclose(outfile);
}
