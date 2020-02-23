/* ========================================================================== *\
||                         RC4 Implementation in C99                          ||
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
#include <sys/stat.h>
#include <fcntl.h>

#ifndef INLINE
#  define INLINE inline static
#endif

#define KEYSIZE	256
FILE *pwfile;
uint8_t sbox[256];
uint8_t key[KEYSIZE];
size_t keylength=0;
uint8_t i=0, j=0;

/* Bulk IO */
uint8_t *inbuf;
uint8_t *outbuf;
ssize_t bufnbyte=0;
size_t bufsize=(1<<18);

/* File Descriptor */
int infd;
int outfd;

uint8_t status=0;
#define ST_KEY_MASK	0x01
#define ST_IN_MASK	0x02
#define ST_OUT_MASK	0x04

#define ST_KEY		(status & ST_KEY_MASK)
#define ST_IN		(status & ST_IN_MASK)
#define ST_OUT		(status & ST_OUT_MASK)

INLINE void swap(uint8_t *a, uint8_t *b)
{
	uint8_t temp=0;
	temp = *a;
	*a = *b;
	*b = temp;
}

void ksa(uint8_t *sbox, uint8_t *key, size_t len)
{
	int ksa_i=0, ksa_j=0;
	for(ksa_i=0; ksa_i < (1<<8); ++ksa_i)
		sbox[ksa_i]=ksa_i;
	for(ksa_i=0; ksa_i < (1<<8); ++ksa_i)
	{
		ksa_j = (ksa_j + sbox[ksa_i] + key[ksa_i % len]) & 0xFF;
		swap(sbox + ksa_i, sbox + ksa_j);
	}
}

INLINE uint8_t prga(uint8_t *sbox)
{
	i = (i + 1) & 0xFF;
	j = (j + sbox[i]) & 0xFF;
	swap(sbox + i, sbox + j);
	return sbox[(sbox[i] + sbox[j]) & 0xFF];
}

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

void panic(char *msg, int err)
{
	fputs(msg, stderr);
	putc('\n', stderr);
	exit(err);
}

void parsearg(int argc, char **argv)
{
	int opt;
	while((opt = getopt(argc, argv, "hi:o:k:p:b:")) != -1)
	{
		switch(opt)
		{
			case 'i':	/* Input from fd */
				if(strcmp(optarg, "-"))
				{
					if((infd = open(optarg, O_RDONLY)) == EOF)
					{
						perror(optarg);
						exit(8);
					}
				}
				else
					infd=0;	/* stdin */
				status |= ST_IN_MASK;
				break;
			case 'o':	/* Output */
				if(strcmp(optarg, "-"))
				{
					/* if not "-" */
					if((outfd = open(optarg, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR)) == EOF)
					{
						perror(optarg);
						exit(8);
					}
				}
				else
					outfd=1;	/* stdout */
				status |= ST_OUT_MASK;
				break;
			case 'k':	/* Key from argument */
				strncpy((char*)key, optarg, KEYSIZE - 1);
				keylength = strlen((char*)key);
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
					if(infd == 0)	/* fd == stdin */
						panic("?PWDIN", 6);
					fputs("?PW=", stderr);
					keylength = readbyte(key, KEYSIZE, stdin);
				}
				status |= ST_KEY_MASK;
				break;
			case 'b':
				sscanf(optarg, "%lu", &bufsize);
				if(bufsize == 0)
					panic("?BUFSIZE", 7);
				break;
			default:
			case 'h': /* Help */
				printf("Usage: %s [-h] [-i infile] [-o outfile] [-k key] [-p keyfile] [-b bufsize]\n", argv[0]);
				exit(0);
				break;
		}
	}
}

INLINE void blkprga(uint8_t *in, uint8_t *out, size_t bs)
{
	size_t i=0;
	for(i=0; i < bs; i++)
		out[i] = in[i] ^ prga(sbox);
}

int main(int argc, char **argv)
{
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);

	parsearg(argc, argv);

	if(! (ST_KEY && ST_IN && ST_OUT))
	{
		fputs("?ARG\n", stderr);
		exit(8);
	}

	ksa(sbox, key, keylength);

	inbuf	= calloc(bufsize, 1);
	outbuf	= calloc(bufsize, 1);

	while((bufnbyte = read(infd, inbuf, bufsize)) > 0)
	{
		blkprga(inbuf, outbuf, bufnbyte);
		write(outfd, outbuf, bufnbyte);
	}

	return 0;
}
