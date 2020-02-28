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

/* Use POSIX C Source */
#ifndef _POSIX_C_SOURCE
#  define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
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
size_t bufnbyte=0;
size_t bufsize=(1<<18);

/* Main I/O */
FILE *in;
FILE *out;
char infile[PATH_MAX];
char outfile[PATH_MAX];

uint8_t status=0;
#define ST_KEY_MASK	0x1
#define ST_KEY		(status & ST_KEY_MASK)

uint8_t verbose=0;

#ifndef XORSWAP
INLINE void swap(uint8_t *a, uint8_t *b)
{
	uint8_t temp=0;
	temp = *a;
	*a = *b;
	*b = temp;
}
#else
INLINE void swap(uint8_t *a, uint8_t *b)
{
	*a ^= *b;
	*b ^= *a;
	*a ^= *b;
}
#endif

void ksa(uint8_t *sbox, uint8_t *key, size_t len)
{
	unsigned int ksa_i=0, ksa_j=0;

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
	i = (i + 1);
	j = (j + sbox[i]);
	swap(sbox + i, sbox + j);
	return sbox[(uint8_t)(sbox[i] + sbox[j])];
}

#define PRGA(x) \
	out[x] = in[x] ^ prga(sbox)

#ifndef UNROLL
INLINE void blkprga(uint8_t *in, uint8_t *out, size_t bs)
{
	size_t i=0;
	for(i=0; i < bs; i++)
		out[i] = in[i] ^ prga(sbox);
}
#else
INLINE void blkprga(uint8_t *in, uint8_t *out, size_t bs)	/* 16-fold loop unroll */
{
	size_t i=0;
	for(i=0; i < bs; i += 16)
	{
		PRGA(i + 0);
		PRGA(i + 1);
		PRGA(i + 2);
		PRGA(i + 3);
		PRGA(i + 4);
		PRGA(i + 5);
		PRGA(i + 6);
		PRGA(i + 7);
		PRGA(i + 8);
		PRGA(i + 9);
		PRGA(i + 10);
		PRGA(i + 11);
		PRGA(i + 12);
		PRGA(i + 13);
		PRGA(i + 14);
		PRGA(i + 15);
	}
}
#endif


size_t readbyte(uint8_t *dst, size_t limit, FILE *fd)
{
	size_t size=0;
	int input=0;
	while((size < limit) && ((input = getc(fd)) != EOF))
	{
		dst[size++] = input;
	}
	return size;
}

void panic(char *msg)
{
	fputs(msg, stderr);
	putc('\n', stderr);
	exit(1);
}

void info(char *fmt, ...)
{
	va_list args;
	va_start (args, fmt);
	if(verbose > 0)
	{
		vfprintf(stderr, fmt, args);
	}
	va_end(args);
}

void parsearg(int argc, char **argv)
{
	int opt;
	while((opt = getopt(argc, argv, "hi:o:k:p:b:v")) != -1)
	{
		switch(opt)
		{
			case 'i':	/* Input */
				if(strcmp(optarg, "-"))
				{
					/* if not "-" */
					if((in = fopen(optarg, "rb")) == NULL)
					{
						perror(optarg);
						exit(8);
					}
				}
				else
					in=stdin;	/* stdin */
				strncpy(infile, optarg, PATH_MAX - 1);
				break;
			case 'o':	/* Output */
				if(strcmp(optarg, "-"))
				{
					/* if not "-" */
					if((out = fopen(optarg, "wb+")) == NULL)
					{
						perror(optarg);
						exit(8);
					}
				}
				else
					out=stdout;	/* stdout */
				strncpy(outfile, optarg, PATH_MAX - 1);
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
					if(in == stdin)	/* fd == stdin */
						panic("in == pwfile == stdin");

					/* Prompt */
					fputs("PASSWORD=", stderr);
					keylength = readbyte(key, KEYSIZE, stdin);
				}
				status |= ST_KEY_MASK;
				break;
			case 'b':	/* Buffer size in KiB */
				bufsize = 0;
				sscanf(optarg, "%lu", &bufsize);
				if(bufsize == 0)
					panic("Buffer size == 0");
				else
					bufsize <<= 10;
				break;
			case 'v':
				verbose++;
				break;
			default:
			case 'h': /* Help */
				fprintf(stderr, "Usage: %s [-h] [-i infile] [-o outfile] [-k key] [-p keyfile] [-b bufsize]\n", argv[0]);
				exit(0);
				break;
		}
	}
}

int main(int argc, char **argv)
{
	info("RC4 Cipher Utility\n");
	setvbuf(stdin,  NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);

	in  = stdin;
	out = stdout;

	parsearg(argc, argv);
	info("bufsize = %zdK\n", bufsize >> 10);

	setvbuf(in,  NULL, _IONBF, 0);
	setvbuf(out, NULL, _IONBF, 0);

	if(!ST_KEY)
		panic("No key is given");

	ksa(sbox, key, keylength);
	info("KSA Done\n");

	inbuf = malloc(bufsize);
	outbuf = malloc(bufsize);

	info("Entering Bulk-PRGA Loop\n");
	while((bufnbyte = fread(inbuf, 1, bufsize, in)) != 0)
	{
		blkprga(inbuf, outbuf, bufnbyte);
		if(fwrite(outbuf, 1, bufnbyte, out) != bufnbyte)
			break;
	}

	if(ferror(in))
		perror(infile);
	if(ferror(out))
		perror(outfile);

	/* Final clean-up */
	info("Clean-up\n");
	fclose(in);
	fclose(out);
	free(inbuf);
	free(outbuf);
	return 0;
}
