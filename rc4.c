/* ========================================================================== *\
 *                            RC4 Implementation in C                         *
 *                                   Neo_Chen                                 *
\* ========================================================================== */

/* ========================================================================== *\
 *   This is free and unencumbered software released into the public domain.  *
 *									      *
 *   Anyone is free to copy, modify, publish, use, compile, sell, or	      *
 *   distribute this software, either in source code form or as a compiled    *
 *   binary, for any purpose, commercial or non-commercial, and by any	      *
 *   means.								      *
 *									      *
 *   In jurisdictions that recognize copyright laws, the author or authors    *
 *   of this software dedicate any and all copyright interest in the	      *
 *   software to the public domain. We make this dedication for the benefit   *
 *   of the public at large and to the detriment of our heirs and	      *
 *   successors. We intend this dedication to be an overt act of	      *
 *   relinquishment in perpetuity of all present and future rights to this    *
 *   software under copyright law.					      *
 *									      *
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,	      *
 *   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF       *
 *   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.   *
 *   IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR        *
 *   OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,    *
 *   ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR    *
 *   OTHER DEALINGS IN THE SOFTWARE.					      *
 *									      *
 *   For more information, please refer to <http://unlicense.org/>            *
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

int verbose=0;
uint8_t status=0;
#define ST_KEY_MASK	0x01
#define ST_IN_MASK	0x02
#define ST_INSTR_MASK	0x04
#define ST_OUT_MASK	0x08
#define ST_OUTHEX_MASK	0x10
#define ST_INHEX_MASK	0x20

#define ST_KEY		(status & ST_KEY_MASK)
#define ST_IN		(status & ST_IN_MASK)
#define ST_INSTR	(status & ST_INSTR_MASK)
#define ST_OUT		(status & ST_OUT_MASK)
#define ST_OUTHEX	(status & ST_OUTHEX_MASK)
#define ST_INHEX	(status & ST_INHEX_MASK)

void swap(uint8_t *a, uint8_t *b)
{
	(*a) ^= (*b);
	(*b) ^= (*a);
	(*a) ^= (*b);
}

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

uint8_t prga(uint8_t *sbox, uint8_t input)
{
	static int i=0, j=0;
	uint8_t output=0;
	i = (i + 1) & 0xFF;
	j = (j + sbox[i]) & 0xFF;
	swap(sbox + i, sbox +j);
	output = input ^ sbox[(sbox[i] + sbox[j]) & 0xFF];
	if(verbose)
		fprintf(stderr, "PRGA: S[i = %#x]=%#x,\tS[j = %#x]=%#x,\tIN=%#x,\tOUT=%#x\n", i, sbox[i], j, sbox[j], input, output);
	return output;
}

void hex2str(char *hex, size_t *strlength, uint8_t *str)
{
	int length=0;
	int ptr=0;
	int strptr=0;
	uint8_t value=0;
	if((length = strlen(hex)) == 0)
	{
		fputs("?HEX\n", stderr);
		exit(4);
	}
	while((length - ptr) > 0)
	{
		sscanf(hex + ptr, "%2hhx", &value);
		str[strptr++] = value;
		ptr+=2;
	}
	(*strlength)=strptr;
}

int fgethex(FILE *fp)
{
	char hexbuffer[3]={0,0,0};
	int c=0;
	int ret=0;

	if((c = fgetc(fp)) != EOF)
		hexbuffer[0]=(char)c;
	else
		return EOF;

	if((c = fgetc(fp)) != EOF)
		hexbuffer[1]=(char)c;
	else
		hexbuffer[1]=0;

	sscanf(hexbuffer, "%2x", &ret);
	return ret;
}

/*
 *	The following is a slightly modifed version taken from:
 *	http://www.gnu.org/software/libc/manual/html_node/getpass.html
 *
 *	Get from https://stackoverflow.com/a/30801407
 */

ssize_t my_getpass (char *prompt, char **lineptr, size_t *n, FILE *stream)
{
	struct termios _old, _new;
	int nread;

	/* Turn echoing off and fail if we can’t. */
	if (tcgetattr (fileno (stream), &_old) != 0)
		return -1;
	_new = _old;
	_new.c_lflag &= ~ECHO;
	if (tcsetattr (fileno (stream), TCSAFLUSH, &_new) != 0)
		return -1;

	/* Display the prompt */
	if (prompt)
		fprintf(stderr, "%s", prompt);

	/* Read the password. */
	nread = getline (lineptr, n, stream);

	/* Remove the carriage return */
	if (nread >= 1 && (*lineptr)[nread - 1] == '\n')
	{
		(*lineptr)[nread-1] = 0;
		nread--;
	}
	fputc('\n', stderr);

	/* Restore terminal. */
	(void) tcsetattr (fileno (stream), TCSAFLUSH, &_old);

	return nread;
}

int main(int argc, char **argv)
{
	setvbuf(stderr, NULL, _IONBF, 0);

	int input=0;
	int ret=0;
	size_t ptr=0;
	int opt;
	int opt_hex=0;
	while((opt = getopt(argc, argv, "has:i:o:k:p:v")) != -1)
	{
		switch(opt)
		{
			case 'a':
				opt_hex=1;
				break;
			case 'i': /* File */
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
				if(opt_hex)
				{
					status |= ST_INHEX_MASK;
					opt_hex=0;
				}
				status |= ST_IN_MASK;
				break;
			case 's':
				strlength = strlen(optarg);
				if(opt_hex)
				{
					str = calloc((strlength / 2) + (strlength % 2) + 1, sizeof(char));
					hex2str(optarg, &strlength, (uint8_t *)str);
					strlength = strlen(optarg);
					opt_hex=0;
				}
				else
				{
					if(strlength == 0)
					{
						fputs("?STR\n", stderr);
						exit(2);
					}
					str = calloc(strlength, sizeof(char));
					strlcpy(str, optarg, strlength);
				}
				status |= ST_INSTR_MASK;
				break;
			case 'o':
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
				if(opt_hex)
				{
					status |= ST_OUTHEX_MASK;
					opt_hex=0;
				}
				status |= ST_OUT_MASK;
				break;
			case 'k':
				if(opt_hex)
				{
					hex2str(optarg, &keylength, key);
					status |= ST_KEY_MASK;
					opt_hex=0;
				}
				else
				{
					strlcpy((char*)key, optarg, KEYSIZE);
					keylength = strnlen((char*)key, KEYSIZE);
					if(keylength == 0)
					{
						fputs("?KEY\n", stderr);
						exit(4);
					}
					status |= ST_KEY_MASK;
				}
				break;
			case 'p':
				if(strcmp(optarg, "-"))
				{
					if((pwfile = fopen(optarg, "r")) == NULL)
					{
						perror(optarg);
						exit(8);
					}
				}
				else
				{
					pwfile=stdin;
					if(infile == stdin)
					{
						fputs("?PWDIN\n", stderr);
						exit(4);
					}
				}
				if(opt_hex)
				{
					if(pwfile == stdin)
						fputs("PW: ", stderr);
					while((input = fgethex(pwfile)) != EOF && keylength < KEYSIZE)
						key[keylength++]=(uint8_t)input;
					opt_hex=0;
				}
				else
				{
					if(pwfile == stdin)
					{
						my_getpass("PW: ", (char**) &key, &keylength, stdin);
						if(keylength == 0 || keylength > KEYSIZE)
						{
							fputs("?KEY\n", stderr);
							exit(4);
						}
					}
					else
					{
						while((input = fgethex(pwfile)) != EOF && keylength < KEYSIZE)
							key[keylength++]=(uint8_t)input;
					}
				}
				status |= ST_KEY_MASK;
				break;
			case 'v':
				verbose++;
				break;
			case 'h': /* Help */
				printf("Usage: %s [-h] [-a] [-f] [-i infile] [-o outfile] [-k key] [-s instr] [-x hex] [-v]\n", argv[0]);
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

	size_t count=0;
	if(verbose)
	{
		for(count=0; count < 256; count++)
		{
			fprintf(stderr, "S[0x%02zx]=0x%02x ", count, sbox[count]);
			if((count & 0x07)  == 7)
				fputc('\n', stderr);
		}
		fprintf(stderr, "KEY = \"%s\\0\"\n", key);
	}

	if(ST_IN)
	{
		if(ST_INHEX)
		{
			while((input = fgethex(infile)) != EOF && ret != EOF)
			{
				if(ST_OUTHEX)
					fprintf(outfile, "%02x", prga(sbox, (uint8_t)input));
				else
					ret = fputc(prga(sbox, (uint8_t)input), outfile);
			}
		}
		else
		{
			while((input = fgetc(infile)) != EOF && ret != EOF)
			{
				if(ST_OUTHEX)
					fprintf(outfile, "%02x", prga(sbox, (uint8_t)input));
				else
					ret = fputc(prga(sbox, (uint8_t)input), outfile);
			}
		}
		fclose(infile);
	}
	else if(ST_INSTR)
	{
		while(ptr < strlength && ret != EOF)
		{
			if(ST_OUTHEX)
				ret = fprintf(outfile, "%02x", prga(sbox, str[ptr]));
			else
				ret = fputc(prga(sbox, str[ptr]), outfile);
			ptr++;
		}
	}

	if(ST_OUTHEX)
		fputc('\n', outfile);

	fclose(outfile);
}
