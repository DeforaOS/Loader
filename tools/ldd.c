/* $Id$ */
/* Copyright (c) 2010-2021 Pierre Pronchery <khorben@defora.org> */
/* This file is part of DeforaOS System Loader */
/* All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */



#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "common.h"
#include "elf.h"

#ifndef PROGNAME_LDD
# define PROGNAME_LDD "ldd"
#endif


/* private */
/* prototypes */
static int _ldd(char const * filename, char const * ldpath);
static int _usage(void);


/* public */
/* functions */
/* main */
int main(int argc, char * argv[])
{
	int ret = 0;
	int o;
	int i;
	char const * ldpath;

	while((o = getopt(argc, argv, "")) != -1)
		switch(o)
		{
			default:
				return _usage();
		}
	if(optind == argc)
		return _usage();
	ldpath = getenv("LD_LIBRARY_PATH");
	for(i = optind; i < argc; i++)
		ret |= _ldd(argv[i], ldpath);
	return (ret == 0) ? 0 : 2;
}


/* private */
/* functions */
/* ldd */
static int _ldd(char const * filename, char const * ldpath)
{
	int ret = 1;
	FILE * fp;
	union
	{
		unsigned char e_ident[EI_NIDENT];
		Elf32_Ehdr ehdr32;
		Elf64_Ehdr ehdr64;
	} elf;

	if((fp = fopen(filename, "r")) == NULL)
		return error(filename, strerror(errno), 1);
	if(fread(&elf, sizeof(elf), 1, fp) == 1)
	{
		if(memcmp(elf.e_ident, ELFMAG, SELFMAG) != 0)
			ret = -error(filename, "Not an ELF file", 1);
		else if(elf.e_ident[EI_CLASS] == ELFCLASS32)
			ret = elf32_ldd(filename, fp, &elf.ehdr32, ldpath);
		else if(elf.e_ident[EI_CLASS] == ELFCLASS64)
			ret = elf64_ldd(filename, fp, &elf.ehdr64, ldpath);
		else
			ret = -error(filename, "Could not determine ELF class",
					1);
	}
	else if(ferror(fp) != 0)
		ret = -error(filename, strerror(errno), 1);
	else
		ret = -error(filename, "Not an ELF file", 1);
	if(fclose(fp) != 0)
		ret = -error(filename, strerror(errno), 1);
	return ret;
}


/* usage */
static int _usage(void)
{
	fputs("Usage: " PROGNAME_LDD " filename...\n", stderr);
	return 1;
}
