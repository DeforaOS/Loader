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



#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "common.h"
#include "elf.h"


#if defined(__ELF__)
/* macros */
# if ELFSIZE == 32
#  define ELFFUNC(func) elf32_ ## func
#  define ELFTYPE(type) Elf ## 32 ## _ ## type
# elif ELFSIZE == 64
#  define ELFFUNC(func) elf64_ ## func
#  define ELFTYPE(type) Elf ## 64 ## _ ## type
# else
#  error ELFSIZE is not defined
# endif


/* functions */
/* elf_ldd */
static int ELFFUNC(phdr)(char const * filename, FILE * fp, ELFTYPE(Ehdr) * ehdr,
		ELFTYPE(Phdr) * phdr, char const * ldpath);
static int ELFFUNC(phdr_dyn)(char const * filename, FILE * fp,
		ELFTYPE(Ehdr) * ehdr, ELFTYPE(Phdr) * phdr, ELFTYPE(Dyn) * dyn,
		char const * ldpath);
static int ELFFUNC(phdr_dyn_print)(char const * filename, char const * rpath);
static char * ELFFUNC(string)(char const * filename, FILE * fp,
		ELFTYPE(Ehdr) * ehdr, ELFTYPE(Addr) addr, ELFTYPE(Addr) index);

int ELFFUNC(ldd)(char const * filename, FILE * fp, ELFTYPE(Ehdr) * ehdr,
		char const * ldpath)
{
	int ret;
	ELFTYPE(Phdr) * phdr;

	if(ehdr->e_phnum == 0)
		return -error(filename, "No program header found", 1);
	if(ehdr->e_phentsize != sizeof(*phdr))
		return -error(filename, "Unexpected program header size", 1);
	if(fseek(fp, ehdr->e_phoff, SEEK_SET) != 0)
		return -error(filename, strerror(errno), 1);
	if((phdr = malloc(sizeof(*phdr) * ehdr->e_phnum)) == NULL)
		return -error(filename, strerror(errno), 1);
	ret = ELFFUNC(phdr)(filename, fp, ehdr, phdr, ldpath);
	free(phdr);
	return ret;
}

static int ELFFUNC(phdr)(char const * filename, FILE * fp, ELFTYPE(Ehdr) * ehdr,
		ELFTYPE(Phdr) * phdr, char const * ldpath)
{
	int ret = 0;
	size_t i;
	size_t cnt;
	ELFTYPE(Dyn) * dyn;

	if(fread(phdr, sizeof(*phdr), ehdr->e_phnum, fp) != ehdr->e_phnum)
	{
		if(ferror(fp) != 0)
			ret = -error(filename, strerror(errno), 1);
		else
			ret = -error(filename, "Corrupted ELF file", 1);
		return ret;
	}
	for(i = 0, cnt = 0; i < ehdr->e_phnum; i++)
	{
		if(phdr[i].p_type != PT_DYNAMIC)
			continue;
		if(cnt++ == 0)
			printf("%s:\n", filename);
		if(fseek(fp, phdr[i].p_offset, SEEK_SET) != 0)
		{
			ret |= -error(filename, strerror(errno), 1);
			continue;
		}
		if((dyn = malloc(phdr[i].p_filesz)) == NULL)
		{
			ret |= -error(filename, strerror(errno), 1);
			continue;
		}
		if(fread(dyn, phdr[i].p_filesz, 1, fp) == 1)
			ret = ELFFUNC(phdr_dyn)(filename, fp, ehdr, &phdr[i],
					dyn, ldpath);
		else
		{
			if(ferror(fp) != 0)
				ret |= -error(filename, strerror(errno), 1);
			else
				ret |= -error(filename, "Corrupted ELF file",
						1);
		}
		free(dyn);
	}
	if(cnt == 0)
		ret |= -error(filename, "Not a dynamic ELF object", 1);
	return ret;
}

static int ELFFUNC(phdr_dyn)(char const * filename, FILE * fp,
		ELFTYPE(Ehdr) * ehdr, ELFTYPE(Phdr) * phdr, ELFTYPE(Dyn) * dyn,
		char const * ldpath)
{
	ssize_t s = -1;
	ssize_t r = -1;
	size_t i;
	char * p;
	char * rpath = NULL;

	for(i = 0; (i + 1) * sizeof(*dyn) < phdr->p_filesz; i++)
	{
		if(dyn[i].d_tag == DT_NULL)
			break;
		if(dyn[i].d_tag == DT_STRTAB)
			s = i;
		else if(dyn[i].d_tag == DT_RPATH)
			r = i;
	}
	if(s < 0)
		return -error(filename, "Missing string section", 1);
	if(s >= 0 && r >= 0)
		rpath = ELFFUNC(string)(filename, fp, ehdr, dyn[s].d_un.d_val,
				dyn[r].d_un.d_val);
# ifdef DEBUG
	fprintf(stderr, "DEBUG: %s() strtab=%ld rpath=%ld \"%s\"\n", __func__,
			dyn[s].d_un.d_val, dyn[r].d_un.d_val, rpath);
# endif
	for(i = 0; (i + 1) * sizeof(*dyn) < phdr->p_filesz; i++)
	{
		if(dyn[i].d_tag == DT_NULL)
			break;
		if(dyn[i].d_tag != DT_NEEDED)
			continue;
		if((p = ELFFUNC(string)(filename, fp, ehdr, dyn[s].d_un.d_ptr,
						dyn[i].d_un.d_val)) == NULL)
			continue;
		if(ELFFUNC(phdr_dyn_print)(p, ldpath) != 0
				&& ELFFUNC(phdr_dyn_print)(p, rpath) != 0
				&& ELFFUNC(phdr_dyn_print)(p,
					"/usr/lib:/lib") != 0)
			printf("\t%s\n", p);
		free(p);
	}
	return 0;
}

static int ELFFUNC(phdr_dyn_print)(char const * filename, char const * rpath)
{
	size_t len = strlen(filename);
	size_t i;
	char * p;
	struct stat st;
	int res;

# ifdef DEBUG
	fprintf(stderr, "DEBUG: %s(\"%s\", \"%s\")\n", __func__, filename,
			rpath);
# endif
	if(rpath == NULL)
		return -1;
	for(i = 0;;)
	{
		if(rpath[i] != ':' && rpath[i] != '\0')
		{
			i++;
			continue;
		}
		p = malloc(i + len + 2);
		snprintf(p, i + 1, "%s", rpath);
		snprintf(&p[i], len + 2, "/%s", filename);
		if((res = stat(p, &st)) == 0)
			printf("\t%s => %s\n", filename, p);
		free(p);
		if(res == 0)
			return 0;
		if(rpath[i] == '\0')
			break;
		rpath += i + 1;
		i = 0;
	}
	return -1;
}

static char * ELFFUNC(string)(char const * filename, FILE * fp,
		ELFTYPE(Ehdr) * ehdr, ELFTYPE(Addr) addr, ELFTYPE(Addr) index)
{
	char * ret;
	size_t i;
	ELFTYPE(Shdr) shdr;
	char * p = NULL;

	if(fseek(fp, ehdr->e_shoff, SEEK_SET) != 0)
	{
		error(filename, strerror(errno), 1);
		return NULL;
	}
	for(i = 0; i < ehdr->e_shnum; i++)
	{
		if(fread(&shdr, sizeof(shdr), 1, fp) != 1)
		{
			if(ferror(fp) != 0)
				error(filename, strerror(errno), 1);
			else
				error(filename, "Corrupted ELF file", 1);
			break;
		}
		if(shdr.sh_type != SHT_STRTAB)
			continue;
		if(shdr.sh_addr != addr)
			continue;
		if(fseek(fp, shdr.sh_offset, SEEK_SET) != 0
				|| (p = malloc(shdr.sh_size)) == NULL)
		{
			error(filename, strerror(errno), 1);
			break;
		}
		if(fread(p, sizeof(*p), shdr.sh_size, fp) != shdr.sh_size)
		{
			if(ferror(fp) != 0)
				error(filename, strerror(errno), 1);
			else
				error(filename, "Corrupted ELF file", 1);
			break;
		}
		for(i = index; i < shdr.sh_size; i++)
		{
			if(p[i] != '\0')
				continue;
			if((ret = strdup(&p[index])) == NULL)
				error(filename, strerror(errno), 1);
			free(p);
			return ret;
		}
		break;
	}
	free(p);
	return NULL;
}
#endif
