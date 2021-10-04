/* $Id$ */
/* Copyright (c) 2021 Pierre Pronchery <khorben@defora.org> */
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



#define DEBUG
#include <sys/mman.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <elf.h>
#include "loader.h"

#ifndef PROGNAME_LOADER
# define PROGNAME_LOADER	"ld.so"
#endif


/* Loader */
/* private */
/* prototypes */
static int _error(int code, char const * format, ...);


/* public */
/* functions */
/* loader */
static int _loader_do(int fd, char const * filename, int argc, char * argv[]);
static int _do_phdr(int fd, char const * filename, Elf_Ehdr * ehdr);
static size_t _do_phdr_align_bits(unsigned long align);
static int _do_shdr(int fd, char const * filename, Elf_Ehdr * ehdr);
static int _do_shdr_rela(int fd, char const * filename, Elf_Shdr * shdr,
		size_t entsize);

int loader(char const * filename, int argc, char * argv[])
{
	int ret;
	int fd;

	if((fd = open(filename, O_RDONLY)) < 0)
		return _error(2, "%s: %s", filename, strerror(errno));
	ret = _loader_do(fd, filename, argc, argv);
	close(fd);
	return ret;
}

static int _loader_do(int fd, char const * filename, int argc, char * argv[])
{
	int ret;
	Elf_Ehdr ehdr;

	if(read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr))
		return _error(2, "%s: %s", filename, strerror(errno));
	/* sanity checks */
	if(memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0)
		return _error(2, "%s: %s", filename, "Not an ELF file");
	if(ehdr.e_version != EV_CURRENT)
		return _error(2, "%s: %u: %s", filename, ehdr.e_version,
				"Unsupported ELF version");
	if(ehdr.e_ehsize != sizeof(ehdr))
		return _error(2, "%s: %s", filename,
				"Invalid or unsupported ELF file");
	if((ret = _do_phdr(fd, filename, &ehdr)) != 0
			|| (ret = _do_shdr(fd, filename, &ehdr)) != 0)
		return ret;
#ifdef DEBUG
	fprintf(stderr, "DEBUG: e_entry=%#lx\n", (unsigned long)ehdr.e_entry);
#endif
	return 0;
}

static int _do_phdr(int fd, char const * filename, Elf_Ehdr * ehdr)
{
	Elf_Phdr phdr;
	size_t i;
	char * addr;
	int prot;
	int flags;
	int f;
	off_t offset;

	if(ehdr->e_phentsize != sizeof(phdr))
		return _error(2, "%s: %s", filename,
				"Invalid or unsupported ELF file");
	if(lseek(fd, ehdr->e_phoff, SEEK_SET) != (off_t)ehdr->e_phoff)
		return _error(2, "%s: %s", filename, strerror(errno));
	for(i = 0; i < ehdr->e_phnum; i++)
	{
		if(read(fd, &phdr, sizeof(phdr)) != sizeof(phdr))
			return _error(2, "%s: %s", filename,
					"Invalid or unsupported ELF file");
#ifdef DEBUG
		fprintf(stderr, "DEBUG: %zu: p_type=%u p_flags=%#x"
				" p_offset=%#lx p_vaddr=%#lx, p_paddr=%#lx"
				" p_filesz=%lu p_memsz=%lu p_align=%lu\n", i,
				phdr.p_type, phdr.p_flags,
				(unsigned long)phdr.p_offset,
				(unsigned long)phdr.p_vaddr,
				(unsigned long)phdr.p_paddr,
				(unsigned long)phdr.p_filesz,
				(unsigned long)phdr.p_memsz,
				(unsigned long)phdr.p_align);
#endif
		if(phdr.p_type != PT_LOAD)
			continue;
		prot = PROT_NONE;
		prot |= (phdr.p_flags & PF_R) ? PROT_READ : 0;
		prot |= (phdr.p_flags & PF_W) ? PROT_WRITE : 0;
		prot |= (phdr.p_flags & PF_X) ? PROT_EXEC : 0;
		flags = MAP_ALIGNED(_do_phdr_align_bits(phdr.p_align));
		if(phdr.p_filesz == 0)
		{
#if 0
			addr = NULL;
#endif
			flags |= MAP_ANON;
			f = -1;
			offset = 0;
		}
		else
		{
#if 0
			addr = (void *)phdr.p_vaddr;
#endif
			flags |= MAP_FILE;
#if 0
			if(phdr.p_vaddr != 0)
				flags |= MAP_TRYFIXED;
#endif
			if(prot & PROT_WRITE)
				flags |= MAP_PRIVATE;
			f = fd;
			offset = phdr.p_offset;
		}
#ifdef DEBUG
		fprintf(stderr, "DEBUG: mmap(%p, %lu, %d, %d, %d, %lld)\n",
				NULL, (unsigned long)phdr.p_memsz, prot, flags,
				f, (long long)offset);
#endif
		if((addr = mmap(NULL, phdr.p_memsz, prot, flags, f, offset))
				== MAP_FAILED)
			return _error(2, "%s: %s", filename, strerror(errno));
		/* zero memory if relevant */
		if(phdr.p_filesz > 0
				&& prot & PROT_WRITE
				&& phdr.p_memsz > phdr.p_filesz)
			/* FIXME will crash if a page too far */
			memset(&addr[phdr.p_filesz], 0,
					phdr.p_memsz - phdr.p_filesz);
		/* FIXME keep this value */
		phdr.p_vaddr = (intptr_t)addr;
	}
	return 0;
}

static size_t _do_phdr_align_bits(unsigned long align)
{
	size_t i = 0;

	if(align == 0)
		return 0;
	for(i = 0; i < sizeof(align) * 8; i++)
		if(align & (1 << i))
		{
#ifdef DEBUG
			fprintf(stderr, "DEBUG: %s(0x%lx) => %zu\n", __func__,
					align, i);
#endif
			return i;
		}
	return 0;
}

static int _do_shdr(int fd, char const * filename, Elf_Ehdr * ehdr)
{
	int ret;
	Elf_Shdr shdr;
	size_t i;
	off_t offset;

	if(ehdr->e_shentsize != sizeof(shdr))
		return _error(2, "%s: %s", filename,
				"Invalid or unsupported ELF file");
	if(lseek(fd, ehdr->e_shoff, SEEK_SET) != (off_t)ehdr->e_shoff)
		return _error(2, "%s: %s", filename, strerror(errno));
	for(i = 0; i < ehdr->e_shnum; i++)
	{
		if(read(fd, &shdr, sizeof(shdr)) != sizeof(shdr))
			return _error(2, "%s: %s", filename,
					"Invalid or unsupported ELF file");
#ifdef DEBUG
		fprintf(stderr, "DEBUG: %zu: sh_name=%u sh_type=%u"
				" sh_flags=%#lx sh_addr=%#lx sh_offset=%#lx"
				" sh_size=%lu sh_link=%u sh_info=%u"
				" sh_addralign=%#lx sh_entsize=%lu\n", i,
				shdr.sh_name, shdr.sh_type,
				(unsigned long)shdr.sh_flags,
				(unsigned long)shdr.sh_addr,
				(unsigned long)shdr.sh_offset,
				(unsigned long)shdr.sh_size,
				shdr.sh_link, shdr.sh_info,
				(unsigned long)shdr.sh_addralign,
				(unsigned long)shdr.sh_entsize);
#endif
		if(shdr.sh_type == SHT_REL
				|| shdr.sh_type == SHT_RELA)
			ret = _do_shdr_rela(fd, filename, &shdr,
					shdr.sh_entsize);
		else
			continue;
		if(ret != 0)
			return ret;
		offset = ehdr->e_shoff + i * sizeof(shdr);
		if(lseek(fd, offset, SEEK_SET) != offset)
			return _error(2, "%s: %s", filename, strerror(errno));
	}
	return 0;
}

static int _do_shdr_rela(int fd, char const * filename, Elf_Shdr * shdr,
		size_t entsize)
{
	Elf_Rela rela;
	size_t i;

	rela.r_addend = 0;
	/* TODO test according to sh_type */
	if(entsize != sizeof(rela) && entsize != sizeof(Elf_Rel))
		return _error(2, "%s: %s", filename,
				"Invalid or unsupported ELF file");
	if(lseek(fd, shdr->sh_offset, SEEK_SET) != (off_t)shdr->sh_offset)
		return _error(2, "%s: %s", filename, strerror(errno));
	for(i = 0; i + entsize < shdr->sh_size; i += entsize)
	{
		if(read(fd, &rela, entsize) != (ssize_t)entsize)
			return _error(2, "%s: %s", filename,
					"Invalid or unsupported ELF file");
#ifdef DEBUG
		fprintf(stderr, "DEBUG: %zu: r_offset=%#lx r_type=%lu"
				" r_addend=%ld\n", i,
				(unsigned long)rela.r_offset,
				(unsigned long)ELF_R_TYPE(rela.r_info),
				(long)rela.r_addend);
#endif
		switch(ELF_R_TYPE(rela.r_info))
		{
#if defined(__amd64__)
			case R_X86_64_NONE:
				break;
			case R_X86_64_GLOB_DAT:
			case R_X86_64_JUMP_SLOT:
			case R_X86_64_RELATIVE:
				/* FIXME implement */
				break;
#endif
			default:
				return _error(2, "%s: %lu:"
						" Unsupported relocation\n",
						filename,
						ELF_R_TYPE(rela.r_info));
		}
	}
	return 0;
}


/* private */
/* functions */
/* error */
static int _error(int code, char const * format, ...)
{
	va_list ap;

	fputs(PROGNAME_LOADER ": ", stderr);
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	fputs("\n", stderr);
	return code;
}
