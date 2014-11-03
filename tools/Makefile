TARGETS	= $(OBJDIR)ldd
OBJDIR	=
PREFIX	= /usr/local
DESTDIR	=
BINDIR	= $(PREFIX)/bin
SBINDIR	= $(PREFIX)/sbin
CC	= cc
CPPFLAGSF=
CPPFLAGS=
CFLAGSF	= -W
CFLAGS	= -Wall -g -O2 -pedantic
RM	= rm -f
LN	= ln -f
MKDIR	= mkdir -m 0755 -p
INSTALL	= install


all: $(TARGETS)

ldd_OBJS = $(OBJDIR)ldd.o
ldd_CFLAGS = $(CPPFLAGSF) $(CPPFLAGS) $(CFLAGSF) $(CFLAGS)
ldd_LDFLAGS = $(LDFLAGSF) $(LDFLAGS)

$(OBJDIR)ldd: $(ldd_OBJS)
	$(CC) -o $(OBJDIR)ldd $(ldd_OBJS) $(ldd_LDFLAGS)

$(OBJDIR)ldd.o: ldd.c elf.c
	$(CC) $(ldd_CFLAGS) -o $(OBJDIR)ldd.o -c ldd.c

clean:
	$(RM) -- $(ldd_OBJS)

distclean: clean
	$(RM) -- $(TARGETS)

install: $(TARGETS)
	$(MKDIR) $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(OBJDIR)ldd $(DESTDIR)$(BINDIR)/ldd

uninstall:
	$(RM) -- $(DESTDIR)$(BINDIR)/ldd

.PHONY: all clean distclean install uninstall
