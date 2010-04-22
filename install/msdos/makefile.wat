# This is a makefile for watcom compatible make.
# This seems to work with Version 10.5 of Watcom C/C++
# It produces DOS4GW executables and character mode Watcom NT executables

# extension for object files
O = obj

# commands
CC = wcc386
LIB = wlib
ASM = as

# name of temporary library script
TEMPFILE = $(TEMP)\temp.mak

# Watcom Standard include directory, change to suit
STDINCDIR = \watcom\include

# The places to look for include files (in order).
INCL = -i. -I$(RSAEURODIR) -I$(STDINCDIR)

# Extra Defs

# To select CPU type set CPUT to any of the following
#
# 386 = i386+ processor, 80386 and above processor
# 68k = M680x0 series processor.
#
# Leave empty to disable assembler routines.
# Not Used in Watcom Version.
# CPUT = 386

# Set to 1 for ANSI Standard Routine to be Used, only availible
# if assembler routines not it use.
# Dosn't seem to work with Watcom ??
# ANSISTD = 1

# utility routines
del = del
COPY = copy

# name of main executable to build
PROG = all

# Standard DOS4GW Executable Flags. Change -3s to -4s for i486
CFLAGS = $(INCL) -3s -zq -ox -r -sg -zm -zdf -dPROTOTYPES=0

# Windows Win32 Executable Flags, works for 10.5
# CFLAGS = $(INCL) -4s -zq -ox -r -sg -dPROTOTYPES=0

ASMFL = $(INCL) -c -Wa,-L
MFLAGS = -I. -I$(RSAEURODIR)

# The location of the common source directory.
RSAEURODIR = ..\source\
RSAEUROLIB = rsaeuro.lib
RSAREFLIB = rsaref.lib

# The location of the demo source directory.
DEMODIR = ..\demo\

all : demo $(RSAREFLIB)

$(RSAREFLIB) : $(RSAEUROLIB)
	$(COPY) $(RSAEUROLIB) $(RSAREFLIB)

demo : redemo mdemo randemo

randemo.exe : randemo.$(O) $(RSAEUROLIB)
        wcl386 -k65535 randemo.$(O) $(RSAEUROLIB)
        del *.$(O)

mdemo.exe : mdemo.$(O) $(RSAEUROLIB)
        wcl386 -k65535 mdemo.$(O) $(RSAEUROLIB)
        del *.$(O)

redemo.exe : redemo.$(O) $(RSAEUROLIB)
        wcl386 -k65535 redemo.$(O) $(RSAEUROLIB)
        del *.$(O)

$(RSAEUROLIB) : desc.$(O) shsc.$(O) md2c.$(O) md4c.$(O) md5c.$(O) nn.$(O) prime.$(O) rsa.$(O) r_encode.$(O) r_dh.$(O) r_enhanc.$(O) r_keygen.$(O) r_random.$(O) r_stdlib.$(O)
        $(LIB) -n $@ @rsa.wat

randemo.$(O) : $(DEMODIR)randemo.c $(RSAEURODIR)global.h $(RSAEURODIR)rsaref.h
	$(CC) $(CFLAGS) $(DEMODIR)randemo.c

mdemo.$(O) : $(DEMODIR)mdemo.c $(RSAEURODIR)global.h $(RSAEURODIR)rsaref.h
	$(CC) $(CFLAGS) $(DEMODIR)mdemo.c

redemo.$(O) : $(DEMODIR)redemo.c $(RSAEURODIR)global.h $(RSAEURODIR)rsaref.h
	$(CC) $(CFLAGS) $(DEMODIR)redemo.c

desc.$(O) : $(RSAEURODIR)desc.c $(RSAEURODIR)rsaeuro.h $(RSAEURODIR)des.h
	$(CC) $(CFLAGS) $(RSAEURODIR)desc.c
        echo -+$@ > rsa.wat

shsc.$(O) : $(RSAEURODIR)shsc.c $(RSAEURODIR)rsaeuro.h $(RSAEURODIR)shs.h
	$(CC) $(CFLAGS) $(RSAEURODIR)shsc.c
        echo -+$@ >> rsa.wat

md2c.$(O) : $(RSAEURODIR)md2c.c $(RSAEURODIR)rsaeuro.h $(RSAEURODIR)md2.h
	$(CC) $(CFLAGS) $(RSAEURODIR)md2c.c
        echo -+$@ >> rsa.wat

md4c.$(O) : $(RSAEURODIR)md4c.c $(RSAEURODIR)rsaeuro.h $(RSAEURODIR)md4.h
	$(CC) $(CFLAGS) $(RSAEURODIR)md4c.c
        echo -+$@ >> rsa.wat

md5c.$(O) : $(RSAEURODIR)md5c.c $(RSAEURODIR)rsaeuro.h $(RSAEURODIR)md5.h
	$(CC) $(CFLAGS) $(RSAEURODIR)md5c.c
        echo -+$@ >> rsa.wat

nn.$(O) : $(RSAEURODIR)nn.c $(RSAEURODIR)rsaeuro.h $(RSAEURODIR)nn.h
	$(CC) $(CFLAGS) $(RSAEURODIR)nn.c
        echo -+$@ >> rsa.wat

prime.$(O) : $(RSAEURODIR)prime.c $(RSAEURODIR)rsaeuro.h $(RSAEURODIR)r_random.h $(RSAEURODIR)nn.h $(RSAEURODIR)prime.h
	$(CC) $(CFLAGS) $(RSAEURODIR)prime.c
        echo -+$@ >> rsa.wat

rsa.$(O) : $(RSAEURODIR)rsa.c $(RSAEURODIR)rsaeuro.h $(RSAEURODIR)r_random.h $(RSAEURODIR)rsa.h $(RSAEURODIR)nn.h
	$(CC) $(CFLAGS) $(RSAEURODIR)rsa.c
        echo -+$@ >> rsa.wat

r_dh.$(O) : $(RSAEURODIR)r_dh.c $(RSAEURODIR)rsaeuro.h $(RSAEURODIR)r_random.h $(RSAEURODIR)nn.h $(RSAEURODIR)prime.h
	$(CC) $(CFLAGS) $(RSAEURODIR)r_dh.c
        echo -+$@ >> rsa.wat

r_encode.$(O) : $(RSAEURODIR)r_encode.c $(RSAEURODIR)rsaeuro.h
	$(CC) $(CFLAGS) $(RSAEURODIR)r_encode.c
        echo -+$@ >> rsa.wat

r_enhanc.$(O) : $(RSAEURODIR)r_enhanc.c $(RSAEURODIR)rsaeuro.h $(RSAEURODIR)r_random.h $(RSAEURODIR)rsa.h
	$(CC) $(CFLAGS) $(RSAEURODIR)r_enhanc.c
        echo -+$@ >> rsa.wat

r_keygen.$(O) : $(RSAEURODIR)r_keygen.c $(RSAEURODIR)rsaeuro.h $(RSAEURODIR)r_random.h $(RSAEURODIR)nn.h $(RSAEURODIR)prime.h
	$(CC) $(CFLAGS) $(RSAEURODIR)r_keygen.c
        echo -+$@ >> rsa.wat

r_random.$(O) : $(RSAEURODIR)r_random.c $(RSAEURODIR)rsaeuro.h $(RSAEURODIR)r_random.h $(RSAEURODIR)md5.h
	$(CC) $(CFLAGS) $(RSAEURODIR)r_random.c
        echo -+$@ >> rsa.wat

r_stdlib.$(O) : $(RSAEURODIR)r_stdlib.c $(RSAEURODIR)rsaeuro.h
	$(CC) $(CFLAGS) $(RSAEURODIR)r_stdlib.c
        echo -+$@ >> rsa.wat

# Dependencies for header files

$(RSAREDIR)rsaeuro.h : $(RSAEURODIR)shs.h $(RSAEURODIR)nn.h $(RSAEURODIR)md2.h $(RSAEURODIR)md5.h $(RSAEURODIR)des.h $(RSAEURODIR)global.h

