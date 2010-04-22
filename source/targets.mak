# Source Modules Source files

desc.$(O) : $(RSAEURODIR)desc.c $(RSAEURODIR)rsaeuro.h $(RSAEURODIR)des.h
	$(CC) $(CFLAGS) $(RSAEURODIR)desc.c

shsc.$(O) : $(RSAEURODIR)shsc.c $(RSAEURODIR)shs.h $(RSAEURODIR)rsaeuro.h
	$(CC) $(CFLAGS) $(RSAEURODIR)shsc.c

md2c.$(O) : $(RSAEURODIR)md2c.c $(RSAEURODIR)rsaeuro.h $(RSAEURODIR)md2.h
	$(CC) $(CFLAGS) $(RSAEURODIR)md2c.c

md4c.$(O) : $(RSAEURODIR)md4c.c $(RSAEURODIR)rsaeuro.h $(RSAEURODIR)md4.h
	$(CC) $(CFLAGS) $(RSAEURODIR)md4c.c

md5c.$(O) : $(RSAEURODIR)md5c.c $(RSAEURODIR)rsaeuro.h $(RSAEURODIR)md5.h
	$(CC) $(CFLAGS) $(RSAEURODIR)md5c.c

nn.$(O) : $(RSAEURODIR)nn.c $(RSAEURODIR)rsaeuro.h $(RSAEURODIR)nn.h
	$(CC) $(CFLAGS) $(RSAEURODIR)nn.c

prime.$(O) : $(RSAEURODIR)prime.c $(RSAEURODIR)rsaeuro.h $(RSAEURODIR)r_random.h\
	$(RSAEURODIR)nn.h $(RSAEURODIR)prime.h
	$(CC) $(CFLAGS) $(RSAEURODIR)prime.c

rsa.$(O) : $(RSAEURODIR)rsa.c $(RSAEURODIR)rsaeuro.h $(RSAEURODIR)r_random.h\
	$(RSAEURODIR)rsa.h $(RSAEURODIR)nn.h
	$(CC) $(CFLAGS) $(RSAEURODIR)rsa.c

r_dh.$(O) : $(RSAEURODIR)r_dh.c $(RSAEURODIR)rsaeuro.h\
	$(RSAEURODIR)r_random.h $(RSAEURODIR)nn.h $(RSAEURODIR)prime.h
	$(CC) $(CFLAGS) $(RSAEURODIR)r_dh.c

r_encode.$(O) : $(RSAEURODIR)r_encode.c $(RSAEURODIR)rsaeuro.h
	$(CC) $(CFLAGS) $(RSAEURODIR)r_encode.c

r_enhanc.$(O) : $(RSAEURODIR)r_enhanc.c $(RSAEURODIR)rsaeuro.h\
	$(RSAEURODIR)r_random.h $(RSAEURODIR)rsa.h
	$(CC) $(CFLAGS) $(RSAEURODIR)r_enhanc.c

r_keygen.$(O) : $(RSAEURODIR)r_keygen.c $(RSAEURODIR)rsaeuro.h\
	$(RSAEURODIR)r_random.h $(RSAEURODIR)nn.h $(RSAEURODIR)prime.h
	$(CC) $(CFLAGS) $(RSAEURODIR)r_keygen.c

r_random.$(O) : $(RSAEURODIR)r_random.c $(RSAEURODIR)rsaeuro.h\
	$(RSAEURODIR)r_random.h $(RSAEURODIR)md5.h
	$(CC) $(CFLAGS) $(RSAEURODIR)r_random.c

r_stdlib.$(O) : $(RSAEURODIR)r_stdlib.c $(RSAEURODIR)rsaeuro.h
	$(CC) $(CFLAGS) $(RSAEURODIR)r_stdlib.c

# Dependencies for header files

$(RSAREDIR)rsaeuro.h : $(RSAEURODIR)shs.h $(RSAEURODIR)nn.h\
	$(RSAEURODIR)md2.h $(RSAEURODIR)md5.h $(RSAEURODIR)des.h\
	$(RSAEURODIR)global.h
