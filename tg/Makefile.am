AUTOMAKE_OPTIONS = subdir-objects
lib_LTLIBRARIES = libtg.la

libtg_la_SOURCES = \
				   crypto/aes.c \
				   crypto/cmn.c \
				   crypto/fact.cpp \
				   crypto/hsh.c \
				   crypto/rnd.c \
				   crypto/rsa.c \
				   crypto/sha1.c \
				   crypto/sha256.c \
				   
libtg_la_CFLAGS = -fPIC
libtg_la_LIBADD = -lcrypto
libtg_la_LDFLAGS = -Wl,-w
