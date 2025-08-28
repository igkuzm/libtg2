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
				   transport/http.c \
				   mtproto/ack.c \
				   mtproto/ds.c \
				   mtproto/header.c \
				   mtproto/encrypt.c \
				   mtproto/transport.c \
				   mtproto/mtproto.c \
				   tg.c \
				   strerr.c \
				   send_query.c \
				   answer.c \
				   updates.c \
				   
libtg_la_CFLAGS = -fPIC
libtg_la_LIBADD = -lcrypto -lcurl
libtg_la_LDFLAGS = -Wl,-w

if MACOS
libtg_la_SOURCES += mtproto/clock_gettime.c
endif
