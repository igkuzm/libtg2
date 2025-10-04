AUTOMAKE_OPTIONS = subdir-objects
lib_LTLIBRARIES = libtg.la

libtg_la_SOURCES = \
	crypto/aes.c \
	crypto/cmn.c \
	crypto/hsh.c \
	crypto/rnd.c \
	crypto/rsa.c \
	crypto/pbkdf2.c \
	transport/http.c \
	transport/socket.c \
	transport/header.c \
	mtproto/ack.c \
	mtproto/ds.c \
	mtproto/header.c \
	mtproto/encrypt.c \
	mtproto/mtproto.c \
	tg.c \
	strerr.c \
	send_query.c \
	answer.c \
	updates.c \
	auth_key1.c \
	auth_key_mtx.c \
	auth.c \
	connect.c \
	2fa.c \
	errors.c \
	dialogs.c \
	peer.c
					 
libtg_la_CFLAGS = -fPIC -I../essential
libtg_la_LIBADD = -lcrypto -lcurl -lz ../tl/*.o ../mtx/src/*.o
libtg_la_LDFLAGS = -Wl,-w

if MACOS
libtg_la_SOURCES += mtproto/clock_gettime.c
endif
