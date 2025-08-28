AUTOMAKE_OPTIONS = subdir-objects
lib_LTLIBRARIES = libtl.la

libtl_la_SOURCES = \
					 libtl.c \
				   deserialize_table.c \
				   methods.c \
					 free.c \
				   ../essential/gunzip.c \
				   ../essential/buf.c \
				   ../essential/serialize.c \
				   ../essential/deserialize.c
				   
libtl_la_CFLAGS = -fPIC
libtl_la_LIBADD = -lz
libtl_la_LDFLAGS = -Wl,-w
