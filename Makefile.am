SUBDIRS = tl_generator tl tg
ACLOCAL_AMFLAGS = -I m4

if MAKE_TEST
bin_PROGRAMS = tgtest
tgtest_SOURCES = test.c
tgtest_LDADD = tg/libtg.la tl/libtl.la -lstdc++ -lz
endif
