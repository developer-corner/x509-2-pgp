AM_CFLAGS = -fPIC -pthread -D__USE_GNU -pedantic -Wall -Wextra -Werror -fmessage-length=0 -I$(top_srcdir)/../inc @AM_CFLAGS@
AM_LDFLAGS = -pthread -L/usr/lib64 @AM_LDFLAGS@
LIBS += -lpthread -ldl

AM_CFLAGS += -Wno-error=address-of-packed-member -Wno-address-of-packed-member 
AM_CFLAGS += -Wno-error=deprecated-declarations  -Wno-deprecated-declarations 
AM_CFLAGS += -Wno-error=use-after-free -Wno-use-after-free 
AM_CFLAGS += -Wno-error=stringop-truncation -Wno-stringop-truncation
AM_CFLAGS += -Wno-error=stringop-overflow -Wno-stringop-overflow 
AM_CFLAGS += -Wno-error=format-truncation -Wno-format-truncation
AM_CFLAGS += -Wno-error=array-bounds -Wno-array-bounds 

man1_MANS = ../man/x509-2-pgp.1

# -D_WITH_TESTS still missing

if LINUX
AM_CFLAGS += -D_LINUX
endif

if MACOS
AM_CFLAGS += -D_MACOS
endif

if LITTLE_ENDIAN
AM_CFLAGS += -DDATA_ORDER_IS_LITTLE_ENDIAN
endif

if BIG_ENDIAN
AM_CFLAGS += -DDATA_ORDER_IS_BIG_ENDIAN
endif

bin_PROGRAMS = x509-2-pgp

x509_2_pgp_SOURCES = main.c \
	osslimpl.c \
	pgpimpl.c \
	pkcs11impl.c \
	tests.c \
	utils.c
	
# x509_2_pgp_LDADD = $(AM_LDFLAGS)
x509_2_pgp_LDFLAGS = $(AM_LDFLAGS)


