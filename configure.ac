#
# Essential ideas taken from https://www.bioinf.uni-freiburg.de/~mmann/HowTo/automake.html
#

AC_INIT([x509-2-pgp],[0.1],[ingo.kubbilun@gmail.com])

AC_CONFIG_SRCDIR([src/main.c])

# check for C preprocessor and C compiler
# (save current compiler flags and restore them afterwards because we do not want to get -O2 -g)
OLD_CFLAGS=$CFLAGS
AC_PROG_CPP
AC_PROG_CC
CFLAGS=$OLD_CFLAGS

# automake 1.9 is sufficient

AM_INIT_AUTOMAKE([1.9])

AC_LANG([C])
AC_CHECK_HEADERS([stdlib.h])
AC_CHECK_HEADERS([stdio.h])
AC_CHECK_HEADERS([string.h])
AC_CHECK_HEADERS([stdint.h])
AC_CHECK_HEADERS([stdbool.h])
AC_CHECK_HEADERS([errno.h])
AC_CHECK_HEADERS([time.h])
AC_CHECK_HEADERS([unistd.h])
AC_CHECK_HEADERS([sys/types.h])
AC_CHECK_HEADERS([sys/stat.h])
AC_CHECK_HEADERS([sys/time.h])
AC_CHECK_HEADERS([byteswap.h])
AC_CHECK_HEADERS([fcntl.h])
AC_CHECK_HEADERS([pthread.h])
AC_CHECK_HEADERS([dlfcn.h])

AC_TYPE_SIZE_T

# also incorporate user's flags choices

AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([src/Makefile])

# we are either on Linux or MacOS (Windows comes with its own build stuff)

AC_CANONICAL_HOST

build_linux=no
build_macos=no

case "${host_os}" in
	linux*)
		build_linux=yes
		;;
	darwin*)
		build_macos=yes
		;;
	*)
		AC_MSG_ERROR(["OS $host_os is NOT supported"])
		;;
esac
	
AM_CONDITIONAL([LINUX], [test "$build_linux" = "yes"])
AM_CONDITIONAL([MACOS], [test "$build_macos" = "yes"])

# check if this is a Little Endian or Big Endian host

little_endian=no
big_endian=no

AC_MSG_CHECKING([endianess])
RES=$(exec /bin/bash -c 'echo -n I | od -to2 | head -n1 | cut -f2 -d" " | cut -c6')
case "${RES}" in
 	"0")
  		big_endian=yes
  		AC_MSG_RESULT([This is a Big Endian machine])
  		;;
  	"1")
  		little_endian=yes
  		AC_MSG_RESULT([This is a Little Endian machine])
  		;;
  	*)
  		AC_MSG_ERROR(["Unable to determine if this is Little or Big Endian, respectively."])
  		;;
esac

AM_CONDITIONAL([LITTLE_ENDIAN], [test "$little_endian" = "yes"])
AM_CONDITIONAL([BIG_ENDIAN], [test "$big_endian" = "yes"])

# debug support

AC_MSG_CHECKING([whether to build with debug information])
AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug],
        [include debugging information and do not optimize (default=no)])],
    [debugging="$enableval"],
    [debugging=no])
AC_MSG_RESULT([$debugging])

if test x"$debugging" = x"yes"; then
    AC_DEFINE([_DEBUG],[],[Debug Mode])
    AM_CFLAGS="$AM_CFLAGS -O0 -g3 -ggdb"
else
    AC_DEFINE([NDEBUG],[],[No-debug Mode])
    AM_CFLAGS="$AM_CFLAGS -O3"
    AM_LDFLAGS="-s"
fi

# test(suite) support

AC_MSG_CHECKING([whether to build with test suite])
AC_ARG_ENABLE([tests],
    [AS_HELP_STRING([--enable-tests],
        [include full test suite (default=no)])],
    [testsuite="$enableval"],
    [testsuite=no])
AC_MSG_RESULT([$testsuite])

if test x"$testsuite" = x"yes"; then
    AC_DEFINE([_WITH_TESTS],[],[Test Suite])
fi

# option specifying an alternative location of OpenSSL

AC_ARG_WITH([ssl],
    [AS_HELP_STRING([--with-ssl=prefix],
        [use this for an alternative OpenSSL installation location])],
    [OSSLPATHSET=1],
    [OSSLPATHSET=0])
	
if test $OSSLPATHSET = 1; then
    AM_CFLAGS="$AM_CFLAGS -I$with_ssl/include"
    AM_LDFLAGS="$AM_LDFLAGS -L$with_ssl/lib"
fi

AC_ARG_WITH([ssl-ldflags],
    [AS_HELP_STRING([--with-ssl-ldflags=flags],
        [specify additional OpenSSL LDFLAGS, e.g. rpath])],
    [OSSL_LDFLAGS_SET=1],
    [OSSL_LDFLAGS_SET=0])

if test $OSSL_LDFLAGS_SET = 1; then
    AM_LDFLAGS="$AM_LDFLAGS $with_ssl_ldflags"
else
    LIBS="$LIBS -lcrypto"
fi

##########################################################################
# check for OpenSSL library 'libcrypto'
##########################################################################

OLD_CFLAGS=$CFLAGS;
OLD_LDFLAGS=$LDFLAGS;
CFLAGS="$AM_CFLAGS $CFLAGS"
LDFLAGS="$AM_LDFLAGS $LDFLAGS"
# OLD_LIBS=$LIBS
# LIBS="$LIBS -lcrypto"

AC_MSG_CHECKING([for the OpenSSL library headers])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <openssl/crypto.h>]])],
        [AC_MSG_RESULT([found])
        AC_MSG_CHECKING([whether the OpenSSL library 'libcrypto' can be linked])
        AC_LINK_IFELSE(
            [AC_LANG_PROGRAM([[#include <openssl/crypto.h>]],
                [[(void)SSLeay();]])],
            [AC_MSG_RESULT([yes])
                FOUND_OSSL=1;],
            [AC_MSG_RESULT([no])
                LIBS=$OLD_LIBS; dnl reset to old value since libcrypto was not found
                FOUND_OSSL=0;])],
        [AC_MSG_RESULT([not found])
        FOUND_OSSL=0;])

CFLAGS=$OLD_CFLAGS
LDFLAGS=$OLD_LDFLAGS
# LIBS=$OLD_LIBS

if test $FOUND_OSSL != 1; then
    AC_MSG_NOTICE([])
    AC_MSG_NOTICE([The OpenSSL library 'libcrypto' was not found. On Debian-style systems, try 'apt install libssl-dev'.])
    if test  $OSSLPATHSET = 1 ; then
        AC_MSG_NOTICE([ The install prefix '$with_ssl' was set for the OpenSSL installation location.])
        AC_MSG_NOTICE([ --> Please cross-check.])
    else
        AC_MSG_NOTICE([ No non-standard install prefix was set.])
        AC_MSG_NOTICE([ --> You might want to use '--with-ssl=PREFIX'?])
    fi
    AC_MSG_NOTICE([])
    AC_MSG_ERROR([ OpenSSL library is an essential dependency. STOP.])
fi

#
# Perform OpenSSL version check because we need a 3+ OpenSSL
#

AC_LANG_PUSH(C)

OLD_CFLAGS=$CFLAGS;
OLD_LDFLAGS=$LDFLAGS;
CFLAGS="$AM_CFLAGS $CFLAGS"
LDFLAGS="$AM_LDFLAGS $LDFLAGS"
# OLD_LIBS=$LIBS
# LIBS="$LIBS -lcrypto"

AC_RUN_IFELSE([dnl
        AC_LANG_PROGRAM(
                [#include <stdio.h>
                #include <openssl/crypto.h>],
                [fprintf(stderr, "%u\n",(SSLeay()>>28)&15)])],
                [openssl_version_major=$(./conftest$EXEEXT 2>&1)],
        [AC_MSG_ERROR(Failed to compile the OpenSSL version test program)])
        
CFLAGS=$OLD_CFLAGS
LDFLAGS=$OLD_LDFLAGS
# LIBS=$OLD_LIBS
        
AC_LANG_POP(C)

eval "OPENSSL_VERSION_MAJOR=$openssl_version_major"
AC_SUBST(OPENSSL_VERSION_MAJOR)

AC_MSG_CHECKING([if OpenSSL major version is three (3) or greater])

if test "$openssl_version_major" -ge "3"; then
        AC_MSG_RESULT([yes])
else
        AC_MSG_RESULT([no])
        AC_MSG_ERROR(["Need OpenSSL (major version) 3 or higher (is: $openssl_version_major). STOP."])
fi

##########################################################################

AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_LDFLAGS])
AC_SUBST([LIBS])

AC_OUTPUT

