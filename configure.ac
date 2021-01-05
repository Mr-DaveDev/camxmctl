AC_INIT(camxmctl,0.0.01)
AM_INIT_AUTOMAKE([subdir-objects foreign])
AM_MAINTAINER_MODE([enable])
AC_PROG_CC
AC_PROG_CXX
AC_GNU_SOURCE
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_SRCDIR([src/camxmctl.c])
AC_CANONICAL_HOST
AC_CONFIG_MACRO_DIR([m4])

##############################################################################
###  Check pkg-config  - Required.  Needed to get lib paths/info
##############################################################################
AC_CHECK_PROG([PKGCONFIG],[pkg-config],[yes],[no])
AS_IF([test "${PKGCONFIG}" = "no" ],[
    AC_MSG_ERROR([Required package 'pkg-config' not found.])
  ]
)

##############################################################################
###  Check pthread
##############################################################################
AC_CHECK_HEADERS(pthread.h,,AC_MSG_ERROR([pthread is required.]))
TEMP_CFLAGS="-D_THREAD_SAFE"
LIBS="$LIBS -pthread "

##############################################################################
###  Check libmicrohttpd
##############################################################################
AC_CHECK_HEADERS(microhttpd.h,[MHTTP="yes"],[MHTTP="no"])
AC_MSG_CHECKING(libmicrohttpd libraries)
AC_MSG_RESULT($MHTTP)
AS_IF([test "${MHTTP}" = "yes" ], [
    TEMP_CPPFLAGS="$TEMP_CPPFLAGS "`pkg-config --cflags libmicrohttpd`
    TEMP_LIBS="$TEMP_LIBS "`pkg-config --libs libmicrohttpd`
  ],[
    AC_MSG_ERROR([Required package libmicrohttpd-dev not found.])
  ]
)

##############################################################################
###  Check libjson-c
##############################################################################
AC_CHECK_HEADERS(json-c/json.h,[JSONC="yes"],[JSONC="no"])
AC_MSG_CHECKING(json libraries)
AC_MSG_RESULT($JSONC)
AS_IF([test "${JSONC}" = "yes" ], [
    TEMP_CPPFLAGS="$TEMP_CPPFLAGS "`pkg-config --cflags json-c`
    TEMP_LIBS="$TEMP_LIBS "`pkg-config --libs json-c`
  ],[
    AC_MSG_ERROR([Required package json-c-dev not found.])
  ]
)

##############################################################################
###  Check libjson-c
##############################################################################
AC_CHECK_HEADERS(openssl/md5.h,[OPNSSL="yes"],[OPNSSL="no"])
AC_MSG_CHECKING(openssl libraries)
AC_MSG_RESULT($OPNSSL)
AS_IF([test "${OPNSSL}" = "yes" ], [
    TEMP_CPPFLAGS="$TEMP_CPPFLAGS "`pkg-config --cflags openssl`
    TEMP_LIBS="$TEMP_LIBS "`pkg-config --libs openssl`
  ],[
    AC_MSG_ERROR([Required package openssl-dev not found.])
  ]
)

##############################################################################
###  Set the compiler flags
##############################################################################
TEMP_CFLAGS="$TEMP_CFLAGS -W -Werror -Wall -Wextra -Wformat -Wshadow -Wpointer-arith -Wwrite-strings -Wstrict-prototypes -Wmissing-prototypes -Wnested-externs -Winline -Wredundant-decls -Wno-long-long -ggdb -g3"


AC_SUBST(AM_CFLAGS, "$TEMP_CFLAGS")
LIBS="$LIBS $TEMP_LIBS"
AC_SUBST(AM_LDFLAGS, "$TEMP_LDFLAGS")

AC_CONFIG_FILES([Makefile src/Makefile])

AC_OUTPUT

##############################################################################
###  Report results to user
##############################################################################
echo ""
echo "   **************************"
echo "      Configure status       "
echo "      ${PACKAGE_NAME} ${PACKAGE_VERSION}"
echo "   **************************"
echo
echo "CFLAGS: $TEMP_CFLAGS $CFLAGS"
echo
echo "LIBS: $LIBS"
echo
echo "LDFLAGS: $TEMP_LDFLAGS $LDFLAGS"
echo
echo  "Install prefix:       $prefix"
echo
