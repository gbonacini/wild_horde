#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([tssh], m4_esyscmd([ tr -d '\n' < version ]))

CXXFLAGS=""
LDFLAGS=""

AC_CONFIG_SRCDIR([src/wh_main.cpp])

AC_CONFIG_HEADER([include/config.h])

LT_INIT
AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE([disable])

AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_FILES([Makefile
		src/Makefile])

# Checks for programs.
AC_PROG_CXX
AC_PROG_INSTALL

# Checks for header files.
AC_HEADER_STDC

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

AC_CANONICAL_HOST
case $host_os in
  darwin* )
              BUILD_OSX=true
              OPTIMIZATION="-O2 "
              if test "x$CC" = xgcc; then
                    CXXFLAGS=" -std=c++11 -g -Weverything -DMAC_OSX\
                             -D_FORTIFY_SOURCE=2 ${OPTIMIZATION} -fstack-protector \
                             --param=ssp-buffer-size=4 -Wformat -Werror=format-security \
                             -Wno-deprecated-declarations -Wno-documentation -Wno-c++98-compat \
                             -Wno-padded -Wno-c++98-compat-pedantic -Wno-undefined-func-template "
		    LDFLAGS="$LDFLAGS  "
              else
                    CXXFLAGS=" -std=c++11 -O2 -g -Wall -DMAC_OSX"
		    LDFLAGS="$LDFLAGS  "
              fi

        ;;
  linux*)
              BUILD_LINUX=true
              OPTIMIZATION="-O2 "
              if test "x$CC" = xgcc; then
                    CXXFLAGS=" -std=c++11 -pthread -g -Wall -Wextra -DLINUX_OS\
                             -D_FORTIFY_SOURCE=2 ${OPTIMIZATION} -fstack-protector \
                             --param=ssp-buffer-size=4 -Wformat -Werror=format-security \
                             -Wno-misleading-indentation "
                    LDFLAGS="$LDFLAGS  -Wl,-z,relro "
              else
                    CXXFLAGS=" -std=c++11 -pthread -O2 -g -Wall -DLINUX_OS"
		    LDFLAGS="$LDFLAGS  "
              fi
        ;;
    *)
             AC_MSG_ERROR([Your platform is not currently supported])
        ;;
esac

# Libs list autmatically generated prom dependecy script
AC_CHECK_LIB([readline],[readline],[],[AC_MSG_FAILURE([could not find lib readline])])
AS_IF([test "x$BUILD_LINUX" = xtrue],
	[
          AC_CHECK_LIB([cap],[cap_get_proc],[],[AC_MSG_FAILURE([could not find lib capability])])
	])

AC_OUTPUT
