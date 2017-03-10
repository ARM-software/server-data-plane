#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([qdofs], [0.0.1], [Geoffrey.Blake@arm.com])
AM_INIT_AUTOMAKE([1.9])
AC_CONFIG_SRCDIR([])
AC_CONFIG_HEADERS([config.h])

AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([tcmalloc], [malloc])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h stddef.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_CHECK_DECLS([sys_siglist])
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([memset socket])

AC_OUTPUT(Makefile src/Makefile)
