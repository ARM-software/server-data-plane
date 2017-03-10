# Enable -fvisibility=hidden if using a gcc that supports it
OLD_CFLAGS="$CFLAGS"
AC_MSG_CHECKING([whether $CC supports -fvisibility=hidden])
VISIBILITY_CFLAGS="-fvisibility=hidden"
CFLAGS="$CFLAGS $VISIBILITY_CFLAGS"
AC_LINK_IFELSE([AC_LANG_PROGRAM()], AC_MSG_RESULT([yes]),
       [VISIBILITY_CFLAGS=""; AC_MSG_RESULT([no])]);

AC_SUBST(VISIBILITY_CFLAGS)
# Restore CFLAGS; VISIBILITY_CFLAGS are added to it where needed.
CFLAGS=$OLD_CFLAGS

AC_MSG_CHECKING(for GCC atomic builtins)
AC_LINK_IFELSE(
    [AC_LANG_SOURCE(
      [[int main() {
        int v = 1;
        __atomic_fetch_add(&v, 1, __ATOMIC_RELAXED);
        __atomic_fetch_sub(&v, 1, __ATOMIC_RELAXED);
        __atomic_store_n(&v, 1, __ATOMIC_RELAXED);
        __atomic_load_n(&v, __ATOMIC_RELAXED);
        return 0;
        }
    ]])],
    AC_MSG_RESULT(yes),
    AC_MSG_RESULT(no)
    echo "GCC-style __atomic builtins not supported by the compiler."
    echo "Use newer version. For gcc > 4.7.0"
    exit -1)

# linux-generic PCAP support is not relevant as the code doesn't use
# linux-generic pktio at all. And DPDK has its own PCAP support anyway
AM_CONDITIONAL([HAVE_PCAP], [false])
m4_include([platform/linux-dpdk/m4/odp_pthread.m4])
m4_include([platform/linux-dpdk/m4/odp_openssl.m4])
m4_include([platform/linux-dpdk/m4/odp_schedule.m4])

#
# Check that SDK_INSTALL_PATH provided to right dpdk version
#
## HACK until the upstream project fix their paths
## distributions use /usr/include/dpdk
if test ${DPDK_HEADER_HACK} = 1;
then
  AM_CPPFLAGS="$AM_CPPFLAGS -I/usr/include/dpdk"
fi

# Check if we should link against the static or dynamic dpdk library
AC_ARG_ENABLE([shared-dpdk],
	[  --enable-shared-dpdk    link against the shared dpdk library],
	[if test "x$enableval" = "xyes"; then
		shared_dpdk=true
	fi])
AM_CONDITIONAL([SHARED_DPDK], [test x$shared_dpdk = xtrue])

##########################################################################
# Save and set temporary compilation flags
##########################################################################
OLD_LDFLAGS=$LDFLAGS
OLD_CPPFLAGS=$CPPFLAGS
LDFLAGS="$AM_LDFLAGS $LDFLAGS"
CPPFLAGS="$AM_CPPFLAGS $CPPFLAGS"

if test "x$shared_dpdk" = "xtrue"; then
	enable_static=no
	AC_SEARCH_LIBS([rte_eal_init], [dpdk], [],
		[AC_MSG_ERROR([DPDK libraries required])], [-ldl])
fi
AC_CHECK_HEADERS([rte_config.h], [],
    [AC_MSG_FAILURE(["can't find DPDK headers"])])

##########################################################################
# Restore old saved variables
##########################################################################
LDFLAGS=$OLD_LDFLAGS
CPPFLAGS=$OLD_CPPFLAGS

AC_CONFIG_FILES([platform/linux-dpdk/Makefile
		 platform/linux-dpdk/include/odp/api/inlines.h])

