dnl configure.ac
AC_PREREQ([2.60])
AC_INIT([resolv], [0.0], [hvr@gnu.org])
AC_CONFIG_SRCDIR([resolv.cabal])

AC_PROG_CC
AC_C_CONST

AC_CHECK_HEADER([resolv.h],,AC_MSG_ERROR([required <resolv.h> header not found]))

AC_SEARCH_LIBS([res_query],[resolv bind],[EXTRA_LIBS="$EXTRA_LIBS $ac_lib"],[
AC_SEARCH_LIBS([__res_query],[resolv bind],[EXTRA_LIBS="$EXTRA_LIBS $ac_lib"],[
AC_MSG_ERROR([could not figure out which library contains res_query(3)])
])])

AC_SUBST([EXTRA_LIBS])
AC_CONFIG_FILES([resolv.buildinfo])

AC_OUTPUT

dnl EOF
