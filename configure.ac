dnl configure.ac
AC_PREREQ([2.60])
AC_INIT([resolv], [0.0], [hvr@gnu.org])
AC_CONFIG_SRCDIR([resolv.cabal])
AC_CONFIG_HEADER(cbits/hs_resolv_config.h)

AC_PROG_CC
AC_C_CONST

AC_CHECK_HEADERS([netinet/in.h arpa/nameser.h])
AC_CHECK_HEADER([resolv.h],,AC_MSG_ERROR([required <resolv.h> header not found]))

MY_AC_SEARCH_LIBS([res_query],[res_query(0,0,0,0,0)],[resolv bind],[EXTRA_LIBS="$EXTRA_LIBS $ac_lib"],[
AC_MSG_ERROR([could not figure out which C library contains res_query(3)])
])

AC_CHECK_DECLS([res_query, res_nquery, __res_state], [], [], [[
        #include <sys/types.h>
	#ifdef HAVE_NETINET_IN_H
	# include <netinet/in.h>
	#endif
	#ifdef HAVE_ARPA_NAMESER_H
	# include <arpa/nameser.h>
	#endif
	#include <resolv.h>
	]])

CPP_OPTIONS="-DUSE_RES_NQUERY=1 -DSIZEOF_RES_STATE=0"

if test "x$ac_cv_have_decl_res_nquery$ac_cv_have_decl___res_state" = xyesyes; then

AC_CHECK_SIZEOF([struct __res_state],[],[[
      #include <sys/types.h>
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_NAMESER_H
# include <arpa/nameser.h>
#endif
#include <resolv.h>
]])

if test "$ac_cv_sizeof_struct___res_state" -gt 0; then

MY_AC_SEARCH_LIBS([res_nquery],[res_nquery(0,0,0,0,0,0)],[resolv bind],[EXTRA_LIBS="$EXTRA_LIBS $ac_lib"],[
AC_MSG_ERROR([could not figure out which C library contains res_nquery(3)])
])

CPP_OPTIONS="-DUSE_RES_NQUERY=1 -DSIZEOF_RES_STATE=$ac_cv_sizeof_struct___res_state"
fi

fi

AC_SUBST([CPP_OPTIONS])
AC_SUBST([EXTRA_LIBS])
AC_CONFIG_FILES([resolv.buildinfo])

AC_OUTPUT

dnl EOF
