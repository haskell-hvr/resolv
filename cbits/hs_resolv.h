#if !defined(HS_RESOLV_H)
#define HS_RESOLV_H

#include "hs_resolv_config.h"

#include <sys/types.h>

#if defined(HAVE_NETINET_IN_H)
# include <netinet/in.h>
#endif

#if defined(HAVE_ARPA_NAMESER_H)
# include <arpa/nameser.h>
#endif

#include <resolv.h>

#include <assert.h>

/* This is usually provided via <arpa/nameser_compat.h> */
#if !defined(QUERY)
# define QUERY ns_o_query
#endif

#if !defined(USE_RES_NQUERY)
# error USE_RES_NQUERY not defined
#endif

#if USE_RES_NQUERY && (SIZEOF_STRUCT___RES_STATE <= 0)
# error broken invariant
#endif

#if USE_RES_NQUERY

inline static int
res_opt_set_use_dnssec(struct __res_state *s)
{
  assert(s);

  if (!(s->options & RES_INIT)) {
    int rc = res_ninit(s);
    if (rc) return rc;
  }

  s->options |= RES_USE_DNSSEC | RES_USE_EDNS0;

  return 0;
}

inline static int
hs_res_mkquery(struct __res_state *s, const char *dname, int class, int type, unsigned char *req, int reqlen0)
{
  assert(s);

  int reqlen = res_nmkquery(s, QUERY, dname, class, type, NULL, 0, NULL, req, reqlen0);

  assert(reqlen <= reqlen0);

  return reqlen;
}

inline static int
hs_res_send(struct __res_state *s, const unsigned char *msg, int msglen, unsigned char *answer, int anslen)
{
  assert(s);

  return res_nsend(s, msg, msglen, answer, anslen);
}

inline static int
hs_res_query(struct __res_state *s, const char *dname, int class, int type, unsigned char *answer, int anslen)
{
  assert(s);

  return res_nquery(s, dname, class, type, answer, anslen);
}

inline static void
hs_res_nclose(struct __res_state *s)
{
  assert(s);

  res_nclose(s);
}

#else

/* use non-reentrant API */

inline static int
res_opt_set_use_dnssec(void *s)
{
  assert(!s);

  if (!(_res.options & RES_INIT)) {
    int rc = res_init();
    if (rc) return rc;
  }

  _res.options |= RES_USE_DNSSEC | RES_USE_EDNS0;

  return 0;
}


inline static int
hs_res_mkquery(void *s, const char *dname, int class, int type, unsigned char *req, int reqlen0)
{
  assert(!s);

  int reqlen = res_mkquery(QUERY, dname, class, type, NULL, 0, NULL, req, reqlen0);

  assert(reqlen <= reqlen0);

  return reqlen;
}

inline static int
hs_res_send(void *s, const unsigned char *msg, int msglen, unsigned char *answer, int anslen)
{
  assert(!s);

  return res_send(msg, msglen, answer, anslen);
}

inline static int
hs_res_query(void *s, const char *dname, int class, int type, unsigned char *answer, int anslen)
{
  assert(!s);

  return res_query(dname, class, type, answer, anslen);
}

inline static void
hs_res_nclose(struct __res_state *s)
{
}

#endif

#endif /* HS_RESOLV_H */
