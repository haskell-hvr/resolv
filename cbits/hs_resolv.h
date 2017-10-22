#if !defined(HS_RESOLV_H)
#define HS_RESOLV_H

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <assert.h>

/* This is usually provided via <arpa/nameser_compat.h> */
#if !defined(QUERY)
# define QUERY ns_o_query
#endif

inline static int
res_opt_set_use_dnssec(void)
{
  if (!(_res.options & RES_INIT)) {
    int rc = res_init();
    if (rc) return rc;
  }

  _res.options |= RES_USE_DNSSEC | RES_USE_EDNS0;
    
  return 0;
}


inline static int
hs_res_mkquery(const char *dname, int class, int type, unsigned char *req, int reqlen0)
{
  int reqlen = res_mkquery(QUERY, dname, class, type, NULL, 0, NULL, req, reqlen0);

  assert(reqlen <= reqlen0);

  return reqlen;
}

#endif /* HS_RESOLV_H */
