/*
 * types.c
 * - RR-type-specific code, and the machinery to call it
 */
/*
 *  This file is part of adns, which is
 *    Copyright (C) 1997-2000,2003,2006  Ian Jackson
 *    Copyright (C) 1999-2000,2003,2006  Tony Finch
 *    Copyright (C) 1991 Massachusetts Institute of Technology
 *  (See the file INSTALL for full details.)
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software Foundation,
 *  Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. 
 */

#include <stddef.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "internal.h"

#define R_NOMEM       return adns_s_nomemory
#define CSP_ADDSTR(s) do {			\
    if (!adns__vbuf_appendstr(vb,(s))) R_NOMEM;	\
  } while (0)

/*
 * order of sections:
 *
 * _string                    (pap)
 * _textdata, _qstring        (csp)
 * _str                       (mf,cs)
 * _intstr                    (mf,csp,cs)
 * _manyistr                  (mf,cs)
 * _txt                       (pa)
 * _inaddr                    (pa,cs,di, +search_sortlist, dip_genaddr)
 * _in6addr                   (pa,cs,di)
 * _addr                      (pap,pa,di,csp,cs,qs,  +search_sortlist_sa,
 *				dip_sockaddr, rrtypes)
 * _domain                    (pap)
 * _host_raw                  (pa)
 * _hostaddr                  (pap,pa,dip,di,mfp,mf,csp,cs +pap_findaddrs)
 * _mx_raw                    (pa,di)
 * _mx                        (pa,di)
 * _inthostaddr               (mf,cs)
 * _ptr                       (pa)
 * _strpair                   (mf,cs)
 * _intstrpair                (mf,cs)
 * _hinfo                     (pa)
 * _mailbox                   (pap +pap_mailbox822)
 * _rp                        (pa)
 * _soa                       (pa,mf,cs)
 * _srv*                      (qdpl,(pap),pa,mf,di,(csp),cs,postsort)
 * _byteblock                 (mf)
 * _opaque                    (pa,cs)
 * _flat                      (mf)
 *
 * within each section:
 *    qdpl_*
 *    pap_*
 *    pa_*
 *    dip_*
 *    di_*
 *    mfp_*
 *    mf_*
 *    csp_*
 *    cs_*
 *    postsort_*
 */

/*
 * _qstring               (pap,csp)
 */

static adns_status pap_qstring(const parseinfo *pai, int *cbyte_io, int max,
			      int *len_r, char **str_r) {
  /* Neither len_r nor str_r may be null.
   * End of datagram (overrun) is indicated by returning adns_s_invaliddata;
   */
  const byte *dgram= pai->dgram;
  int l, cbyte;
  char *str;

  cbyte= *cbyte_io;

  if (cbyte >= max) return adns_s_invaliddata;
  GET_B(cbyte,l);
  if (cbyte+l > max) return adns_s_invaliddata;
  
  str= adns__alloc_interim(pai->qu, l+1);
  if (!str) R_NOMEM;
  
  str[l]= 0;
  memcpy(str,dgram+cbyte,l);

  *len_r= l;
  *str_r= str;
  *cbyte_io= cbyte+l;
  
  return adns_s_ok;
}

static adns_status csp_qstring(vbuf *vb, const char *dp, int len) {
  unsigned char ch;
  char buf[10];
  int cn;

  CSP_ADDSTR("\"");
  for (cn=0; cn<len; cn++) {
    ch= *dp++;
    if (ch == '\\') {
      CSP_ADDSTR("\\\\");
    } else if (ch == '"') {
      CSP_ADDSTR("\\\"");
    } else if (ch >= 32 && ch <= 126) {
      if (!adns__vbuf_append(vb,&ch,1)) R_NOMEM;
    } else {
      sprintf(buf,"\\x%02x",ch);
      CSP_ADDSTR(buf);
    }
  }
  CSP_ADDSTR("\"");
  
  return adns_s_ok;
}

/*
 * _str  (mf)
 */

static void mf_str(adns_query qu, void *datap) {
  char **rrp= datap;

  adns__makefinal_str(qu,rrp);
}

/*
 * _intstr  (mf)
 */

static void mf_intstr(adns_query qu, void *datap) {
  adns_rr_intstr *rrp= datap;

  adns__makefinal_str(qu,&rrp->str);
}

/*
 * _manyistr   (mf)
 */

static void mf_manyistr(adns_query qu, void *datap) {
  adns_rr_intstr **rrp= datap;
  adns_rr_intstr *te, *table;
  void *tablev;
  int tc;

  for (tc=0, te= *rrp; te->i >= 0; te++, tc++);
  tablev= *rrp;
  adns__makefinal_block(qu,&tablev,sizeof(*te)*(tc+1));
  *rrp= table= tablev;
  for (te= *rrp; te->i >= 0; te++)
    adns__makefinal_str(qu,&te->str);
}

/*
 * _txt   (pa,cs)
 */

static adns_status pa_txt(const parseinfo *pai, int cbyte,
			  int max, void *datap) {
  adns_rr_intstr **rrp= datap, *table, *te;
  const byte *dgram= pai->dgram;
  int ti, tc, l, startbyte;
  adns_status st;

  startbyte= cbyte;
  if (cbyte >= max) return adns_s_invaliddata;
  tc= 0;
  while (cbyte < max) {
    GET_B(cbyte,l);
    cbyte+= l;
    tc++;
  }
  if (cbyte != max || !tc) return adns_s_invaliddata;

  table= adns__alloc_interim(pai->qu,sizeof(*table)*(tc+1));
  if (!table) R_NOMEM;

  for (cbyte=startbyte, ti=0, te=table; ti<tc; ti++, te++) {
    st= pap_qstring(pai, &cbyte, max, &te->i, &te->str);
    if (st) return st;
  }
  assert(cbyte == max);

  te->i= -1;
  te->str= 0;
  
  *rrp= table;
  return adns_s_ok;
}

static adns_status cs_txt(vbuf *vb, const void *datap) {
  const adns_rr_intstr *const *rrp= datap;
  const adns_rr_intstr *current;
  adns_status st;
  int spc;

  for (current= *rrp, spc=0;  current->i >= 0;  current++, spc=1) {
    if (spc) CSP_ADDSTR(" ");
    st= csp_qstring(vb,current->str,current->i); if (st) return st;
  }
  return adns_s_ok;
}

/*
 * _hinfo   (cs)
 */

static adns_status cs_hinfo(vbuf *vb, const void *datap) {
  const adns_rr_intstrpair *rrp= datap;
  adns_status st;

  st= csp_qstring(vb,rrp->array[0].str,rrp->array[0].i);  if (st) return st;
  CSP_ADDSTR(" ");
  st= csp_qstring(vb,rrp->array[1].str,rrp->array[1].i);  if (st) return st;
  return adns_s_ok;
}

/*
 * _inaddr   (pa,di,cs +search_sortlist, dip_genaddr)
 */

static adns_status pa_inaddr(const parseinfo *pai, int cbyte,
			     int max, void *datap) {
  struct in_addr *storeto= datap;
  
  if (max-cbyte != 4) return adns_s_invaliddata;
  memcpy(storeto, pai->dgram + cbyte, 4);
  return adns_s_ok;
}

static int search_sortlist(adns_state ads, int af, const void *ad) {
  const struct sortlist *slp;
  const struct in6_addr *a6;
  union gen_addr a;
  int i;
  int v6mappedp = 0;

  if (af == AF_INET6) {
    a6 = ad;
    if (IN6_IS_ADDR_V4MAPPED(a6)) {
      a.v4.s_addr = htonl(((unsigned long)a6->s6_addr[12] << 24) |
			  ((unsigned long)a6->s6_addr[13] << 16) |
			  ((unsigned long)a6->s6_addr[14] <<  8) |
			  ((unsigned long)a6->s6_addr[15] <<  0));
      v6mappedp = 1;
    }
  }

  for (i=0, slp=ads->sortlist;
       i<ads->nsortlist &&
       !(af == slp->ai->af &&
	 slp->ai->matchp(ad, &slp->base, &slp->mask)) &&
       !(v6mappedp && slp->ai->af == AF_INET &&
	 slp->ai->matchp(&a, &slp->base, &slp->mask));
       i++, slp++);
  return i;
}

static int dip_genaddr(adns_state ads, int af, const void *a, const void *b) {
  int ai, bi;
  
  if (!ads->nsortlist) return 0;

  ai= search_sortlist(ads,af,a);
  bi= search_sortlist(ads,af,b);
  return bi<ai;
}

static int di_inaddr(adns_state ads,
		     const void *datap_a, const void *datap_b) {
  return dip_genaddr(ads,AF_INET,datap_a,datap_b);
}

static adns_status cs_inaddr(vbuf *vb, const void *datap) {
  const struct in_addr *rrp= datap, rr= *rrp;
  const char *ia;

  ia= inet_ntoa(rr); assert(ia);
  CSP_ADDSTR(ia);
  return adns_s_ok;
}

/*
 * _in6addr   (pa,di,cs)
 */

static adns_status pa_in6addr(const parseinfo *pai, int cbyte,
			     int max, void *datap) {
  struct in6_addr *storeto= datap;

  if (max-cbyte != 16) return adns_s_invaliddata;
  memcpy(storeto->s6_addr, pai->dgram + cbyte, 16);
  return adns_s_ok;
}

static int di_in6addr(adns_state ads,
		     const void *datap_a, const void *datap_b) {
  return dip_genaddr(ads,AF_INET6,datap_a,datap_b);
}

static adns_status cs_in6addr(vbuf *vb, const void *datap) {
  char buf[INET6_ADDRSTRLEN];
  const char *ia;

  ia= inet_ntop(AF_INET6, datap, buf, sizeof(buf)); assert(ia);
  CSP_ADDSTR(ia);
  return adns_s_ok;
}

/*
 * _addr   (pap,pa,di,csp,cs,qs, +search_sortlist_sa, dip_sockaddr,
 *		addr_rrtypes, addr_rrsz)
 */

static adns_status pap_addr(const parseinfo *pai, int rrty, size_t rrsz,
			    int *cbyte_io, int max, adns_rr_addr *storeto)
{
  const byte *dgram= pai->dgram;
  int af, addrlen, salen;
  struct in6_addr v6map;
  const void *oaddr = dgram + *cbyte_io;
  int avail = max - *cbyte_io;
  int step = -1;
  void *addrp = 0;

  switch (rrty) {
    case adns_r_a:
      if (pai->qu->flags & adns_qf_domapv4) {
	if (avail < 4) return adns_s_invaliddata;
	memset(v6map.s6_addr +  0, 0x00, 10);
	memset(v6map.s6_addr + 10, 0xff,  2);
	memcpy(v6map.s6_addr + 12, oaddr, 4);
	oaddr = v6map.s6_addr; avail = sizeof(v6map.s6_addr);
	if (step < 0) step = 4;
	goto aaaa;
      }
      af = AF_INET; addrlen = 4;
      addrp = &storeto->addr.inet.sin_addr;
      salen = sizeof(storeto->addr.inet);
      break;
    case adns_r_aaaa:
    aaaa:
      af = AF_INET6; addrlen = 16;
      addrp = storeto->addr.inet6.sin6_addr.s6_addr;
      salen = sizeof(storeto->addr.inet6);
      break;
  }
  assert(addrp);

  assert(offsetof(adns_rr_addr, addr) + salen <= rrsz);
  if (addrlen < avail) return adns_s_invaliddata;
  if (step < 0) step = addrlen;
  *cbyte_io += step;
  memset(&storeto->addr, 0, salen);
  storeto->len = salen;
  storeto->addr.sa.sa_family = af;
  memcpy(addrp, oaddr, addrlen);

  return adns_s_ok;
}

static adns_status pa_addr(const parseinfo *pai, int cbyte,
			   int max, void *datap) {
  int err = pap_addr(pai, pai->qu->answer->type & adns_rrt_typemask,
		     pai->qu->answer->rrsz, &cbyte, max, datap);
  if (err) return err;
  if (cbyte != max) return adns_s_invaliddata;
  return adns_s_ok;
}

static int search_sortlist_sa(adns_state ads, const struct sockaddr *sa)
{
  const afinfo *ai = 0;

  switch (sa->sa_family) {
    case AF_INET: ai = &adns__inet_afinfo; break;
    case AF_INET6: ai = &adns__inet6_afinfo; break;
  }
  assert(ai);

  return search_sortlist(ads, sa->sa_family, ai->sockaddr_to_inaddr(sa));
}

static int dip_sockaddr(adns_state ads,
			const struct sockaddr *sa,
			const struct sockaddr *sb)
{
  if (!ads->sortlist) return 0;
  return search_sortlist_sa(ads, sa) > search_sortlist_sa(ads, sb);
}

static int di_addr(adns_state ads, const void *datap_a, const void *datap_b) {
  const adns_rr_addr *ap= datap_a, *bp= datap_b;

  return dip_sockaddr(ads, &ap->addr.sa, &bp->addr.sa);
}

static int div_addr(void *context, const void *datap_a, const void *datap_b) {
  const adns_state ads= context;

  return di_addr(ads, datap_a, datap_b);
}		     

static adns_status csp_addr(vbuf *vb, const adns_rr_addr *rrp) {
  char buf[128];
  int err;

  switch (rrp->addr.inet.sin_family) {
  case AF_INET:
    CSP_ADDSTR("INET ");
    goto ntop;
  case AF_INET6:
    CSP_ADDSTR("INET6 ");
    goto ntop;
  ntop:
    err= getnameinfo(&rrp->addr.sa, rrp->len, buf, sizeof(buf), 0, 0,
		     NI_NUMERICHOST); assert(!err);
    CSP_ADDSTR(buf);
    break;
  default:
    sprintf(buf,"AF=%u",rrp->addr.sa.sa_family);
    CSP_ADDSTR(buf);
    break;
  }
  return adns_s_ok;
}

static adns_status cs_addr(vbuf *vb, const void *datap) {
  const adns_rr_addr *rrp= datap;

  return csp_addr(vb,rrp);
}

#define ADDR_MAXRRTYPES 2

static void addr_rrtypes(adns_state ads, adns_rrtype type,
			 adns_queryflags qf,
			 adns_rrtype *rrty, size_t *nrrty)
{
  size_t n = 0;
  adns_rrtype qtf = type & adns__qtf_deref;

  if (!(type & adns__qtf_bigaddr) || !(type & adns__qtf_manyaf))
    qf = (qf & adns__qf_afmask) | adns_qf_ipv4_only;

  if (qf & adns_qf_ipv4_only) rrty[n++] = adns_r_a | qtf;
  if (qf & adns_qf_ipv6_only) rrty[n++] = adns_r_aaaa | qtf;

  *nrrty = n;
}

static size_t addr_rrsz(adns_query qu)
{
  return qu->answer->type & adns__qtf_bigaddr ?
    sizeof(adns_rr_addr) : sizeof(adns_rr_addr_v4only);
}

static adns_status append_addrs(adns_query qu, size_t rrsz,
				adns_rr_addr **dp, int *dlen,
				const adns_rr_addr *sp, int slen)
{
  size_t drrsz = *dlen*rrsz, srrsz = slen*rrsz;
  byte *p = adns__alloc_interim(qu, drrsz + srrsz);
  if (!p) R_NOMEM;
  if (*dlen) {
    memcpy(p, *dp, drrsz);
    adns__free_interim(qu, *dp);
  }
  memcpy(p + drrsz, sp, srrsz);
  *dlen += slen;
  *dp = (adns_rr_addr *)p;
  return adns_s_ok;
}

static void icb_addr(adns_query parent, adns_query child)
{
  adns_state ads = parent->ads;
  adns_answer *pans = parent->answer, *cans = child->answer;
  struct timeval tvbuf;
  adns_status err;
  const struct timeval *now = 0;

  /* Must handle CNAMEs correctly.  This gets very hairy if the answers we
   * get are inconsistent.
   */

  if ((parent->flags & adns_qf_search) &&
      cans->status == adns_s_nxdomain) {
    if (parent->expires > child->expires) parent->expires = child->expires;
    adns__cancel_children(parent);
    adns__free_interim(parent, pans->rrs.bytes);
    pans->rrs.bytes = 0; pans->nrrs = 0;
    adns__must_gettimeofday(ads, &now, &tvbuf);
    if (now) adns__search_next(ads, parent, *now);
    return;
  }

  if (cans->status && cans->status != adns_s_nodata) {
    adns__query_fail(parent, cans->status);
    return;
  }

  assert(pans->rrsz == cans->rrsz);
  err = append_addrs(parent, pans->rrsz,
		     &pans->rrs.addr, &pans->nrrs,
		     cans->rrs.addr, cans->nrrs);
  if (err) { adns__query_fail(parent, err); return; }

  if (parent->expires > child->expires) parent->expires = child->expires;

  if (parent->children.head) LIST_LINK_TAIL(ads->childw, parent);
  else if (!pans->nrrs) adns__query_fail(parent, adns_s_nodata);
  else adns__query_done(parent);
}

static void addr_subqueries(adns_query qu, struct timeval now,
			    const adns_rrtype *rrty, size_t nrrty)
{
  int i, err, id;
  adns_query cqu;
  adns_queryflags qf =
    (qu->flags | adns__qf_senddirect) &
    ~(adns_qf_search);
  qcontext ctx;

  if (!(qu->answer->type & adns__qtf_bigaddr))
    qu->answer->rrsz = sizeof(adns_rr_addr_v4only);

  /* This always makes child queries, even if there's only the one.  This
   * seems wasteful, but there's only one case where it'd be safe -- namely
   * IPv4-only -- and that's not the case I want to optimize.
   */
  memset(&ctx, 0, sizeof(ctx));
  ctx.callback = icb_addr;
  for (i = 0; i < nrrty; i++) {
    err = adns__mkquery_frdgram(qu->ads, &qu->vb, &id, qu->query_dgram,
				qu->query_dglen, DNS_HDRSIZE, rrty[i], qf);
    if (err) goto x_error;
    err = adns__internal_submit(qu->ads, &cqu, qu->typei, rrty[i],
				&qu->vb, id, qf, now, &ctx);
    if (err) goto x_error;
    cqu->answer->rrsz = qu->answer->rrsz;
    cqu->parent = qu;
    LIST_LINK_TAIL_PART(qu->children, cqu,siblings.);
  }
  qu->state = query_childw;
  LIST_LINK_TAIL(qu->ads->childw, qu);
  return;

x_error:
  adns__query_fail(qu, err);
}

static adns_status addr_submit(adns_query parent, adns_query *query_r,
			       vbuf *qumsg_vb, int id,
			       const adns_rrtype *rrty, size_t nrrty,
			       adns_queryflags flags, struct timeval now,
			       const qcontext *ctx)
{
  /* This is effectively a substitute for adns__internal_submit, intended for
   * the case where the caller (possibly) only wants a subset of the
   * available record types.  The memory management and callback rules are
   * the same as for adns__internal_submit.
   *
   * Some differences: the query is linked onto the parent's children list
   * before exit (though the parent's state is not changed, and it is not
   * linked into the childw list queue).
   */

  adns_state ads = parent->ads;
  adns_status err;
  adns_rrtype type =
    (adns_r_addr & adns_rrt_reprmask) |
    (parent->answer->type & ~adns_rrt_reprmask);

  err = adns__internal_submit(ads, query_r, adns__findtype(adns_r_addr),
			      type, qumsg_vb, id, flags | adns__qf_nosend,
			      now, ctx);
  if (err) return err;

  (*query_r)->parent = parent;
  LIST_LINK_TAIL_PART(parent->children, *query_r, siblings.);
  addr_subqueries(*query_r, now, rrty, nrrty);
  return adns_s_ok;
}

static void qs_addr(adns_query qu, struct timeval now)
{
  adns_rrtype rrty[ADDR_MAXRRTYPES];
  size_t nrrty;

  addr_rrtypes(qu->ads, qu->answer->type, qu->flags, rrty, &nrrty);
  addr_subqueries(qu, now, rrty, nrrty);
}

/*
 * _domain      (pap,csp,cs)
 * _dom_raw     (pa)
 */

static adns_status pap_domain(const parseinfo *pai, int *cbyte_io, int max,
			      char **domain_r, parsedomain_flags flags) {
  adns_status st;
  char *dm;
  
  st= adns__parse_domain(pai->qu->ads, pai->serv, pai->qu, &pai->qu->vb, flags,
			 pai->dgram,pai->dglen, cbyte_io, max);
  if (st) return st;
  if (!pai->qu->vb.used) return adns_s_invaliddata;

  dm= adns__alloc_interim(pai->qu, pai->qu->vb.used+1);
  if (!dm) R_NOMEM;

  dm[pai->qu->vb.used]= 0;
  memcpy(dm,pai->qu->vb.buf,pai->qu->vb.used);
  
  *domain_r= dm;
  return adns_s_ok;
}

static adns_status csp_domain(vbuf *vb, const char *domain) {
  CSP_ADDSTR(domain);
  if (!*domain) CSP_ADDSTR(".");
  return adns_s_ok;
}

static adns_status cs_domain(vbuf *vb, const void *datap) {
  const char *const *domainp= datap;
  return csp_domain(vb,*domainp);
}

static adns_status pa_dom_raw(const parseinfo *pai, int cbyte,
			      int max, void *datap) {
  char **rrp= datap;
  adns_status st;

  st= pap_domain(pai, &cbyte, max, rrp, pdf_quoteok);
  if (st) return st;
  
  if (cbyte != max) return adns_s_invaliddata;
  return adns_s_ok;
}

/*
 * _host_raw   (pa)
 */

static adns_status pa_host_raw(const parseinfo *pai, int cbyte,
			       int max, void *datap) {
  char **rrp= datap;
  adns_status st;

  st= pap_domain(pai, &cbyte, max, rrp,
		 pai->qu->flags & adns_qf_quoteok_anshost ? pdf_quoteok : 0);
  if (st) return st;
  
  if (cbyte != max) return adns_s_invaliddata;
  return adns_s_ok;
}

/*
 * _hostaddr   (pap,pa,dip,di,mfp,mf,csp,cs +icb_hostaddr, pap_findaddrs)
 */

static adns_status pap_findaddrs(const parseinfo *pai, adns_rr_hostaddr *ha,
				 adns_rrtype *rrty, size_t *nrrty_io,
				 size_t addrsz, int *cbyte_io, int count,
				 int dmstart) {
  int rri, naddrs, j;
  int type, class, rdlen, rdend, rdstart, ownermatched;
  size_t nrrty = *nrrty_io;
  unsigned long ttl;
  adns_status st;
  
  for (rri=0, naddrs=0; rri<count; rri++) {
    st= adns__findrr_anychk(pai->qu, pai->serv, pai->dgram,
			    pai->dglen, cbyte_io,
			    &type, &class, &ttl, &rdlen, &rdstart,
			    pai->dgram, pai->dglen, dmstart, &ownermatched);
    if (st) return st;
    if (!ownermatched || class != DNS_CLASS_IN) continue;
    for (j = 0; j < nrrty && type != (rrty[j] & adns_rrt_typemask); j++);
    if (j >= nrrty) continue;
    if (j < *nrrty_io) {
      (*nrrty_io)--;
      adns_rrtype t = rrty[j];
      rrty[j] = rrty[*nrrty_io];
      rrty[*nrrty_io] = t;
    }
    if (!adns__vbuf_ensure(&pai->qu->vb, (naddrs+1)*addrsz)) R_NOMEM;
    adns__update_expires(pai->qu,ttl,pai->now);
    rdend = rdstart + rdlen;
    st= pap_addr(pai, type, addrsz, &rdstart, rdend,
		 (adns_rr_addr *)(pai->qu->vb.buf + naddrs*addrsz));
    if (st) return st;
    if (rdstart != rdend) return adns_s_invaliddata;
    naddrs++;
  }
  if (naddrs > 0) {
    st = append_addrs(pai->qu, addrsz, &ha->addrs, &ha->naddrs,
		      (const adns_rr_addr *)pai->qu->vb.buf, naddrs);
    if (st) return st;
    ha->astatus= adns_s_ok;

    if (!*nrrty_io) {
      adns__isort(ha->addrs, naddrs, addrsz, pai->qu->vb.buf,
		  div_addr, pai->ads);
    }
  }
  return adns_s_ok;
}

static void icb_hostaddr(adns_query parent, adns_query child) {
  adns_answer *cans= child->answer;
  adns_rr_hostaddr *rrp= child->ctx.info.hostaddr;
  adns_state ads= parent->ads;
  adns_status st;
  size_t addrsz = addr_rrsz(parent);

  st= cans->status == adns_s_nodata ? adns_s_ok : cans->status;
  rrp->astatus= st;

  if (st) goto done;
  assert(addrsz == cans->rrsz);
  if (parent->expires > child->expires) parent->expires = child->expires;
  st = append_addrs(parent, addrsz,
		    &rrp->addrs, &rrp->naddrs,
		    cans->rrs.addr, cans->nrrs);
  if (st) goto done;
  if (!rrp->naddrs) { st = adns_s_nodata; goto done; }

  if (!adns__vbuf_ensure(&parent->vb, addrsz))
    { st = adns_s_nomemory; goto done; }
  adns__isort(rrp->addrs, rrp->naddrs, addrsz, parent->vb.buf,
	      div_addr, ads);

done:
  if (st) {
    adns__free_interim(parent, rrp->addrs);
    rrp->naddrs= (st>0 && st<=adns_s_max_tempfail) ? -1 : cans->nrrs;
  }

  if (parent->children.head) {
    LIST_LINK_TAIL(ads->childw,parent);
  } else {
    adns__query_done(parent);
  }
}

static adns_status pap_hostaddr(const parseinfo *pai, int *cbyte_io,
				int max, adns_rr_hostaddr *rrp) {
  adns_status st;
  int dmstart, cbyte;
  qcontext ctx;
  int id;
  adns_query nqu;
  adns_queryflags nflags;
  adns_rrtype rrty[ADDR_MAXRRTYPES];
  size_t nrrty;
  size_t addrsz = addr_rrsz(pai->qu);

  dmstart= cbyte= *cbyte_io;
  st= pap_domain(pai, &cbyte, max, &rrp->host,
		 pai->qu->flags & adns_qf_quoteok_anshost ? pdf_quoteok : 0);
  if (st) return st;
  *cbyte_io= cbyte;

  rrp->astatus= adns_s_ok;
  rrp->naddrs= 0;
  rrp->addrs= 0;

  cbyte= pai->nsstart;

  addr_rrtypes(pai->ads, pai->qu->answer->type,
	       pai->qu->flags, rrty, &nrrty);

  st= pap_findaddrs(pai, rrp, rrty, &nrrty, addrsz,
		    &cbyte, pai->nscount, dmstart);
  if (st) return st;
  if (!nrrty) return adns_s_ok;

  st= pap_findaddrs(pai, rrp, rrty, &nrrty, addrsz,
		    &cbyte, pai->arcount, dmstart);
  if (st) return st;
  if (!nrrty) return adns_s_ok;

  st= adns__mkquery_frdgram(pai->ads, &pai->qu->vb, &id,
			    pai->dgram, pai->dglen, dmstart,
			    adns_r_addr, adns_qf_quoteok_query);
  if (st) return st;

  ctx.ext= 0;
  ctx.callback= icb_hostaddr;
  ctx.info.hostaddr= rrp;
  
  nflags= adns_qf_quoteok_query | (pai->qu->flags & adns__qf_afmask);
  if (!(pai->qu->flags & adns_qf_cname_loose)) nflags |= adns_qf_cname_forbid;
  
  st= addr_submit(pai->qu, &nqu, &pai->qu->vb, id, rrty, nrrty,
		  nflags, pai->now, &ctx);
  if (st) return st;

  return adns_s_ok;
}

static adns_status pa_hostaddr(const parseinfo *pai, int cbyte,
			       int max, void *datap) {
  adns_rr_hostaddr *rrp= datap;
  adns_status st;

  st= pap_hostaddr(pai, &cbyte, max, rrp);
  if (st) return st;
  if (cbyte != max) return adns_s_invaliddata;

  return adns_s_ok;
}

static int dip_hostaddr(adns_state ads,
			const adns_rr_hostaddr *ap, const adns_rr_hostaddr *bp) {
  if (ap->astatus != bp->astatus) return ap->astatus;
  if (ap->astatus) return 0;

  return dip_sockaddr(ads, &ap->addrs[0].addr.sa, &bp->addrs[0].addr.sa);
}

static int di_hostaddr(adns_state ads,
		       const void *datap_a, const void *datap_b) {
  const adns_rr_hostaddr *ap= datap_a, *bp= datap_b;

  return dip_hostaddr(ads, ap,bp);
}

static void mfp_hostaddr(adns_query qu, adns_rr_hostaddr *rrp) {
  void *tablev;
  size_t sz = qu->answer->type & adns__qtf_bigaddr ?
    sizeof(adns_rr_addr) : sizeof(adns_rr_addr_v4only);
  adns__makefinal_str(qu,&rrp->host);
  tablev= rrp->addrs;
  adns__makefinal_block(qu, &tablev, rrp->naddrs*sz);
  rrp->addrs= tablev;
}

static void mf_hostaddr(adns_query qu, void *datap) {
  adns_rr_hostaddr *rrp= datap;

  mfp_hostaddr(qu,rrp);
}

static adns_status csp_hostaddr(vbuf *vb, const adns_rr_hostaddr *rrp) {
  const char *errstr;
  adns_status st;
  char buf[20];
  int i;

  st= csp_domain(vb,rrp->host);  if (st) return st;

  CSP_ADDSTR(" ");
  CSP_ADDSTR(adns_errtypeabbrev(rrp->astatus));

  sprintf(buf," %d ",rrp->astatus);
  CSP_ADDSTR(buf);

  CSP_ADDSTR(adns_errabbrev(rrp->astatus));
  CSP_ADDSTR(" ");

  errstr= adns_strerror(rrp->astatus);
  st= csp_qstring(vb,errstr,strlen(errstr));  if (st) return st;
  
  if (rrp->naddrs >= 0) {
    CSP_ADDSTR(" (");
    for (i=0; i<rrp->naddrs; i++) {
      CSP_ADDSTR(" ");
      st= csp_addr(vb,&rrp->addrs[i]);
    }
    CSP_ADDSTR(" )");
  } else {
    CSP_ADDSTR(" ?");
  }
  return adns_s_ok;
}

static adns_status cs_hostaddr(vbuf *vb, const void *datap) {
  const adns_rr_hostaddr *rrp= datap;

  return csp_hostaddr(vb,rrp);
}

/*
 * _mx_raw   (pa,di)
 */

static adns_status pa_mx_raw(const parseinfo *pai, int cbyte,
			     int max, void *datap) {
  const byte *dgram= pai->dgram;
  adns_rr_intstr *rrp= datap;
  adns_status st;
  int pref;

  if (cbyte+2 > max) return adns_s_invaliddata;
  GET_W(cbyte,pref);
  rrp->i= pref;
  st= pap_domain(pai, &cbyte, max, &rrp->str,
		 pai->qu->flags & adns_qf_quoteok_anshost ? pdf_quoteok : 0);
  if (st) return st;
  
  if (cbyte != max) return adns_s_invaliddata;
  return adns_s_ok;
}

static int di_mx_raw(adns_state ads, const void *datap_a, const void *datap_b) {
  const adns_rr_intstr *ap= datap_a, *bp= datap_b;

  if (ap->i < bp->i) return 0;
  if (ap->i > bp->i) return 1;
  return 0;
}

/*
 * _mx   (pa,di)
 */

static adns_status pa_mx(const parseinfo *pai, int cbyte,
			 int max, void *datap) {
  const byte *dgram= pai->dgram;
  adns_rr_inthostaddr *rrp= datap;
  adns_status st;
  int pref;

  if (cbyte+2 > max) return adns_s_invaliddata;
  GET_W(cbyte,pref);
  rrp->i= pref;
  st= pap_hostaddr(pai, &cbyte, max, &rrp->ha);
  if (st) return st;
  
  if (cbyte != max) return adns_s_invaliddata;
  return adns_s_ok;
}

static int di_mx(adns_state ads, const void *datap_a, const void *datap_b) {
  const adns_rr_inthostaddr *ap= datap_a, *bp= datap_b;

  if (ap->i < bp->i) return 0;
  if (ap->i > bp->i) return 1;
  return dip_hostaddr(ads, &ap->ha, &bp->ha);
}

/*
 * _inthostaddr  (mf,cs)
 */

static void mf_inthostaddr(adns_query qu, void *datap) {
  adns_rr_inthostaddr *rrp= datap;

  mfp_hostaddr(qu,&rrp->ha);
}

static adns_status cs_inthostaddr(vbuf *vb, const void *datap) {
  const adns_rr_inthostaddr *rrp= datap;
  char buf[10];

  sprintf(buf,"%u ",rrp->i);
  CSP_ADDSTR(buf);

  return csp_hostaddr(vb,&rrp->ha);
}

/*
 * _inthost  (cs)
 */

static adns_status cs_inthost(vbuf *vb, const void *datap) {
  const adns_rr_intstr *rrp= datap;
  char buf[10];

  sprintf(buf,"%u ",rrp->i);
  CSP_ADDSTR(buf);
  return csp_domain(vb,rrp->str);
}

/*
 * _ptr   (pa, +icb_ptr)
 */

static void icb_ptr(adns_query parent, adns_query child) {
  adns_answer *cans= child->answer;
  const union gen_addr *queried;
  const unsigned char *found;
  adns_state ads= parent->ads;
  int i;

  if (cans->status == adns_s_nxdomain || cans->status == adns_s_nodata) {
    adns__query_fail(parent,adns_s_inconsistent);
    return;
  } else if (cans->status) {
    adns__query_fail(parent,cans->status);
    return;
  }

  queried= &parent->ctx.info.ptr_parent_addr.addr;
  for (i=0, found=cans->rrs.bytes; i<cans->nrrs; i++, found += cans->rrsz) {
    if (!memcmp(queried,found,cans->rrsz)) {
      if (!parent->children.head) {
	adns__query_done(parent);
	return;
      } else {
	LIST_LINK_TAIL(ads->childw,parent);
	return;
      }
    }
  }

  adns__query_fail(parent,adns_s_inconsistent);
}

static adns_status pa_ptr(const parseinfo *pai, int dmstart,
			  int max, void *datap) {
  static const struct {
    const afinfo *ai;
    const char *const tail[3];
  } expectdomain[] = {
    { &adns__inet_afinfo, { DNS_INADDR_ARPA, 0 } },
    { &adns__inet6_afinfo, { DNS_IP6_ARPA, 0 } }
  };
  enum { n_ed = sizeof(expectdomain)/sizeof(expectdomain[0]) };
  
  char **rrp= datap;
  adns_status st;
  struct afinfo_addr *ap;
  findlabel_state fls;
  byte ipv[n_ed][32];
  int cbyte, i, j, foundj = -1, lablen, labstart, id, f, ac;
  const char *tp;
  adns_query nqu;
  qcontext ctx;

  cbyte= dmstart;
  st= pap_domain(pai, &cbyte, max, rrp,
		 pai->qu->flags & adns_qf_quoteok_anshost ? pdf_quoteok : 0);
  if (st) return st;
  if (cbyte != max) return adns_s_invaliddata;

  ap= &pai->qu->ctx.info.ptr_parent_addr;
  if (!ap->ai) {
    adns__findlabel_start(&fls, pai->ads, -1, pai->qu,
			  pai->qu->query_dgram, pai->qu->query_dglen,
			  pai->qu->query_dglen, DNS_HDRSIZE, 0);

    f = (1 << n_ed) - 1; /* superposition of address types */
    for (i = 0;; i++) {
      st= adns__findlabel_next(&fls,&lablen,&labstart); assert(!st);
      if (lablen <= 0) break;
      for (j = 0; j < n_ed; j++) {
	if (!(f & (1 << j))) continue;
	if (i < expectdomain[j].ai->nrevcomp) {
	  ac = expectdomain[j].ai->rev_parsecomp(
	    pai->qu->query_dgram + labstart, lablen);
	  if (ac < 0) goto mismatch;
	  assert(i < sizeof(ipv[j]));
	  ipv[j][i] = ac;
	} else {
	  tp = expectdomain[j].tail[i - expectdomain[j].ai->nrevcomp];
	  if (!tp ||
	      strncmp(pai->qu->query_dgram + labstart, tp, lablen) != 0 ||
	      tp[lablen] != 0)
	    goto mismatch;
	}
	continue;

      mismatch:
	f &= ~(1 << j);
	if (!f) return adns_s_querydomainwrong;
      }
    }

    if (lablen < 0) return adns_s_querydomainwrong;
    for (j = 0; j < n_ed; j++) {
      if (!(f & (1 << j))) continue;
      if (i >= expectdomain[j].ai->nrevcomp &&
	  !expectdomain[j].tail[i - expectdomain[j].ai->nrevcomp])
	{ foundj = j; continue; }
      f &= ~(1 << j);
      if (!f) return adns_s_querydomainwrong;
    }
    assert(foundj >= 0 && f == (1 << foundj)); /* collapsed to a single type */

    ap->ai = expectdomain[foundj].ai;
    ap->ai->rev_mkaddr(&ap->addr, ipv[foundj]);
  }

  st= adns__mkquery_frdgram(pai->ads, &pai->qu->vb, &id,
			    pai->dgram, pai->dglen, dmstart,
			    ap->ai->rrtype, adns_qf_quoteok_query);
  if (st) return st;

  ctx.ext= 0;
  ctx.callback= icb_ptr;
  memset(&ctx.info,0,sizeof(ctx.info));
  st= adns__internal_submit(pai->ads, &nqu, adns__findtype(ap->ai->rrtype),
			    ap->ai->rrtype, &pai->qu->vb, id,
			    adns_qf_quoteok_query, pai->now, &ctx);
  if (st) return st;

  nqu->parent= pai->qu;
  LIST_LINK_TAIL_PART(pai->qu->children,nqu,siblings.);
  return adns_s_ok;
}

/*
 * _strpair   (mf)
 */

static void mf_strpair(adns_query qu, void *datap) {
  adns_rr_strpair *rrp= datap;

  adns__makefinal_str(qu,&rrp->array[0]);
  adns__makefinal_str(qu,&rrp->array[1]);
}

/*
 * _intstrpair   (mf)
 */

static void mf_intstrpair(adns_query qu, void *datap) {
  adns_rr_intstrpair *rrp= datap;

  adns__makefinal_str(qu,&rrp->array[0].str);
  adns__makefinal_str(qu,&rrp->array[1].str);
}

/*
 * _hinfo   (pa)
 */

static adns_status pa_hinfo(const parseinfo *pai, int cbyte,
			    int max, void *datap) {
  adns_rr_intstrpair *rrp= datap;
  adns_status st;
  int i;

  for (i=0; i<2; i++) {
    st= pap_qstring(pai, &cbyte, max, &rrp->array[i].i, &rrp->array[i].str);
    if (st) return st;
  }

  if (cbyte != max) return adns_s_invaliddata;
  
  return adns_s_ok;
}

/*
 * _mailbox   (pap,cs)
 */

static adns_status pap_mailbox822(const parseinfo *pai,
				  int *cbyte_io, int max, char **mb_r) {
  int lablen, labstart, i, needquote, c, r, neednorm;
  const unsigned char *p;
  char *str;
  findlabel_state fls;
  adns_status st;
  vbuf *vb;

  vb= &pai->qu->vb;
  vb->used= 0;
  adns__findlabel_start(&fls, pai->ads,
			-1, pai->qu,
			pai->dgram, pai->dglen, max,
			*cbyte_io, cbyte_io);
  st= adns__findlabel_next(&fls,&lablen,&labstart);
  if (!lablen) {
    adns__vbuf_appendstr(vb,".");
    goto x_ok;
  }

  neednorm= 1;
  for (i=0, needquote=0, p= pai->dgram+labstart; i<lablen; i++) {
    c= *p++;
    if ((c&~128) < 32 || (c&~128) == 127) return adns_s_invaliddata;
    if (c == '.' && !neednorm) neednorm= 1;
    else if (c==' ' || c>=127 || ctype_822special(c)) needquote++;
    else neednorm= 0;
  }

  if (needquote || neednorm) {
    r= adns__vbuf_ensure(vb, lablen+needquote+4); if (!r) R_NOMEM;
    adns__vbuf_appendq(vb,"\"",1);
    for (i=0, needquote=0, p= pai->dgram+labstart; i<lablen; i++, p++) {
      c= *p;
      if (c == '"' || c=='\\') adns__vbuf_appendq(vb,"\\",1);
      adns__vbuf_appendq(vb,p,1);
    }
    adns__vbuf_appendq(vb,"\"",1);
  } else {
    r= adns__vbuf_append(vb, pai->dgram+labstart, lablen); if (!r) R_NOMEM;
  }

  r= adns__vbuf_appendstr(vb,"@"); if (!r) R_NOMEM;

  st= adns__parse_domain_more(&fls,pai->ads, pai->qu,vb,0, pai->dgram);
  if (st) return st;

 x_ok:
  str= adns__alloc_interim(pai->qu, vb->used+1); if (!str) R_NOMEM;
  memcpy(str,vb->buf,vb->used);
  str[vb->used]= 0;
  *mb_r= str;
  return adns_s_ok;
}

static adns_status pap_mailbox(const parseinfo *pai, int *cbyte_io, int max,
			       char **mb_r) {
  if (pai->qu->typei->typekey & adns__qtf_mail822) {
    return pap_mailbox822(pai, cbyte_io, max, mb_r);
  } else {
    return pap_domain(pai, cbyte_io, max, mb_r, pdf_quoteok);
  }
}

static adns_status csp_mailbox(vbuf *vb, const char *mailbox) {
  return csp_domain(vb,mailbox);
}

/*
 * _rp   (pa,cs)
 */

static adns_status pa_rp(const parseinfo *pai, int cbyte,
			 int max, void *datap) {
  adns_rr_strpair *rrp= datap;
  adns_status st;

  st= pap_mailbox(pai, &cbyte, max, &rrp->array[0]);
  if (st) return st;

  st= pap_domain(pai, &cbyte, max, &rrp->array[1], pdf_quoteok);
  if (st) return st;

  if (cbyte != max) return adns_s_invaliddata;
  return adns_s_ok;
}

static adns_status cs_rp(vbuf *vb, const void *datap) {
  const adns_rr_strpair *rrp= datap;
  adns_status st;

  st= csp_mailbox(vb,rrp->array[0]);  if (st) return st;
  CSP_ADDSTR(" ");
  st= csp_domain(vb,rrp->array[1]);  if (st) return st;

  return adns_s_ok;
}  

/*
 * _soa   (pa,mf,cs)
 */

static adns_status pa_soa(const parseinfo *pai, int cbyte,
			  int max, void *datap) {
  adns_rr_soa *rrp= datap;
  const byte *dgram= pai->dgram;
  adns_status st;
  int msw, lsw, i;

  st= pap_domain(pai, &cbyte, max, &rrp->mname,
		 pai->qu->flags & adns_qf_quoteok_anshost ? pdf_quoteok : 0);
  if (st) return st;

  st= pap_mailbox(pai, &cbyte, max, &rrp->rname);
  if (st) return st;

  if (cbyte+20 != max) return adns_s_invaliddata;
  
  for (i=0; i<5; i++) {
    GET_W(cbyte,msw);
    GET_W(cbyte,lsw);
    (&rrp->serial)[i]= (msw<<16) | lsw;
  }

  return adns_s_ok;
}

static void mf_soa(adns_query qu, void *datap) {
  adns_rr_soa *rrp= datap;

  adns__makefinal_str(qu,&rrp->mname);
  adns__makefinal_str(qu,&rrp->rname);
}

static adns_status cs_soa(vbuf *vb, const void *datap) {
  const adns_rr_soa *rrp= datap;
  char buf[20];
  int i;
  adns_status st;
  
  st= csp_domain(vb,rrp->mname);  if (st) return st;
  CSP_ADDSTR(" ");
  st= csp_mailbox(vb,rrp->rname);  if (st) return st;

  for (i=0; i<5; i++) {
    sprintf(buf," %lu",(&rrp->serial)[i]);
    CSP_ADDSTR(buf);
  }

  return adns_s_ok;
}

/*
 * _srv*  (pa*2,di,cs*2,qdpl,postsort)
 */

static adns_status qdpl_srv(adns_state ads,
			    const char **p_io, const char *pe, int labelnum,
			    char label_r[DNS_MAXDOMAIN], int *ll_io,
			    adns_queryflags flags,
			    const typeinfo *typei) {
  int useflags;
  const char *p_orig;
  adns_status st;

  if (labelnum < 2 && !(flags & adns_qf_quoteok_query)) {
    useflags= adns_qf_quoteok_query;
    p_orig= *p_io;
  } else {
    useflags= flags;
    p_orig= 0;
  }
  st= adns__qdpl_normal(ads, p_io,pe, labelnum,label_r, ll_io, useflags,typei);
  if (st) return st;

  if (p_orig) {
    int ll= *ll_io;
    if (!ll || label_r[0]!='_')
      return adns_s_querydomaininvalid;
    if (memchr(p_orig+1, '\\', pe - (p_orig+1)))
      return adns_s_querydomaininvalid;
  }
  return adns_s_ok;
}

static adns_status pap_srv_begin(const parseinfo *pai, int *cbyte_io, int max,
				 adns_rr_srvha *rrp
				   /* might be adns_rr_srvraw* */) {
  const byte *dgram= pai->dgram;
  int ti, cbyte;

  cbyte= *cbyte_io;
  if ((*cbyte_io += 6) > max) return adns_s_invaliddata;
  
  rrp->priority= GET_W(cbyte, ti);
  rrp->weight=   GET_W(cbyte, ti);
  rrp->port=     GET_W(cbyte, ti);
  return adns_s_ok;
}

static adns_status pa_srvraw(const parseinfo *pai, int cbyte,
			     int max, void *datap) {
  adns_rr_srvraw *rrp= datap;
  adns_status st;

  st= pap_srv_begin(pai,&cbyte,max,datap);
  if (st) return st;
  
  st= pap_domain(pai, &cbyte, max, &rrp->host,
		 pai->qu->flags & adns_qf_quoteok_anshost ? pdf_quoteok : 0);
  if (st) return st;
  
  if (cbyte != max) return adns_s_invaliddata;
  return adns_s_ok;
}

static adns_status pa_srvha(const parseinfo *pai, int cbyte,
			    int max, void *datap) {
  adns_rr_srvha *rrp= datap;
  adns_status st;

  st= pap_srv_begin(pai,&cbyte,max,datap);       if (st) return st;
  st= pap_hostaddr(pai, &cbyte, max, &rrp->ha);  if (st) return st;
  if (cbyte != max) return adns_s_invaliddata;
  return adns_s_ok;
}

static void mf_srvraw(adns_query qu, void *datap) {
  adns_rr_srvraw *rrp= datap;
  adns__makefinal_str(qu, &rrp->host);
}

static void mf_srvha(adns_query qu, void *datap) {
  adns_rr_srvha *rrp= datap;
  mfp_hostaddr(qu,&rrp->ha);
}

static int di_srv(adns_state ads, const void *datap_a, const void *datap_b) {
  const adns_rr_srvraw *ap= datap_a, *bp= datap_b;
    /* might be const adns_rr_svhostaddr* */

  if (ap->priority < bp->priority) return 0;
  if (ap->priority > bp->priority) return 1;
  return 0;
}

static adns_status csp_srv_begin(vbuf *vb, const adns_rr_srvha *rrp
				   /* might be adns_rr_srvraw* */) {
  char buf[30];
  sprintf(buf,"%u %u %u ", rrp->priority, rrp->weight, rrp->port);
  CSP_ADDSTR(buf);
  return adns_s_ok;
}

static adns_status cs_srvraw(vbuf *vb, const void *datap) {
  const adns_rr_srvraw *rrp= datap;
  adns_status st;
  
  st= csp_srv_begin(vb,(const void*)rrp);  if (st) return st;
  return csp_domain(vb,rrp->host);
}

static adns_status cs_srvha(vbuf *vb, const void *datap) {
  const adns_rr_srvha *rrp= datap;
  adns_status st;

  st= csp_srv_begin(vb,(const void*)datap);  if (st) return st;
  return csp_hostaddr(vb,&rrp->ha);
}

static void postsort_srv(adns_state ads, void *array, int nrrs,
			 const struct typeinfo *typei) {
  /* we treat everything in the array as if it were an adns_rr_srvha
   * even though the array might be of adns_rr_srvraw.  That's OK
   * because they have the same prefix, which is all we access.
   * We use typei->rrsz, too, rather than naive array indexing, of course.
   */
  char *workbegin, *workend, *search, *arrayend;
  const adns_rr_srvha *rr;
  union { adns_rr_srvha ha; adns_rr_srvraw raw; } rrtmp;
  int cpriority, totalweight, runtotal;
  long randval;

  for (workbegin= array, arrayend= workbegin + typei->rrsz * nrrs;
       workbegin < arrayend;
       workbegin= workend) {
    cpriority= (rr=(void*)workbegin)->priority;
    
    for (workend= workbegin, totalweight= 0;
	 workend < arrayend && (rr=(void*)workend)->priority == cpriority;
	 workend += typei->rrsz) {
      totalweight += rr->weight;
    }

    /* Now workbegin..(workend-1) incl. are exactly all of the RRs of
     * cpriority.  From now on, workbegin points to the `remaining'
     * records: we select one record at a time (RFC2782 `Usage rules'
     * and `Format of the SRV RR' subsection `Weight') to place at
     * workbegin (swapping with the one that was there, and then
     * advance workbegin. */
    for (;
	 workbegin + typei->rrsz < workend; /* don't bother if just one */
	 workbegin += typei->rrsz) {
      
      randval= nrand48(ads->rand48xsubi);
      randval %= (totalweight + 1);
        /* makes it into 0..totalweight inclusive; with 2^10 RRs,
	 * totalweight must be <= 2^26 so probability nonuniformity is
	 * no worse than 1 in 2^(31-26) ie 1 in 2^5, ie
	 *  abs(log(P_intended(RR_i) / P_actual(RR_i)) <= log(2^-5).
	 */

      for (search=workbegin, runtotal=0;
	   (runtotal += (rr=(void*)search)->weight) < randval;
	   search += typei->rrsz);
      assert(search < arrayend);
      totalweight -= rr->weight;
      if (search != workbegin) {
	memcpy(&rrtmp, workbegin, typei->rrsz);
	memcpy(workbegin, search, typei->rrsz);
	memcpy(search, &rrtmp, typei->rrsz);
      }
    }
  }
  /* tests:
   *  dig -t srv _srv._tcp.test.iwj.relativity.greenend.org.uk.
   *   ./adnshost_s -t srv- _sip._udp.voip.net.cam.ac.uk.
   *   ./adnshost_s -t srv- _jabber._tcp.jabber.org
   */
}

/*
 * _byteblock   (mf)
 */

static void mf_byteblock(adns_query qu, void *datap) {
  adns_rr_byteblock *rrp= datap;
  void *bytes= rrp->data;
  adns__makefinal_block(qu,&bytes,rrp->len);
  rrp->data= bytes;
}

/*
 * _opaque   (pa,cs)
 */

static adns_status pa_opaque(const parseinfo *pai, int cbyte,
			     int max, void *datap) {
  adns_rr_byteblock *rrp= datap;

  rrp->len= max - cbyte;
  rrp->data= adns__alloc_interim(pai->qu, rrp->len);
  if (!rrp->data) R_NOMEM;
  memcpy(rrp->data, pai->dgram + cbyte, rrp->len);
  return adns_s_ok;
}

static adns_status cs_opaque(vbuf *vb, const void *datap) {
  const adns_rr_byteblock *rrp= datap;
  char buf[10];
  int l;
  unsigned char *p;

  sprintf(buf,"\\# %d",rrp->len);
  CSP_ADDSTR(buf);
  
  for (l= rrp->len, p= rrp->data;
       l>=4;
       l -= 4, p += 4) {
    sprintf(buf," %02x%02x%02x%02x",p[0],p[1],p[2],p[3]);
    CSP_ADDSTR(buf);
  }
  for (;
       l>0;
       l--, p++) {
    sprintf(buf," %02x",*p);
    CSP_ADDSTR(buf);
  }
  return adns_s_ok;
}
  
/*
 * _flat   (mf)
 */

static void mf_flat(adns_query qu, void *data) { }

/*
 * Now the table.
 */

#define TYPESZ_M(member)           (sizeof(*((adns_answer*)0)->rrs.member))

#define DEEP_MEMB(memb) TYPESZ_M(memb), mf_##memb, cs_##memb
#define FLAT_MEMB(memb) TYPESZ_M(memb), mf_flat, cs_##memb

#define DEEP_TYPE(code,rrt,fmt,memb,parser,comparer,printer)	\
{ adns_r_##code & adns_rrt_reprmask, rrt,fmt,TYPESZ_M(memb),	\
    mf_##memb, printer,parser,comparer, adns__qdpl_normal,0,0 }
#define FLAT_TYPE(code,rrt,fmt,memb,parser,comparer,printer)	\
{ adns_r_##code & adns_rrt_reprmask, rrt,fmt,TYPESZ_M(memb),	\
     mf_flat, printer,parser,comparer, adns__qdpl_normal,0,0 }
#define XTRA_TYPE(code,rrt,fmt,memb,parser,comparer,printer,		   \
		  makefinal,qdpl,postsort,sender)			   \
{ adns_r_##code & adns_rrt_reprmask, rrt,fmt,TYPESZ_M(memb), makefinal,	   \
    printer,parser,comparer,qdpl,postsort,sender }

static const typeinfo typeinfos[] = {
/* Must be in ascending order of rrtype ! */
/* mem-mgmt code  rrt     fmt   member   parser      comparer  printer */

FLAT_TYPE(a,      "A",     0,   inaddr,  pa_inaddr,  di_inaddr,cs_inaddr     ),
DEEP_TYPE(ns_raw, "NS",   "raw",str,     pa_host_raw,0,        cs_domain     ),
DEEP_TYPE(cname,  "CNAME", 0,   str,     pa_dom_raw, 0,        cs_domain     ),
DEEP_TYPE(soa_raw,"SOA",  "raw",soa,     pa_soa,     0,        cs_soa        ),
DEEP_TYPE(ptr_raw,"PTR",  "raw",str,     pa_host_raw,0,        cs_domain     ),
DEEP_TYPE(hinfo,  "HINFO", 0, intstrpair,pa_hinfo,   0,        cs_hinfo      ),
DEEP_TYPE(mx_raw, "MX",   "raw",intstr,  pa_mx_raw,  di_mx_raw,cs_inthost    ),
DEEP_TYPE(txt,    "TXT",   0,   manyistr,pa_txt,     0,        cs_txt        ),
DEEP_TYPE(rp_raw, "RP",   "raw",strpair, pa_rp,      0,        cs_rp         ),
FLAT_TYPE(aaaa,   "AAAA",  0,   in6addr, pa_in6addr, di_in6addr,cs_in6addr   ),
XTRA_TYPE(srv_raw,"SRV",  "raw",srvraw , pa_srvraw,  di_srv,   cs_srvraw,
					 mf_srvraw, qdpl_srv, postsort_srv, 0),

XTRA_TYPE(addr,   "A",  "addr", addr,    pa_addr,    di_addr,  cs_addr,
				       mf_flat, adns__qdpl_normal, 0, qs_addr),
DEEP_TYPE(ns,     "NS", "+addr",hostaddr,pa_hostaddr,di_hostaddr,cs_hostaddr ),
DEEP_TYPE(ptr,    "PTR","checked",str,   pa_ptr,     0,        cs_domain     ),
DEEP_TYPE(mx,     "MX", "+addr",inthostaddr,pa_mx,   di_mx,    cs_inthostaddr),
XTRA_TYPE(srv,    "SRV","+addr",srvha,   pa_srvha,   di_srv,   cs_srvha,
					  mf_srvha, qdpl_srv, postsort_srv, 0),

DEEP_TYPE(soa,    "SOA","822",  soa,     pa_soa,     0,        cs_soa        ),
DEEP_TYPE(rp,     "RP", "822",  strpair, pa_rp,      0,        cs_rp         ),
};

static const typeinfo typeinfo_unknown=
DEEP_TYPE(unknown,0, "unknown",byteblock,pa_opaque,  0,        cs_opaque     );

const typeinfo *adns__findtype(adns_rrtype type) {
  const typeinfo *begin, *end, *mid;

  if (type & adns_r_unknown) return &typeinfo_unknown;
  type &= adns_rrt_reprmask;

  begin= typeinfos;  end= typeinfos+(sizeof(typeinfos)/sizeof(typeinfo));

  while (begin < end) {
    mid= begin + ((end-begin)>>1);
    if (mid->typekey == type) return mid;
    if (type > mid->typekey) begin= mid+1;
    else end= mid;
  }
  return 0;
}
