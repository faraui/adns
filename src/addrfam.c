/*
 * addrfam.c
 * - address-family specific code
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

#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>

#include <sys/types.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "internal.h"

/*
 * IPv4
 */

#define SIN(sa) ((struct sockaddr_in *)(sa))
#define CSIN(sa) ((const struct sockaddr_in *)(sa))

static void *inet_sockaddr_to_inaddr(struct sockaddr *sa)
  { return &SIN(sa)->sin_addr; }

static int inet_sockaddr_equalp(const struct sockaddr *sa,
				const struct sockaddr *sb)
{
  const struct sockaddr_in *sina = CSIN(sa), *sinb = CSIN(sb);
  return (sina->sin_addr.s_addr == sinb->sin_addr.s_addr &&
	  sina->sin_port == sinb->sin_port);
}

static void inet_prefix_mask(int len, union gen_addr *mask)
  { mask->v4.s_addr = htonl(!len ? 0 : 0xffffffff << (32 - len)); }

static int inet_guess_len(const union gen_addr *addr)
{
  unsigned a = (ntohl(addr->v4.s_addr) >> 24) & 0xff;

  if (a < 128) return 8;
  else if (a < 192) return 16;
  else if (a < 224) return 24;
  else return -1;
}

static int inet_matchp(const union gen_addr *addr,
		       const union gen_addr *base,
		       const union gen_addr *mask)
  { return (addr->v4.s_addr & mask->v4.s_addr) == base->v4.s_addr; }

static int inet_rev_parsecomp(const char *p, size_t n)
{
  int i = 0;
  if (n > 3) return -1;

  while (n--) {
    if ('0' <= *p && *p <= '9') i = 10*i + *p++ - '0';
    else return -1;
  }
  return i;
}

static void inet_rev_mkaddr(union gen_addr *addr, const byte *ipv)
{
  addr->v4.s_addr = htonl((ipv[3]<<24) | (ipv[2]<<16) |
			  (ipv[1]<<8) | (ipv[0]));
}

static char *inet_rev_mkname(const struct sockaddr *sa, char *buf)
{
  unsigned long a = ntohl(CSIN(sa)->sin_addr.s_addr);
  int i;

  for (i = 0; i < 4; i++) {
    if (i) *buf++ = '.';
    buf += sprintf(buf, "%d", (int)(a & 0xff));
    a >>= 8;
  }
  return buf;
}

const afinfo adns__inet_afinfo = {
  AF_INET, 32, '.', 4, 3, adns_r_a,
  inet_sockaddr_to_inaddr, inet_sockaddr_equalp,
  inet_prefix_mask, inet_guess_len, inet_matchp,
  inet_rev_parsecomp, inet_rev_mkaddr, inet_rev_mkname
};

/*
 * IPv6
 */

#define SIN6(sa) ((struct sockaddr_in6 *)(sa))
#define CSIN6(sa) ((const struct sockaddr_in6 *)(sa))

static void *inet6_sockaddr_to_inaddr(struct sockaddr *sa)
  { return &SIN6(sa)->sin6_addr; }

static int inet6_sockaddr_equalp(const struct sockaddr *sa,
				 const struct sockaddr *sb)
{
  const struct sockaddr_in6 *sin6a = CSIN6(sa), *sin6b = CSIN6(sb);
  return (memcmp(sin6a->sin6_addr.s6_addr,
		 sin6b->sin6_addr.s6_addr,
		 sizeof(sin6a->sin6_addr.s6_addr)) == 0 &&
	  sin6a->sin6_port == sin6b->sin6_port &&
	  sin6a->sin6_scope_id == sin6b->sin6_scope_id);
}

static void inet6_prefix_mask(int len, union gen_addr *mask)
{
  int i = len/8, j = len%8;
  unsigned char *m = mask->v6.s6_addr;

  assert(len < 128);
  memset(m, 0xff, i);
  if (j) m[i++] = (0xff << (8-j)) & 0xff;
  memset(m + i, 0, 16-i);
}

static int inet6_guess_len(const union gen_addr *addr)
  { return 64; }

static int inet6_matchp(const union gen_addr *addr,
			const union gen_addr *base,
			const union gen_addr *mask)
{
  int i;
  const char *a = addr->v6.s6_addr;
  const char *b = base->v6.s6_addr;
  const char *m = mask->v6.s6_addr;

  for (i = 0; i < 16; i++)
    if ((a[i] & m[i]) != b[i]) return 0;
  return 1;
}

static int inet6_rev_parsecomp(const char *p, size_t n)
{
  if (n != 1) return -1;
  else if ('0' <= *p && *p <= '9') return *p - '0';
  else if ('a' <= *p && *p <= 'f') return *p - 'a' + 10;
  else if ('A' <= *p && *p <= 'F') return *p - 'a' + 10;
  else return -1;
}

static void inet6_rev_mkaddr(union gen_addr *addr, const byte *ipv)
{
  unsigned char *a = addr->v6.s6_addr;
  int i;

  for (i = 0; i < 16; i++)
    a[i] = (ipv[31-2*i] << 4) | (ipv[30-2*i] << 0);
}

static char *inet6_rev_mkname(const struct sockaddr *sa, char *buf)
{
  const unsigned char *a = CSIN6(sa)->sin6_addr.s6_addr + 16;
  unsigned c, y;
  int i, j;

  for (i = 0; i < 16; i++) {
    c = *--a;
    for (j = 0; j < 2; j++) {
      if (i || j) *buf++ = '.';
      y = c & 0xf;
      if (y < 10) *buf++ = y + '0';
      else *buf++ = y - 10 + 'a';
      c >>= 4;
    }
  }
  return buf;
}

const afinfo adns__inet6_afinfo = {
  AF_INET6, 128, ':', 32, 1, adns_r_aaaa,
  inet6_sockaddr_to_inaddr, inet6_sockaddr_equalp,
  inet6_prefix_mask, inet6_guess_len, inet6_matchp,
  inet6_rev_parsecomp, inet6_rev_mkaddr, inet6_rev_mkname
};
