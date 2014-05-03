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

static void *inet_sockaddr_to_inaddr(struct sockaddr *sa)
  { return &SIN(sa)->sin_addr; }

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

const afinfo adns__inet_afinfo = {
  AF_INET, 32, '.',
  inet_sockaddr_to_inaddr, inet_prefix_mask, inet_guess_len, inet_matchp
};

/*
 * IPv6
 */

#define SIN6(sa) ((struct sockaddr_in6 *)(sa))

static void *inet6_sockaddr_to_inaddr(struct sockaddr *sa)
  { return &SIN6(sa)->sin6_addr; }

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

const afinfo adns__inet6_afinfo = {
  AF_INET6, 128, ':',
  inet6_sockaddr_to_inaddr, inet6_prefix_mask, inet6_guess_len, inet6_matchp
};
