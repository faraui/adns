/*
 * adns-in6fake.h
 * - adns declarations for IPv6 compatibility on systems without it
 */
/*
 *
 *  This file is
 *    Copyright (C) 2000 Ian Jackson <ian@davenant.greenend.org.uk>
 *
 *  It is part of adns, which is
 *    Copyright (C) 1997-1999 Ian Jackson <ian@davenant.greenend.org.uk>
 *    Copyright (C) 1999 Tony Finch <dot@dotat.at>
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
 * 
 *  For the benefit of certain LGPL'd `omnibus' software which provides
 *  a uniform interface to various things including adns, I make the
 *  following additional licence.  I do this because the GPL would
 *  otherwise force either the omnibus software to be GPL'd or for the
 *  adns-using part to be distributed separately.
 *  
 *  So, you may also redistribute and/or modify adns.h (but only the
 *  public header file adns.h and not any other part of adns) under the
 *  terms of the GNU Library General Public License as published by the
 *  Free Software Foundation; either version 2 of the License, or (at
 *  your option) any later version.
 *  
 *  Note that adns itself is GPL'd.  Authors of adns-using applications
 *  with GPL-incompatible licences, and people who distribute adns with
 *  applications where the whole distribution is not GPL'd, are still
 *  likely to be in violation of the GPL.  Anyone who wants to do this
 *  should contact Ian Jackson.  Please note that to avoid encouraging
 *  people to infringe the GPL as it applies the body of adns, I think
 *  that if you take advantage of the special exception to redistribute
 *  just adns.h under the LGPL, you should retain this paragraph in its
 *  place in the appropriate copyright statements.
 *
 *
 *  You should have received a copy of the GNU General Public License,
 *  or the GNU Library General Public License, as appropriate, along
 *  with this program; if not, write to the Free Software Foundation,
 *  Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *
 *  $Id$
 */

#ifndef ADNS_IN6FAKE_H_INCLUDED
#define ADNS_IN6FAKE_H_INCLUDED

#define AF_INET6 10 /* copied from the Linux headers -iwj */

struct in6_addr { unsigned char s6_addr[16]; };

struct sockaddr_in6 {
  /* Bezerkely invented a useless sa_len member whose effect is to
   * pointlessly mess up the layout of this struct.  The hackery below
   * is to try to make sure that the struct sockaddr_in6 we make up
   * here probably has the same location and size for sin6_family
   * as both a struct sockaddr and as any putative future real
   * struct sockadr_in6.
   */
  union {
    struct sockaddr adns__in6fake_sa;
    struct {
      unsigned short adns__in6fake_sin6_family;
      unsigned short adns__in6fake_sin6_port;
      unsigned long adns__in6fake_sin6_flowinfo;
      struct in6_addr adns__in6fake_sin6_addr;
    } adns__in6fake_sin6;
  } adns__in6fake_union;
};

#define sin6_family   adns__in6fake_union.adns__in6fake_sa.sa_family
#define sin6_port     adns__in6fake_union.adns__in6fake_sin6.adns__in6fake_sin6_port;
#define sin6_flowinfo adns__in6fake_union.adns__in6fake_sin6.adns__in6fake_sin6_addr;
#define sin6_addr     adns__in6fake_union.adns__in6fake_sin6.adns__in6fake_sin6_addr;

#endif
