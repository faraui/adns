/*
 * adnsmt.h
 * - adns multi-threaded API
 */
/*
 *  This file is part of adns, which is Copyright (C) 1997-1999 Ian Jackson
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
 *
 *  $Id$
 */

#ifndef ADNSMT_H_INCLUDED
#define ADNSMT_H_INCLUDED

#include <adns.h>

typedef struct adns_mt__state *adns_mt_state;
typedef struct adns_mt__query *adns_mt_query;

int adns_mt_init(adns_mt_state *newstate_r, adns_initflags flags,
		 FILE *diagfile /*0=>stderr*/);

int adns_mt_init_strcfg(adns_mt_state *newstate_r, adns_initflags flags,
			FILE *diagfile /*0=>discard*/, const char *configtext);

int adns_mt_synchronous(adns_mt_state adts,
			const char *owner,
			adns_rrtype type,
			adns_queryflags flags,
			adns_answer **answer_r);

int adns_mt_submit(adns_mt_state adts,
		   const char *owner,
		   adns_rrtype type,
		   adns_queryflags flags,
		   void *context,
		   adns_mt_query *query_r);

int adns_mt_wait(adns_mt_state adts,
		 adns_mt_query *query_io,
		 adns_answer **answer_r,
		 void **context_r);

void adns_mt_cancel(adns_mt_query query);
/* Do not cancel a query while another thread is waiting for it ! */

void adns_mt_finish(adns_mt_state);
/* You may call this even if you have queries outstanding;
 * they will be cancelled.  NB the comment about _mt_cancel above.
 */

#endif
