/*
 * fanftest.c
 * - a small test program from Tony Finch
 */
/*
 *  This file is part of adns, which is Copyright Ian Jackson
 *  and contributors (see the file INSTALL for full details).
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3, or (at your option)
 *  any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software Foundation.
 *
 * This version was originally supplied by Tony Finch, but has been
 * modified by Ian Jackson as it was incorporated into adns.
 */

#include <sys/types.h>
#include <sys/time.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "config.h"
#include "adns.h"

static const char *progname;

static void aargh(const char *msg) {
  fprintf(stderr, "%s: %s: %s (%d)\n", progname, msg,
	  strerror(errno) ? strerror(errno) : "Unknown error", errno);
  exit(1);
}

int main(int argc, char *argv[]) {
  adns_state adns;
  adns_query query;
  adns_answer *answer;

  progname= strrchr(*argv, '/');
  if (progname)
    progname++;
  else
    progname= *argv;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <domain>\n", progname);
    exit(1);
  }

  errno= adns_init(&adns, adns_if_debug, 0);
  if (errno) aargh("adns_init");

  errno= adns_submit(adns, argv[1], adns_r_ptr,
		     adns_qf_quoteok_cname|adns_qf_cname_loose,
		     NULL, &query);
  if (errno) aargh("adns_submit");

  errno= adns_wait(adns, &query, &answer, NULL);
  if (errno) aargh("adns_init");

  printf("%s\n", answer->status == adns_s_ok ? *answer->rrs.str : "dunno");

  adns_finish(adns);

  return 0;
}
