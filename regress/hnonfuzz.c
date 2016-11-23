/* nhonfuzz.c
 * (part of complex test harness, not of the library)
 * - routines used for record and playback but not for fuzzing
 *
 *  This file is part of adns, which is
 *    Copyright (C) 1997-2000,2003,2006,2014-2016  Ian Jackson
 *    Copyright (C) 2014  Mark Wooding
 *    Copyright (C) 1999-2000,2003,2006  Tony Finch
 *    Copyright (C) 1991 Massachusetts Institute of Technology
 *  (See the file INSTALL for full details.)
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
 */

#include <stdio.h>

#include "harness.h"

extern int Hmain(int argc, char **argv);
int main(int argc, char **argv) { return Hmain(argc, argv); }

FILE *Hfopen(const char *path, const char *mode) { return fopen(path,mode); }

void Texit(int rv) {
  Tcommonshutdown();
  exit(rv);
}

int Ttestinputfd(void) {
  const char *fdstr= getenv("ADNS_TEST_IN_FD");
  if (!fdstr) return -1;
  return atoi(fdstr);
}

struct malloced {
  struct malloced *next, *back;
  size_t sz;
  unsigned long count;
  struct { double d; long ul; void *p; void (*fp)(void); } data;
};

static unsigned long malloccount, mallocfailat;
static struct { struct malloced *head, *tail; } mallocedlist;

#define MALLOCHSZ ((char*)&mallocedlist.head->data - (char*)mallocedlist.head)

void *Hmalloc(size_t sz) {
  struct malloced *newnode;
  const char *mfavar;
  char *ep;

  assert(sz);

  newnode= malloc(MALLOCHSZ + sz);  if (!newnode) Tnomem();

  LIST_LINK_TAIL(mallocedlist,newnode);
  newnode->sz= sz;
  newnode->count= ++malloccount;
  if (!mallocfailat) {
    mfavar= getenv("ADNS_REGRESS_MALLOCFAILAT");
    if (mfavar) {
      mallocfailat= strtoul(mfavar,&ep,10);
      if (!mallocfailat || *ep) Tfailed("ADNS_REGRESS_MALLOCFAILAT bad value");
    } else {
      mallocfailat= ~0UL;
    }
  }
  assert(newnode->count != mallocfailat);
  memset(&newnode->data,0xc7,sz);
  return &newnode->data;
}

void Hfree(void *ptr) {
  struct malloced *oldnode;

  if (!ptr) return;

  oldnode= (void*)((char*)ptr - MALLOCHSZ);
  LIST_UNLINK(mallocedlist,oldnode);
  memset(&oldnode->data,0x38,oldnode->sz);
  free(oldnode);
}

void *Hrealloc(void *op, size_t nsz) {
  struct malloced *oldnode;
  void *np;
  size_t osz;

  if (op) { oldnode= (void*)((char*)op - MALLOCHSZ); osz= oldnode->sz; } else { osz= 0; }
  np= Hmalloc(nsz);
  if (osz) memcpy(np,op, osz>nsz ? nsz : osz);
  Hfree(op);
  return np;
}

void Tmallocshutdown(void) {
  struct malloced *loopnode;
  if (mallocedlist.head) {
    fprintf(stderr,"adns test harness: memory leaked:");
    for (loopnode=mallocedlist.head; loopnode; loopnode=loopnode->next)
      fprintf(stderr," %lu",loopnode->count);
    putc('\n',stderr);
    if (ferror(stderr)) exit(-1);
  }
}
