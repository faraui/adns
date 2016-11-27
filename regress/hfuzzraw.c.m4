m4_dnl hfuzzraw.c.m4
m4_dnl (part of complex test harness, not of the library)
m4_dnl - routines for fuzzing

m4_dnl  This file is part of adns, which is
m4_dnl    Copyright (C) 1997-2000,2003,2006,2014-2016  Ian Jackson
m4_dnl    Copyright (C) 2014  Mark Wooding
m4_dnl    Copyright (C) 1999-2000,2003,2006  Tony Finch
m4_dnl    Copyright (C) 1991 Massachusetts Institute of Technology
m4_dnl  (See the file INSTALL for full details.)
m4_dnl  
m4_dnl  This program is free software; you can redistribute it and/or modify
m4_dnl  it under the terms of the GNU General Public License as published by
m4_dnl  the Free Software Foundation; either version 3, or (at your option)
m4_dnl  any later version.
m4_dnl  
m4_dnl  This program is distributed in the hope that it will be useful,
m4_dnl  but WITHOUT ANY WARRANTY; without even the implied warranty of
m4_dnl  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
m4_dnl  GNU General Public License for more details.
m4_dnl  
m4_dnl  You should have received a copy of the GNU General Public License
m4_dnl  along with this program; if not, write to the Free Software Foundation.

m4_include(hmacros.i4)

#include <assert.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include <unistd.h>
#include <fcntl.h>
#include <limits.h>


#include "harness.h"

static vbuf fdtab;
#define FDF_OPEN     001u
#define FDF_NONBLOCK 002u

static FILE *Tinputfile;
static int stdout_enable;

void Q_vb(void) {
  if (!adns__vbuf_append(&vb,"",1)) Tnomem();
  if (fprintf(stdout," %s\n",vb.buf) == EOF) Toutputerr();
  if (fflush(stdout)) Toutputerr();
}

static void Pformat(const char *what) {
  fprintf(stderr,"adns test harness: format error in raw log input file: %s\n",what);
  exit(-1);
}

extern void Tshutdown(void) {
  int c= fgetc(Tinputfile);
  if (c!=EOF) Pformat("unwanted additional syscall reply data");
  if (ferror(Tinputfile)) Tfailed("read test log input (at end)");
}

static void Pcheckinput(void) {
  if (ferror(Tinputfile)) Tfailed("read test log input file");
  if (feof(Tinputfile)) Pformat("eof at syscall reply");
}

void Tensurerecordfile(void) {
  static int done;

  if (done) return;
  done++;

  int fd;

  fd = Ttestinputfd();
  assert(fd >= 0);
  Tinputfile= fdopen(fd,"rb");
    if (!Tinputfile) Tfailed("fdopen record fd");

  while (fdtab.used < 3) {
    const char fdfstd = FDF_OPEN;
    if (!adns__vbuf_append(&fdtab,&fdfstd,1)) Tnomem();
  }

  const char *proutstr= getenv("ADNS_TEST_FUZZRAW_STDOUT_ENABLE");
  if (proutstr) stdout_enable= atoi(proutstr);
}

static void P_read(void *p, size_t sz) {
  ssize_t got = fread(p,1,sz,Tinputfile);
  Pcheckinput();
  assert(got==sz);
}

#define P_READ(x) (P_read(&(x), sizeof((x))))

static unsigned P_fdf(int fd) {
  assert(fd>=0 && fd<fdtab.used);
  return fdtab.buf[fd];
}

void T_gettimeofday_hook(void) {
  struct timeval delta, sum;
  P_READ(delta);
  timeradd(&delta, &currenttime, &sum);
  currenttime= sum;
}

static void Paddr(struct sockaddr *addr, int *lenr) {
  int l, r;
  uint16_t port;
  char buf[512];
  socklen_t sl = *lenr;

  P_READ(l);
  if (l<0 || l>=sizeof(buf)-1) Pformat("bad addr len");
  buf[l]= 0;
  P_READ(port);
  r= adns_text2addr(buf,port, adns_qf_addrlit_scope_numeric, addr, &sl);
  if (r==EINVAL) Pformat("bad addr text");
  assert(r==ENOSPC);
  *lenr = sl;
}

static int Pbytes(byte *buf, int maxlen) {
  int l;
  P_READ(l);
  if (l<0 || l>maxlen) Pformat("bad byte block len");
  P_read(buf, l);
  return l;
}

static void Pfdset(fd_set *set, int max) {
  uint16_t got;
  int fd, ngot=0;

  for (fd=0; fd<max; fd++) {
    if (!FD_ISSET(fd,set)) continue;
    P_fdf(fd);
    if (ngot==0) {
      P_READ(got);
      ngot= 16;
    }
    if (!(got & 1u)) {
      FD_CLR(fd,set);
    }
    got >>= 1;
    ngot--;
  }
}

#ifdef HAVE_POLL
static void Ppollfds(struct pollfd *fds, int nfds) {
int fd;
  for (fd=0; fd<nfds; fd++) {
    if (!fds[fd].events) continue;
    P_fdf(fd);
    P_READ(fds[fd].revents);
  }
}
#endif

static int P_succfail(void) {
  int r;
  P_READ(r);
  if (r<0 && -r<Tnerrnos) {
    errno= Terrnos[-r].v;
    return -1;
  } else if (r>0 && r<=255) {
    errno= r;
    return -1;
  } else if (r) {
    Pformat("wrong errno value");
  }
  return 0;
}

m4_define(`hm_syscall', `
 hm_create_proto_h
int H$1(hm_args_massage($3,void)) {
 int r;
 m4_define(`hm_rv_fd',`')
 m4_define(`hm_rv_any',`')
 m4_define(`hm_rv_len',`')
 m4_define(`hm_rv_must',`')
 m4_define(`hm_rv_succfail',`')
 m4_define(`hm_rv_fcntl',`')
 $2

 hm_create_hqcall_vars
 $3

 hm_create_hqcall_init($1)
 $3

 Tensurerecordfile();

 if (stdout_enable) {
   hm_create_hqcall_args
   Q$1(hm_args_massage($3));
 }

 m4_define(`hm_rv_succfail',`
  r= P_succfail();
  if (r<0) return r;
 ')

 m4_define(`hm_rv_any',`
  hm_rv_succfail
  if (!r) {
    P_READ(r);
    if (r<0) Pformat("negative nonerror syscall return");
  }
 ')
 m4_define(`hm_rv_len',`
  hm_rv_any
  if (r>($'`1)) Pformat("syscall length return is excessive");
 ')
 m4_define(`hm_rv_must',`
  r= 0;
 ')
 m4_define(`hm_rv_fcntl',`
  unsigned flg = P_fdf(fd);
  if (cmd == F_GETFL) {
    r= (flg & FDF_NONBLOCK) ? O_NONBLOCK : 0;
  } else if (cmd == F_SETFL) {
    flg &= ~FDF_NONBLOCK;
    if (arg & O_NONBLOCK)
      flg |= FDF_NONBLOCK;
    fdtab.buf[fd]= flg;
    r= 0;
  } else {
    abort();
  }
 ')
 m4_define(`hm_rv_fd',`
  hm_rv_succfail
  if (!r) {
    int newfd;
    P_READ(newfd);
    if (newfd<0 || newfd>1000) Pformat("new fd out of range");
    adns__vbuf_ensure(&fdtab, newfd+1);
    if (fdtab.used <= newfd) {
      memset(fdtab.buf+fdtab.used, 0, newfd+1-fdtab.used);
      fdtab.used= newfd+1;
    }
    if (fdtab.buf[newfd]) Pformat("new fd already in use");
    fdtab.buf[newfd] |= FDF_OPEN;
    r= newfd;
 }
 ')
 $2

 hm_create_nothing
 m4_define(`hm_arg_fdset_io',`Pfdset($'`1,$'`2);')
 m4_define(`hm_arg_pollfds_io',`Ppollfds($'`1,$'`2);')
 m4_define(`hm_arg_addr_out',`Paddr($'`1,$'`2);')
 $3

 hm_create_nothing
 m4_define(`hm_arg_bytes_out',`r= Pbytes($'`2,$'`4);')
 $3

 return r;
}
')

m4_define(`hm_specsyscall', `')

m4_include(`hsyscalls.i4')

int Hclose(int fd) {
  P_fdf(fd);
  fdtab.buf[fd]= 0;
  return P_succfail();
}
