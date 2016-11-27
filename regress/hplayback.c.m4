m4_dnl hplayback.c.m4
m4_dnl (part of complex test harness, not of the library)
m4_dnl - playback routines

m4_dnl  This file is part of adns, which is
m4_dnl    Copyright (C) 1997-2000,2003,2006,2014-2016,2020  Ian Jackson
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

static FILE *Tinputfile, *Tfuzzrawfile, *Treportfile;
static vbuf vb2;

static void Tensurereportfile(void) {
  const char *fdstr;
  int fd;

  if (Treportfile) return;
  Treportfile= stderr;
  fdstr= getenv("ADNS_TEST_REPORT_FD"); if (!fdstr) return;
  fd= atoi(fdstr);
  Treportfile= fdopen(fd,"a"); if (!Treportfile) Tfailed("fdopen ADNS_TEST_REPORT_FD");
}

static void Tensurefuzzrawfile(void) {
  static int done;

  if (done) return;
  done++;

  const char *fdstr= getenv("ADNS_TEST_FUZZRAW_DUMP_FD");
  if (!fdstr) return;

  int fd= atoi(fdstr);
  Tfuzzrawfile= fdopen(fd,"ab");
  if (!Tfuzzrawfile) Tfailed("fdopen ADNS_TEST_FUZZRAW_DUMP_FD");
}

static void FR_write(const void *p, size_t sz) {
  if (!Tfuzzrawfile) return;
  ssize_t got = fwrite(p,1,sz,Tfuzzrawfile);
  if (ferror(Tfuzzrawfile)) Tfailed("write fuzzraw output file");
  assert(got==sz);
}

#define FR_WRITE(x) (FR_write(&(x), sizeof((x))))

extern void Tshutdown(void) {
  adns__vbuf_free(&vb2);
  if (Tfuzzrawfile) {
    if (fclose(Tfuzzrawfile)) Tfailed("close fuzzraw output file");
  }
}

static void Psyntax(const char *where) {
  fprintf(stderr,"adns test harness: syntax error in test log input file: %s\n",where);
  exit(-1);
}

static void Pcheckinput(void) {
  if (ferror(Tinputfile)) Tfailed("read test log input file");
  if (feof(Tinputfile)) Psyntax("eof at syscall reply");
}

void T_gettimeofday_hook(void) {
  static struct timeval previously;
  struct timeval delta;
  memset(&delta,0,sizeof(delta));
  timersub(&currenttime, &previously, &delta);
  previously = currenttime;
  FR_WRITE(delta);
}

void Tensurerecordfile(void) {
  int fd;
  int chars;
  unsigned long sec, usec;

  if (Tinputfile) return;
  Tinputfile= stdin;
  fd = Ttestinputfd();
  if (fd >= 0) {
    Tinputfile= fdopen(fd,"r"); if (!Tinputfile) Tfailed("fdopen ADNS_TEST_IN_FD");
  }
  setvbuf(Tinputfile,0,_IONBF,0);

  if (!adns__vbuf_ensure(&vb2,1000)) Tnomem();
  fgets(vb2.buf,vb2.avail,Tinputfile); Pcheckinput();
  chars= -1;
  sscanf(vb2.buf," start %lu.%lu%n",&sec,&usec,&chars);
  if (chars==-1) Psyntax("start time invalid");
  currenttime.tv_sec= sec;
  currenttime.tv_usec= usec;
  if (vb2.buf[chars] != hm_squote\nhm_squote) Psyntax("not newline after start time");
}

static void Parg(const char *argname) {
  int l;

  if (vb2.buf[vb2.used++] != hm_squote hm_squote) Psyntax("not a space before argument");
  l= strlen(argname);
  if (memcmp(vb2.buf+vb2.used,argname,l)) Psyntax("argument name wrong");
  vb2.used+= l;
  if (vb2.buf[vb2.used++] != hm_squote=hm_squote) Psyntax("not = after argument name");
}

static int Pstring_maybe(const char *string) {
  int l;

  l= strlen(string);
  if (memcmp(vb2.buf+vb2.used,string,l)) return 0;
  vb2.used+= l;
  return 1;
}

static void Pstring(const char *string, const char *emsg) {
  if (Pstring_maybe(string)) return;
  Psyntax(emsg);
}

static int Perrno(const char *stuff) {
  const struct Terrno *te;
  int r;
  char *ep;

  for (te= Terrnos; te->n && strcmp(te->n,stuff); te++);
  if (te->n) return te->v;
  r= strtoul(stuff+2,&ep,10);
  if (*ep) Psyntax("errno value not recognised, not numeric");
  if (r==0 || r>255) Psyntax("numeric errno out of range 1..255");
  return r;
}

static void P_updatetime(void) {
  int chars;
  unsigned long sec, usec;

  if (!adns__vbuf_ensure(&vb2,1000)) Tnomem();
  fgets(vb2.buf,vb2.avail,Tinputfile); Pcheckinput();
  chars= -1;
  sscanf(vb2.buf," +%lu.%lu%n",&sec,&usec,&chars);
  if (chars==-1) Psyntax("update time invalid");
  currenttime.tv_sec+= sec;
  currenttime.tv_usec+= usec;
  if (currenttime.tv_usec > 1000000) {
    currenttime.tv_sec++;
    currenttime.tv_usec -= 1000000;
  }
  if (vb2.buf[chars] != hm_squote\nhm_squote) Psyntax("not newline after update time");
}

static void Pfdset(fd_set *set, int max) {
  int c;
  unsigned long ul;
  char *ep;

  if (!set) {
    Pstring("null","null fdset pointer");
    return;
  }
  
  if (vb2.buf[vb2.used++] != hm_squote[hm_squote) Psyntax("fd set start not [");
  FD_ZERO(set);
  if (vb2.buf[vb2.used] == hm_squote]hm_squote) { vb2.used++; return; }
  for (;;) {
    ul= strtoul(vb2.buf+vb2.used,&ep,10);
    if (ul>=max) Psyntax("fd set member > max");
    if (ep == (char*)vb2.buf+vb2.used) Psyntax("empty entry in fd set");
    FD_SET(ul,set);
    vb2.used= ep - (char*)vb2.buf;
    c= vb2.buf[vb2.used++];
    if (c == hm_squote]hm_squote) break;
    if (c != hm_squote,hm_squote) Psyntax("fd set separator not ,");
  }

  uint16_t accum;
  int inaccum=0, fd;
  for (fd=0; ; fd++) {
    if (fd>=max || inaccum==16) {
      FR_WRITE(accum);
      inaccum= 0;
    }
    if (fd>=max)
      break;
    accum <<= 1;
    accum |= !!FD_ISSET(fd,set);
    inaccum++;
  }
}

#ifdef HAVE_POLL
static int Ppollfdevents(void) {
  int events;

  if (Pstring_maybe("0")) return 0;
  events= 0;

  if (Pstring_maybe("POLLIN")) {
    events |= POLLIN;
    if (!Pstring_maybe("|")) return events;
  }

  if (Pstring_maybe("POLLOUT")) {
    events |= POLLOUT;
    if (!Pstring_maybe("|")) return events;
  }

  Pstring("POLLPRI","pollfdevents PRI?");
  return events;
}

static void Ppollfds(struct pollfd *fds, int nfds) {
  int i;
  char *ep;
  const char *comma= "";
  
  if (vb2.buf[vb2.used++] != hm_squote[hm_squote) Psyntax("pollfds start not [");
  for (i=0; i<nfds; i++) {
    Pstring("{fd=","{fd= in pollfds");
    fds->fd= strtoul(vb2.buf+vb2.used,&ep,10);
    vb2.used= ep - (char*)vb2.buf;    
    Pstring(", events=",", events= in pollfds");
    fds->events= Ppollfdevents();
    Pstring(", revents=",", revents= in pollfds");
    fds->revents= Ppollfdevents();
    Pstring("}","} in pollfds");
    Pstring(comma,"separator in pollfds");
    comma= ", ";
  }
  if (vb2.buf[vb2.used++] != hm_squote]hm_squote) Psyntax("pollfds end not ]");
}
#endif

static void Paddr(struct sockaddr *addr, int *lenr) {
  adns_rr_addr a;
  char *p, *q, *ep;
  int err;
  unsigned long ul;

  p= vb2.buf+vb2.used;
  if (*p!='[') {
    q= strchr(p,':');
    if (!q) Psyntax("missing :");
    *q++= 0;
  } else {
    p++;
    q= strchr(p,']');
    if (!q) Psyntax("missing ]");
    *q++= 0;
    if (*q!=':') Psyntax("expected : after ]");
    q++;
  }
  ul= strtoul(q,&ep,10);
  if (*ep && *ep != ' ') Psyntax("invalid port (bad syntax)");
  if (ul >= 65536) Psyntax("port too large");

  a.len= sizeof(a.addr);
  err= adns_text2addr(p, (int)ul, 0, &a.addr.sa,&a.len);
  if (err) Psyntax("invalid address");

  assert(*lenr >= a.len);
  memcpy(addr, &a.addr, a.len);
  *lenr= a.len;
  vb2.used= ep - (char*)vb2.buf;
}

static int Pbytes(byte *buf, int maxlen) {
  static const char hexdigits[]= "0123456789abcdef";

  int c, v, done;
  const char *pf;

  done= 0;
  for (;;) {
    c= getc(Tinputfile); Pcheckinput();
    if (c=='\n' || c==' ' || c=='\t') continue;
    if (c=='.') break;
    pf= strchr(hexdigits,c); if (!pf) Psyntax("invalid first hex digit");
    v= (pf-hexdigits)<<4;
    c= getc(Tinputfile); Pcheckinput();
    pf= strchr(hexdigits,c); if (!pf) Psyntax("invalid second hex digit");
    v |= (pf-hexdigits);
    if (maxlen<=0) Psyntax("buffer overflow in bytes");
    *buf++= v;
    maxlen--; done++;
  }
  for (;;) {
    c= getc(Tinputfile); Pcheckinput();
    if (c=='\n') return done;
  }
}
  
void Q_vb(void) {
  const char *nl;

  Tensurerecordfile();
  if (!adns__vbuf_ensure(&vb2,vb.used+2)) Tnomem();
  fread(vb2.buf,1,vb.used+2,Tinputfile);
  if (feof(Tinputfile)) {
    fprintf(stderr,"adns test harness: input ends prematurely; program did:\n %.*s\n",
           vb.used,vb.buf);
    exit(-1);
  }
  Pcheckinput();
  if (vb2.buf[0] != hm_squote hm_squote) Psyntax("not space before call");
  if (memcmp(vb.buf,vb2.buf+1,vb.used) ||
      vb2.buf[vb.used+1] != hm_squote\nhm_squote) {
    fprintf(stderr,
            "adns test harness: program did unexpected:\n %.*s\n"
            "was expecting:\n %.*s\n",
            vb.used,vb.buf, vb.used,vb2.buf+1);
    exit(1);
  }
  Tensurereportfile();
  nl= memchr(vb.buf,'\n',vb.used);
  fprintf(Treportfile," %.*s\n", (int)(nl ? nl - (const char*)vb.buf : vb.used), vb.buf);
}

m4_define(`hm_syscall', `
 hm_create_proto_h
int H$1(hm_args_massage($3,void)) {
 int r, amtread;
 hm_create_nothing
 m4_define(`hm_rv_fd',`char *ep;')
 m4_define(`hm_rv_any',`char *ep;')
 $2

 hm_create_hqcall_vars
 $3

 hm_create_hqcall_init($1)
 $3

 hm_create_hqcall_args
 Q$1(hm_args_massage($3));

 m4_define(`hm_r_offset',`m4_len(` $1=')')
 if (!adns__vbuf_ensure(&vb2,1000)) Tnomem();
 fgets(vb2.buf,vb2.avail,Tinputfile); Pcheckinput();

 Tensurereportfile();
 Tensurefuzzrawfile();
 fprintf(Treportfile,"%s",vb2.buf);
 amtread= strlen(vb2.buf);
 if (amtread<=0 || vb2.buf[--amtread]!=hm_squote\nhm_squote)
  Psyntax("badly formed line");
 vb2.buf[amtread]= 0;
 if (memcmp(vb2.buf," $1=",hm_r_offset)) Psyntax("syscall reply mismatch");

#ifdef FUZZRAW_SYNC
 FR_WRITE("$1");
#endif

 m4_define(`hm_rv_check_errno',`
 if (vb2.buf[hm_r_offset] == hm_squoteEhm_squote) {
  int e;
  e= Perrno(vb2.buf+hm_r_offset);
  P_updatetime();
  errno= e;
  FR_WRITE(e);
  return -1;
 }
 r= 0;
 FR_WRITE(r);
 ')
 m4_define(`hm_rv_check_success',`
  if (memcmp(vb2.buf+hm_r_offset,"OK",2)) Psyntax("success/fail not E* or OK");
  vb2.used= hm_r_offset+2;
  r= 0;
 ')
 m4_define(`hm_rv_any_nowrite',`
  hm_rv_check_errno
  unsigned long ul_r= strtoul(vb2.buf+hm_r_offset,&ep,10);
  if (ul_r < 0 || ul_r > INT_MAX ||
      (*ep && *ep!=hm_squote hm_squote))
    Psyntax("return value not E* or positive number");
  r= ul_r;
  vb2.used= ep - (char*)vb2.buf;
 ')

 m4_define(`hm_rv_succfail',`
  hm_rv_check_errno
  hm_rv_check_success
 ')
 m4_define(`hm_rv_len',`
  hm_rv_check_errno
  hm_rv_check_success
 ')
 m4_define(`hm_rv_must',`
  hm_rv_check_success
 ')
 m4_define(`hm_rv_any',`
  hm_rv_any_nowrite
  FR_WRITE(r);
 ')
 m4_define(`hm_rv_fd',`hm_rv_any')
 m4_define(`hm_rv_select',`hm_rv_any_nowrite')
 m4_define(`hm_rv_poll',`hm_rv_any_nowrite')
 m4_define(`hm_rv_fcntl',`
  r= 0;
  if (cmd == F_GETFL) {
    if (!memcmp(vb2.buf+hm_r_offset,"O_NONBLOCK|...",14)) {
      r= O_NONBLOCK;
      vb2.used= hm_r_offset+14;
    } else if (!memcmp(vb2.buf+hm_r_offset,"~O_NONBLOCK&...",15)) {
      vb2.used= hm_r_offset+15;
    } else {
      Psyntax("fcntl flags not O_NONBLOCK|... or ~O_NONBLOCK&...");
    }
  } else if (cmd == F_SETFL) {
    hm_rv_check_success
  } else {
    Psyntax("fcntl not F_GETFL or F_SETFL");
  }
 ')
 $2

 hm_create_nothing
 m4_define(`hm_arg_fdset_io',`Parg("$'`1"); Pfdset($'`1,$'`2);')
 m4_define(`hm_arg_pollfds_io',`Parg("$'`1"); Ppollfds($'`1,$'`2);')
 m4_define(`hm_arg_addr_out',`Parg("$'`1"); Paddr($'`1,$'`2);')
 $3
 assert(vb2.used <= amtread);
 if (vb2.used != amtread) Psyntax("junk at end of line");

 hm_create_nothing
 m4_define(`hm_arg_bytes_out',`
  r= Pbytes($'`2,$'`4);
  FR_WRITE(r);
  FR_write(buf,r);
 ')
 $3

 P_updatetime();
 return r;
}
')

m4_define(`hm_specsyscall', `')

m4_include(`hsyscalls.i4')

hm_stdsyscall_close
