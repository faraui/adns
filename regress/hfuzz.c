/* nfuzz.c
 * (part of complex test harness, not of the library)
 * - routines used for fuzzing (a kind of playback)
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
 *
 */
/*
 * We read from stdin:
 *  - command line arguments
 *  - syscall stream
 *  - stdin
 */

#include <stdio.h>

#include "harness.h"

extern int Hmain(int argc, char **argv);

FILE *Hfopen(const char *path, const char *mode) {
  /* we do not allow adns to open any files */
  errno = EPERM;
  return 0;
}

static int t_argc;
static char **t_argv;

static FILE *t_stdin;
static int t_sys_fd;

static int bail(const char *msg) {
  fprintf(stderr,"adns fuzz client: %s\n", msg);
  exit(-1);
}
static int baile(const char *msg) {
  fprintf(stderr,"adns fuzz client: %s: %s\n", msg, strerror(errno));
  exit(-1);
}

static void chkin(void) {
  if (ferror(stdin)) baile("read stdin");
  if (feof(stdin)) bail("eof on stdin");
}

static int getint(int max) {
  int val;
  char c;
  chkin();
  int r = scanf("%d%c", &val, &c);
  chkin();
  if (r != 2 || c != '\n') bail("bad input format: not integer");
  if (val < 0 || val > max) bail("bad input format: wrong value");
  return val;
}

static void getnl(void) {
  chkin();
  int c = getchar();
  chkin();
  if (c != '\n') bail("bad input format: expected newline");
}

int Ttestinputfd(void) {
  return t_sys_fd;
}

void Texit(int rv) {
  fprintf(stderr,"**Texit(%d)**\n",rv);
  Tcommonshutdown();
  exit(0);
}

int main(int argc, char **argv) {
  int i, l;

  if (argc!=1)
    bail("usage: *_fuzz  (no arguments)");

  t_argc = getint(50);
  t_argv = calloc(t_argc+1, sizeof(*t_argv));
  for (i=0; i<t_argc; i++) {
    l = getint(1000);
    t_argv[i] = calloc(1, l+1);
    fread(t_argv[i], 1,l, stdin);
    t_argv[i][l] = 0;
    getnl();
  }

  t_stdin = tmpfile();
  l = getint(100000);
  while (l>0) {
    int c = getchar();
    if (c==EOF) break;
    fputc(c, t_stdin);
    l--;
  }
  getnl();
  if (ferror(t_stdin) || fflush(t_stdin)) baile("write/flush t_stdin");
  if (fseek(stdin, 0, SEEK_CUR)) baile("seek-flush stdin");
  t_sys_fd = dup(0);  if (t_sys_fd < 0) baile("dup stdin");
  if (dup2(fileno(t_stdin), 0)) baile("dup2 t_stdin");
  if (fseek(stdin, 0, SEEK_SET)) baile("rewind t_stdin");

  int estatus = Hmain(t_argc, t_argv);
  Texit(estatus);
}

void Tmallocshutdown(void) { }
void *Hmalloc(size_t s) { assert(s); return malloc(s); }
void *Hrealloc(void *p, size_t s) { assert(s); return realloc(p,s); }
void Hfree(void *p) { free(p); }
