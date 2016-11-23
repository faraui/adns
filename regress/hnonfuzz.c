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
