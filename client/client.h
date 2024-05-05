/*
 * clients.h
 * - useful declarations and definitions for adns client programs
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
 */

#ifndef CLIENT_H_INCLUDED
#define CLIENT_H_INCLUDED

#define ADNS_VERSION_STRING "1.6.1"

#define COPYRIGHT_MESSAGE \
 "Copyright Ian Jackson and contributors\n" \
 "This is free software; see the source for copying conditions.  There is NO\n" \
 "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n"

#define VERSION_MESSAGE(program) \
 program " (GNU adns) " ADNS_VERSION_STRING "\n\n" COPYRIGHT_MESSAGE

#define VERSION_PRINT_QUIT(program)                               \
  if (fputs(VERSION_MESSAGE(program),stdout) == EOF ||            \
      fclose(stdout)) {                                           \
    perror(program ": write version message");                    \
    quitnow(-1);                                                  \
  }                                                               \
  quitnow(0);

void quitnow(int rc) NONRETURNING;

#endif
