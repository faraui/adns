# src/adns.make - library definitions, including list of object files
# 
#  This file is part of adns, which is Copyright Ian Jackson
#  and contributors (see the file INSTALL for full details).
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3, or (at your option)
#  any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software Foundation.

LIBOBJS=	types.o event.o query.o reply.o general.o setup.o transmit.o \
		parse.o poll.o check.o addrfam.o
