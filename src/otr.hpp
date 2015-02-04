/*
 *  Off-the-Record Messaging bindings for nodejs
 *  Copyright (C) 2013  Mokhtar Naamani,
 *                      <mokhtar.naamani@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of version 2 of the GNU General Public License as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __NODE_OTR_H__
#define __NODE_OTR_H__

#include <node.h>
#include <v8.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string>

#include "userstate.hpp"
#include "context.hpp"
#include "message.hpp"
#include "privkey.hpp"
#include "fingerprint.hpp"

#define GCRY_EXCEPTION(error) v8::ThrowException(v8::Exception::Error(v8::String::New(gcry_strerror(error))))
#define V8EXCEPTION(error) v8::ThrowException(v8::Exception::Error(v8::String::New(error)))

#ifndef NODE_SET_PROTOTYPE_ACCESSOR
#define NODE_SET_PROTOTYPE_ACCESSOR(templ, name, getter, setter)          \
do {                                                                      \
  templ->PrototypeTemplate()->SetAccessor(v8::String::NewSymbol(name),    \
								  getter, setter);                        \
} while (0)
#endif


#define IfStrEqual(a,b) if(a.compare(b)==0)


#endif
