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

#include "otr.hpp"

extern "C" {
    #include <libotr/proto.h>
}


namespace otr {
    v8::Handle<v8::Value> Version(const v8::Arguments& args) {
      v8::HandleScope scope;
      return scope.Close(v8::String::New(otrl_version()));
    }
}

void RegisterModule(v8::Handle<v8::Object> target) {
  OTRL_INIT;

  target->Set(v8::String::NewSymbol("version"), v8::FunctionTemplate::New(otr::Version)->GetFunction());
}


NODE_MODULE(otrnat, RegisterModule)


