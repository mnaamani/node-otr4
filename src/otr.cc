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
    GCRY_THREAD_OPTION_PTHREAD_IMPL;
    #include <libotr/proto.h>
}


namespace otr {
    v8::Handle<v8::Value> Version(const v8::Arguments& args) {
      v8::HandleScope scope;
      return scope.Close(v8::String::New(otrl_version()));
    }
}

void RegisterModule(v8::Handle<v8::Object> target) {
  /* Version check should be the very first call because it
      makes sure that important subsystems are intialized. */
  gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
  if (!gcry_check_version (GCRYPT_VERSION))
  {
    fputs ("libgcrypt version mismatch\n", stderr);
    exit (2);
  }

  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
  OTRL_INIT;

  target->Set(v8::String::NewSymbol("version"), v8::FunctionTemplate::New(otr::Version)->GetFunction());

  otr::UserState::Init(target);
  otr::ConnectionCtx::Init(target);
  otr::MessageAppOps::Init(target);
  otr::PrivateKey::Init(target);
}


NODE_MODULE(otrnat, RegisterModule)


