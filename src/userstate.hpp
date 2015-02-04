/*
 *  Off-the-Record Messaging bindings for nodejs
 *  Copyright (C) 2012  Mokhtar Naamani,
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

#ifndef __NODE_OTR_USERSTATE_H__
#define __NODE_OTR_USERSTATE_H__

#include "otr.hpp"

extern "C" {
	#include <gcrypt.h>			//added for libotr-v4
	#include <libotr/userstate.h>
}

namespace otr {
class UserState : public node::ObjectWrap {
 public:
  static void Init(v8::Handle<v8::Object> target);
  static v8::Persistent<v8::FunctionTemplate> constructor;

 protected:
  friend class MessageAppOps;
  friend class ConnectionCtx;
  friend class PrivateKey;

  OtrlUserState userstate_;
  bool reference;

  UserState(OtrlUserState userstate);
  ~UserState();

  static v8::Handle<v8::Value> New(const v8::Arguments& args);
  static v8::Handle<v8::Value> WrapUserState(OtrlUserState userstate);
  static v8::Handle<v8::Value> Destroy(const v8::Arguments &args);
  //Async
  static v8::Handle<v8::Value> Generate_Key(const v8::Arguments& args);
  static v8::Handle<v8::Value> Read_Keys(const v8::Arguments& args);
  static v8::Handle<v8::Value> Read_Fingerprints(const v8::Arguments& args);
  static v8::Handle<v8::Value> Write_Fingerprints(const v8::Arguments& args);
  //Sync
  static v8::Handle<v8::Value> GetFingerprint(const v8::Arguments& args);
  static v8::Handle<v8::Value> Accounts(const v8::Arguments& args);
  static v8::Handle<v8::Value> Get_Key(const v8::Arguments& args);
  static v8::Handle<v8::Value> Import_PrivKey(const v8::Arguments& args);
  static v8::Handle<v8::Value> Read_Keys_Sync(const v8::Arguments& args);
  static v8::Handle<v8::Value> Write_Keys_Sync(const v8::Arguments& args);
  static v8::Handle<v8::Value> Delete_Key_On_File(const v8::Arguments& args);
  static v8::Handle<v8::Value> Find_Key(const v8::Arguments& args);
  static v8::Handle<v8::Value> Forget_All_Keys(const v8::Arguments& args);
  static v8::Handle<v8::Value> Read_Fingerprints_Sync(const v8::Arguments& args);
  static v8::Handle<v8::Value> Write_Fingerprints_Sync(const v8::Arguments& args);
  static v8::Handle<v8::Value> Write_Trusted_Fingerprints_Sync(const v8::Arguments& args);
  static v8::Handle<v8::Value> Read_Instags_Sync(const v8::Arguments& args);
  static v8::Handle<v8::Value> Write_Instags_Sync(const v8::Arguments& args);
  static v8::Handle<v8::Value> Generate_Instag(const v8::Arguments& args);
  static v8::Handle<v8::Value> Find_Instag(const v8::Arguments& args);
  static v8::Handle<v8::Value> MessagePoll_DefaultInterval(const v8::Arguments& args);
  static v8::Handle<v8::Value> MessagePoll(const v8::Arguments& args);
  static v8::Handle<v8::Value> Free(const v8::Arguments& args);
  static v8::Handle<v8::Value> MasterContexts(const v8::Arguments& args);

  //Workers
  static void Worker_Generate_Key (uv_work_t* req);
  static void Worker_Read_Keys (uv_work_t* req);
  static void Worker_Read_Fingerprints (uv_work_t* req);
  static void Worker_Write_Fingerprints (uv_work_t* req);
  static void Worker_After (uv_work_t* req);

};

//information about the asynchronous "work request".
struct Baton {
	uv_work_t request;
	bool hasCallback;
	v8::Persistent<v8::Function> callback;
	gcry_error_t error;
	OtrlUserState  userstate;
	std::string arg0;
	std::string arg1;
	std::string arg2;
};

}
#endif
