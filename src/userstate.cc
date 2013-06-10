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
#include "cvv8/convert.hpp"

extern "C" {
    #include <libotr/privkey.h>
    #include "otr-extras.c"
}

using namespace v8;

namespace otr {
v8::Persistent<v8::FunctionTemplate> UserState::constructor;

UserState::UserState(OtrlUserState userstate) : ObjectWrap(),
      userstate_(userstate) {};

UserState::~UserState(){
    if(!reference){
        if(userstate_!=NULL) {
            otrl_userstate_free(userstate_);
        }
    }
};

void UserState::Init(Handle<Object> target) {
  HandleScope scope;

  // Prepare constructor template
  Local<FunctionTemplate> tpl = FunctionTemplate::New(New);
  Local<String> name = String::NewSymbol("UserState");

  constructor = Persistent<FunctionTemplate>::New(tpl);
  // ObjectWrap uses the first internal field to store the wrapped pointer.
  constructor->InstanceTemplate()->SetInternalFieldCount(1);
  constructor->SetClassName(name);

  NODE_SET_PROTOTYPE_METHOD(constructor, "generateKey",Generate_Key);
  NODE_SET_PROTOTYPE_METHOD(constructor, "readKeys",Read_Keys);
  NODE_SET_PROTOTYPE_METHOD(constructor, "readFingerprints",Read_Fingerprints);
  NODE_SET_PROTOTYPE_METHOD(constructor, "writeFingerprints",Write_Fingerprints);

  NODE_SET_PROTOTYPE_METHOD(constructor, "fingerprint",GetFingerprint);
  NODE_SET_PROTOTYPE_METHOD(constructor, "accounts",Accounts);

  NODE_SET_PROTOTYPE_METHOD(constructor, "readKeysSync",Read_Keys_Sync);
  NODE_SET_PROTOTYPE_METHOD(constructor, "writeKeysSync",Write_Keys_Sync);
  NODE_SET_PROTOTYPE_METHOD(constructor, "deleteKeyOnFile",Delete_Key_On_File);
  NODE_SET_PROTOTYPE_METHOD(constructor, "findKey",Find_Key);

  NODE_SET_PROTOTYPE_METHOD(constructor, "readInstagsSync",Read_Instags_Sync);
  NODE_SET_PROTOTYPE_METHOD(constructor, "writeInstagsSync",Write_Instags_Sync);
  NODE_SET_PROTOTYPE_METHOD(constructor, "generateInstag",Generate_Instag);
  NODE_SET_PROTOTYPE_METHOD(constructor, "findInstag",Find_Instag);

  NODE_SET_PROTOTYPE_METHOD(constructor, "readFingerprintsSync",Read_Fingerprints_Sync);
  NODE_SET_PROTOTYPE_METHOD(constructor, "writeFingerprintsSync",Write_Fingerprints_Sync);
  NODE_SET_PROTOTYPE_METHOD(constructor, "writeTrustedFingerprintsSync",Write_Trusted_Fingerprints_Sync);

  NODE_SET_PROTOTYPE_METHOD(constructor, "getMessagePollDefaultInterval",MessagePoll_DefaultInterval);
  NODE_SET_PROTOTYPE_METHOD(constructor, "messagePoll",MessagePoll);

  NODE_SET_PROTOTYPE_METHOD(constructor, "free",Free);

  target->Set(name, constructor->GetFunction());
}

Handle<Value> UserState::New(const Arguments& args) {
  HandleScope scope;
  OtrlUserState us = otrl_userstate_create();
  UserState* obj = new UserState( us );
  obj->reference=false;
  obj->Wrap(args.This());
  return args.This();
}

Handle<Value> UserState::Free(const Arguments &args){
  HandleScope scope;
  UserState* obj = ObjectWrap::Unwrap<UserState>(args.This());
  if(obj->userstate_!=NULL) otrl_userstate_free(obj->userstate_);
  obj->userstate_ = NULL;
  return scope.Close(Undefined());
}

Handle<Value> UserState::WrapUserState(OtrlUserState userstate)
{
        v8::Local<v8::Object> o = constructor->InstanceTemplate()->NewInstance();
        UserState *obj = node::ObjectWrap::Unwrap<UserState>(o);
        obj->userstate_ = userstate;
        obj->reference = true;
        return o;
}

Handle<Value> UserState::MessagePoll_DefaultInterval(const Arguments& args) {
  HandleScope scope;
  UserState* obj = ObjectWrap::Unwrap<UserState>(args.This());

  int interval = otrl_message_poll_get_default_interval(obj->userstate_);

  return scope.Close(Number::New(interval));
}

Handle<Value> UserState::MessagePoll(const Arguments& args) {
  HandleScope scope;
  UserState* obj = ObjectWrap::Unwrap<UserState>(args.This());

  otrl_message_poll(obj->userstate_,NULL,NULL);

  return scope.Close(Undefined());
}

Handle<Value> UserState::GetFingerprint(const Arguments& args) {
  HandleScope scope;
  UserState* obj = ObjectWrap::Unwrap<UserState>(args.This());

  if(!args.Length() > 1 || !args[0]->IsString() || !args[1]->IsString() ){
    return scope.Close(V8EXCEPTION("Invalid arguments. First argument 'accountname' (string), second argument 'protocol' (string)."));
  }

  String::Utf8Value accountname(args[0]->ToString());
  String::Utf8Value protocol(args[1]->ToString());

  char fingerprint[45];
  if( otrl_privkey_fingerprint(obj->userstate_, fingerprint, *accountname, *protocol) ){
      return scope.Close(String::New(fingerprint));
  }
  return scope.Close(Undefined());
}

Handle<Value> UserState::Accounts(const Arguments& args){
    HandleScope scope;
    UserState* us = ObjectWrap::Unwrap<UserState>(args.This());

    OtrlPrivKey *p;
    v8::Local<v8::Array> result = v8::Array::New();
    int count=0;
    char fingerprint[45];
    Local<Object> account;

    for(p=us->userstate_->privkey_root; p; p=p->next) {
        account = Object::New();
   	    account->Set(String::NewSymbol("accountname"),String::New(p->accountname));
        account->Set(String::NewSymbol("protocol"), String::New(p->protocol));
        otrl_privkey_fingerprint(us->userstate_, fingerprint, p->accountname, p->protocol);
        account->Set(String::NewSymbol("fingerprint"), String::New(fingerprint));
    	result->Set(count++,account);
    }
    return scope.Close(result);
}

Handle<Value> UserState::Read_Keys_Sync(const Arguments& args) {
  HandleScope scope;
  UserState* obj = ObjectWrap::Unwrap<UserState>(args.This());

  if(!args.Length() > 0 || !args[0]->IsString()){
    return scope.Close(V8EXCEPTION("Invalid arguments. One argument 'filename' (string) excpected."));
  }
  String::Utf8Value filename(args[0]->ToString());

  gcry_error_t error = otrl_privkey_read(obj->userstate_, *filename);

  if(error) return scope.Close(GCRY_EXCEPTION(error));
  return scope.Close(Undefined());
}

Handle<Value> UserState::Read_Keys(const Arguments& args) {
  HandleScope scope;
  UserState* obj = ObjectWrap::Unwrap<UserState>(args.This());
  Local<Function> callback;

  if(!args.Length() > 0 || !args[0]->IsString()){
    return scope.Close(V8EXCEPTION("Invalid arguments. First argument 'filename' (string) excpected."));
  }
  if(args.Length() > 1 && !args[1]->IsFunction()){
    return scope.Close(V8EXCEPTION("Invalid arguments. Second argument 'callback' (function) excpected."));
  }
  if(args.Length() > 1){
    callback = Local<Function>::Cast(args[1]);
  }

  Baton* baton = new Baton();
  baton->error = 0;
  baton->request.data = baton;
  baton->callback = Persistent<Function>::New(callback);
  if(args.Length() > 1) baton->hasCallback = true;
  baton->arg0 = cvv8::CastFromJS<std::string>(args[0]);//filename
  baton->userstate = obj->userstate_;

  int status = uv_queue_work(uv_default_loop(), &baton->request, Worker_Read_Keys, (uv_after_work_cb)Worker_After);
  assert(status == 0);

  return scope.Close(Undefined());
}

void UserState::Worker_Read_Keys(uv_work_t* req){
  Baton* baton = static_cast<Baton*>(req->data);
  baton->error = otrl_privkey_read(baton->userstate, baton->arg0.c_str());
}

Handle<Value> UserState::Write_Keys_Sync(const Arguments& args) {
  HandleScope scope;
  UserState* obj = ObjectWrap::Unwrap<UserState>(args.This());

  if(!args.Length() > 0 || !args[0]->IsString()){
    return scope.Close(V8EXCEPTION("Invalid arguments. One argument 'filename' (string) excpected."));
  }
  String::Utf8Value filename(args[0]->ToString());

  gcry_error_t error = jsapi_userstate_write_to_file(obj->userstate_, *filename);

  if(error) return scope.Close(GCRY_EXCEPTION(error));
  return scope.Close(Undefined());
}

Handle<Value> UserState::Delete_Key_On_File(const Arguments& args) {
  HandleScope scope;
  UserState* obj = ObjectWrap::Unwrap<UserState>(args.This());
    if(!args.Length() > 0 || !args[0]->IsString()){
    return scope.Close(V8EXCEPTION("Invalid arguments. First argument 'filename' (string) excpected."));
  }
  if(!args.Length() > 1 || !args[1]->IsString()){
    return scope.Close(V8EXCEPTION("Invalid arguments. Second argument 'accountname' (string) excpected."));
  }
  if(!args.Length() > 2 || !args[2]->IsString()){
    return scope.Close(V8EXCEPTION("Invalid arguments. Third argument 'protocol' (string) excpected."));
  }
  String::Utf8Value filename(args[0]->ToString());
  String::Utf8Value accountname(args[1]->ToString());
  String::Utf8Value protocol(args[2]->ToString());
  
  gcry_error_t error = jsapi_privkey_delete(obj->userstate_, *filename, *accountname, *protocol);

  if(error) return scope.Close(GCRY_EXCEPTION(error));
  return scope.Close(Undefined());
}

Handle<Value> UserState::Read_Fingerprints_Sync(const Arguments& args) {
  HandleScope scope;
  UserState* obj = ObjectWrap::Unwrap<UserState>(args.This());
  if(!args.Length() > 0 || !args[0]->IsString()){
    return scope.Close(V8EXCEPTION("Invalid arguments. One argument 'filename' (string) excpected."));
  }
  String::Utf8Value filename(args[0]->ToString());
  gcry_error_t error = otrl_privkey_read_fingerprints(obj->userstate_, *filename, NULL, NULL);

  if(error) return scope.Close(GCRY_EXCEPTION(error));
  return scope.Close(Undefined());
}

Handle<Value> UserState::Read_Fingerprints(const Arguments& args) {
  HandleScope scope;
  UserState* obj = ObjectWrap::Unwrap<UserState>(args.This());
  Local<Function> callback;

  if(!args.Length() > 0 || !args[0]->IsString()){
    return scope.Close(V8EXCEPTION("Invalid arguments. First argument 'filename' (string) excpected."));
  }
  if(args.Length() > 1 && !args[1]->IsFunction()){
    return scope.Close(V8EXCEPTION("Invalid arguments. Second argument 'callback' (function) excpected."));
  }
  if(args.Length() > 1){
    callback = Local<Function>::Cast(args[1]);
  }

  Baton* baton = new Baton();
  baton->error = 0;
  baton->request.data = baton;
  baton->callback = Persistent<Function>::New(callback);
  if(args.Length() > 1) baton->hasCallback = true;
  baton->arg0 = cvv8::CastFromJS<std::string>(args[0]);//filename
  baton->userstate = obj->userstate_;

  int status = uv_queue_work(uv_default_loop(), &baton->request, Worker_Read_Fingerprints, (uv_after_work_cb)Worker_After);
  assert(status == 0);

  return scope.Close(Undefined());
}

void UserState::Worker_Read_Fingerprints(uv_work_t* req){
  Baton* baton = static_cast<Baton*>(req->data);
  baton->error = otrl_privkey_read_fingerprints(baton->userstate, baton->arg0.c_str(), NULL, NULL);
}

Handle<Value> UserState::Write_Fingerprints_Sync(const Arguments& args) {
  HandleScope scope;
  UserState* obj = ObjectWrap::Unwrap<UserState>(args.This());

  if(!args.Length() > 0 || !args[0]->IsString()){
    return scope.Close(V8EXCEPTION("Invalid arguments. One argument 'filename' (string) excpected."));
  }
  String::Utf8Value filename(args[0]->ToString());
  gcry_error_t error = otrl_privkey_write_fingerprints(obj->userstate_, *filename);

  if(error) return scope.Close(GCRY_EXCEPTION(error));
  return scope.Close(Undefined());
}

Handle<Value> UserState::Write_Fingerprints(const Arguments& args) {
  HandleScope scope;
  UserState* obj = ObjectWrap::Unwrap<UserState>(args.This());
  Local<Function> callback;

  if(!args.Length() > 0 || !args[0]->IsString()){
    return scope.Close(V8EXCEPTION("Invalid arguments. First argument 'filename' (string) excpected."));
  }
  if(args.Length() > 1 && !args[1]->IsFunction()){
    return scope.Close(V8EXCEPTION("Invalid arguments. Second argument 'callback' (function) excpected."));
  }
  if(args.Length() > 1){
    callback = Local<Function>::Cast(args[1]);
  }

  Baton* baton = new Baton();
  baton->error = 0;
  baton->request.data = baton;
  baton->callback = Persistent<Function>::New(callback);
  if(args.Length() > 1) baton->hasCallback = true;
  baton->arg0 = cvv8::CastFromJS<std::string>(args[0]);//filename
  baton->userstate = obj->userstate_;

  int status = uv_queue_work(uv_default_loop(), &baton->request, Worker_Write_Fingerprints, (uv_after_work_cb)Worker_After);
  assert(status == 0);

  return Undefined();
}

void UserState::Worker_Write_Fingerprints(uv_work_t* req){
  Baton* baton = static_cast<Baton*>(req->data);
  baton->error = otrl_privkey_write_fingerprints(baton->userstate, baton->arg0.c_str());
}

Handle<Value> UserState::Write_Trusted_Fingerprints_Sync(const Arguments& args) {
  HandleScope scope;
  UserState* obj = ObjectWrap::Unwrap<UserState>(args.This());
  OtrlUserState us = obj->userstate_;
  FILE *storef = NULL;
  ConnContext *context;
  Fingerprint *fingerprint;
  gcry_error_t error;

  if(!args.Length() > 0 || !args[0]->IsString()){
    return scope.Close(V8EXCEPTION("Invalid arguments. One argument 'filename' (string) excpected."));
  }
  String::Utf8Value filename(args[0]->ToString());

  error = gcry_error(GPG_ERR_NO_ERROR);

    for(context = us->context_root; context; context = context->next) {
      /* Fingerprints are only stored in the master contexts */
      if (context->their_instance != OTRL_INSTAG_MASTER) continue;
      
      /* Don't bother with the first (fingerprintless) entry. */
      for (fingerprint = context->fingerprint_root.next; fingerprint && fingerprint->trust[0]!='\0' ;
        fingerprint = fingerprint->next) {
        int i;
        //only open the file if we have something to write
        if(storef == NULL){
             storef = fopen(*filename, "wb");
            if(!storef) {
                error = gcry_error_from_errno(errno);
                return scope.Close(GCRY_EXCEPTION(error));
            }
        }
        fprintf(storef, "%s\t%s\t%s\t", context->username,
            context->accountname, context->protocol);
        for(i=0;i<20;++i) {
        fprintf(storef, "%02x", fingerprint->fingerprint[i]);
        }
        fprintf(storef, "\t%s\n", fingerprint->trust ? fingerprint->trust : "");
      }
    }
  if(storef != NULL) fclose(storef);
  if(error) return scope.Close(GCRY_EXCEPTION(error));
  return scope.Close(Undefined());
}

Handle<Value> UserState::Read_Instags_Sync(const Arguments& args) {
  HandleScope scope;
  UserState* obj = ObjectWrap::Unwrap<UserState>(args.This());
  if(!args.Length() > 0 || !args[0]->IsString()){
    return scope.Close(V8EXCEPTION("Invalid arguments. One argument 'filename' (string) excpected."));
  }
  String::Utf8Value filename(args[0]->ToString());
  gcry_error_t error = otrl_instag_read(obj->userstate_, *filename);

  if(error) return scope.Close(GCRY_EXCEPTION(error));
  return scope.Close(Undefined());
}

Handle<Value> UserState::Write_Instags_Sync(const Arguments& args) {
  HandleScope scope;
  UserState* obj = ObjectWrap::Unwrap<UserState>(args.This());
  if(!args.Length() > 0 || !args[0]->IsString()){
    return scope.Close(V8EXCEPTION("Invalid arguments. One argument 'filename' (string) excpected."));
  }
  String::Utf8Value filename(args[0]->ToString());
  gcry_error_t error = otrl_instag_write(obj->userstate_, *filename);

  if(error) return scope.Close(GCRY_EXCEPTION(error));
  return scope.Close(Undefined());
}

Handle<Value> UserState::Generate_Instag(const Arguments& args) {
  HandleScope scope;
  UserState* obj = ObjectWrap::Unwrap<UserState>(args.This());
    if(!args.Length() > 0 || !args[0]->IsString()){
    return scope.Close(V8EXCEPTION("Invalid arguments. First argument 'filename' (string) excpected."));
  }
  if(!args.Length() > 1 || !args[1]->IsString()){
    return scope.Close(V8EXCEPTION("Invalid arguments. Second argument 'accountname' (string) excpected."));
  }
  if(!args.Length() > 2 || !args[2]->IsString()){
    return scope.Close(V8EXCEPTION("Invalid arguments. Third argument 'protocol' (string) excpected."));
  }
  String::Utf8Value filename(args[0]->ToString());
  String::Utf8Value accountname(args[1]->ToString());
  String::Utf8Value protocol(args[2]->ToString());
  
  gcry_error_t error = otrl_instag_generate(obj->userstate_, *filename, *accountname, *protocol);

  if(error) return scope.Close(GCRY_EXCEPTION(error));
  return scope.Close(Undefined());
}

Handle<Value> UserState::Find_Instag(const Arguments& args) {
  HandleScope scope;
  UserState* obj = ObjectWrap::Unwrap<UserState>(args.This());

  if(!args.Length() > 0 || !args[0]->IsString()){
    return scope.Close(V8EXCEPTION("Invalid arguments. First argument 'accountname' (string) excpected."));
  }
  if(!args.Length() > 1 || !args[1]->IsString()){
    return scope.Close(V8EXCEPTION("Invalid arguments. Second argument 'protocol' (string) excpected."));
  }

  String::Utf8Value accountname(args[0]->ToString());
  String::Utf8Value protocol(args[1]->ToString());
  
  OtrlInsTag * instag = otrl_instag_find(obj->userstate_, *accountname, *protocol);

  if(instag != NULL) return scope.Close(Number::New(instag->instag));
  return scope.Close(Undefined());
}


Handle<Value> UserState::Generate_Key(const Arguments& args) {
  HandleScope scope;
  UserState* obj = ObjectWrap::Unwrap<UserState>(args.This());
  Local<Function> callback;

  if(!args.Length() > 0 || !args[0]->IsString()){
    return scope.Close(V8EXCEPTION("Invalid arguments. First argument 'filename' (string) excpected."));
  }
  if(!args.Length() > 1 || !args[1]->IsString()){
    return scope.Close(V8EXCEPTION("Invalid arguments. Second argument 'accountname' (string) excpected."));
  }
  if(!args.Length() > 2 || !args[2]->IsString()){
    return scope.Close(V8EXCEPTION("Invalid arguments. Third argument 'protocol' (string) excpected."));
  }
  if(args.Length() > 3 && !args[3]->IsFunction()){
    return scope.Close(V8EXCEPTION("Invalid arguments. Fourth argument 'callback' (function) excpected."));
  }
  if(args.Length() > 3){
    callback = Local<Function>::Cast(args[3]);
  }

  Baton* baton = new Baton();
  baton->error = 0;
  baton->request.data = baton;
  baton->callback = Persistent<Function>::New(callback);
  if(args.Length() > 3) baton->hasCallback = true;
  baton->arg0 = cvv8::CastFromJS<std::string>(args[0]);//filename
  baton->arg1 = cvv8::CastFromJS<std::string>(args[1]);//accountname
  baton->arg2 = cvv8::CastFromJS<std::string>(args[2]);//protocol
  baton->userstate = obj->userstate_;

  int status = uv_queue_work(uv_default_loop(), &baton->request, Worker_Generate_Key, (uv_after_work_cb)Worker_After);
  assert(status == 0);

  return Undefined();
}

void UserState::Worker_Generate_Key(uv_work_t* req){
  Baton* baton = static_cast<Baton*>(req->data);
  baton->error = otrl_privkey_generate(baton->userstate, baton->arg0.c_str(), baton->arg1.c_str(), baton->arg2.c_str());
}

Handle<Value> UserState::Find_Key(const Arguments& args) {
  HandleScope scope;
  UserState* obj = ObjectWrap::Unwrap<UserState>(args.This());

  if(!args.Length() > 0 || !args[0]->IsString()){
    return scope.Close(V8EXCEPTION("Invalid arguments. First argument 'accountname' (string) excpected."));
  }
  if(!args.Length() > 1 || !args[1]->IsString()){
    return scope.Close(V8EXCEPTION("Invalid arguments. Second argument 'protocol' (string) excpected."));
  }

  String::Utf8Value accountname(args[0]->ToString());
  String::Utf8Value protocol(args[1]->ToString());
  
  OtrlPrivKey * privkey = otrl_privkey_find(obj->userstate_, *accountname, *protocol);

  if(privkey != NULL) return scope.Close(Number::New(1));
  return scope.Close(Undefined());
}

void UserState::Worker_After(uv_work_t* req) {
    HandleScope scope;
    Baton* baton = static_cast<Baton*>(req->data);
    if(baton->hasCallback){
        if (baton->error) {
            Local<Value> err = Exception::Error(String::New(gcry_strerror(baton->error)));
            const unsigned argc = 1;
            Local<Value> argv[argc] = { err };
            TryCatch try_catch;
            baton->callback->Call(Context::GetCurrent()->Global(), argc, argv);
            if (try_catch.HasCaught()) {
                node::FatalException(try_catch);
            }
        } else {
            const unsigned argc = 1;
            Local<Value> argv[argc] = {
                Local<Value>::New(Null())
            };
            TryCatch try_catch;
            baton->callback->Call(Context::GetCurrent()->Global(), argc, argv);
            if (try_catch.HasCaught()) {
                node::FatalException(try_catch);
            }
        }
    }
    // The callback is a permanent handle, so we have to dispose of it manually.
    baton->callback.Dispose();
    delete baton;
}

} //namespace otr
