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
#include <node_buffer.h>

extern "C" {
	#include <libotr/privkey.h>
	#include <libotr/tlv.h>
}

using namespace v8;

namespace otr {
void NullAsyncWork(uv_work_t* req) {
}

v8::Persistent<v8::FunctionTemplate> MessageAppOps::constructor;

MessageAppOps::MessageAppOps() {};

MessageAppOps::~MessageAppOps() {
	delete messageops_;
	ui_event_.Dispose();
};

void MessageAppOps::Init(Handle<Object> target) {
  HandleScope scope;

  // Prepare constructor template
  Local<FunctionTemplate> tpl = FunctionTemplate::New(New);
  Local<String> name = String::NewSymbol("MessageAppOps");

  constructor = Persistent<FunctionTemplate>::New(tpl);
  // ObjectWrap uses the first internal field to store the wrapped pointer.
  constructor->InstanceTemplate()->SetInternalFieldCount(1);
  constructor->SetClassName(name);

  // Prototype
  NODE_SET_PROTOTYPE_METHOD(constructor, "messageSending",Message_Sending);
  NODE_SET_PROTOTYPE_METHOD(constructor, "messageReceiving",Message_Receiving);
  NODE_SET_PROTOTYPE_METHOD(constructor, "disconnect",Disconnect);
  NODE_SET_PROTOTYPE_METHOD(constructor, "initSMP",Initiate_SMP);
  NODE_SET_PROTOTYPE_METHOD(constructor, "respondSMP",Respond_SMP);
  NODE_SET_PROTOTYPE_METHOD(constructor, "abortSMP",Abort_SMP);
  NODE_SET_PROTOTYPE_METHOD(constructor, "extraSymKey",Extra_Sym_Key);

  target->Set(name, constructor->GetFunction());
}

Handle<Value> MessageAppOps::New(const Arguments& args) {
	HandleScope scope;

	MessageAppOps* obj = new MessageAppOps();

	obj->messageops_ = new OtrlMessageAppOps();
	obj->messageops_->policy=op_policy;
	obj->messageops_->create_privkey=op_create_privkey;
	obj->messageops_->is_logged_in=op_is_logged_in;
	obj->messageops_->inject_message=op_inject_message;
	obj->messageops_->update_context_list=op_update_context_list;
	obj->messageops_->new_fingerprint=op_new_fingerprint;
	obj->messageops_->write_fingerprints=op_write_fingerprints;
	obj->messageops_->gone_secure=op_gone_secure;
	obj->messageops_->gone_insecure=op_gone_insecure;
	obj->messageops_->still_secure=op_still_secure;
	obj->messageops_->max_message_size=op_max_message_size;
	obj->messageops_->account_name=op_account_name;
	obj->messageops_->account_name_free=op_account_name_free;

	//new in libotr-4
	obj->messageops_->received_symkey = op_received_symkey;
	obj->messageops_->otr_error_message = op_otr_error_message;
	obj->messageops_->otr_error_message_free = op_otr_error_message_free;
	obj->messageops_->resent_msg_prefix = NULL;
	obj->messageops_->resent_msg_prefix_free = NULL;
	obj->messageops_->handle_smp_event = op_handle_smp_event;
	obj->messageops_->handle_msg_event = op_handle_msg_event;
	obj->messageops_->create_instag = op_create_instag;
	obj->messageops_->convert_msg = NULL;
	obj->messageops_->convert_free = NULL;
	obj->messageops_->timer_control = NULL;

	obj->ui_event_ = Persistent<Function>::New(Local<Function>::Cast(args[0]));
	obj->Wrap(args.This());
	return args.This();
}

Handle<Value> MessageAppOps::Message_Sending(const Arguments& args) {
  HandleScope scope;
  Handle<Value> retvalue;
  MessageAppOps* ops = ObjectWrap::Unwrap<MessageAppOps>(args.This());

  if(!args.Length() > 0 || !args[0]->IsObject()){
	return scope.Close(V8EXCEPTION("Invalid arguments. First argument 'userstate' (UserState) excpected."));
  }
  if(!args.Length() > 1 || !args[1]->IsString()){
	return scope.Close(V8EXCEPTION("Invalid arguments. Second argument 'accountname' (string) excpected."));
  }
  if(!args.Length() > 2 || !args[2]->IsString()){
	return scope.Close(V8EXCEPTION("Invalid arguments. Third argument 'protocol' (string) excpected."));
  }
  if(!args.Length() > 3 || !args[3]->IsString()){
	return scope.Close(V8EXCEPTION("Invalid arguments. Fourth argument 'recipient' (string) excpected."));
  }
  if(!args.Length() > 4 || !args[4]->IsString()){
	return scope.Close(V8EXCEPTION("Invalid arguments. Fifth argument 'message' (string) excpected."));
  }
  if(!args.Length() > 5 || !args[5]->IsNumber()){
	return scope.Close(V8EXCEPTION("Invalid arguments. Sixth argument 'instag' (number) excpected."));
  }
  if(!args.Length() > 6 || !args[6]->IsObject()){
	return scope.Close(V8EXCEPTION("Invalid arguments. Seventh argument 'context' (ConnContext) excpected."));
  }

  UserState* user = node::ObjectWrap::Unwrap<UserState>(args[0]->ToObject());
  String::Utf8Value accountname(args[1]->ToString());
  String::Utf8Value protocol(args[2]->ToString());
  String::Utf8Value recipient(args[3]->ToString());
  String::Utf8Value message(args[4]->ToString());
  int to_instag = args[5]->Int32Value();
  ConnectionCtx* ctx = node::ObjectWrap::Unwrap<ConnectionCtx>(args[6]->ToObject());
  char *messagep=NULL;
  gcry_error_t err = otrl_message_sending(user->userstate_, ops->messageops_,(void *)ops,
		*accountname, *protocol, *recipient, to_instag, *message,NULL, &messagep,OTRL_FRAGMENT_SEND_SKIP,&ctx->context_,NULL,NULL);
  if( err ){
	retvalue = scope.Close(Undefined());
  }else{
	retvalue = scope.Close(String::New(messagep));
  }
  if(messagep !=NULL) otrl_message_free(messagep);

  return retvalue;
}

Handle<Value> MessageAppOps::Message_Receiving(const Arguments& args) {
  HandleScope scope;
  Handle<Value> retvalue;
  char *newmessage =NULL;
  OtrlTLV *tlvs = NULL;
  OtrlTLV *tlv = NULL;

  MessageAppOps* ops = ObjectWrap::Unwrap<MessageAppOps>(args.This());

  if(!args.Length() > 0 || !args[0]->IsObject()){
	return scope.Close(V8EXCEPTION("Invalid arguments. First argument 'userstate' (UserState) excpected."));
  }
  if(!args.Length() > 1 || !args[1]->IsString()){
	return scope.Close(V8EXCEPTION("Invalid arguments. Second argument 'accountname' (string) excpected."));
  }
  if(!args.Length() > 2 || !args[2]->IsString()){
	return scope.Close(V8EXCEPTION("Invalid arguments. Third argument 'protocol' (string) excpected."));
  }
  if(!args.Length() > 3 || !args[3]->IsString()){
	return scope.Close(V8EXCEPTION("Invalid arguments. Fourth argument 'sender' (string) excpected."));
  }
  if(!args.Length() > 4 || !args[4]->IsString()){
	return scope.Close(V8EXCEPTION("Invalid arguments. Fifth argument 'message' (string) excpected."));
  }
  if(!args.Length() > 5 || !args[5]->IsObject()){
	return scope.Close(V8EXCEPTION("Invalid arguments. Sixth argument 'context' (ConnContext) excpected."));
  }
  UserState* user = node::ObjectWrap::Unwrap<UserState>(args[0]->ToObject());
  String::Utf8Value accountname(args[1]->ToString());
  String::Utf8Value protocol(args[2]->ToString());
  String::Utf8Value sender(args[3]->ToString());
  String::Utf8Value message(args[4]->ToString());
  ConnectionCtx* ctx = node::ObjectWrap::Unwrap<ConnectionCtx>(args[5]->ToObject());

  int status = otrl_message_receiving(user->userstate_, ops->messageops_,(void *)ops,
		*accountname, *protocol, *sender, *message, &newmessage, &tlvs,&ctx->context_,NULL,NULL);

  tlv = otrl_tlv_find(tlvs, OTRL_TLV_DISCONNECTED);
  if(tlv){
	notifyRemoteDisconnected(ops,ctx->context_);
  }
  if(tlvs!=NULL) otrl_tlv_free(tlvs);

  if(status==1) retvalue = Undefined();
  if(status==0) {
	 retvalue = (newmessage==NULL) ? (Handle<Value>)args[4] : String::New(newmessage);
  }
  if(newmessage!=NULL) otrl_message_free(newmessage);
  return scope.Close(retvalue);
}

Handle<Value> MessageAppOps::Extra_Sym_Key(const Arguments& args) {
  HandleScope scope;
  Handle<Value> retvalue;

  MessageAppOps* ops = ObjectWrap::Unwrap<MessageAppOps>(args.This());

  if(!args.Length() > 0 || !args[0]->IsObject()){
	return scope.Close(V8EXCEPTION("Invalid arguments. First argument 'userstate' (UserState) excpected."));
  }
  if(!args.Length() > 1 || !args[1]->IsObject()){
	return scope.Close(V8EXCEPTION("Invalid arguments. Second argument 'context' (ConnContext) excpected."));
  }
  if(!args.Length() > 2 || !args[2]->IsNumber()){
	return scope.Close(V8EXCEPTION("Invalid arguments. Third argument 'use' (Number) excpected."));
  }
  if(!args.Length() > 3 || !args[3]->IsObject()){
	return scope.Close(V8EXCEPTION("Invalid arguments. Fourth argument 'usedata' (Buffer) excpected."));
  }
  UserState* user = node::ObjectWrap::Unwrap<UserState>(args[0]->ToObject());
  ConnectionCtx* ctx = node::ObjectWrap::Unwrap<ConnectionCtx>(args[1]->ToObject());
  int use = args[2]->Int32Value();
  size_t usedata_length = node::Buffer::Length(args[3]->ToObject());
  unsigned char *usedata = (unsigned char*)node::Buffer::Data(args[3]->ToObject());

  unsigned char symkey[OTRL_EXTRAKEY_BYTES];
  node::Buffer *slowBuf;

  gcry_error_t err = otrl_message_symkey(user->userstate_,ops->messageops_,(void*)ops,ctx->context_,
		use, usedata, usedata_length, symkey);
  if(err==0){
	  slowBuf = node::Buffer::New(OTRL_EXTRAKEY_BYTES);
	  ::memcpy((void *) node::Buffer::Data(slowBuf), symkey, OTRL_EXTRAKEY_BYTES);
  }else{
	  return scope.Close(Undefined());
  }

  v8::Local<v8::Object> globalObj = v8::Context::GetCurrent()->Global();
  v8::Local<v8::Function> bufferConstructor = v8::Local<v8::Function>::Cast(globalObj->Get(v8::String::New("Buffer")));
  v8::Handle<v8::Value> constructorArgs[3] = { slowBuf->handle_, v8::Integer::New(OTRL_EXTRAKEY_BYTES), v8::Integer::New(0) };
  v8::Local<v8::Object> actualBuffer = bufferConstructor->NewInstance(3, constructorArgs);

  return scope.Close(actualBuffer);
}
void MessageAppOps::notifyRemoteDisconnected(MessageAppOps* ops, ConnContext *context){

	otrl_context_force_plaintext(context);

	Local<Object> eobj = Object::New();
	eobj->Set(String::NewSymbol("EVENT"),String::New( "remote_disconnected" ));
	eobj->Set(String::NewSymbol("username"), String::New(context->username));
	eobj->Set(String::NewSymbol("accountname"), String::New(context->accountname));
	eobj->Set(String::NewSymbol("protocol"), String::New(context->protocol));
	eobj->Set(String::NewSymbol("context"), ConnectionCtx::WrapConnectionCtx(context) );

	QueEvent(eobj,ops->ui_event_);
}

void MessageAppOps::notifySMPResult(MessageAppOps* ops, ConnContext *context,const char* result){
	Local<Object> eobj = Object::New();
	eobj->Set(String::NewSymbol("EVENT"),String::New( result ));
	eobj->Set(String::NewSymbol("username"), String::New(context->username));
	eobj->Set(String::NewSymbol("accountname"), String::New(context->accountname));
	eobj->Set(String::NewSymbol("protocol"), String::New(context->protocol));
	eobj->Set(String::NewSymbol("context"), ConnectionCtx::WrapConnectionCtx(context) );

	QueEvent(eobj,ops->ui_event_);
}
void MessageAppOps::notifyIncomingSMPRequest(MessageAppOps* ops, ConnContext *context, char* question){
	Local<Object> eobj = Object::New();
	eobj->Set(String::NewSymbol("EVENT"),String::New( "smp_request" ));
	eobj->Set(String::NewSymbol("username"), String::New(context->username));
	eobj->Set(String::NewSymbol("accountname"), String::New(context->accountname));
	eobj->Set(String::NewSymbol("protocol"), String::New(context->protocol));
	eobj->Set(String::NewSymbol("context"), ConnectionCtx::WrapConnectionCtx(context) );

	if(question==NULL){
		eobj->Set(String::NewSymbol("question"),Undefined());
	}else{
		eobj->Set(String::NewSymbol("question"),String::New(question));
	}

	QueEvent(eobj,ops->ui_event_);
}

Handle<Value> MessageAppOps::Disconnect(const Arguments& args) {
  HandleScope scope;
  MessageAppOps* ops = ObjectWrap::Unwrap<MessageAppOps>(args.This());

  if(!args.Length() > 0 || !args[0]->IsObject()){
	return scope.Close(V8EXCEPTION("Invalid arguments. First argument 'userstate' (UserState) excpected."));
  }
  if(!args.Length() > 1 || !args[1]->IsString()){
	return scope.Close(V8EXCEPTION("Invalid arguments. Second argument 'accountname' (string) excpected."));
  }
  if(!args.Length() > 2 || !args[2]->IsString()){
	return scope.Close(V8EXCEPTION("Invalid arguments. Third argument 'protocol' (string) excpected."));
  }
  if(!args.Length() > 3 || !args[3]->IsString()){
	return scope.Close(V8EXCEPTION("Invalid arguments. Fourth argument 'recipient' (string) excpected."));
  }
  if(!args.Length() > 4 || !args[4]->IsNumber()){
	return scope.Close(V8EXCEPTION("Invalid arguments. Fifth argument 'instag' (number) excpected."));
  }

  UserState* user = node::ObjectWrap::Unwrap<UserState>(args[0]->ToObject());
  String::Utf8Value accountname(args[1]->ToString());
  String::Utf8Value protocol(args[2]->ToString());
  String::Utf8Value recipient(args[3]->ToString());
  int instag = args[4]->Int32Value();
  otrl_message_disconnect(user->userstate_,ops->messageops_,(void*)ops,*accountname,*protocol,*recipient,instag);
  return scope.Close(Undefined());
}

Handle<Value> MessageAppOps::Initiate_SMP(const Arguments& args) {
  HandleScope scope;
  MessageAppOps* ops = ObjectWrap::Unwrap<MessageAppOps>(args.This());

  if(!args.Length() > 0 || !args[0]->IsObject()){
	return scope.Close(V8EXCEPTION("Invalid arguments. First argument 'userstate' (UserState) excpected."));
  }
  if(!args.Length() > 1 || !args[1]->IsObject()){
	return scope.Close(V8EXCEPTION("Invalid arguments. Second argument 'context' (ConnContext) excpected."));
  }
  if(!args.Length() > 2 || !args[2]->IsString()){
	return scope.Close(V8EXCEPTION("Invalid arguments. Third argument 'secret' (string) excpected."));
  }
  if(args.Length() > 3 && !args[3]->IsString()){
	return scope.Close(V8EXCEPTION("Invalid arguments. Optional Fourth argument 'question' (string) excpected."));
  }

  UserState* user = node::ObjectWrap::Unwrap<UserState>(args[0]->ToObject());
  ConnectionCtx* ctx = node::ObjectWrap::Unwrap<ConnectionCtx>(args[1]->ToObject());
  String::Utf8Value secret(args[2]->ToString());

  //don't init SMP auth if its is already progressing
  if(ctx->context_->smstate->nextExpected == OTRL_SMP_EXPECT1 ){
	  if(args.Length()>3){
		  String::Utf8Value question(args[3]->ToString());
		  otrl_message_initiate_smp_q(user->userstate_,ops->messageops_,(void*)ops,ctx->context_,(const char*)*question,(const unsigned char*)*secret,strlen(*secret));
	  }else{
		 otrl_message_initiate_smp(user->userstate_,ops->messageops_,(void*)ops,ctx->context_,(const unsigned char*)*secret,strlen(*secret));
	  }
  }
  return scope.Close(Undefined());
}

Handle<Value> MessageAppOps::Respond_SMP(const Arguments& args) {
  HandleScope scope;
  MessageAppOps* ops = ObjectWrap::Unwrap<MessageAppOps>(args.This());

  if(!args.Length() > 0 || !args[0]->IsObject()){
	return scope.Close(V8EXCEPTION("Invalid arguments. First argument 'userstate' (UserState) excpected."));
  }
  if(!args.Length() > 1 || !args[1]->IsObject()){
	return scope.Close(V8EXCEPTION("Invalid arguments. Second argument 'context' (ConnContext) excpected."));
  }
  if(!args.Length() > 2 || !args[2]->IsString()){
	return scope.Close(V8EXCEPTION("Invalid arguments. Third argument 'secret' (string) excpected."));
  }

  UserState* user = node::ObjectWrap::Unwrap<UserState>(args[0]->ToObject());
  ConnectionCtx* ctx = node::ObjectWrap::Unwrap<ConnectionCtx>(args[1]->ToObject());
  String::Utf8Value secret(args[2]->ToString());

  otrl_message_respond_smp(user->userstate_,ops->messageops_,(void*)ops,ctx->context_,(const unsigned char*)*secret,strlen(*secret));

  return scope.Close(Undefined());
}

Handle<Value> MessageAppOps::Abort_SMP(const Arguments& args) {
  HandleScope scope;
  MessageAppOps* ops = ObjectWrap::Unwrap<MessageAppOps>(args.This());

  if(!args.Length() > 0 || !args[0]->IsObject()){
	return scope.Close(V8EXCEPTION("Invalid arguments. First argument 'userstate' (UserState) excpected."));
  }
  if(!args.Length() > 1 || !args[1]->IsObject()){
	return scope.Close(V8EXCEPTION("Invalid arguments. Second argument 'context' (ConnContext) excpected."));
  }

  UserState* user = node::ObjectWrap::Unwrap<UserState>(args[0]->ToObject());
  ConnectionCtx* ctx = node::ObjectWrap::Unwrap<ConnectionCtx>(args[1]->ToObject());

  otrl_message_abort_smp(user->userstate_,ops->messageops_,(void*)ops,ctx->context_);

  return scope.Close(Undefined());
}

OtrlPolicy MessageAppOps::op_policy(void *opdata, ConnContext *context){
	MessageAppOps* ops = (MessageAppOps*)opdata;

	Local<Object> eobj = Object::New();
	eobj->Set(String::NewSymbol("EVENT"),String::New("policy"));
	eobj->Set(String::NewSymbol("username"), String::New(context->username));
	eobj->Set(String::NewSymbol("accountname"), String::New(context->accountname));
	eobj->Set(String::NewSymbol("protocol"), String::New(context->protocol));

	const unsigned argc = 1;
	Local<Value> argv[argc] = { eobj };
	TryCatch try_catch;
	Handle<Value> result = ops->ui_event_->Call(Context::GetCurrent()->Global(), argc, argv);
	if (try_catch.HasCaught()) {
		node::FatalException(try_catch);
	}

	if(!result->IsNumber()) return OTRL_POLICY_ALWAYS;

	return (OtrlPolicy)((unsigned int)result->NumberValue());
}

void MessageAppOps::op_create_privkey(void *opdata, const char *accountname, const char *protocol){
	MessageAppOps* ops = (MessageAppOps*)opdata;

	Local<Object> eobj = Object::New();
	eobj->Set(String::NewSymbol("EVENT"),String::New("create_privkey"));
	eobj->Set(String::NewSymbol("accountname"), String::New(accountname));
	eobj->Set(String::NewSymbol("protocol"), String::New(protocol));

	SyncEvent(eobj,ops->ui_event_);
}

int MessageAppOps::op_is_logged_in(void *opdata, const char *accountname,const char *protocol, const char *recipient){
	MessageAppOps* ops = (MessageAppOps*)opdata;

	Local<Object> eobj = Object::New();
	eobj->Set(String::NewSymbol("EVENT"),String::New("is_logged_in"));
	eobj->Set(String::NewSymbol("accountname"), String::New(accountname));
	eobj->Set(String::NewSymbol("protocol"), String::New(protocol));
	eobj->Set(String::NewSymbol("recipient"), String::New(recipient));

	const unsigned argc = 1;
	Local<Value> argv[argc] = { eobj };
	TryCatch try_catch;
	Handle<Value> result = ops->ui_event_->Call(Context::GetCurrent()->Global(), argc, argv);
	if (try_catch.HasCaught()) {
		node::FatalException(try_catch);
	}

	if(!result->IsNumber()) return 0;
	return (int)result->NumberValue();
}

void MessageAppOps::op_inject_message(void *opdata, const char *accountname, const char *protocol, const char *recipient, const char *message){
	MessageAppOps* ops = (MessageAppOps*)opdata;

	Local<Object> eobj = Object::New();
	eobj->Set(String::NewSymbol("EVENT"),String::New("inject_message"));
	eobj->Set(String::NewSymbol("accountname"), String::New(accountname));
	eobj->Set(String::NewSymbol("protocol"), String::New(protocol));
	eobj->Set(String::NewSymbol("username"), String::New(recipient));
	eobj->Set(String::NewSymbol("message"), String::New(message));

	QueEvent(eobj,ops->ui_event_);
}

void MessageAppOps::op_update_context_list(void *opdata){
	MessageAppOps* ops = (MessageAppOps*)opdata;

	Local<Object> eobj = Object::New();
	eobj->Set(String::NewSymbol("EVENT"),String::New("update_context_list"));

	QueEvent(eobj,ops->ui_event_);
}

void MessageAppOps::op_new_fingerprint(void *opdata, OtrlUserState us,	const char *accountname, const char *protocol, const char *username, unsigned char fingerprint[20]){
	MessageAppOps* ops = (MessageAppOps*)opdata;

	Local<Object> eobj = Object::New();
	eobj->Set(String::NewSymbol("EVENT"),String::New("new_fingerprint"));
	eobj->Set(String::NewSymbol("accountname"), String::New(accountname));
	eobj->Set(String::NewSymbol("protocol"), String::New(protocol));
	eobj->Set(String::NewSymbol("username"), String::New(username));
	eobj->Set(String::NewSymbol("userstate"), UserState::WrapUserState(us) );

	char human[45];
	otrl_privkey_hash_to_human(human, fingerprint);
	eobj->Set(String::NewSymbol("fingerprint"), String::New(human));

	SyncEvent(eobj,ops->ui_event_);
}

void MessageAppOps::op_write_fingerprints(void *opdata){
	MessageAppOps* ops = (MessageAppOps*)opdata;

	Local<Object> eobj = Object::New();
	eobj->Set(String::NewSymbol("EVENT"),String::New("write_fingerprints"));

	SyncEvent(eobj,ops->ui_event_);
}

void MessageAppOps::op_gone_secure(void *opdata, ConnContext *context){
	contextSecureStatusUpdate(opdata,context,"gone_secure");
}

void MessageAppOps::op_gone_insecure(void *opdata, ConnContext *context){
	contextSecureStatusUpdate(opdata,context,"gone_insecure");
}

void MessageAppOps::op_still_secure(void *opdata, ConnContext *context, int is_reply){
	contextSecureStatusUpdate(opdata,context,"still_secure");
}

int MessageAppOps::op_max_message_size(void *opdata, ConnContext *context){
	MessageAppOps* ops = (MessageAppOps*)opdata;

	Local<Object> eobj = Object::New();
	eobj->Set(String::NewSymbol("EVENT"),String::New("max_message_size"));
	eobj->Set(String::NewSymbol("username"), String::New(context->username));
	eobj->Set(String::NewSymbol("accountname"), String::New(context->accountname));
	eobj->Set(String::NewSymbol("protocol"), String::New(context->protocol));
	eobj->Set(String::NewSymbol("context"), ConnectionCtx::WrapConnectionCtx(context) );

	const unsigned argc = 1;
	Local<Value> argv[argc] = { eobj };
	TryCatch try_catch;
	Handle<Value> result = ops->ui_event_->Call(Context::GetCurrent()->Global(), argc, argv);
	if (try_catch.HasCaught()) {
		node::FatalException(try_catch);
	}

	if(!result->IsNumber()) return 0;//default no fragmentation
	return (int)result->NumberValue();
}

const char *MessageAppOps::op_account_name(void *opdata, const char *account, const char *protocol){
	return account;
}

void MessageAppOps::op_account_name_free(void *opdata, const char *account_name){
	return;
}
//new libotr4 ops
void MessageAppOps::op_received_symkey(void *opdata, ConnContext *context,
		unsigned int use, const unsigned char *usedata,
		size_t usedatalen, const unsigned char *symkey){

	MessageAppOps* ops = (MessageAppOps*)opdata;

	v8::Local<v8::Object> globalObj = v8::Context::GetCurrent()->Global();
	v8::Local<v8::Function> bufferConstructor = v8::Local<v8::Function>::Cast(globalObj->Get(v8::String::New("Buffer")));
	Local<Object> eobj = Object::New();
	eobj->Set(String::NewSymbol("EVENT"),String::New("received_symkey"));
	eobj->Set(String::NewSymbol("use"), Number::New(use));

	node::Buffer *slowBuf_usedata = node::Buffer::New(usedatalen);
	::memcpy((void *) node::Buffer::Data(slowBuf_usedata), usedata, usedatalen);
	v8::Handle<v8::Value> constructorArgs[3] = { slowBuf_usedata->handle_, v8::Integer::New(usedatalen), v8::Integer::New(0) };
	v8::Local<v8::Object> actualBuffer_usedata = bufferConstructor->NewInstance(3, constructorArgs);

	node::Buffer *slowBuf_key = node::Buffer::New(OTRL_EXTRAKEY_BYTES);
	::memcpy((void *) node::Buffer::Data(slowBuf_key), symkey, OTRL_EXTRAKEY_BYTES);
	v8::Handle<v8::Value> constructorArgs_key[3] = { slowBuf_key->handle_, v8::Integer::New(OTRL_EXTRAKEY_BYTES), v8::Integer::New(0) };
	v8::Local<v8::Object> actualBuffer_key = bufferConstructor->NewInstance(3, constructorArgs_key);

	eobj->Set(String::NewSymbol("usedata"), actualBuffer_usedata);
	eobj->Set(String::NewSymbol("key"), actualBuffer_key);
	eobj->Set(String::NewSymbol("context"), ConnectionCtx::WrapConnectionCtx(context) );

	QueEvent(eobj,ops->ui_event_);
}

const char * MessageAppOps::op_otr_error_message(void *opdata, ConnContext *context, OtrlErrorCode err_code){
	switch( err_code ){
		case OTRL_ERRCODE_ENCRYPTION_ERROR: return "encryption-error";
		case OTRL_ERRCODE_MSG_NOT_IN_PRIVATE: return "msg-not-in-private";
		case OTRL_ERRCODE_MSG_UNREADABLE: return "msg-unreadble";
		case OTRL_ERRCODE_MSG_MALFORMED: return "msg-malformed";
		case OTRL_ERRCODE_NONE: return "no-error";
	}
	return "";
}

void MessageAppOps::op_otr_error_message_free(void *opdata, const char *err_msg){
}

void MessageAppOps::op_handle_smp_event(void *opdata, OtrlSMPEvent smp_event,
		ConnContext *context, unsigned short progress_percent,
		char *question){
	MessageAppOps* ops = (MessageAppOps*)opdata;

	switch(smp_event){
		case OTRL_SMPEVENT_ASK_FOR_SECRET:
			notifyIncomingSMPRequest(ops,context,NULL);return;
		case OTRL_SMPEVENT_ASK_FOR_ANSWER:
			notifyIncomingSMPRequest(ops,context,question);return;
		case OTRL_SMPEVENT_IN_PROGRESS:
			return;
		case OTRL_SMPEVENT_SUCCESS:
			notifySMPResult(ops,context,"smp_complete");return;
		case OTRL_SMPEVENT_FAILURE:
			notifySMPResult(ops,context,"smp_failed");return;
		case OTRL_SMPEVENT_CHEATED:
		case OTRL_SMPEVENT_ERROR:
			notifySMPResult(ops,context,"smp_error");return;//must call otrl_message_abort_smp
		case OTRL_SMPEVENT_ABORT:
			notifySMPResult(ops,context,"smp_aborted");return;
		case OTRL_SMPEVENT_NONE:
			break;
	}
}

void MessageAppOps::op_handle_msg_event(void *opdata, OtrlMessageEvent msg_event,
		ConnContext *context, const char *message,
		gcry_error_t err){

	MessageAppOps* ops = (MessageAppOps*)opdata;

	Local<Object> eobj = Object::New();
	eobj->Set(String::NewSymbol("EVENT"),String::New("msg_event"));
	eobj->Set(String::NewSymbol("event"), Number::New(msg_event));
	eobj->Set(String::NewSymbol("message"), message == NULL ? Undefined():String::New(message));
	eobj->Set(String::NewSymbol("err"), err == 0 ? Undefined():String::New(gcry_strerror(err)));

	QueEvent(eobj,ops->ui_event_);
}

void MessageAppOps::op_create_instag(void *opdata, const char *accountname,
		const char *protocol){
	MessageAppOps* ops = (MessageAppOps*)opdata;

	Local<Object> eobj = Object::New();
	eobj->Set(String::NewSymbol("EVENT"),String::New("create_instag"));
	eobj->Set(String::NewSymbol("accountname"), String::New(accountname));
	eobj->Set(String::NewSymbol("protocol"), String::New(protocol));

	SyncEvent(eobj,ops->ui_event_);
}


void MessageAppOps::contextSecureStatusUpdate(void *opdata, ConnContext* context, const char* event){
	MessageAppOps* ops = (MessageAppOps*)opdata;

	Local<Object> eobj = Object::New();
	eobj->Set(String::NewSymbol("EVENT"),String::New( event ));
	eobj->Set(String::NewSymbol("username"), String::New(context->username));
	eobj->Set(String::NewSymbol("accountname"), String::New(context->accountname));
	eobj->Set(String::NewSymbol("protocol"), String::New(context->protocol));
	eobj->Set(String::NewSymbol("context"), ConnectionCtx::WrapConnectionCtx(context) );

	QueEvent(eobj,ops->ui_event_);

}

void MessageAppOps::SyncEvent(Local<Object> obj, Persistent<Function> callback){
	HandleScope scope;
	const unsigned argc = 1;
	Local<Value> argv[argc] = { obj };
	TryCatch try_catch;
	callback->Call(Context::GetCurrent()->Global(), argc, argv);
	if (try_catch.HasCaught()) {
		puts(">> Node Fatal Exception <<");
		node::FatalException(try_catch);
	}
	scope.Close(Undefined());
}
void MessageAppOps::QueEvent(Local<Object> obj, Persistent<Function> callback){
	EventBaton *baton = new EventBaton();
	baton->request.data = baton;
	//baton->callback = Persistent<Function>::New(callback);
	baton->callback = callback;
	baton->event = Persistent<Object>::New(obj);
	int status = uv_queue_work(uv_default_loop(), &baton->request, NullAsyncWork, (uv_after_work_cb)FireEvent);
	assert(status == 0);
}
void MessageAppOps::FireEvent(uv_work_t* req){
	HandleScope scope;
	EventBaton* baton = static_cast<EventBaton*>(req->data);
	const unsigned argc = 1;
	Local<Object> obj_ = Local<Object>::New(baton->event);
	Local<Value> argv[argc] = { obj_ };
	TryCatch try_catch;
	baton->callback->Call(Context::GetCurrent()->Global(), argc, argv);
	if (try_catch.HasCaught()) {
		puts(">> Node Fatal Exception <<");
		node::FatalException(try_catch);
	}
	baton->event.Dispose();
	delete baton;
}

}
