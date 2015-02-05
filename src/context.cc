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

extern "C"{
	#include <libotr/privkey.h>
}

using namespace v8;

namespace otr {
v8::Persistent<v8::FunctionTemplate> ConnectionCtx::constructor;

ConnectionCtx::ConnectionCtx(ConnContext* context) : ObjectWrap(),
	context_(context) {};

ConnectionCtx::~ConnectionCtx() {};

void ConnectionCtx::Init(Handle<Object> target) {
  HandleScope scope;

  // Prepare constructor template
  Local<FunctionTemplate> tpl = FunctionTemplate::New(New);
  Local<String> name = String::NewSymbol("ConnContext");

  constructor = Persistent<FunctionTemplate>::New(tpl);
  // ObjectWrap uses the first internal field to store the wrapped pointer.
  constructor->InstanceTemplate()->SetInternalFieldCount(1);
  constructor->SetClassName(name);

  // Prototype
  NODE_SET_PROTOTYPE_ACCESSOR(constructor, "protocol_", ctxGetter,ctxSetter);
  NODE_SET_PROTOTYPE_ACCESSOR(constructor, "username_", ctxGetter,ctxSetter);
  NODE_SET_PROTOTYPE_ACCESSOR(constructor, "accountname_", ctxGetter,ctxSetter);
  NODE_SET_PROTOTYPE_ACCESSOR(constructor, "msgstate_", ctxGetter,ctxSetter);
  NODE_SET_PROTOTYPE_ACCESSOR(constructor, "fingerprint_", ctxGetter,ctxSetter);
  NODE_SET_PROTOTYPE_ACCESSOR(constructor, "protocol_version_", ctxGetter,ctxSetter);
  NODE_SET_PROTOTYPE_ACCESSOR(constructor, "smstate_", ctxGetter,ctxSetter);
  NODE_SET_PROTOTYPE_ACCESSOR(constructor, "trust_", ctxGetter,ctxSetter);
  NODE_SET_PROTOTYPE_ACCESSOR(constructor, "their_instance_", ctxGetter,ctxSetter);
  NODE_SET_PROTOTYPE_ACCESSOR(constructor, "our_instance_", ctxGetter,ctxSetter);
  NODE_SET_PROTOTYPE_ACCESSOR(constructor, "master_", ctxGetter,ctxSetter);

  NODE_SET_PROTOTYPE_METHOD(constructor, "masterFingerprints",MasterFingerprints);
  NODE_SET_PROTOTYPE_METHOD(constructor, "forget",Forget);

  target->Set(name, constructor->GetFunction());
}

Handle<Value> ConnectionCtx::New(const Arguments& args) {
  HandleScope scope;
  ConnContext *context=NULL;
  if(args.Length()==0){

  }else{
	  if(!args[0]->IsObject()){
		return scope.Close(V8EXCEPTION("Invalid arguments. First argument 'userstate' (UserState) excpected."));
	  }
	  if(!(args.Length() > 1) || !args[1]->IsString()){
		return scope.Close(V8EXCEPTION("Invalid arguments. Second argument 'accountname' (string) excpected."));
	  }
	  if(!(args.Length() > 2) || !args[2]->IsString()){
		return scope.Close(V8EXCEPTION("Invalid arguments. Third argument 'protocol' (string) excpected."));
	  }
	  if(!(args.Length() > 3) || !args[3]->IsString()){
		return scope.Close(V8EXCEPTION("Invalid arguments. Fourth argument 'recipient' (string) excpected."));
	  }

	  int addedp;
	  UserState* us = node::ObjectWrap::Unwrap<UserState>(args[0]->ToObject());
	  String::Utf8Value accountname(args[1]->ToString());
	  String::Utf8Value protocol(args[2]->ToString());
	  String::Utf8Value user(args[3]->ToString());
	  context = otrl_context_find(us->userstate_, *user,*accountname, *protocol, OTRL_INSTAG_MASTER, 1, &addedp, NULL,NULL);
  }
  ConnectionCtx* obj = new ConnectionCtx(context);
  obj->Wrap(args.This());

  return scope.Close(args.This());
}
v8::Handle<v8::Value> ConnectionCtx::WrapConnectionCtx(ConnContext *context){
		v8::Local<v8::Object> o = constructor->InstanceTemplate()->NewInstance();
		ConnectionCtx *obj = node::ObjectWrap::Unwrap<ConnectionCtx>(o);
		obj->context_ = context;
		return o;
}

Handle<Value> ConnectionCtx::Forget(const Arguments& args){
	HandleScope scope;
	ConnectionCtx *obj = ObjectWrap::Unwrap<ConnectionCtx>(args.This());
	ConnContext *ctx = obj->context_;
	obj->context_ = NULL;
	return scope.Close(Number::New(otrl_context_forget(ctx)));
}

Handle<Value> ConnectionCtx::MasterFingerprints(const Arguments& args){
	HandleScope scope;
	ConnectionCtx *obj = ObjectWrap::Unwrap<ConnectionCtx>(args.This());
	ConnContext *ctx = obj->context_;
	Fingerprint *fp;
	int count=0;

	if(!ctx) return scope.Close(Undefined());

	v8::Local<v8::Array> result = v8::Array::New();

	for(fp=ctx->m_context->fingerprint_root.next; fp; fp=fp->next) {
		result->Set(count++, KeyFingerprint::WrapKeyFingerprint(fp));
	}

	return scope.Close(result);
}

void ConnectionCtx::ctxSetter(Local<String> property, Local<Value> value, const AccessorInfo& info) {
}

Handle<Value> ConnectionCtx::ctxGetter(Local<String> property, const AccessorInfo& info) {
	HandleScope scope;
	ConnectionCtx* obj = node::ObjectWrap::Unwrap<ConnectionCtx>(info.This());
	ConnContext *ctx = obj->context_;
	if(!ctx) return scope.Close(Undefined());

	std::string prop = cvv8::CastFromJS<std::string>(property);

	IfStrEqual(prop,"protocol_"){
		return scope.Close(String::New(ctx->protocol));
	}
	IfStrEqual(prop,"username_"){
		return scope.Close(String::New(ctx->username));
	}
	IfStrEqual(prop,"accountname_"){
		return scope.Close(String::New(ctx->accountname));
	}
	IfStrEqual(prop,"msgstate_"){
		return scope.Close(Int32::New((unsigned int)ctx->msgstate));
	}
	IfStrEqual(prop,"protocol_version_"){
		return scope.Close(Int32::New((unsigned int)ctx->protocol_version));
	}
	IfStrEqual(prop,"smstate_"){
		return scope.Close(Int32::New((unsigned int)ctx->smstate->sm_prog_state));
	}
	IfStrEqual(prop,"fingerprint_"){
		if(ctx->active_fingerprint==NULL) return scope.Close(Undefined());
		char human[45];
		otrl_privkey_hash_to_human(human, ctx->active_fingerprint->fingerprint);
		return scope.Close(String::New(human));
	}
	IfStrEqual(prop,"trust_"){
		if(ctx->active_fingerprint==NULL) return scope.Close(Undefined());
		if(ctx->active_fingerprint->trust == NULL) return scope.Close(Undefined());
		return scope.Close(String::New(ctx->active_fingerprint->trust));
	}
	IfStrEqual(prop,"their_instance_"){
		return scope.Close(Number::New(ctx->their_instance));
	}
	IfStrEqual(prop,"our_instance_"){
		return scope.Close(Number::New(ctx->our_instance));
	}
	IfStrEqual(prop,"master_"){
		return scope.Close(WrapConnectionCtx(ctx->m_context));
	}

	IfStrEqual(prop,"master_fingerprint_root_"){
		return scope.Close(KeyFingerprint::WrapKeyFingerprint(ctx->m_context->fingerprint_root.next));
	}
	return scope.Close(Undefined());
}

}
