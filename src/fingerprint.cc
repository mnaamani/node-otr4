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
v8::Persistent<v8::FunctionTemplate> KeyFingerprint::constructor;

KeyFingerprint::KeyFingerprint(Fingerprint* fp) : ObjectWrap(),
	fingerprint_(fp) {};

KeyFingerprint::~KeyFingerprint() {};

void KeyFingerprint::Init(Handle<Object> target) {
  HandleScope scope;

  // Prepare constructor template
  Local<FunctionTemplate> tpl = FunctionTemplate::New(New);
  Local<String> name = String::NewSymbol("Fingerprint");

  constructor = Persistent<FunctionTemplate>::New(tpl);
  // ObjectWrap uses the first internal field to store the wrapped pointer.
  constructor->InstanceTemplate()->SetInternalFieldCount(1);
  constructor->SetClassName(name);

  // Prototype
  NODE_SET_PROTOTYPE_ACCESSOR(constructor, "human_", fpGetter,NULL);
  NODE_SET_PROTOTYPE_ACCESSOR(constructor, "trust_", fpGetter,fpSetter);

  NODE_SET_PROTOTYPE_METHOD(constructor, "forget",Forget);

  target->Set(name, constructor->GetFunction());
}

Handle<Value> KeyFingerprint::New(const Arguments& args) {
  HandleScope scope;
  Fingerprint *fp=NULL;
  KeyFingerprint* obj = new KeyFingerprint(fp);
  obj->Wrap(args.This());

  return scope.Close(args.This());
}
v8::Handle<v8::Value> KeyFingerprint::WrapKeyFingerprint(Fingerprint *fp){
		v8::Local<v8::Object> o = constructor->InstanceTemplate()->NewInstance();
		KeyFingerprint *obj = node::ObjectWrap::Unwrap<KeyFingerprint>(o);
		obj->fingerprint_ = fp;
		return o;
}

void KeyFingerprint::fpSetter(Local<String> property, Local<Value> value, const AccessorInfo& info) {
	KeyFingerprint* obj = node::ObjectWrap::Unwrap<KeyFingerprint>(info.This());
	Fingerprint *fp = obj->fingerprint_;
	if(!fp) return;

	std::string prop = cvv8::CastFromJS<std::string>(property);
	String::Utf8Value newTrust(value->ToString());

	IfStrEqual(prop,"trust_"){
		otrl_context_set_trust(fp,(const char*)*newTrust);
	}
}

Handle<Value> KeyFingerprint::fpGetter(Local<String> property, const AccessorInfo& info) {
	KeyFingerprint* obj = node::ObjectWrap::Unwrap<KeyFingerprint>(info.This());
	Fingerprint *fp = obj->fingerprint_;
	if(!fp) return Undefined();

	std::string prop = cvv8::CastFromJS<std::string>(property);

	IfStrEqual(prop,"human_"){
		char human[45];
		otrl_privkey_hash_to_human(human, fp->fingerprint);
		return String::New(human);
	}
	IfStrEqual(prop,"trust_"){
		if(fp->trust == NULL) return Undefined();
		return String::New(fp->trust);
	}

	return Undefined();
}

Handle<Value> KeyFingerprint::Forget(const Arguments& args){
	KeyFingerprint *obj = ObjectWrap::Unwrap<KeyFingerprint>(args.This());
	Fingerprint *fp = obj->fingerprint_;
	otrl_context_forget_fingerprint(fp, 1);
	obj->fingerprint_ = NULL;
	return Undefined();
}

}
