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
    #include "otr-extras.h"
}

using namespace v8;

namespace otr {
v8::Persistent<v8::FunctionTemplate> PrivateKey::constructor;

PrivateKey::PrivateKey(OtrlPrivKey* privkey) : ObjectWrap(),
    privkey_(privkey) {};

PrivateKey::~PrivateKey() {};

void PrivateKey::Init(Handle<Object> target) {
  HandleScope scope;

  // Prepare constructor template
  Local<FunctionTemplate> tpl = FunctionTemplate::New(New);
  Local<String> name = String::NewSymbol("PrivateKey");

  constructor = Persistent<FunctionTemplate>::New(tpl);
  // ObjectWrap uses the first internal field to store the wrapped pointer.
  constructor->InstanceTemplate()->SetInternalFieldCount(1);
  constructor->SetClassName(name);

  // Prototype
  NODE_SET_PROTOTYPE_ACCESSOR(constructor, "protocol", keyGetter,keySetter);
  NODE_SET_PROTOTYPE_ACCESSOR(constructor, "accountname", keyGetter,keySetter);
  NODE_SET_PROTOTYPE_ACCESSOR(constructor, "p", keyGetter,keySetter);
  NODE_SET_PROTOTYPE_ACCESSOR(constructor, "q", keyGetter,keySetter);
  NODE_SET_PROTOTYPE_ACCESSOR(constructor, "g", keyGetter,keySetter);
  NODE_SET_PROTOTYPE_ACCESSOR(constructor, "y", keyGetter,keySetter);
  NODE_SET_PROTOTYPE_ACCESSOR(constructor, "x", keyGetter,keySetter);

  target->Set(name, constructor->GetFunction());
}

Handle<Value> PrivateKey::New(const Arguments& args) {
  HandleScope scope;
  OtrlPrivKey *privkey = NULL;
  PrivateKey* obj = new PrivateKey(privkey);
  obj->Wrap(args.This());

  return scope.Close(args.This());
}
v8::Handle<v8::Value> PrivateKey::WrapPrivateKey(OtrlPrivKey *privkey){
        v8::Local<v8::Object> o = constructor->InstanceTemplate()->NewInstance();
        PrivateKey *obj = node::ObjectWrap::Unwrap<PrivateKey>(o);
        obj->privkey_ = privkey;
        return o;
}

void PrivateKey::keySetter(Local<String> property, Local<Value> value, const AccessorInfo& info) {
}

Handle<Value> PrivateKey::keyGetter(Local<String> property, const AccessorInfo& info) {
    HandleScope scope;
    PrivateKey* obj = node::ObjectWrap::Unwrap<PrivateKey>(info.This());
    OtrlPrivKey *privkey = obj->privkey_;
    if(privkey==NULL) return scope.Close(Undefined());

    char buffer[1024];
    size_t nbytes = 0;
    gcry_error_t err;

    std::string prop = cvv8::CastFromJS<std::string>(property);

    IfStrEqual(prop,"protocol"){
        return scope.Close(String::New(privkey->protocol));
    }
    IfStrEqual(prop,"accountname"){
        return scope.Close(String::New(privkey->accountname));
    }

    IfStrEqual(prop,"p"){
        err = jsapi_privkey_get_dsa_token(privkey,"p",(unsigned char*)buffer,1024,&nbytes);
        if(err ==0 && nbytes > 0) return scope.Close(String::New(buffer));
    }
    IfStrEqual(prop,"q"){
        err = jsapi_privkey_get_dsa_token(privkey,"q",(unsigned char*)buffer,1024,&nbytes);
        if(err ==0 && nbytes > 0) return scope.Close(String::New(buffer));
    }
    IfStrEqual(prop,"g"){
        err = jsapi_privkey_get_dsa_token(privkey,"g",(unsigned char*)buffer,1024,&nbytes);
        if(err ==0 && nbytes > 0) return scope.Close(String::New(buffer));
    }
    IfStrEqual(prop,"x"){
        err = jsapi_privkey_get_dsa_token(privkey,"x",(unsigned char*)buffer,1024,&nbytes);
        if(err ==0 && nbytes > 0) return scope.Close(String::New(buffer));
    }
    IfStrEqual(prop,"y"){
        err = jsapi_privkey_get_dsa_token(privkey,"y",(unsigned char*)buffer,1024,&nbytes);
        if(err ==0 && nbytes > 0) return scope.Close(String::New(buffer));
    }
    return scope.Close(Undefined());
}

}
