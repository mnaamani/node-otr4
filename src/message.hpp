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

#ifndef __NODE_OTR_MESSAGE_H__
#define __NODE_OTR_MESSAGE_H__

#include "otr.hpp"

extern "C" {
    #include <libotr/proto.h>
    #include <libotr/message.h>
}

namespace otr {
class MessageAppOps : public node::ObjectWrap {
 public:
  static void Init(v8::Handle<v8::Object> target); 
  static v8::Persistent<v8::FunctionTemplate> constructor;

 protected:  
  OtrlMessageAppOps* messageops_;
  v8::Persistent<v8::Function> ui_event_;

  MessageAppOps();
  ~MessageAppOps();
  
    static void contextSecureStatusUpdate(void *opdata, ConnContext* context, const char* event);
    static void notifyIncomingSMPRequest(MessageAppOps *ops, ConnContext *context, char *question);
    static void notifySMPResult(MessageAppOps* ops, ConnContext *context, const char* result);
    static void notifyRemoteDisconnected(MessageAppOps* ops, ConnContext *context);

    static OtrlPolicy op_policy(void *opdata, ConnContext *context);
    static void op_create_privkey(void *opdata, const char *accountname,const char *protocol);
    static int op_is_logged_in(void *opdata, const char *accountname,const char *protocol, const char *recipient);
    static void op_inject_message(void *opdata, const char *accountname, const char *protocol, const char *recipient, const char *message);
    static void op_update_context_list(void *opdata);
    static void op_new_fingerprint(void *opdata, OtrlUserState us,	const char *accountname, const char *protocol, const char *username, unsigned char fingerprint[20]);
    static void op_write_fingerprints(void *opdata);
    static void op_gone_secure(void *opdata, ConnContext *context);
    static void op_gone_insecure(void *opdata, ConnContext *context);
    static void op_still_secure(void *opdata, ConnContext *context, int is_reply);
    static int op_max_message_size(void *opdata, ConnContext *context);
    static const char *op_account_name(void *opdata, const char *account, const char *protocol);
    static void op_account_name_free(void *opdata, const char *account_name);
    static void op_received_symkey(void *opdata, ConnContext *context, unsigned int use, const unsigned char *usedata, size_t usedatalen, const unsigned char *symkey);
    static void op_otr_error_message_free(void *opdata, const char *err_msg);
    static const char *op_otr_error_message(void *opdata, ConnContext *context, OtrlErrorCode err_code);
    static void op_handle_smp_event(void *opdata, OtrlSMPEvent smp_event,
        ConnContext *context, unsigned short progress_percent,
        char *question);
    static void op_handle_msg_event(void *opdata, OtrlMessageEvent msg_event,
        ConnContext *context, const char *message,
        gcry_error_t err);
    static void op_create_instag(void *opdata, const char *accountname,
        const char *protocol);

    static v8::Handle<v8::Value> New(const v8::Arguments& args);
    static v8::Handle<v8::Value> Message_Sending(const v8::Arguments& args);
    static v8::Handle<v8::Value> Message_Receiving(const v8::Arguments& args);
    static v8::Handle<v8::Value> Disconnect(const v8::Arguments& args);
    static v8::Handle<v8::Value> Initiate_SMP(const v8::Arguments& args);
    static v8::Handle<v8::Value> Respond_SMP(const v8::Arguments& args);
    static v8::Handle<v8::Value> Abort_SMP(const v8::Arguments& args);
    static v8::Handle<v8::Value> Extra_Sym_Key(const v8::Arguments& args);

    static void QueEvent(v8::Local<v8::Object> obj, v8::Persistent<v8::Function> callback);
    static void FireEvent(uv_work_t* req);
    static void SyncEvent(v8::Local<v8::Object> obj, v8::Persistent<v8::Function> callback);

};

struct EventBaton {
    uv_work_t request;
    v8::Persistent<v8::Function> callback;
    v8::Persistent<v8::Object> event;
};

}
#endif
