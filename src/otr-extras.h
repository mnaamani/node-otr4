#include <errno.h>
#include <gcrypt.h>
#include <libotr/proto.h>
#include <libotr/userstate.h>
#include <libotr/privkey.h>
#include <libotr/tlv.h>
#include <libotr/message.h>
#include <libotr/serial.h>

gcry_error_t jsapi_privkey_delete(OtrlUserState us, const char *filename, const char *accountname, const char *protocol);
gcry_error_t jsapi_privkey_get_dsa_token(OtrlPrivKey *keyToExport, const char* token, unsigned char *buffer, size_t buflen, size_t *nbytes);
gcry_error_t jsapi_userstate_import_privkey(OtrlUserState us, char *accountname, char * protocol, char *p, char *q, char *g, char *y, char *x);
gcry_error_t jsapi_userstate_write_to_file(OtrlUserState us, const char *filename);
