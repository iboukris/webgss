// MIT Licensed, see LICENSE file
// Copyright (c) 2021 Isaac Boukris <iboukris@gmail.com>

#ifndef K5DRV_H_INCLUDED
#define K5DRV_H_INCLUDED

extern "C" {

#include <krb5/krb5.h>
#include <gssapi/gssapi_krb5.h>


/* Missing exports */

typedef struct _krb5_kkdcp_message {
    krb5_data kerb_message;
    krb5_data target_domain;
    krb5_int32 dclocator_hint;
} krb5_kkdcp_message;

krb5_error_code
encode_krb5_kkdcp_message(const krb5_kkdcp_message *, krb5_data **);

krb5_error_code
decode_krb5_kkdcp_message(const krb5_data *, krb5_kkdcp_message **);

void k5_free_kkdcp_message(krb5_context context, krb5_kkdcp_message *val);


/* utils.c */

extern gss_OID_desc mech_spnego;

void
log_k5err(krb5_context context, const char *msg, krb5_error_code code);

void
log_gsserr(const char *msg, OM_uint32 major, OM_uint32 minor);

unsigned int  load_32_be (const void *cvp);

void store_32_be (unsigned int val, void *vp);


/* k5drv.cpp */

krb5_error_code
decode_kkdcp_message(krb5_context ctx, const std::string &msg,
                     std::vector<uint8_t> &reply);

krb5_error_code
encode_kkdcp_message(krb5_context ctx, std::vector<uint8_t> &in_data,
                     std::vector<uint8_t> &realm, std::string &out_data);

} // extern "C"

#endif // K5DRV_H_INCLUDED
