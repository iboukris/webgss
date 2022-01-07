// MIT Licensed, see LICENSE file
// Copyright (c) 2021 Isaac Boukris <iboukris@gmail.com>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <krb5/krb5.h>
#include <gssapi/gssapi_krb5.h>


gss_OID_desc mech_spnego = { 6, "\053\006\001\005\005\002" };

unsigned int
load_32_be (const void *cvp)
{
    const unsigned char *p = (const unsigned char *) cvp;
    return (p[3] | (p[2] << 8)
            | ((uint32_t) p[1] << 16)
            | ((uint32_t) p[0] << 24));
}
void
store_32_be (unsigned int val, void *vp)
{
    unsigned char *p = (unsigned char *) vp;
    p[0] = (val >> 24) & 0xff;
    p[1] = (val >> 16) & 0xff;
    p[2] = (val >>  8) & 0xff;
    p[3] = (val      ) & 0xff;
}

static void
display_status(const char *msg, OM_uint32 code, int type)
{
    OM_uint32 min_stat, msg_ctx = 0;
    gss_buffer_desc buf;

    do {
        (void)gss_display_status(&min_stat, code, type, GSS_C_NULL_OID,
                                 &msg_ctx, &buf);
        fprintf(stderr, "%s: %.*s\n", msg, (int)buf.length, (char *)buf.value);
        (void)gss_release_buffer(&min_stat, &buf);
    } while (msg_ctx != 0);
}

void
log_gsserr(const char *msg, OM_uint32 major, OM_uint32 minor)
{
    if (GSS_ERROR(major)) {
        display_status(msg, major, GSS_C_GSS_CODE);
        display_status(msg, minor, GSS_C_MECH_CODE);
    } else {
        fprintf(stderr, "No GSS error!\n");
    }
}

void
log_k5err(krb5_context context, const char *msg, krb5_error_code code)
{
    const char *errmsg;

    if (code) {
        errmsg = krb5_get_error_message(context, code);
        fprintf(stderr, "%s: %s\n", msg, errmsg);
        krb5_free_error_message(context, errmsg);
    }
}
