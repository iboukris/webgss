// MIT Licensed, see LICENSE file
// Copyright (c) 2021 Isaac Boukris <iboukris@gmail.com>

#include <string>
#include <vector>

#include "k5drv.h"

using namespace std;

krb5_error_code
decode_kkdcp_message(krb5_context ctx, const string &msg, vector<uint8_t> &reply)
{
    krb5_error_code ret;
    vector<uint8_t> in;
    krb5_data in_data = {};
    krb5_kkdcp_message *pm = NULL;

    if (msg.empty())
        return 0;

    in.assign(msg.begin(), msg.end());

    in_data.data = (char *) in.data();
    in_data.length = in.size();

    ret = decode_krb5_kkdcp_message(&in_data, &pm);
    if (ret) {
        log_k5err(ctx, "decode_krb5_kkdcp_message", ret);
        return ret;
    }

    if (pm->kerb_message.length < 4 ||
        load_32_be(pm->kerb_message.data) != pm->kerb_message.length - 4) {
        fprintf(stderr, "decode: invalid KKDCP message");
        k5_free_kkdcp_message(NULL, pm);
        return -1;
    }

    reply.assign(pm->kerb_message.data + 4,
                 pm->kerb_message.data + pm->kerb_message.length);

    k5_free_kkdcp_message(NULL, pm);

    return 0;
}

krb5_error_code
encode_kkdcp_message(krb5_context ctx, vector<uint8_t> &in_data,
                     vector<uint8_t> &realm, string &out_data)
{
    krb5_error_code ret;
    uint32_t msg_len;
    krb5_kkdcp_message pm;
    krb5_data *encoded_pm = NULL;

    if (in_data.size() == 0)
        return 0;

    store_32_be(in_data.size(), &msg_len);
    in_data.insert(in_data.begin(), (uint8_t*)&msg_len, (uint8_t*)&msg_len + 4);

    pm.kerb_message.length = in_data.size();
    pm.kerb_message.data = (char *) in_data.data();

    pm.target_domain.length = realm.size();
    pm.target_domain.data = (char *) realm.data();

    ret = encode_krb5_kkdcp_message(&pm, &encoded_pm);
    if (ret) {
        log_k5err(ctx, "encode_krb5_kkdcp_message", ret);
        return ret;
    }

    out_data = string(encoded_pm->data, encoded_pm->length);

    krb5_free_data(NULL, encoded_pm);

    return 0;
}

krb5_error_code
ccache_to_buffer(string &ccache, string &out_buffer)
{
    OM_uint32 maj, min;
    OM_uint32 time_rec; // XXX
    gss_cred_id_t creds = GSS_C_NO_CREDENTIAL;
    gss_key_value_element_desc element = { "ccache", ccache.c_str() };
    gss_key_value_set_desc store = { 1, &element };
    gss_buffer_desc buffer = GSS_C_EMPTY_BUFFER;


    maj = gss_acquire_cred_from(&min, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                                GSS_C_NO_OID_SET, GSS_C_INITIATE, &store,
                                &creds, NULL, &time_rec);
    if (GSS_ERROR(maj)) {
        log_gsserr("gss_acquire_cred_from()", maj, min);
        return ENOMEM;
    }

    maj = gss_export_cred(&min, creds, &buffer);
    gss_release_cred(&min, &creds);
    if (GSS_ERROR(maj)) {
        log_gsserr("gss_export_cred()", maj, min);
        return ENOMEM;
    }

    out_buffer = string((const char *) buffer.value, buffer.length);
    gss_release_buffer(&min, &buffer);

    return 0;
}

krb5_error_code
buffer_to_ccache(string &in_buffer, string &ccache)
{
    OM_uint32 maj, min;
    gss_cred_id_t creds = GSS_C_NO_CREDENTIAL;
    gss_key_value_element_desc store_elm = { "ccache", ccache.c_str() };
    gss_key_value_set_desc store = { 1, &store_elm };
    gss_buffer_desc buffer = GSS_C_EMPTY_BUFFER;
    vector<uint8_t> data;

    data.assign(in_buffer.begin(), in_buffer.end());
    buffer.value = (void *) data.data();
    buffer.length = data.size();

    maj = gss_import_cred(&min, &buffer, &creds);
    if (GSS_ERROR(maj)) {
        log_gsserr("gss_import_cred()", maj, min);
        return ENOMEM;
    }

    maj = gss_store_cred_into(&min, creds, GSS_C_INITIATE, GSS_C_NO_OID,
                              1, 1, &store, NULL, NULL);
    gss_release_cred(&min, &creds);
    if (GSS_ERROR(maj)) {
        log_gsserr("gss_store_cred_into()", maj, min);
        return ENOMEM;
    }

    return 0;
}
