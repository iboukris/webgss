// MIT Licensed, see LICENSE file
// Copyright (c) 2021 Isaac Boukris <iboukris@gmail.com>

#include <iostream>
#include <string>

#include <emscripten/bind.h>
#include <emscripten/val.h>
#include <sanitizer/lsan_interface.h>

#include "k5drv.h"

using namespace std;

krb5_context kctx = NULL;

extern krb5_pre_send_fn em_send_to_realm_hook;

struct gssCredsHandle
{
    gss_cred_id_t gss_creds;
    gss_name_t target_name;
    gss_ctx_id_t gss_ctx;

    gssCredsHandle(gss_cred_id_t gss_creds, gss_name_t target_name) :
        gss_creds(gss_creds), target_name(target_name), gss_ctx(NULL) {}

    emscripten::val step(string msg) {

        OM_uint32 minor, major;
        OM_uint32 ret_flags = 0, flags = GSS_C_MUTUAL_FLAG;
        gss_buffer_desc token = {};
        gss_buffer_desc out = {};
        vector<uint8_t> data;

        emscripten::val obj = emscripten::val::object();

        obj.set("status", "error");

        if (!msg.empty()) {
            data.assign(msg.begin(), msg.end());
            token.value = data.data();
            token.length = data.size();
        }

        major = gss_init_sec_context(&minor, gss_creds, &gss_ctx, target_name,
                                     &mech_spnego, flags, GSS_C_INDEFINITE,
                                     GSS_C_NO_CHANNEL_BINDINGS, &token, NULL,
                                     &out, &ret_flags, NULL);
        if (GSS_ERROR(major)) {
            log_gsserr("gss_init_sec_context", major, minor);
            return obj;
        }

        if (out.length != 0) {
            string data((const char*)out.value, out.length);
            obj.set("token", emscripten::val::array(data.begin(), data.end()));
            gss_release_buffer(&minor, &out);
        }

        if (major == GSS_S_COMPLETE && !(ret_flags & GSS_C_MUTUAL_FLAG)) {
            cerr << "mutual auth failed" << endl;
            return obj;
        }

        obj.set("status", major == GSS_S_COMPLETE ? "ok" : "continue");

        return obj;
    }

    ~gssCredsHandle() {
        OM_uint32 min;
        if (target_name != GSS_C_NO_NAME)
            gss_release_name(&min, &target_name);
        if (gss_creds != GSS_C_NO_CREDENTIAL)
            gss_release_cred(&min, &gss_creds);
        if (gss_ctx != GSS_C_NO_CONTEXT)
            gss_delete_sec_context(&min, &gss_ctx, GSS_C_NO_BUFFER);
    }
};

gssCredsHandle* gssCreds(string in_creds, string target)
{
    OM_uint32 minor, major;
    gss_name_t target_name;
    gss_buffer_desc tname_buffer = {};
    gss_buffer_desc creds_buffer = {};
    gss_cred_id_t creds = GSS_C_NO_CREDENTIAL;
    vector<uint8_t> data;

    data.assign(target.begin(), target.end());
    tname_buffer.value = (void *) data.data();
    tname_buffer.length = data.size();

    /* GSS_C_NT_HOSTBASED_SERVICE doesn't play nice with short names */
    major = gss_import_name(&minor, &tname_buffer, GSS_C_NT_USER_NAME,
                            &target_name);
    if (GSS_ERROR(major)) {
        log_gsserr("gss_import_name", major, minor);
        return NULL;
    }

    data.assign(in_creds.begin(), in_creds.end());
    creds_buffer.value = (void *) data.data();
    creds_buffer.length = data.size();

    major = gss_import_cred(&minor, &creds_buffer, &creds);
    if (GSS_ERROR(major)) {
        log_gsserr("gss_import_cred", major, minor);
        return NULL;
    }

    gssCredsHandle *ctx = new gssCredsHandle(creds, target_name);

    return ctx;
}

static void set_krb5_trace(bool enable) {
    setenv("KRB5_TRACE", enable ? "/dev/stderr" : "/dev/null", 1);
}

static void leak_check() {
#if defined(__has_feature) && __has_feature(address_sanitizer)
    __lsan_do_leak_check();
#endif
}

static emscripten::val gssError(const char *func, OM_uint32 major, OM_uint32 minor)
{
    emscripten::val obj = emscripten::val::object();

    obj.set("error", func);

    return obj;
}

static krb5_error_code
em_fetch_send_hook(krb5_context context, void *data, const krb5_data *realm,
                 const krb5_data *message, krb5_data **new_message_out,
                 krb5_data **reply_out)
{
    vector<uint8_t> msg, rlm, rep;
    emscripten::val obj = emscripten::val::module_property("wgssEnv");
    krb5_data rep_data;

    msg.assign(message->data, message->data + message->length);
    rlm.assign(realm->data, realm->data + realm->length);

    string encoded;
    krb5_error_code ret = encode_kkdcp_message(kctx, msg, rlm, encoded);
    if (ret) {
        log_k5err(kctx, "encode_kkdcp_message", ret);
        return ret;
    }

    emscripten::val msgArray = emscripten::val::array(encoded.begin(), encoded.end());

    emscripten::val retProm = obj.call<emscripten::val>("sendToRealm", obj, msgArray);

    emscripten::val retData = retProm.await();

    rep = emscripten::vecFromJSArray<uint8_t>(retData);
    if (rep.empty()) {
        fprintf(stderr, "sendToRealm failed in JS\n");
        return KRB5_KDC_UNREACH;
    }

    ret = decode_kkdcp_message(kctx, string(rep.begin(), rep.end()), rep);
    if (ret) {
        log_k5err(kctx, "decode_kkdcp_message", ret);
        return ret;
    }

    rep_data.data = (char *) rep.data();
    rep_data.length = rep.size();

    ret = krb5_copy_data(kctx, &rep_data, reply_out);
    if (ret) {
        log_k5err(kctx, "krb5_copy_data", ret);
        return ret;
    }

    fprintf(stderr, "IN_KDC_SEND_HOOK: OK\n");

    return 0;
}

static emscripten::val acquireCreds(string username, string pwd)
{
    OM_uint32 major, minor;
    gss_name_t name;
    gss_buffer_desc buffer;
    gss_cred_id_t creds;
    vector<uint8_t> data;
    gss_OID_set_desc mechlist;

    em_send_to_realm_hook = em_fetch_send_hook;

    mechlist.count = 1;
    mechlist.elements = &mech_spnego;

    data.assign(username.begin(), username.end());
    buffer.value = data.data();
    buffer.length = data.size();

    major = gss_import_name(&minor, &buffer, GSS_C_NT_USER_NAME, &name);
    if (GSS_ERROR(major))
        return gssError("gss_import_name", major, minor);

    data.assign(pwd.begin(), pwd.end());
    buffer.value = data.data();
    buffer.length = data.size();

    major = gss_acquire_cred_with_password(&minor, name, &buffer,
                                           GSS_C_INDEFINITE, &mechlist,
                                           GSS_C_INITIATE, &creds, NULL, NULL);
    gss_release_name(&minor, &name);
    if (GSS_ERROR(major))
        return gssError("gss_acquire_cred_with_password", major, minor);

    major = gss_export_cred(&minor, creds, &buffer);
    gss_release_cred(&minor, &creds);
    if (GSS_ERROR(major))
        return gssError("gss_export_cred", major, minor);

    data.assign((char*)buffer.value, (char*)buffer.value + buffer.length);
    gss_release_buffer(&minor, &buffer);

    return emscripten::val::array(data.begin(), data.end());
}


using namespace emscripten;

EMSCRIPTEN_BINDINGS(k5lib_driver) {
  class_<gssCredsHandle>("gssCredsHandle").function("step", &gssCredsHandle::step);
  emscripten::function("gssCreds", &gssCreds, allow_raw_pointers());
  emscripten::function("setKrb5Trace", &set_krb5_trace);
  emscripten::function("doLeakCheck", &leak_check);
  emscripten::function("acquireCreds", &acquireCreds);
}

