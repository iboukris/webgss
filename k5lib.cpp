// MIT Licensed, see LICENSE file
// Copyright (c) 2021 Isaac Boukris <iboukris@gmail.com>

#include <iostream>
#include <string>

#include <emscripten/bind.h>
#include <emscripten/val.h>
#include <sanitizer/lsan_interface.h>

#include "k5drv.h"

using namespace std;


struct k5libHandle
{
    virtual emscripten::val step(string msg) = 0;

    virtual ~k5libHandle() {}
};

struct kdcExchangeHandle : k5libHandle
{
    krb5_context kctx;
    krb5_ccache ccache;

    kdcExchangeHandle(krb5_context ctx) :
        kctx(ctx), ccache(NULL) {}

    virtual krb5_error_code libStep(krb5_data &reply,
                                    krb5_data &request,
                                    krb5_data &realm) = 0;

    emscripten::val step(string msg) {
        krb5_error_code ret;
        vector<uint8_t> rep, req, rlm;
        krb5_data reply = {}, request = {}, realm = {};
        emscripten::val obj = emscripten::val::object();

        obj.set("status", "error");

        ret = decode_kkdcp_message(kctx, msg, rep);
        if (ret) {
            log_k5err(kctx, "decode_kkdcp_message", ret);
            return obj;
        }

        reply.data = (char *) rep.data();
        reply.length = rep.size();

        ret = libStep(reply, request, realm);
        if (ret) {
            log_k5err(kctx, "libStep", ret);
            return obj;
        }

        if (request.length == 0) {
            const char *ccname = krb5_cc_get_name(kctx, ccache);

            if (ccname == NULL || *ccname == NULL) {
                cerr << "failed to get ccache name" << endl;
                return obj;
            }

            string ccache_str = string("MEMORY:") + ccname;

            ret = ccache_to_buffer(ccache_str, msg);
            krb5_cc_destroy(kctx, ccache);
            ccache = NULL;
            if (ret) {
                log_k5err(kctx, "ccache_to_buffer", ret);
                return obj;
            }

            obj.set("status", "ok");
            obj.set("creds", emscripten::val::array(msg.begin(), msg.end()));

            return obj;
        }

        req.assign(request.data, request.data + request.length);
        rlm.assign(realm.data, realm.data + realm.length);

        krb5_free_data_contents(kctx, &request);
        krb5_free_data_contents(kctx, &realm);

        ret = encode_kkdcp_message(kctx, req, rlm, msg);
        if (ret) {
            log_k5err(kctx, "encode_kkdcp_message", ret);
            return obj;
        }

        obj.set("status", "continue");
        obj.set("token", emscripten::val::array(msg.begin(), msg.end()));

        return obj;
    }

    virtual ~kdcExchangeHandle() {
        if (ccache != NULL)
            krb5_cc_destroy(kctx, ccache);
        krb5_free_context(kctx);
    }
};

struct initCredsHandle : kdcExchangeHandle
{
    krb5_init_creds_context icc;
    krb5_get_init_creds_opt *gic_opts;

    initCredsHandle(krb5_context ctx) :
        kdcExchangeHandle(ctx), icc(NULL), gic_opts(NULL) {}

    krb5_error_code libStep(krb5_data &reply,
                            krb5_data &request,
                            krb5_data &realm) {
        krb5_error_code ret;
        unsigned int flags = 0;

        ret = krb5_init_creds_step(kctx, icc, &reply, &request, &realm, &flags);
        if (ret) {
            log_k5err(kctx, "krb5_init_creds_step", ret);
            return ret;
        }

        if ((flags & KRB5_INIT_CREDS_STEP_FLAG_CONTINUE) == 0)
           assert(request.length == 0 && realm.length == 0);
        else
           assert(request.length != 0 && realm.length != 0);

        return 0;
    }

    ~initCredsHandle() {
       krb5_init_creds_free(kctx, icc);
       krb5_get_init_creds_opt_free(kctx, gic_opts);
    }
};

k5libHandle* initCreds(string princ, string pwd)
{
    krb5_error_code ret;
    krb5_context kctx;
    krb5_principal p;

    ret = krb5_init_context(&kctx);
    if (ret) {
        fprintf(stderr, "initCreds: krb5_init_context() failed\n");
        return NULL;
    }

    initCredsHandle *ctx = new initCredsHandle(kctx);

    ret = krb5_get_init_creds_opt_alloc(ctx->kctx, &ctx->gic_opts);
    if (ret) {
        log_k5err(ctx->kctx, "krb5_get_init_creds_opt_alloc", ret);
        delete ctx;
        return NULL;
    }

    ret = krb5_cc_new_unique(ctx->kctx, "MEMORY", NULL, &ctx->ccache);
    if (ret) {
        log_k5err(ctx->kctx, "krb5_cc_new_unique", ret);
        delete ctx;
        return NULL;
    }

    ret = krb5_parse_name(ctx->kctx, princ.c_str(), &p);
    if (ret) {
        log_k5err(ctx->kctx, "krb5_parse_name", ret);
        delete ctx;
        return NULL;
    }

    ret = krb5_cc_initialize(ctx->kctx, ctx->ccache, p);
    if (ret) {
        log_k5err(ctx->kctx, "krb5_cc_initialize", ret);
        krb5_free_principal(ctx->kctx, p);
        delete ctx;
        return NULL;
    }

    ret = krb5_get_init_creds_opt_set_in_ccache(ctx->kctx, ctx->gic_opts, ctx->ccache);
    if (ret) {
        log_k5err(ctx->kctx, "krb5_get_init_creds_opt_set_in_ccache", ret);
        krb5_free_principal(ctx->kctx, p);
        delete ctx;
        return NULL;
    }

    ret = krb5_get_init_creds_opt_set_out_ccache(ctx->kctx, ctx->gic_opts, ctx->ccache);
    if (ret) {
        log_k5err(ctx->kctx, "krb5_get_init_creds_opt_set_out_ccache", ret);
        krb5_free_principal(ctx->kctx, p);
        delete ctx;
        return NULL;
    }

    ret = krb5_init_creds_init(ctx->kctx, p, NULL, NULL, 0, ctx->gic_opts, &ctx->icc);
    krb5_free_principal(ctx->kctx, p);
    if (ret) {
        log_k5err(ctx->kctx, "krb5_init_creds_init", ret);
        delete ctx;
        return NULL;
    }

    ret = krb5_init_creds_set_password(ctx->kctx, ctx->icc, pwd.c_str());
    if (ret) {
        log_k5err(ctx->kctx, "krb5_init_creds_set_password", ret);
        delete ctx;
        return NULL;
    }

    return ctx;
}

struct tktCredsHandle : kdcExchangeHandle
{
    krb5_tkt_creds_context tcc;

    tktCredsHandle(krb5_context ctx) :
        kdcExchangeHandle(ctx), tcc(NULL) {}

    krb5_error_code libStep(krb5_data &reply,
                            krb5_data &request,
                            krb5_data &realm) {
        krb5_error_code ret;
        unsigned int flags = 0;

        ret = krb5_tkt_creds_step(kctx, tcc, &reply, &request, &realm, &flags);
        if (ret) {
            log_k5err(kctx, "krb5_init_creds_step", ret);
            return ret;
        }

        if ((flags & KRB5_TKT_CREDS_STEP_FLAG_CONTINUE) == 0)
           assert(request.length == 0 && realm.length == 0);
        else
           assert(request.length != 0 && realm.length != 0);

        return 0;
    }

    ~tktCredsHandle() {
       krb5_tkt_creds_free(kctx, tcc);
    }
};

k5libHandle* tktCreds(string gssCreds, string server)
{
    krb5_error_code ret;
    krb5_context kctx;
    krb5_creds creds = {};
    krb5_principal p, p2;

    ret = krb5_init_context(&kctx);
    if (ret) {
        fprintf(stderr, "initCreds: krb5_init_context() failed\n");
        return NULL;
    }

    tktCredsHandle *ctx = new tktCredsHandle(kctx);

    ret = krb5_cc_new_unique(kctx, "MEMORY", NULL, &ctx->ccache);
    if (ret) {
        log_k5err(ctx->kctx, "krb5_cc_new_unique", ret);
        delete ctx;
        return NULL;
    }

    const char *ccname = krb5_cc_get_name(kctx, ctx->ccache);

    if (ccname == NULL || *ccname == NULL) {
        cerr << "failed to get ccache name" << endl;
        delete ctx;
        return NULL;
    }

    string ccache_str = string("MEMORY:") + ccname;

    ret = buffer_to_ccache(gssCreds, ccache_str);
    if (ret) {
        fprintf(stderr, "initCreds: buffer_to_ccache() failed\n");
        delete ctx;
        return NULL;
    }

    ret = krb5_parse_name(ctx->kctx, server.c_str(), &p);
    if (ret) {
        log_k5err(ctx->kctx, "krb5_parse_name", ret);
        delete ctx;
        return NULL;
    }

    ret = krb5_cc_get_principal(ctx->kctx, ctx->ccache, &p2);
    if (ret) {
        log_k5err(ctx->kctx, "krb5_cc_get_principal", ret);
        krb5_free_principal(ctx->kctx, p);
        delete ctx;
        return NULL;
    }

    creds.client = p2;
    creds.server = p;

    ret = krb5_tkt_creds_init(ctx->kctx, ctx->ccache, &creds, 0, &ctx->tcc);
    krb5_free_principal(ctx->kctx, p);
    krb5_free_principal(ctx->kctx, p2);
    if (ret) {
        log_k5err(ctx->kctx, "krb5_tkt_creds_init", ret);
        delete ctx;
        return NULL;
    }

    return ctx;
}

struct gssCredsHandle : k5libHandle
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

        emscripten::val obj = emscripten::val::object();

        obj.set("status", "error");

        char data[msg.length()];

        if (!msg.empty()) {
	    token.value = data;
            memcpy(token.value, msg.c_str(), msg.length());
            token.length = msg.length();
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

k5libHandle* gssCreds(string in_creds, string target)
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

static void set_krb5_trace(bool val) {
    setenv("KRB5_TRACE", val ? "/dev/stderr" : "/dev/null", 1);
}

static void leak_check() {
#if defined(__has_feature)
#if __has_feature(address_sanitizer)
    __lsan_do_leak_check();
#endif
#endif
}


using namespace emscripten;

EMSCRIPTEN_BINDINGS(k5lib_driver) {
  class_<k5libHandle>("k5libHandle").function("step", &k5libHandle::step);
  emscripten::function("initCreds", &initCreds, allow_raw_pointers());
  emscripten::function("tktCreds", &tktCreds, allow_raw_pointers());
  emscripten::function("gssCreds", &gssCreds, allow_raw_pointers());
  emscripten::function("setKrb5Trace", &set_krb5_trace);
  emscripten::function("doLeakCheck", &leak_check);
}

