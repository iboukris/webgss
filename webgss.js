// MIT Licensed, see LICENSE file
// Copyright (c) 2021 Isaac Boukris <iboukris@gmail.com>

function is_node () { return (typeof module === 'object' && module.exports); }

/* Use webgss.gssClient() to get an instance. */
class gssClient
{
    constructor(instance, kdcproxy, initCreds)
    {
        this.i = instance;
        this.kdcp = kdcproxy;
        this.creds = initCreds;
    }

    async #prepSecContext(target)
    {
        let tktHandle = this.i.module.tktCreds(this.creds, target);
        let tktCreds;

        if (!tktHandle)
            throw 'null tktHandle';

        try {
            tktCreds = await kdc_exchange(this.i, this.kdcp, tktHandle);
        } finally {
            tktHandle.delete();
        }

        /* XXX: this can rece and cause cache misses. */
        this.creds = tktCreds;
    }

    /* Fetch a resource protected with HTTP Negotiate authentication (SPNEGO). */
    async fetch(resource, init = {})
    {
        let response = null;

        let origReq = new this.i.req(resource, init);

        let url = new URL(origReq.url);

        let hostname = url.hostname;

        let target = 'HTTP/' + hostname + '@';

        await this.#prepSecContext(target);

        let gssHandle = this.i.module.gssCreds(this.creds, target);
        if (!gssHandle)
            throw 'null gssHandle';

        try {
            let gssReply = gssHandle.step('');

            while (gssReply.status == 'continue')
            {
                let prefix = 'Negotiate ';
                let request = new this.i.req(origReq);
                let auth = new Uint8Array(gssReply.token);

                auth = base64EncArr(auth);
                auth = prefix + auth;
                request.headers.append('Authorization', auth);

                // XXX disable redirects?
                response = await this.i.fetch(request);

                auth = response.headers.get('WWW-Authenticate');
                if (auth == null || !auth.startsWith(prefix))
                    throw 'Missing server mutual auth reply token';

                auth = auth.slice(prefix.length);
                auth = base64DecToArr(auth);
                gssReply = gssHandle.step(auth);

                if (response.status != 401)
                    break;
            }

            if (gssReply.status != 'ok')
                throw 'Authenticate did not succeed';

        } finally {
            if (gssHandle != null)
                gssHandle.delete();
        }

        return response;
    }
}


class webgss
{
    static #instance = null;

    static async #getInstance()
    {
        let createEmModule, module, fetch, req;

        if (this.#instance != null)
            return this.#instance;

        if (is_node ()) {
            let obj = await import('node-fetch');
            fetch = obj.default;
            req = obj.Request;
            createEmModule = require('./lib/k5lib_node.js');
        } else {
            fetch = window.fetch.bind(window);
            req = Request;
            let obj = await import('./lib/k5lib.js');
            createEmModule = obj.default;
        }

        module = await createEmModule();

        if (this.#instance != null)
            module = null;
        else
            this.#instance = { module, fetch, req };

        return this.#instance;
    }

    /* Call when there are no async operations running in the background. */
    static leakCheck()
    {
        if (this.#instance != null)
            this.#instance.module.doLeakCheck();
    }

    /* Enable KRB5_TRACE globally to console log. */
    static setKrb5Trace(enable=true)
    {
        this.#getInstance().then(i => {
            i.module.setKrb5Trace(enable);
            i.module.logReadFiles = true; // XXX
        });
    }

    /* Acquires Kerberos credentials, returns a gssClient with a fetch() method. */
    static async gssClient(kdcproxy, user, pwd)
    {
        let i = await this.#getInstance();
        let initHandle = i.module.initCreds(user, pwd);
        let initCreds;

        if (!initHandle)
            throw 'null initHandle';

        try {
            initCreds = await kdc_exchange(i, kdcproxy, initHandle);
        } finally {
            initHandle.delete();
        }

        return new gssClient(i, kdcproxy, initCreds);
    }
}

if (is_node())
    module.exports = webgss;


async function sendto_kdc(obj, kproxy, req) {
    let init = {
        method: 'POST',
        body: req,
        //cache: 'no-cache',
        //redirect: 'error',
        headers: {
            'Content-type': 'application/kerberos'
        }
    }
    let request = new obj.req(kproxy, init);
    let response = await obj.fetch(request);
    if (response.status != 200)
        throw 'KdcProxy request failed';
    return response;
}

async function kdc_exchange(obj, kdcproxy, handle)
{
    let reply = handle.step('');

    while (reply.status == 'continue') {

        let req = new Uint8Array(reply.token);

        let rep = await sendto_kdc(obj, kdcproxy, req);

        let rep_data = await rep.arrayBuffer();

        rep_data = new Uint8Array(rep_data);

        reply = handle.step(rep_data);
    }

    if (reply.status != 'ok')
        throw 'exchange failed';

    return new Uint8Array(reply.creds);
}



/*\
|*|
|*|  Base64 / binary data / UTF-8 strings utilities
|*|
|*|  https://developer.mozilla.org/en-US/docs/Web/JavaScript/Base64_encoding_and_decoding
|*|
\*/


"use strict";

/* Array of bytes to Base64 string decoding */

function b64ToUint6 (nChr) {

  return nChr > 64 && nChr < 91 ?
      nChr - 65
    : nChr > 96 && nChr < 123 ?
      nChr - 71
    : nChr > 47 && nChr < 58 ?
      nChr + 4
    : nChr === 43 ?
      62
    : nChr === 47 ?
      63
    :
      0;

}

function base64DecToArr (sBase64, nBlocksSize) {

  var
    sB64Enc = sBase64.replace(/[^A-Za-z0-9\+\/]/g, ""), nInLen = sB64Enc.length,
    nOutLen = nBlocksSize ? Math.ceil((nInLen * 3 + 1 >> 2) / nBlocksSize) * nBlocksSize : nInLen * 3 + 1 >> 2,
                  taBytes = new Uint8Array(nOutLen);

  for (var nMod3, nMod4, nUint24 = 0, nOutIdx = 0, nInIdx = 0; nInIdx < nInLen; nInIdx++) {
    nMod4 = nInIdx & 3;
    nUint24 |= b64ToUint6(sB64Enc.charCodeAt(nInIdx)) << 6 * (3 - nMod4);
    if (nMod4 === 3 || nInLen - nInIdx === 1) {
      for (nMod3 = 0; nMod3 < 3 && nOutIdx < nOutLen; nMod3++, nOutIdx++) {
        taBytes[nOutIdx] = nUint24 >>> (16 >>> nMod3 & 24) & 255;
      }
      nUint24 = 0;

    }
  }

  return taBytes;
}

/* Base64 string to array encoding */

function uint6ToB64 (nUint6) {

  return nUint6 < 26 ?
      nUint6 + 65
    : nUint6 < 52 ?
      nUint6 + 71
    : nUint6 < 62 ?
      nUint6 - 4
    : nUint6 === 62 ?
      43
    : nUint6 === 63 ?
      47
    :
      65;

}

function base64EncArr (aBytes) {

  var nMod3 = 2, sB64Enc = "";

  for (var nLen = aBytes.length, nUint24 = 0, nIdx = 0; nIdx < nLen; nIdx++) {
    nMod3 = nIdx % 3;
    //if (nIdx > 0 && (nIdx * 4 / 3) % 76 === 0) { sB64Enc += "\r\n"; }
    nUint24 |= aBytes[nIdx] << (16 >>> nMod3 & 24);
    if (nMod3 === 2 || aBytes.length - nIdx === 1) {
      sB64Enc += String.fromCharCode(uint6ToB64(nUint24 >>> 18 & 63), uint6ToB64(nUint24 >>> 12 & 63),
                     uint6ToB64(nUint24 >>> 6 & 63), uint6ToB64(nUint24 & 63));
      nUint24 = 0;
    }
  }

  return sB64Enc.substr(0, sB64Enc.length - 2 + nMod3) + (nMod3 === 2 ? '' : nMod3 === 1 ? '=' : '==');

}

