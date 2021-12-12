# webgss

NOTICE -- Experimental! Unstable API and code!

A JavaScript & WebAssembly module that brings GSS-API and Kerberos authentication to the web.

Including the library provides a highlevel API for acquiring Kerberos credentials via a
KDCProxy (over HTTPS), and then authenticating resources protected with HTTP Negotiate
protocol (aka SPNEGO).

It incorporates the MIT krb5 libraries compiled to JavaScript & WebAssembly using emscripten.

## Usage
```javascript
async function kerberizedFetch(url, kdcproxy, user, pwd)
{
    webgss.setKrb5Trace();

    let client = await webgss.gssClient(kdcproxy, user, pwd);

    let reply = await client.fetch(url);

    return reply;
}
```

Note, if the kdcproxy and / or the authenticated application are hosted on a different
host or port than the JavaScript application, then you'd have to enable CORS on these
servers, or the browser will likely reject the request.

## Installation

`npm install webgss`

The npm package only contains the release build. For debugging, a debug build can be
made when building from source, as follows.

To build from source, first make sure that emcc is available, see emscripten's
instructions on how to install and enable the emsdk, at:
https://emscripten.org/docs/getting_started/downloads.html

Release build: `make clean && make -j`

Debug build: `make clean && make -j debug`

Optionally, run tests with: `make check`

## Contributing

Bug reports, patches or any improvement ideas are very welcome!

## License

MIT Licensed, see LICENSE file.
