// MIT Licensed, see LICENSE file
// Copyright (c) 2021 Isaac Boukris <iboukris@gmail.com>

async function getAuthResource(user, pwd, realm, server)
{
    let webgss = require('.');

    // Debug

    webgss.setDefaultRealm(realm);
    webgss.leakCheck();

    webgss.setKrb5Trace(true);
    webgss.leakCheck();

    let client = await webgss.gssClient(server + '/KdcProxy', user, pwd);
    webgss.leakCheck();

    let reply = await client.fetch(server + '/hello');

    // TODO: doesn't work with asyncify
    //let reply2 = client.fetch(server + '/hello');
    //let reply3 = client.fetch(server + '/hello');

    webgss.leakCheck();

    let data = await reply.text();
    webgss.leakCheck();

    return data;
}

let user = process.env.KUSER;
let pwd = process.env.KUPWD;
let realm = process.env.KRB5REALM;
user = user +'@'+realm
let srv = 'http://' + process.env.HOSTNAME + ':' + process.env.HTTPDPORT;

getAuthResource(user, pwd, realm, srv).then(data => console.log( data ));

// TODO: add parallel and failed tests

