// MIT Licensed, see LICENSE file
// Copyright (c) 2021 Isaac Boukris <iboukris@gmail.com>

async function getAuthResource(user, pwd, server)
{
    let webgss = require('.');

    // Debug
    webgss.setKrb5Trace(true);

    let client = await webgss.gssClient(server + '/KdcProxy', user, pwd);

    let reply = await client.fetch(server + '/hello');

    webgss.leakCheck();

    let data = await reply.text();

    return data;
}

let user = process.env.KUSER + '@' + process.env.KRB5REALM;
let pwd = process.env.KUPWD;
let srv = 'http://' + process.env.HOSTNAME + ':' + process.env.HTTPDPORT;

getAuthResource(user, pwd, srv).then(data => console.log( data ));

