# MIT Licensed, see LICENSE file
# Copyright (c) 2021 Isaac Boukris <iboukris@gmail.com>

import os
import sys
import mimetypes
import kdcproxy
import base64
import gssapi

from wsgiref.simple_server import make_server
from wsgiref import util


# Run with: KRB5_KTNAME=keytab python ./wsgi-server.py


class gssAuth(object):
    def __init__(self, app):
        self.app = app
        self.creds = gssapi.Credentials(usage='accept')

    def __call__(self, environ, start_response):
        auth = environ.get('HTTP_AUTHORIZATION')
        if not auth or not auth.startswith('Negotiate '):
            start_response('401 Unauthorized', [('WWW-Authenticate', 'Negotiate')])
            return [b'']

        req_token = base64.b64decode(auth[len('Negotiate '):])
        ctx = gssapi.SecurityContext(creds=self.creds, usage='accept')
        rep_token = ctx.step(req_token)

        if not ctx.complete:
            start_response('500 Internal Server Error')
            return [b'']

        environ['REMOTE_USER'] = str(ctx.initiator_name)

        def wrap_start_response(status, headers, exc_info=None):
            if rep_token:
                val = 'Negotiate ' + base64.b64encode(rep_token).decode('ascii')
                headers.append( ('WWW-Authenticate', val) )
            return start_response(status, headers, exc_info)

        return self.app(environ, wrap_start_response)


class webGssApp(object):
    def __init__(self, app, kdcproxy, logindir=None):
        self.app = gssAuth(app)
        self.kproxy = kdcproxy
        self.logindir = logindir

    def __call__(self, environ, start_response):
        path = environ.get('PATH_INFO','')
        if (path == '/KdcProxy'):
            return self.kproxy(environ, start_response)

        if (self.logindir and path.startswith('/login/')):
            fn = os.path.join(self.logindir, path[7:])
            if '.' not in fn.split(os.path.sep)[-1]:
                fn = os.path.join(fn, 'index.html')
            mtype = mimetypes.guess_type(fn)[0] or 'text/plain'

            if os.path.exists(fn):
                start_response('200 OK', [('Content-Type', mtype)])
                return util.FileWrapper(open(fn, "rb"))
            else:
                start_response('404 Not Found', [('Content-Type', 'text/plain')])
                return [b'not found']

        return self.app(environ, start_response)


class helloApp(object):
    def __call__(self, environ, start_response):
        start_response('200 OK', [('Content-type','text/plain')])
        user = environ.get('REMOTE_USER')
        out = 'Hello ' + user + '!\n'
        return [ out.encode('utf8') ]


if __name__ == '__main__':

    hostname = 'localhost'
    port = 8080

    if len(sys.argv) > 1:
        hostname = sys.argv[1]
    if len(sys.argv) > 2:
        port = int(sys.argv[2])

    wgss = webGssApp(helloApp(), kdcproxy.Application(), os.path.abspath(('.')))

    server = make_server(hostname, port, wgss)

    print('Server started')

    server.serve_forever()

