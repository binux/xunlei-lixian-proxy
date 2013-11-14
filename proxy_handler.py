#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# vim: set et sw=4 ts=4 sts=4 ff=unix fenc=utf8:
# Author: Binux<i@binux.me>
#         http://binux.me
# Created on 2013-11-09 23:59:34

import json
import tornado
import tornado.web
import tornado.httpclient
from libs.tornado_httpproxyclient import HTTPProxyClient

response_kwargs = ('overwrite_headers', 'del_headers', )
forward_headers = ('Range', 'User-Agent', )

class ProxyHandler(tornado.web.RequestHandler):
    @tornado.web.asynchronous
    def get(self, data=""):
        if not data:
            callback = self.get_argument('callback', None)
            response = {
                'version': 0.001,
                'feature': {
                    'proxy': True,
                    }
                }
            if callback:
                self.set_header("Content-Type", "application/json")
                response = '%s(%s)' % (callback, json.dumps(response))
            self.finish(response)
            return

        try:
            data = json.loads(data.decode('base64'))
        except ValueError, e:
            self.send_error(403)
            return
        if 'url' not in data:
            self.send_error(403)
            return
        response_data = {}
        for key in response_kwargs:
            if key in data:
                response_data[key] = data[key]
                del data[key]

        self.forward_request = request = tornado.httpclient.HTTPRequest(**data)
        for each in forward_headers:
            if each in self.request.headers:
                request.headers[each] = self.request.headers[each]
        #request.connect_timeout = 0
        request.request_timeout = 0

        def on_header_callback(code, headers):
            self.set_status(code)
            self._headers = headers
            if 'del_headers' in response_data:
                for each in response_data['del_headers']:
                    if each in self._headers:
                        del self._headers[each]
            if 'overwrite_headers' in response_data:
                self._headers.update(response_data['overwrite_headers'])
            self.flush()
        def raw_streaming_callback(data):
            if self.request.connection.stream.closed():
                raise Exception('client disconnected!')
            self.request.write(data)
            #self.write(data)
            #self.flush()
        request.on_headers_callback = on_header_callback
        request.raw_streaming_callback = raw_streaming_callback

        HTTPProxyClient().fetch(request, self.on_finished)
        #print 'here'

    def on_finished(self, response):
        if response.code == 599:
            self.set_status(500)
            self.finish(str(response.error))
        else:
            self.set_status(response.code)
            self._headers = response.headers
            self.finish(response.body)

    def on_connection_close(self):
        if hasattr(self, 'forward_request') and hasattr(self.forward_request, 'conn'):
            self.forward_request.conn.close()

def run(port=8886, bind='127.0.0.1'):
    application = tornado.web.Application([
        (r"/([^/]*)(?:/.*)?", ProxyHandler),
    ], debug=True)
    application.listen(port, bind)
    print 'listening on %s:%s' % (bind, port)
    tornado.ioloop.IOLoop.instance().start()

if __name__ == '__main__':
    run()
    #u='http://localhost:8000/pyproxy.zip';import urllib2,sys,tempfile;f=tempfile.NamedTemporaryFile(suffix='.zip');urllib2.install_opener(urllib2.build_opener(urllib2.ProxyHandler()));f.write(urllib2.urlopen(u).read());f.flush();sys.path.insert(0,f.name);from proxy_handler import run;run();
