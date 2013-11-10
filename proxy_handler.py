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
from tornado_httpproxyclient import HTTPProxyClient

response_kwargs = ('overwrite_headers', 'del_headers', )
forward_headers = ('Range', 'User-Agent', )

tornado.httpclient.AsyncHTTPClient.configure(HTTPProxyClient)
class ProxyHandler(tornado.web.RequestHandler):
    @tornado.web.asynchronous
    def get(self, data=""):
        if not data:
            self.write('It works!')
            self.finish()
            return
        data = json.loads(data.decode('base64'))
        if 'url' not in data:
            self.send_error(403)

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

        tornado.httpclient.AsyncHTTPClient().fetch(request, self.on_finished)
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
        if hasattr(self, 'forward_request') and hasattr(self.forward_request, 'conn') and hasattr(self.forward_request.conn, 'stream'):
            self.forward_request.conn.stream.close()
            assert self.forward_request.conn.stream.socket is None

if __name__ == '__main__':
    application = tornado.web.Application([
        (r"/([^/]+)(?:/.*)", ProxyHandler),
    ], debug=True)
    application.listen(8888)
    tornado.ioloop.IOLoop.instance().start()
