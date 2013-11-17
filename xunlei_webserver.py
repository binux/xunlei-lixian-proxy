#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# vim: set et sw=4 ts=4 sts=4 ff=unix fenc=utf8:
# Author: Binux<i@binux.me>
#         http://binux.me
# Created on 2013-11-15 23:16:01

import time
import json
import urllib
import base64
import tornado
import tornado.httpclient
from libs.xunlei_api import LiXianAPI
from proxy_handler import ProxyHandler

xunlei_cache = {}

class XunleiHandler(tornado.web.RequestHandler):
    @tornado.web.asynchronous
    def get(self, task_id):
        self.task_id = task_id
        if not self.try_auth():
            return
        self.on_ready()

    def on_ready(self):
        if not self.task_id:
            self.list_root()
        elif int(self.task_id) in self.xunlei.info_dict:
            info = self.xunlei.info_dict[int(self.task_id)]
            self.list_task(info)
        else:
            self.send_error(404)

    def try_auth(self):
        auth = self.request.headers.get('Authorization')

        if auth == None or not auth.startswith('Basic '):
            self.set_status(401)
            self.set_header('WWW-Authenticate', 'Basic realm="xunlei"')
            self.finish()
            return False

        auth_decoded = base64.decodestring(auth[6:])
        username, password = auth_decoded.split(':', 1)
        if username+password in xunlei_cache:
            self.xunlei = xunlei_cache[username+password]
            return True

        def on_login(*args, **kwargs):
            if username+password in xunlei_cache:
                self.xunlei = xunlei_cache[username+password]
                self.on_ready()
                return
            if self._xunlei.logined:
                xunlei_cache[username+password] = self._xunlei
                self.xunlei = self._xunlei
                self.xunlei.info_dict = {}
                self.on_ready()
            else:
                self.set_status(401)
                self.set_header('WWW-Authenticate', 'Basic realm="xunlei"')
                self.finish()
                #self.send_error(403)
                #self.finish()
        self._xunlei = LiXianAPI()
        self._xunlei.async_login(username, password, callback=on_login)
        return False


    def list_root(self):
        def on_list(data):
            self.finish(self.list_template(data))
        self.xunlei.get_task_list(50, callback=on_list)

    def list_task(self, info):
        def on_list(data):
            self.finish(self.list_template(data))
        self.xunlei.get_bt_list(info['task_id'], info['cid'], on_list)

    def list_template(self, data):
        result = ['<html><body><ul><li><a href=".">.</a><li><a href="..">..</a>', ]
        for each in data:
            if each["task_type"] == "bt":
                self.xunlei.info_dict[each["task_id"]] = each
            if each.get("lixian_url"):
                result.append('<li><a href="/proxy/%s/%s">%s%s</a>' % (
                    base64.urlsafe_b64encode(json.dumps({
                        "url": each["lixian_url"],
                        "headers": {
                            "Cookie": "gdriveid=%s;" % self.xunlei.gdriveid,
                            },
                        })),
                    urllib.quote_plus(each["taskname"].encode("utf8")),
                    each["taskname"],
                    "/" if each["task_type"] == "bt" else ""))
            else:
                result.append('<li><a href="%s">%s%s</a>' % (
                    each["task_id"],
                    each["taskname"],
                    "/" if each["task_type"] == "bt" else ""))
        result.append("</ul></body></html>")
        return "".join(result)

def run(port=8886, bind='0.0.0.0'):
    from tornado.log import enable_pretty_logging
    enable_pretty_logging()

    application = tornado.web.Application([
        (r"/(\d+)?", XunleiHandler),
        (r"/proxy/([^/]*)(?:/.*)?", ProxyHandler),
    ], debug=True)
    application.listen(port, bind)
    print 'listening on %s:%s' % (bind, port)
    tornado.ioloop.IOLoop.instance().start()

if __name__ == '__main__':
    #try:
        run()
    #except KeyboardInterrupt:
        #from tornado.iostream import IOStream
        #import gc
        #read_buffer = 0
        #write_buffer = 0
        #for each in gc.get_objects():
            #if isinstance(each, IOStream):
                #read_buffer += sum(map(len, each._read_buffer))
                #write_buffer += sum(map(len, each._write_buffer))
        #print read_buffer, write_buffer
        #import IPython; IPython.embed()
