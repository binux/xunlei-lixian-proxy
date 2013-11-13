#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# vim: set et sw=4 ts=4 sts=4 ff=unix fenc=utf8:
# Author: Binux<i@binux.me>
#         http://binux.me
# Created on 2013-11-14 00:40:00

import os
import time
import tornado.httpclient
from libs.xunlei_api import LiXianAPI
from libs.ftpserver import FTPConnection, authed
from libs.tornado_httpproxyclient import HTTPProxyClient

xunlei_cache = {}

class XunleiFTPConnection(FTPConnection):
    def on_auth(self, username, password):
        username = username.replace("*", "@")
        if username+password in xunlei_cache:
            self.xunlei = xunlei_cache[username+password]
            self.respond(200)
            return
        self._xunlei = LiXianAPI()
        def on_login(*args, **kwargs):
            if username+password in xunlei_cache:
                self.xunlei = xunlei_cache[username+password]
                self.respond(200)
            elif self._xunlei.logined:
                self.xunlei = self._xunlei
                self.xunlei.info_dict = {}
                xunlei_cache[username+password] = self.xunlei
                self.respond(200)
            else:
                self.respond("530 USER '%s' failed login." % username)
        self._xunlei.async_login(username, password, callback=on_login)

    @property
    def current_user(self):
        return getattr(self, "xunlei", None)

    @property
    def info_dict(self):
        return self.xunlei.info_dict

    @authed
    def _cmd_LIST(self, line):
        line = line.strip()
        if line.startswith("-"):
            line = line.split()[-1]
            if line.startswith("-"):
                line = ""
        if line:
            path = os.path.normpath(os.path.join(self._current_path, line))
        else:
            path = self._current_path
        if path == "/":
            self.list_root(path)
        elif path in self.info_dict:
            self.list_task(path, self.info_dict[path])
        else:
            self.respond("550 No such dir.")

    def list_root(self, path):
        def on_list(data):
            if not self.datastream:
                self.respond(500)
                return
            self.respond("150 Here comes the directory listing.")
            result = []
            for each in data:
                if each['status'] != 'complete':
                    continue
                self.info_dict[os.path.normpath(os.path.join(path, each['taskname']))] = each
                result.append("%sr-xr-xr-x 1 user group %d %s %s" % (
                    "d" if each['task_type'] == "bt" else "-", each['size'],
                    time.strftime("%b %d %H:%M", time.strptime(each['dt_committed'], "%Y-%m-%d %H:%M:%S")),
                    each["taskname"]))
            self.datastream.write(self._encode("\r\n".join(result))+"\r\n", on_complete)
        def on_complete():
            self.datastream.close()
            self.respond("226 Directory send OK.")
        self.current_user.get_task_list(100, callback=on_list)

    def list_task(self, path, info):
        def on_list(data):
            if not self.datastream:
                self.respond(500)
                return
            self.respond("150 Here comes the directory listing.")
            create_time = info['dt_committed']
            result = []
            for each in data:
                if each['status'] != 'complete':
                    continue
                self.info_dict[os.path.normpath(os.path.join(path, each['taskname']))] = each
                result.append("%sr-xr-xr-x 1 user group %d %s %s" % (
                    "d" if each['task_type'] == "bt" else "-", each['size'],
                    time.strftime("%b %d %H:%M", time.strptime(create_time, "%Y-%m-%d %H:%M:%S")),
                    each["taskname"]))
            self.datastream.write(self._encode("\r\n".join(result))+"\r\n", on_complete)
        def on_complete():
            self.datastream.close()
            self.respond("226 Directory send OK.")
        self.current_user.get_bt_list(info['task_id'], info['cid'], on_list)

    @authed
    def _cmd_SIZE(self, line):
        path = os.path.normpath(os.path.join(self._current_path, line))
        if path not in self.info_dict:
            self.respond("550 No such file.")
        info = self.info_dict[path]
        self.respond("213 %d" % info['size'])

    @authed
    def _cmd_RETR(self, line):
        path = os.path.normpath(os.path.join(self._current_path, line))
        if path not in self.info_dict:
            self.respond("550 No such file.")
            return
        info = self.info_dict[path]
        if not info.get('lixian_url'):
            self.respond("550 File can't open.")

        request = tornado.httpclient.HTTPRequest(info['lixian_url'],
                headers={"Cookie": "gdriveid=%s" % self.xunlei.gdriveid})
        request.request_timeout = 0
        def on_header_callback(code, headers):
            if code != 200:
                self.respond("550 Get file error: %d" % code)
                self.datastream.close()
            else:
                self.respond("150 File goes here.")
        def raw_streaming_callback(data):
            if self.datastream:
                self.datastream.write(data)
            else:
                request.conn.close()
        request.on_headers_callback = on_header_callback
        request.raw_streaming_callback = raw_streaming_callback
        def on_finished(data):
            if self.datastream:
                self.datastream.close()
            self.respond('226 Transfer complete.')
        HTTPProxyClient().fetch(request, on_finished)

def run(port=2221, bind="0.0.0.0"):
    from libs.ftpserver import FTPServer
    from tornado.ioloop import IOLoop
    from tornado import autoreload
    autoreload.start()
    from tornado.log import enable_pretty_logging
    enable_pretty_logging()
    import logging;logging.getLogger().setLevel(logging.DEBUG)
        
    server = FTPServer(connect_cls=XunleiFTPConnection, debug=True)
    server.listen(port, bind)
    print 'listening on %s:%s' % (bind, port)
    IOLoop.instance().start()


if __name__ == "__main__":
    run()
