#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# vim: set et sw=4 ts=4 sts=4 ff=unix fenc=utf8:
# Author: Binux<i@binux.me>
#         http://binux.me
# Created on 2013-11-12 19:45:27

import asyncore
import tornado.ioloop
from pyftpdlib.ioloop import _IOLoop, _CallEvery, _CallLater

_read = asyncore.read
_write = asyncore.write
class TornadoIOLoop(_IOLoop):
    def __init__(self):
        super(TornadoIOLoop, self).__init__()
        self.socket_map = {}

        self.ioloop = tornado.ioloop.IOLoop.instance()
        self.READ = self.ioloop.READ
        self.WRITE = self.ioloop.WRITE
        self._ERROR = self.ioloop.ERROR

    def register(self, fd, instance, events):
        if fd not in self.socket_map:
            self.socket_map[fd] = instance
            self.ioloop.add_handler(fd, self.event_fired, events)

    def unregister(self, fd):
        if fd in self.socket_map:
            del self.socket_map[fd]
        self.ioloop.remove_handler(fd)

    def modify(self, fd, events):
        self.ioloop.update_handler(fd, events)

    def event_fired(self, fd, events):
        inst = self.socket_map.get(fd)
        if inst is None:
            return
        if events & self._ERROR and not events & self.READ:
            inst.handle_close()
        else:
            if events & self.READ and inst.readable():
                _read(inst)
            if events & self.WRITE and inst.writable():
                _write(inst)

    def call_later(self, seconds, target, *args, **kwargs):
        self.ioloop.add_timeout(self.ioloop.time()+seconds, self.timer_handler)
        kwargs['_scheduler'] = self.sched
        return _CallLater(seconds, target, *args, **kwargs)

    def call_every(self, seconds, target, *args, **kwargs):
        tornado.ioloop.PeriodicCallback(self.timer_handler, seconds*1000, self.ioloop)
        kwargs['_scheduler'] = self.sched
        return _CallEvery(seconds, target, *args, **kwargs)

    def timer_handler(self):
        self.sched.poll()

    def start(self):
        self.ioloop.start()

    def loop(self, timeout=None, blocking=True):
        if timeout is None and blocking:
            self.ioloop.start()

    def close(self):
        self.ioloop.close()
        super(TornadoIOLoop, self).close()


if __name__ == '__main__':
    import os
    from pyftpdlib.handlers import FTPHandler
    from pyftpdlib.servers import FTPServer
    from pyftpdlib.authorizers import DummyAuthorizer
    from pyftpdlib.filesystems import UnixFilesystem

    authorizer = DummyAuthorizer()
    authorizer.add_anonymous(os.getcwd())
    handler = FTPHandler
    handler.authorizer = authorizer
    handler.abstracted_fs = UnixFilesystem
    ioloop = TornadoIOLoop()
    server = FTPServer(('', 2221), handler, ioloop=ioloop)
    #server.serve_forever()
    ioloop.start()
