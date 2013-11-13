#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# vim: set et sw=4 ts=4 sts=4 ff=unix fenc=utf8:
# Author: Binux<i@binux.me>
#         http://binux.me
# Created on 2013-11-13 19:47:26

import os
import socket
import functools
from tornado.log import access_log, gen_log
from tornado.platform.auto import set_close_exec
from tornado.tcpserver import TCPServer
from tornado.iostream import IOStream
from tornado import stack_context

class FTPServer(TCPServer):
    def __init__(self, io_loop=None, ssl_options=None, debug=False, **kwargs):
        TCPServer.__init__(self, io_loop=io_loop, ssl_options=ssl_options,
                           **kwargs)

    def handle_stream(self, stream, address):
        FTPConnection(stream, address)

class PassiveServer(TCPServer):
    def __init__(self, callback, io_loop=None, ssl_options=None, **kwargs):
        self.callback = stack_context.wrap(callback)
        TCPServer.__init__(self, io_loop=io_loop, ssl_options=ssl_options,
                           **kwargs)
        self.listen(0)

    def handle_stream(self, stream, address):
        self.callback(stream, address)

def authed(func):
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        if not self.current_user:
            self.respond("530 Log in with USER and PASS first.")
            return
        return func(self, *args, **kwargs)
    return wrap

class FTPConnection(object):
    banner = "Welcome!"
    response_message = {
            200: "OK.",
            451: "Sorry.",
            }

    def __init__(self, stream, address):
        self.stream = stream
        self.address = address

        self._current_type = 'a'
        self._current_path = '/'
        self.rest = None
        self.passive_server = None
        self.datastream = None

        self.data_channel = None

        self._on_connect()

    # export
    def on_connect(self):
        pass

    def on_auth(self, username, password):
        self.respond(200)

    def on_close(self):
        pass

    # #
    def _encode(self, data):
        if isinstance(data, unicode):
            return data.encode('utf8')
        return data

    def _decode(self, data):
        return data.decode('utf8', 'replace')

    def write(self, data):
        gen_log.debug(data)
        if not self.stream.closed():
            self.stream.write(data)
        else:
            self.close()

    def respond(self, resp):
        if isinstance(resp, int):
            self.write("%d %s\r\n" % (resp, self.response_message.get(resp, "OK.")))
        else:
            self.write(self._encode(resp)+"\r\n")

    def _on_connect(self):
        access_log.info("New Connect: %s:%s" % self.address)
        self.on_connect()
        if len(self.banner) <= 75:
            self.respond("220 %s" % self._encode(self.banner))
        else:
            self.respond("220-%s\r\n220 " % self._encode(self.banner))

        self._cmd_callback = stack_context.wrap(self._on_cmd)
        self.stream.set_close_callback(self._on_connection_close)
        self.stream.read_until("\r\n", self._cmd_callback)

    def _on_connection_close(self):
        pass

    def close(self):
        if self.passive_server:
            self.passive_server.stop()
            self.passive_server = None
        if self.datastream:
            self.datastream.close()
            self.datastream = None

    def _on_cmd(self, line):
        try:
            line = self._decode(line)[:-2]
            gen_log.debug(line)
        except UnicodeDecodeError:
            return self.respond("501 Can't decode command.")

        cmd = line.split(' ')[0].upper()
        arg = line[len(cmd)+1:]
        try:
            getattr(self, "_cmd_%s" % cmd)(arg)
        except AttributeError:
            self.respond('500 Command "%s" not understood.' % cmd)
        except UnicodeEncodeError:
            self.respond("501 can't decode path")
        except Exception, e:
            self.respond("501 %s" % e)
            gen_log.exception(e)

        self.stream.read_until("\r\n", self._cmd_callback)

    def _cmd_SYST(self, line):
        self.respond("215 UNIX Type: L8")

    def _cmd_OPTS(self, line):
        cmd, arg = line.split(' ')
        if cmd == "UTF8" and arg == "ON":
            self.respond(200)
        else:
            self.respond(451)

    def _cmd_USER(self, line):
        self.username = line
        self.respond(331)

    def _cmd_PASS(self, line):
        self.password = line
        self.on_auth(self.username, self.password)

    def _cmd_QUIT(self, line):
        self.respond("221 Goodbye.")
        self.close()

    def _cmd_NOOP(self, line):
        self.respond(200)

    def _cmd_TYPE(self, line):
        t = line.upper().replace(' ', '')
        if t in ("A", "L7"):
            self._current_type = 'a'
            self.respond("200 ASCII mode.")
        elif t in ("I", "L8"):
            self._current_type = 'i'
            self.respond("200 Binary mode.")
        else:
            self.respond('504 Unsupported type "%s".' % line)

    def _cmd_CDUP(self, line):
        self._cmd_CWD(line)

    def _cmd_PWD(self, line):
        self.respond('257 "%s"' % self._current_path)

    def _cmd_CWD(self, line):
        self._current_path = os.path.join(self._current_path, line)
        self.respond(250)

    def _cmd_PORT(self, line):
        l = line.split(',')
        assert len(l) == 6, "PORT value error"
        ip = '.'.join(l[:4])
        port = (int(l[4])<<8)+int(l[5])
        if self.datastream:
            self.datastream.close()
            self.datastream = None
        datastream = IOStream(socket.socket(self.stream.socket.family))
        def on_connected():
            self.respond(200)
            self._on_datastream(datastream, (ip, port, 0, 0))
        datastream.connect((ip, port), on_connected)

    def _cmd_EPRT(self, line):
        af, ip, port = line.split(line[0])[1:-1]
        if self.datastream:
            self.datastream.close()
            self.datastream = None
        datastream = IOStream(socket.socket(self.stream.socket.family))
        def on_connected():
            self.respond(200)
            self._on_datastream(datastream, (ip, port, 0, 0))
        datastream.connect((ip, port), on_connected)

    def _new_pasv_socket(self, af=None):
        ip, port = self.stream.socket.getsockname()
        servsock = socket.socket(af or self.stream.socket.family, socket.SOCK_STREAM)
        set_close_exec(servsock.fileno())
        servsock.setblocking(0)
        servsock.bind((ip, 0))
        servsock.listen(1)
        self.passive_server = PassiveServer(self._on_datastream)
        self.passive_server.add_socket(servsock)
        
        port = servsock.getsockname()[1]
        return ip, port

    def _cmd_PASV(self, line):
        if self.passive_server:
            self.passive_server.stop()
            self.passive_server = None
        ip, port = self._new_pasv_socket()
        self.respond('227 Entering Passive Mode (%s,%u,%u).\r\n' %
                (','.join(ip.split('.')), port>>8&0xFF, port&0xFF))

    def _cmd_EPSV(self, line):
        if not line:
            af = None
        elif line == "all":
            self.respond("501 Not support.")
        else:
            af = int(line)
        ip, port = self._new_pasv_socket(int(af))
        self.respond("229 Entering extended passive mode (|||%d|)." % port)

    def _on_datastream(self, stream, address):
        self._datastream = None
        self.datastream = stream
        self.datastream.set_close_callback(stack_context.wrap(self._on_datastream_close))

    def _on_datastream_close(self):
        if self.datastream:
            self.datastream.close()
            self.datastream = None

    #def _cmd_LIST(self, line): pass
    #def _cmd_MKD(self, line): pass
    #def _cmd_RMD(self, line): pass
    #def _cmd_DELE(self, line): pass
    #def _cmd_RNFR(self, line): pass
    #def _cmd_RNTO(self, line): pass
    #def _cmd_MKD(self, line): pass
    #def _cmd_MKD(self, line): pass
    #def _cmd_ABOR(self, line): pass

    def _cmd_REST(self, line):
        self.rest = int(line)
        self.respond("350 File position reseted.")

    def _cmd_RETR(self, line):
        self.respond("150 Opening data connection.")
        def on_complete():
            self.datastream.close()
            self.respond('226 Transfer complete.')
        self.datastream.write("test-data", on_complete)

    def _cmd_STOR(self, line):
        self.conn.send('150 Opening data connection.\r\n')
        def on_complete(data):
            self.datastream.close()
            self.respond('226 Transfer complete.')
        self.datastream.read_until_close(on_complete)

if __name__ == '__main__':
    from tornado.ioloop import IOLoop
    from tornado import autoreload
    autoreload.start()
    from tornado.log import enable_pretty_logging
    enable_pretty_logging()
        
    server = FTPServer(debug=True)
    server.listen(2221)
    IOLoop.instance().start()
