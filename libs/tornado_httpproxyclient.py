#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# vim: set et sw=4 ts=4 sts=4 ff=unix fenc=utf8:
# Author: Binux<i@binux.me>
#         http://binux.me
# Created on 2013-11-09 22:42:57

from tornado.simple_httpclient import SimpleAsyncHTTPClient, _HTTPConnection, native_str, re, HTTPHeaders

class HTTPProxyClient(SimpleAsyncHTTPClient):
    def __init__(self, *args, **kwargs):
        super(HTTPProxyClient, self).__init__(*args, **kwargs)
        self._closed = False

    def close(self):
        super(HTTPProxyClient, self).close()
        self._closed = True

    def _handle_request(self, request, release_callback, final_callback):
        HTTPConnection(self.io_loop, self, request, release_callback,
                       final_callback, self.max_buffer_size, self.resolver)

class HTTPConnection(_HTTPConnection):
    def _on_headers(self, data):
        data = native_str(data.decode("latin1"))
        first_line, _, header_data = data.partition("\n")
        match = re.match("HTTP/1.[01] ([0-9]+) ([^\r]*)", first_line)
        assert match
        code = int(match.group(1))
        self.headers = HTTPHeaders.parse(header_data)
        if 100 <= code < 200:
            self._handle_1xx(code)
            return
        else:
            self.code = code
            self.reason = match.group(2)

        if (self.request.follow_redirects and
            self.request.max_redirects > 0 and
                self.code in (301, 302, 303, 307)):
            self._on_body(b"")
            return

        if "Content-Length" in self.headers:
            if "," in self.headers["Content-Length"]:
                # Proxies sometimes cause Content-Length headers to get
                # duplicated.  If all the values are identical then we can
                # use them but if they differ it's an error.
                pieces = re.split(r',\s*', self.headers["Content-Length"])
                if any(i != pieces[0] for i in pieces):
                    raise ValueError("Multiple unequal Content-Lengths: %r" %
                                     self.headers["Content-Length"])
                self.headers["Content-Length"] = pieces[0]
            content_length = int(self.headers["Content-Length"])
        else:
            content_length = None

        if self.request.header_callback is not None:
            # re-attach the newline we split on earlier
            self.request.header_callback(first_line + _)
            for k, v in self.headers.get_all():
                self.request.header_callback("%s: %s\r\n" % (k, v))
            self.request.header_callback('\r\n')

        if self.request.method == "HEAD" or self.code == 304:
            # HEAD requests and 304 responses never have content, even
            # though they may have content-length headers
            self._on_body(b"")
            return
        if 100 <= self.code < 200 or self.code == 204:
            # These response codes never have bodies
            # http://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.3
            if ("Transfer-Encoding" in self.headers or
                    content_length not in (None, 0)):
                raise ValueError("Response with code %d should not have body" %
                                 self.code)
            self._on_body(b"")
            return

        if self.request.on_headers_callback:
            self.io_loop.add_callback(self.request.on_headers_callback, self.code, self.headers)
        if self.request.raw_streaming_callback:
            self.stream = patch_iostream(self.stream)
            chunk_size = 256*1024
            self.stream.max_buffer_size = 2*1024*1024
            def raw_streaming_callback(data):
                self.request.raw_streaming_callback(data, ready_callback)
                if self.stream.closed():
                    self._on_body(b"")
            def ready_callback():
                if not self.stream.closed():
                    self.stream._read_to_buffer()
                    self.stream.read_bytes(chunk_size, raw_streaming_callback)
            ready_callback()
        else:
            if (self.request.use_gzip and
                    self.headers.get("Content-Encoding") == "gzip"):
                self._decompressor = GzipDecompressor()
            if self.headers.get("Transfer-Encoding") == "chunked":
                self.chunks = []
                self.stream.read_until(b"\r\n", self._on_chunk_length)
            elif content_length is not None:
                self.stream.read_bytes(content_length, self._on_body)
            else:
                self.stream.read_until_close(self._on_body)

        
import socket
def patch_iostream(iostream):
    self = iostream
    def _read_to_buffer():
        if self._read_buffer_size >= self.max_buffer_size:
            return 0
        try:
            chunk = self.read_from_fd()
        except (socket.error, IOError, OSError) as e:
            # ssl.SSLError is a subclass of socket.error
            if e.args[0] == errno.ECONNRESET:
                # Treat ECONNRESET as a connection close rather than
                # an error to minimize log spam  (the exception will
                # be available on self.error for apps that care).
                self.close(exc_info=True)
                return
            self.close(exc_info=True)
            raise
        if chunk is None:
            return 0
        self._read_buffer.append(chunk)
        self._read_buffer_size += len(chunk)
        if self._read_buffer_size >= self.max_buffer_size:
            return 0
        return len(chunk)
    self._read_to_buffer = _read_to_buffer
    return iostream
