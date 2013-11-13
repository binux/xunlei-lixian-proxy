#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# vim: set et sw=4 ts=4 sts=4 ff=unix fenc=utf8:
# Author: Binux<17175297.hk@gmail.com>
#         http://binux.me
# Created on 2012-09-13 21:05:53

import re
import time
import json
import socket
import logging
import mimetypes
import cookie_utils
import xml.sax.saxutils

from hashlib import md5
from urllib import urlencode
from urlparse import urlparse, urlunparse
from random import random, sample
from tornado import httpclient
from libs.jsfunctionParser import parser_js_function_call

def hex_md5(string):
    return md5(string).hexdigest()

def parse_url(url):
    url = urlparse(url)
    return dict([part.split("=") for part in url[4].split("&")])

def is_bt_task(task):
    return task.get("f_url", "").startswith("bt:")

title_fix_re = re.compile(r"\\([\\\"\'])")
def title_fix(title):
    return title_fix_re.sub(r"\1", title)

def unescape_html(html):
	return xml.sax.saxutils.unescape(html)

def get_content_type(filename):
    return mimetypes.guess_type(filename)[0] or 'application/octet-stream'

def catch(callback=None):
    def catch_callback(func):
        def catch_callback_func(response):
            try:
                result = func(response)
                if callback:
                    callback(result)
                else:
                    return result
            except (socket.error, httpclient.HTTPError), e:
                if callback:
                    callback(e)
                else:
                    raise
        return catch_callback_func
    return catch_callback

class LiXianAPIException(Exception):
    pass

class LiXianAPI:
    def __init__(self):
        self.username = None
        self.password = None
        self.reset()

    @property
    def _now(self):
        return int(time.time()*1000)

    @property
    def _random(self):
        return str(self._now)+str(random()*(2000000-10)+10)

    @property
    def logined(self):
        return self.islogin

    @staticmethod
    def _encode_params(data):
        """Encode parameters in a piece of data.

        Will successfully encode parameters when passed as a dict or a list of
        2-tuples. Order is retained if data is a list of 2-tuples but abritrary
        if parameters are supplied as a dict.
        """

        if isinstance(data, basestring):
            return data
        elif hasattr(data, 'read'):
            return data
        elif hasattr(data, '__iter__'):
            result = []
            for k, vs in data.iteritems():
                for v in isinstance(vs, list) and vs or [vs]:
                    if v is not None:
                        result.append(
                            (k.encode('utf-8') if isinstance(k, unicode) else k,
                             v.encode('utf-8') if isinstance(v, unicode) else v))
            return urlencode(result, doseq=True)
        else:
            return data

    @staticmethod
    def _build_url(url, _params):
        """Build the actual URL to use."""

        # Support for unicode domain names and paths.
        scheme, netloc, path, params, query, fragment = urlparse(url)
        netloc = netloc.encode('idna').decode('utf-8')
        if not path:
            path = '/'

        if isinstance(scheme, unicode):
            scheme = scheme.encode('utf-8')
        if isinstance(netloc, unicode):
            netloc = netloc.encode('utf-8')
        if isinstance(path, unicode):
            path = path.encode('utf-8')
        if isinstance(params, unicode):
            params = params.encode('utf-8')
        if isinstance(query, unicode):
            query = query.encode('utf-8')
        if isinstance(fragment, unicode):
            fragment = fragment.encode('utf-8')

        enc_params = LiXianAPI._encode_params(_params)
        if enc_params:
            if query:
                query = '%s&%s' % (query, enc_params)
            else:
                query = enc_params
        url = (urlunparse([scheme, netloc, path, params, query, fragment]))
        return url

    @staticmethod
    def json_loads(string):
        m = re.match(r"(?:([^(]+)()?(.+)(?:)?)", string)
        _, v = parser_js_function_call(string)
        return v

    @staticmethod
    def determin_url_type(url):
        url_lower = url.lower()
        if url_lower.startswith("file://"):
            return "local_file"
        elif url_lower.startswith("ed2k"):
            return "ed2k"
        elif url_lower.startswith("thunder"):
            return "thunder"
        elif url_lower.startswith("magnet"):
            return "magnet"
        elif url_lower.endswith(".torrent"):
            return "bt"
        else:
            return "normal"

    @staticmethod
    def _encode_multipart_formdata(fields, files):
        """
        fields is a sequence of (name, value) elements for regular form fields.
        files is a sequence of (name, filename, value) elements for data to be uploaded as files
        Return (content_type, body) ready for httplib.HTTP instance
        """
        BOUNDARY = '----------ThIs_Is_tHe_bouNdaRY_$'
        CRLF = '\r\n'
        L = []
        for (key, value) in fields:
            L.append('--' + BOUNDARY)
            L.append('Content-Disposition: form-data; name="%s"' % key)
            L.append('')
            L.append(value)
        for (key, filename, value) in files:
            L.append('--' + BOUNDARY)
            L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
            L.append('Content-Type: %s' % get_content_type(filename))
            L.append('')
            L.append(value.read() if hasattr(value, "read") else value)
        L.append('--' + BOUNDARY + '--')
        L.append('')
        body = CRLF.join(L)
        content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
        return content_type, body

    def _request(self, request, _callback, async=False):
        if async:
            return httpclient.AsyncHTTPClient().fetch(request, _callback)
        else:
            try:
                response = httpclient.HTTPClient().fetch(request)
            except httpclient.HTTPError, e:
                response = e.response
            return _callback(response)

    def do_post(self, url, params={}, data={}, files={}, _callback=lambda x: x, callback=None, **kwargs):
        def callback_wrap(response):
            self.session.extract_cookies_to_jar(request, ct)
            return _callback(response)

        content_type = ""
        if files:
            _fields = []
            for key, value in data.iteritems():
                if isinstance(value, list):
                    for each in value:
                        _fields.append((key, each))
                else:
                    _fields.append((key, value))
            _files = []
            for key, value in files.iteritems():
                _files.append((key, value[0], value[1]))
            content_type, body = self._encode_multipart_formdata(_fields, _files)
        else:
            body = self._encode_params(data)

        ct = cookie_utils.CookieTracker()
        request = httpclient.HTTPRequest(self._build_url(url, params), "POST",
                    body=body, header_callback=ct.get_header_callback(), **kwargs)
        cookie = self.session.get_cookie_header(request)
        if cookie:
            request.headers.add('Cookie', self.session.get_cookie_header(request))
        if content_type:
            request.headers.add('Content-Type', content_type)
        return self._request(request, callback_wrap, callback)

    def do_get(self, url, params={}, _callback=lambda x: x, callback=None, **kwargs):
        def callback_wrap(response):
            self.session.extract_cookies_to_jar(request, ct)
            return _callback(response)

        ct = cookie_utils.CookieTracker()
        request = httpclient.HTTPRequest(self._build_url(url, params), "GET",
                    header_callback=ct.get_header_callback(), **kwargs)
        cookie = self.session.get_cookie_header(request)
        if cookie:
            request.headers.add('Cookie', self.session.get_cookie_header(request))
        return self._request(request, callback_wrap, callback)


    CHECK_URL = 'http://login.xunlei.com/check' 
    def verifycode(self, username, callback=None):
        @catch(callback)
        def _callback(response):
            response.rethrow()
            verifycode = self.session['check_result'].split(":", 1)
            assert len(verifycode) >= 1, verifycode
            if verifycode[0] == '0' and len(verifycode) == 2:
                return verifycode[1]
            else:
                return 'NEED_VERIFYCODE'

        return self.do_get(self.CHECK_URL, params={'u':username,'cachetime':self._now},
                           _callback=_callback, callback=callback)

    VERIFY_CODE = 'http://verify2.xunlei.com/image'
    def get_verifycode(self, callback=None):
        @catch(callback)
        def _callback(response):
            response.rethrow()
            return response.body
        
        return self.do_get(self.VERIFY_CODE, params={'cachetime': self._now},
                        _callback=_callback, callback=callback)


    LOGIN_URL = 'http://login.xunlei.com/sec2login/'
    def login(self, username, password, verifycode=None, callback=None):
        @catch(callback)
        def _callback(response):
            response.rethrow()
            return response

        self.username = username
        self.password = password
        data = dict(
                u = username,
                p = hex_md5(hex_md5(hex_md5(password))+verifycode.upper()),
                verifycode = verifycode,
                login_enable = 1,
                login_hour = 720)
        return self.do_post(self.LOGIN_URL, data=data,
                            _callback=_callback, callback=callback)

    def _login(self, username, password):
        verifycode = self.verifycode(username)
        self.login(username, password, verifycode)
        self.redirect_to_user_task()
        return self.verify_login()

    def async_login(self, username, password, callback):
        def verifycode_callback(verifycode):
            if callback and isinstance(verifycode, Exception):
                callback(verifycode)
                return
            return self.login(username, password, verifycode, login_callback)

        def login_callback(response):
            if callback and isinstance(response, Exception):
                callback(response)
                return
            self.redirect_to_user_task(redirect_callback)

        def redirect_callback(response):
            self.verify_login(verify_login_callback)

        def verify_login_callback(response):
            callback(response)
            if self.islogin:
                self.menu_get(menu_get_callback)

        def menu_get_callback(response):
            self.offline_id = None
            if not response:
                return

        def menu_add_callback(response):
            if response:
                self.offline_id = response['id']

        return self.verifycode(username, verifycode_callback)

    REDIRECT_URL = "http://dynamic.lixian.vip.xunlei.com/login"
    def redirect_to_user_task(self, callback=None):
        @catch(callback)
        def _callback(response):
            response.rethrow()
            gdriveid = re.search(r'id="cok" value="([^"]+)"', response.body)
            if not gdriveid:
                return False
            self.gdriveid = gdriveid.group(1)
            return True

        return self.do_get(self.REDIRECT_URL, _callback=_callback, callback=callback)

    VERIFY_LOGIN_URL = "http://dynamic.cloud.vip.xunlei.com/interface/verify_login"
    TASK_URL = "http://dynamic.cloud.vip.xunlei.com/user_task?userid=%s"
    def verify_login(self, callback=None):
        @catch(callback)
        def _callback(response):
            if response.error:
                self.islogin = False
                return False
            args = self.json_loads(response.body)
            if args[0].get('result', 0) != 1:
                self.islogin = False
                return False
            self.uid = int(args[0]["data"].get("userid"))
            self.isvip = args[0]["data"].get("vipstate")
            self.nickname = args[0]["data"].get("nickname")
            #self.username = args[0]["data"].get("usrname")
            self.islogin = bool(self.uid and self.isvip)
            self.task_url = self.TASK_URL % self.uid
            return self.islogin

        return self.do_get(self.VERIFY_LOGIN_URL, _callback=_callback, callback=callback)

    CHECK_LOGIN_URL = "http://dynamic.cloud.vip.xunlei.com/net_interface.php"
    def check_login(self, callback=None):
        @catch(callback)
        def _callback(response):
            if response.error:
                self.islogin = False
                return False
            if "login" in response.body:
                self.islogin = False
                return False
            self.islogin = True
            return True

        return self.do_get(self.CHECK_LOGIN_URL, _callback=_callback, callback=callback)

    d_status = { 0: "waiting", 1: "active", 2: "complete", 3: "error", 5: "paused" }
    d_tasktype = {0: "bt", 1: "normal", 2: "ed2k", 3: "thunder", 4: "magnet" }
    st_dict = {"all": 0, "downloading": 1, "finished": 2}
    def get_task_list(self, pagenum=10, st=0, page=1, callback=None):
        @catch(callback)
        def _callback(response):
            if response.error:
                self.check_login(lambda x: x)
            response.rethrow()

            result = []
            args = json.loads(re.search(r'jsonp1234567890\((.*)\)', response.body).group(1)), 
            if not args:
                return result
            
            self.gdriveid = args[0].get('info', {}).get('user', {}).get('cookie', '') or self.gdriveid
            self.total_size = int(args[0].get('info', {}).get('user', {}).get('max_store', 0))
            self.used_size = args[0].get('userinfo', {}).get('all_used_store', 0)
            self.leave_space = int(args[0].get('info', {}).get('user', {}).get('available_space', 0))
            m = re.search(r'<a class="on">(\d+)</a>', args[0].get('global_new', {}).get('page', ''))
            self.last_page = int(m.group(1)) if m else 1
            self.has_next_page = bool(re.search(r'<li class="next"><a href="/user_task', args[0].get('global_new', {}).get('page', '')))

            for r in args[0].get('info', {}).get('tasks', []):
                if r.get('flag', '4') != '0':
                    self.has_next_page = False
                    continue
                tmp = dict(
                        task_id=int(r["id"]),
                        cid=r['cid'],
                        url=r["url"],
                        taskname=r["taskname"],
                        task_type=self.d_tasktype.get(int(r["tasktype"]), 1),
                        status=self.d_status.get(int(r["download_status"]), "waiting"),
                        process=r["progress"],
                        lixian_url=r["lixian_url"],
                        size=int(r["ysfilesize"]),
                        format=r["openformat"],
                        expired=r["left_live_time"],
                        dt_committed=r["dt_committed"],
                      )
                result.append(tmp)
            return result

        self.session['pagenum'] = str(pagenum)
        return self.do_get("http://dynamic.cloud.vip.xunlei.com/interface/showtask_unfresh", params={
            "callback": "jsonp1234567890",
            "t": self._now,
            "type_id": 4,
            "page": page,
            "tasknum": pagenum,
            "p": page,
            "interfrom": "task",
            }, _callback=_callback, callback=callback)

    def _get_task_list(self, pagenum=10, st=0, page=1, callback=None):
        @catch(callback)
        def _callback(response):
            if response.error:
                self.check_login(lambda x: x)
            response.rethrow()

            gdriveid = re.search(r'id="cok" value="([^"]+)"', response.body)
            if gdriveid:
                self.gdriveid = gdriveid.group(1)

            total_size = re.search(r"var total_size\s*=\s*'(\d+)'", response.body)
            if total_size:
                self.total_size = total_size.group(1)
            used_size = re.search(r"var used_size\s*=\s*'(\d+)'", response.body)
            if used_size:
                self.used_size = used_size.group(1)
            leave_space = re.search(r"var leave_space\s*=\s*(\d+)", response.body)
            if leave_space:
                self.leave_space = leave_space.group(1)
            m = re.search(r"&p=(\d+)", response.effective_url)
            if m:
                self.last_page = int(m.group(1))
            else:
                self.last_page = 1
            self.has_next_page = '<li class="next"><a href="/user_task' in response.body

            def parse_task(html):
                inputs = re.findall(r'<input[^<>]+/>', html)
                def parse_attrs(html):
                    return dict((k, v1 or v2) for k, v1, v2 in re.findall(r'''\b(\w+)=(?:'([^']*)'|"([^"]*)")''', html))
                info = dict((re.sub(r'\d+$', '', x['id']), unescape_html(x['value'])) for x in map(parse_attrs, inputs))
                m = re.search(r'<em class="loadnum"[^<>]*>([^<>]*)</em>', html)
                assert m, "can't find progress"
                info["process"] = float(m.group(1).rstrip("%"))
                m = re.search(ur'<em class="infomag rw_gray info_col01"[^<>]*>(保留.*?)</em>', html)
                if m:
                    info['expired'] = m.group(1)
                else:
                    info['expired'] = ''
                info["taskname"] = title_fix(info["taskname"])
                return info 

            rwbox = re.search(r'<div class="rwbox".*<!--rwbox-->', response.body.decode("utf-8", "replace"), re.S)
            if not rwbox:
                if "top.location" in response.body:
                    self.relogin()
                else:
                    self.check_login(lambda x: x)
                return []
            rwbox = rwbox.group()
            rw_lists = re.findall(r'<div class="rw_list".*?<!-- rw_list -->', rwbox, re.S)
            raw_data = [parse_task(x) for x in rw_lists]
            result = []
            for r in raw_data:
                tmp = dict(
                        task_id=int(r["input"]),
                        cid=r['dcid'],
                        url=r["f_url"],
                        taskname=r["taskname"],
                        task_type=self.d_tasktype.get(int(r["d_tasktype"]), 1),
                        status=self.d_status.get(int(r["d_status"]), "waiting"),
                        process=r["process"],
                        lixian_url=r["dl_url"],
                        size=int(r["ysfilesize"]),
                        format=r["openformat"],
                        expired=r["expired"],
                      )
                result.append(tmp)
            return result

        self.session['pagenum'] = str(pagenum)
        return self.do_get("%s&st=%s&t=%s&p=%s" % (self.task_url, st, self._now, page), _callback=_callback, callback=callback)

    FILL_BT_LIST = "http://dynamic.cloud.vip.xunlei.com/interface/fill_bt_list"
    def get_bt_list(self, tid, cid, callback=None):
        @catch(callback)
        def _callback(response):
            response.rethrow()

            args = self.json_loads(response.body)
            if not args:
                return {}
            if isinstance(args[0], basestring):
                return {}
            raw_data = args[0].get("Result", {})
            assert cid == raw_data.get("Infoid")
            result = []
            for r in raw_data.get("Record", []):
                tmp = dict(
                        task_id=int(r['taskid']),
                        cid=r['cid'],
                        url=r['url'],
                        taskname=r['title'],
                        task_type="normal",
                        status=self.d_status.get(int(r['download_status'])),
                        process=r['percent'],
                        lixian_url=r['downurl'],
                        size=int(r['filesize']),
                        format=r['openformat'],
                        title=r['title'],
                        dirtitle=r['dirtitle'],
                    )
                result.append(tmp)
            return result

        self.session['pagenum'] = str(2000)
        return self.do_get(self.FILL_BT_LIST, params=dict(
                                            callback="fill_bt_list",
                                            tid = tid,
                                            infoid = cid,
                                            g_net = 1,
                                            p = 1,
                                            uid = self.uid,
                                            noCacheIE = self._now), _callback=_callback, callback=callback)

    def fill_bt_list(self, tids, callback=None):
        @catch(callback)
        def _callback(response):
            response.rethrow()

            args = self.json_loads(response.body)
            if not args:
                return {}
            if isinstance(args[0], basestring):
                return {}
            if not args[0]:
                return {}
            raw_data = args[0].get("Result", {})
            result = {}
            for key, value in raw_data.iteritems():
                files = []
                for r in value:
                    tmp = dict(
                            task_id=int(r['taskid']),
                            cid=r['cid'],
                            url=r['url'],
                            taskname=r['title'],
                            task_type="normal",
                            lixian_url=r['downurl'],
                            size=int(r['filesize']),
                            title=r['title'],
                        )
                    files.append(tmp)
                result[key] = files
            return result

        self.session['pagenum'] = str(2000)
        return self.do_get(self.FILL_BT_LIST, params=dict(
                                            callback="json1234567890",
                                            tid = ",".join(tids),
                                            g_net = 1,
                                            uid = self.uid), _callback=_callback, callback=callback)


    QUERY_URL = "http://dynamic.cloud.vip.xunlei.com/interface/url_query"
    def bt_task_check(self, url, callback=None):
        @catch(callback)
        def _callback(response):
            response.rethrow()

            args = self.json_loads(response.body)
            if len(args) < 12:
                return {}
            if not args[2]:
                return {}
            result = dict(
                    flag = args[0],
                    cid = args[1],
                    size = args[2],
                    title = title_fix(args[3]),
                    is_full = args[4],
                    random = args[11])
            filelist = []
            for subtitle, subformatsize, size, valid, file_icon, findex in zip(*args[5:11]):
                tmp_file = dict(
                        title = subtitle,
                        formatsize = subformatsize,
                        size=size,
                        file_icon = file_icon,
                        ext = "",
                        index = findex,
                        valid = int(valid),
                        )
                filelist.append(tmp_file)
            result['filelist'] = filelist
            return result

        return self.do_get(self.QUERY_URL, params={
                                  "callback": "queryUrl",
                                  "u": url,
                                  "random": self._random,
                                  "tcache": self._now}, _callback=_callback, callback=callback)

    TORRENT_UPDATE_URL = "http://dynamic.cloud.vip.xunlei.com/interface/torrent_upload"
    def torrent_upload(self, filename, fp, callback=None):
        @catch(callback)
        def _callback(response):
            response.rethrow()
            m = re.search("""btResult =(.*?);.*?</script>""",
                          response.body)
            if not m:
                m = re.search(r"""(parent\.edit_bt_list.*?);\s*</script>""", response.body)
            if not m:
                return {}
            args = self.json_loads(m.group(1))
            assert args
            info = args[0] if (args and args[0]['ret_value']) else {}
            if not info: return {}
            result = dict(
                    flag = info['ret_value'],
                    cid = info['infoid'],
                    is_full = info['is_full'],
                    random = info.get('random', 0),
                    title = info['ftitle'],
                    size = info['btsize'],
                    )
            filelist = []
            for _file in info['filelist']:
                tmp_file = dict(
                        title = _file['subtitle'],
                        formatsize = _file['subformatsize'],
                        size = _file['subsize'],
                        file_icon = _file['file_icon'],
                        ext = _file['ext'],
                        index = _file['findex'],
                        valid = _file['valid'],
                        )
                filelist.append(tmp_file)
            result['filelist'] = filelist

            return result

        files = {'filepath': (filename, fp)}
        return self.do_post(self.TORRENT_UPDATE_URL, data={"random": self._random,"interfrom": "task"}, files=files,
                                _callback=_callback, callback=callback)

    BT_TASK_COMMIT_URL = "http://dynamic.cloud.vip.xunlei.com/interface/bt_task_commit?callback=jsonp1234567890"
    def add_bt_task_with_dict(self, info, callback=None, classid=0):
        @catch(callback)
        def _callback(response):
            if response.error:
                return False
            if "jsonp1234567890" in response.body:
                return True
            return False

        data = dict(
                uid = self.uid,
                btname = info["title"],
                cid = info["cid"],
                goldbean = 0,
                silverbean = 0,
                tsize = info["size"],
                findex = "_".join(_file['index'] for _file in info["filelist"]),
                size = "_".join(_file['size'] for _file in info["filelist"]),
                #name = "undefined",
                o_taskid = 0,
                o_page = "task",
                class_id = classid)
        data["from"] = 0
        return self.do_post(self.BT_TASK_COMMIT_URL, data=data, _callback=_callback, callback=callback)

    TASK_CHECK_URL = "http://dynamic.cloud.vip.xunlei.com/interface/task_check"
    def task_check(self, url, callback=None):
        @catch(callback)
        def _callback(response):
            response.rethrow()

            #queryCid(cid,gcid,file_size,avail_space,tname,goldbean_need,silverbean_need,is_full,random)
            args = self.json_loads(response.body)
            if len(args) < 8:
                return {}
            result = dict(
                cid = args[0],
                gcid = args[1],
                size = args[2],
                title = title_fix(args[4]),
                goldbean_need = args[5],
                silverbean_need = args[6],
                is_full = args[7],
                random = args[8])
            return result

        return self.do_get(self.TASK_CHECK_URL, params={
                                   "callback": "queryCid",
                                   "url": url,
                                   "random": self._random,
                                   "tcache": self._now}, _callback=_callback, callback=callback)

    TASK_COMMIT_URL = "http://dynamic.cloud.vip.xunlei.com/interface/task_commit"
    def add_task_with_dict(self, url, info, callback=None, classid=0):
        @catch(callback)
        def _callback(response):
            if response.error:
                return False
            if "ret_task" in response.body:
                return True
            if "jsonp1234567890" in response.body:
                return True
            return False

        params = dict(
            callback="jsonp1234567890",
            uid=self.uid,
            cid=info['cid'],
            gcid=info['gcid'],
            size=info['size'],
            goldbean=0,
            silverbean=0,
            t=info['title'],
            url=url,
            type=0,
            o_page="task",
            o_taskid=0,
            class_id=classid,
            database="undefined",
            time="Wed May 30 2012 14:22:01 GMT 0800 (CST)",
            noCacheIE=self._now)
        return self.do_get(self.TASK_COMMIT_URL, params=params, _callback=_callback, callback=callback)

    BATCH_TASK_CHECK_URL = "http://dynamic.cloud.vip.xunlei.com/interface/batch_task_check"
    def batch_task_check(self, url_list, callback=None):
        @catch(callback)
        def _callback(response):
            response.rethrow()

            m = re.search("""(parent.begin_task_batch_resp.*?)</script>""",
                          response.body)
            assert m
            m = m.group(1)
            m = m[:m.rfind(",")]
            args = self.json_loads(m+")")
            assert args
            args = args[0] if args else []
            for each in args: 
                each['title'] = each.get('name')
                each['size'] = (each.get('filesize') or "").strip()
            return args

        data = dict(url="\r\n".join(url_list), random=self._random)
        return self.do_post(self.BATCH_TASK_CHECK_URL, data=data, _callback=_callback, callback=callback)

    BATCH_TASK_COMMIT_URL = "http://dynamic.cloud.vip.xunlei.com/interface/batch_task_commit?callback=jsonp1234567890"
    def add_batch_task_with_dict(self, info, callback=None, classid=0):
        @catch(callback)
        def _callback(response):
            if response.error:
                return False
            if "jsonp1234567890" in response.body:
                return True
            return False

        data = dict(
                batch_old_taskid="0,",
                batch_old_database="0,",
                class_id=classid,
                )
        data["cid[]"] = []
        data["url[]"] = []
        for i, task in enumerate(info):
            data["cid[]"].append(task.get("cid", ""))
            data["url[]"].append(task["url"])
        return self.do_post(self.BATCH_TASK_COMMIT_URL, data=data, _callback=_callback, callback=callback)

    TASK_DELAY_URL = "http://dynamic.cloud.vip.xunlei.com/interface/task_delay?taskids=%(ids)s&noCacheIE=%(cachetime)d"
    def delay_task(self, task_ids, callback=None):
        @catch(callback)
        def _callback(response):
            if response.error:
                return False
            args = self.json_loads(response.body)
            if args and args[0].get("result") == 1:
                return True
            return False

        tmp_ids = [str(x)+"_1" for x in task_ids]
        return self.do_get(self.TASK_DELAY_URL % dict(
                            ids = ",".join(tmp_ids),
                            cachetime = self._now), _callback=_callback, callback=callback)

    TASK_DELETE_URL = "http://dynamic.cloud.vip.xunlei.com/interface/task_delete?type=0"
    def delete_task(self, task_ids, callback=None):
        @catch(callback)
        def _callback(response):
            if response.error:
                return False
            args = self.json_loads(response.body)
            if args and args[0].get("result") == 1:
                return True
            return False

        return self.do_post(self.TASK_DELETE_URL, data = {
                                                      "databases": "0",
                                                      "taskids": ",".join([str(x) for x in task_ids])},
                                                 _callback=_callback, callback=callback)

    TASK_PAUSE_URL = "http://dynamic.cloud.vip.xunlei.com/interface/task_pause"
    def task_pause(self, task_ids, callback=None):
        @catch(callback)
        def _callback(response):
            if response.error:
                return False
            if "pause_task_resp" in response.body:
                return True
            return False

        return self.do_get(self.TASK_PAUSE_URL, params = {
                                                    "tid": ",".join([str(x) for x in task_ids]),
                                                    "uid": self.uid,
                                                    "noCacheIE": self._now
                                                    },
                                                _callback=_callback, callback=callback)

    REDOWNLOAD_URL = "http://dynamic.cloud.vip.xunlei.com/interface/redownload?callback=jsonp1234567890"
    def redownload(self, task_ids, callback=None):
        @catch(callback)
        def _callback(response):
            if response.error:
                return False
            if "jsonp1234567890(1)" in response.body:
                return True
            return False

        return self.do_post(self.REDOWNLOAD_URL, data = {
                                         "id[]": task_ids,
                                         "cid[]": ["",]*len(task_ids),
                                         "url[]": ["",]*len(task_ids),
                                         "taskname[]": ["",]*len(task_ids),
                                         "download_status[]": [5,]*len(task_ids),
                                         "type": 1,
                                         "class_id": 0,
                                         },
                                         _callback=_callback, callback=callback)

    # menu
    MENU_GET_URL = "http://dynamic.cloud.vip.xunlei.com/interface/menu_get"
    def menu_get(self, callback=None):
        @catch(callback)
        def _callback(response):
            response.rethrow()
            args = self.json_loads(response.body)
            if args and args[0] and args[0].get("info"):
                return args[0]["info"]
            return []

        return self.do_get(self.MENU_GET_URL, params = {
                                                    "callback": "jsonp1234567890",
                                                    "t": self._now
                                                    },
                                                _callback=_callback, callback=callback)

    MENU_CHANGE_URL = "http://dynamic.cloud.vip.xunlei.com/interface/menu_change"
    def menu_change(self, menu_id, name, callback=None):
        @catch(callback)
        def _callback(response):
            response.rethrow()
            args = self.json_loads(response.body)
            if args and args[0] and args[0].get("rtcode", "1") == "0" and "info" in args[0]:
                return args[0]["info"]
            return {}

        return self.do_get(self.MENU_CHANGE_URL, params = {
                                                    "callback": "jsonp1234567890",
                                                    "t": self._now,
                                                    "menu_id": menu_id,
                                                    "menu_name": name,
                                                    },
                                                _callback=_callback, callback=callback)
    
    MENU_ADD_URL = "http://dynamic.cloud.vip.xunlei.com/interface/menu_add"
    def menu_add(self, name, callback=None):
        @catch(callback)
        def _callback(response):
            response.rethrow()
            args = self.json_loads(response.body)
            if args and args[0] and args[0].get("rtcode", "1") == "0" and "info" in args[0]:
                return args[0]["info"]
            return {}

        return self.do_get(self.MENU_ADD_URL, params = {
                                                    "callback": "jsonp1234567890",
                                                    "t": self._now,
                                                    "menu_name": name,
                                                    },
                                                _callback=_callback, callback=callback)

    SHOW_CLASS_URL = "http://dynamic.cloud.vip.xunlei.com/interface/show_class"
    def show_class(self, menu_id, callback=None):
        @catch(callback)
        def _callback(response):
            response.rethrow()
            args = self.json_loads(response.body)
            args = args[0] if args else {}
            if not self.gdriveid and 'info' in args and 'user' in args['info'] and 'cookie' in args['info']['user']:
                self.gdriveid = args['info']['user']['cookie']
            return args

        self.session['pagenum'] = str(2000)
        return self.do_get(self.SHOW_CLASS_URL, params = {
                                                    "callback": "jsonp1234567890",
                                                    "t": self._now,
                                                    "type_id": menu_id,
                                                    },
                                                _callback=_callback, callback=callback)

    MOVE_TASK_MORE_URL = "http://dynamic.cloud.vip.xunlei.com/interface/move_task_more?callback=jsonp1234567890"
    def move_task_more(self, taskids, to=0, callback=None):
        @catch(callback)
        def _callback(response):
            if response.error:
                return False
            if "jsonp1234567890" in response.body:
                return True
            return False
        
        return self.do_post(self.MOVE_TASK_MORE_URL, data = {
                                                        "class_id": to,
                                                        "database[]": [0, ]*len(taskids), #database?
                                                        "task_id[]": taskids,
                                                        },
                                                    _callback=_callback, callback=callback)
        
    def reset(self):
        self.islogin = False
        self.session = cookie_utils.CookieSession()
        self.uid = None
        self.isvip = None
        self.nickname = None
        self.task_url = None
        self.gdriveid = None
        self.total_size = 0
        self.used_size = 0
        self.leave_space = 0
        self.last_page = 1
        self.has_next_page = False
        self.offline_id = None

    def relogin(self):
        if self.username and self.password:
            self.reset()
            self.async_login(self.username, self.password, lambda x: x)
