xunlei-lixian-proxy(alpha)
=========================

a http/ftp proxy for xunlei lixian

* visit your xunlei lixian space with any ftp client.
* streaming video to any media player from xunlei lixian online.
* fully asynchronous with tornado ioloop.
* it's just a demo of streaming video through different protocol. ***it may not work fine as a product***.

## USAGE
###http proxy server

* ` python xunlei_webserver.py `
* login with your xunlei account

###ftp proxy server

* ` python xunlei_ftpserver.py `
* login with your xunlei account (replace @ with * in your account)


##中文简介

迅雷离线空间协议转换

* 通过ftp的方式访问你的迅雷离线空间
* 在线串流离线空间中的视频到任何播放器
* 完全异步化(使用tornado ioloop)
* 这只是一个多协议转换的原理验证演示，***不保证可以用于生产环境***
