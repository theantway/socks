import socks
import socket
import urllib

socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5,"localhost", 1080, True)

socket.socket = socks.socksocket
# urllib.urlopen("http://www.twitter.com")
# urllib.urlopen("http://www.baidu.com")

f=urllib.urlopen("http://www.baidu.com")
print "=====Result====="
print f.read()

f=urllib.urlopen("http://localhost:8000")
print ""
print "=====Result====="
print f.read()
