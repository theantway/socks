import socks
import socket
import urllib

socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5,"localhost", 1080, True)

socket.socket = socks.socksocket
urllib.urlopen("http://www.twitter.com")