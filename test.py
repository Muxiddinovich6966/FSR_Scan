import urllib.request
import json

req = urllib.request.Request(
    'http://127.0.0.1:3000/api/scan', 
    data=b'{"url":"http://paypal-support-center.info/login"}', 
    headers={'Content-Type': 'application/json'}
)
res = urllib.request.urlopen(req)
print(res.read().decode())
