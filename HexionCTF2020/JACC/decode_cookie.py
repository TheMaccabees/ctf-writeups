#!/usr/bin/env python3
# encoding: utf-8
"""
Decodes the JACC session cookie.
Based on the article 'https://terryvogelsang.tech/MITRECTF2018-my-flask-app/'
"""

from hashlib import sha512
from flask.sessions import session_json_serializer
from itsdangerous import URLSafeTimedSerializer, BadTimeSignature
import base64
import zlib
import json

EXAMPLE_SESSION = '.eJw9j01vozAYhP_KivMegIqVEqmHpWAolR356zXxzdSRSHgxpEEKm6r_fVGl3fPMPDPzGb1P03A-3aJ9_DPCdcRo_xn96KJ9pEtGfLkqPjQgzBJgTMzJ0D9dbc9u3AUFNPbxeuXGU_34_bH5KwH8rhBaGJpK6t6ccD7KABYe5Ca1fdgkL8RgtQB70KgT0PgKYXamnBMD72tXIhHDroVChG8eipseZiPGJVjdT5teKZyBQlMBYbmDeelq5qDapaoeMkfmmrb5uSvwyUB_OA14ZUZwF_ykCL3beFX0ZSlc6LPj5TWjJA9d6hsek63PS1eJWshN1yRIzXIbY7H945LYXwb7Nw_YUrNyB1NstQe2_TkocqFos-OYVJ7MmpXLN-9_XvW9KbPRgJe-Ii17WZiofXrc9lnEVgfRw4N_8BT_-SnFZrKlJ28xu_one-kUprbksbw_P0dfX38BxSWTJg.XptcZg.o3nKt9KCybh5g2xZAt3UgEJTrrs'

def decodeCookiePayload():
    
    if EXAMPLE_SESSION[0] == '.':
        session_payload = EXAMPLE_SESSION[1:].split('.')[0] + "==="
        print("Extracted Session datas : {}".format(session_payload))
        decoded_session_payload = base64.urlsafe_b64decode(session_payload)
        decompressed_session_payload = zlib.decompress(decoded_session_payload)
        print("Extracted decoded uncompressed datas : {} ".format(decompressed_session_payload))
        xml = base64.b64decode(base64.b64decode(json.loads(decompressed_session_payload)["lxml"][" b"]))
        print(xml.decode())

if __name__ == '__main__':

    print("Flask Cookie Session Datas Decoder")

    # Decode
    print("DECODING COOKIE PAYLOAD")
    decodeCookiePayload()

