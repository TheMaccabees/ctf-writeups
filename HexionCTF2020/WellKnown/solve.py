#!/usr/bin/env python
import requests
domain = "https://wk.hexionteam.com/.well-known/{}"
well_known_uris = [
    "acme-challenge",
    "ashrae",
    "assetlinks.json",
    "caldav",
    "carddav",
    "coap",
    "core",
    "csvm",
    "dnt",
    "dnt-policy.txt",
    "est",
    "genid",
    "hoba",
    "host-meta",
    "host-meta.json",
    "http-opportunistic",
    "keybase.txt",
    "mercure",
    "mta-sts.txt",
    "ni",
    "openid-configuration",
    "openorg",
    "pki-validation",
    "posh",
    "reload-config",
    "repute-template",
    "resourcesync",
    "security.txt",
    "stun-key",
    "time",
    "timezone",
    "uma2-configuration",
    "void",
    "webfinger",
    "apple-app-site-association",
    "apple-developer-merchantid-domain-association",
    "browserid",
    "openpgpkey",
    "autoconfig/mail",
    "change-password",
    "nodeinfo", ]

for well_known_uri in well_known_uris:
    d = domain.format(well_known_uri)
    r = requests.get(d)
    if r.status_code != 404:
        print(well_known_uri)
