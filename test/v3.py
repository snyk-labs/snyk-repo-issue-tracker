import logging

import snyk

import requests

from http.client import HTTPConnection  # py3

log = logging.getLogger('urllib3')
log.setLevel(logging.DEBUG)

# logging from urllib3 to console
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
log.addHandler(ch)

# print statements from `http.client.HTTPConnection` to console/stdout
HTTPConnection.debuglevel = 1


logging.basicConfig(level=logging.DEBUG)


from os import environ


snyk_token = environ['SNYK_TOKEN']
snyk_org = environ['SNYK_ORG']
snyk_group = environ['SNYK_GROUP']

V3_API = "https://api.snyk.io/v3"
V3_VERS = "2021-08-20~beta"
USER_AGENT = "pysnyk/snyk_services/target_sync"

DEBUG=True

v3 = snyk.SnykClient(
    token=snyk_token,
    user_agent=USER_AGENT,
    tries=2,
    url="https://api.snyk.io/v3",
    debug=DEBUG)

client = requests.Session()
client.headers.update({'Authorization': f'token {snyk_token}'})
client.headers.update({'User-Agent': USER_AGENT})
client.headers.update({"Content-Type" : "application/vnd.api+json"})




# this breaks because of https://github.com/snyk-labs/pysnyk/blob/master/snyk/client.py#L42
# 

try:
    resp = v3.get(f'orgs/{snyk_org}/projects?version=2021-08-20%7Ebeta')
except Exception as e:
    print(e.content)
