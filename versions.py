import requests
import logging

obsolete_apache="2.4"
obsolete_lighttpd="1.4"
obsolete_php="5.6"

r = requests.get("http://bee-box")
print(r.headers['server'])
