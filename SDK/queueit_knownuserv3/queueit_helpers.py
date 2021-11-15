import hmac
import hashlib
import urllib
import time
from urllib.parse import urlparse
from datetime import datetime, timedelta


class QueueitHelpers:
    @staticmethod
    def hmacSha256Encode(value, key):
        digest = hmac.new(key, msg=value, digestmod=hashlib.sha256).hexdigest()
        return digest

    @staticmethod
    def getCurrentTime():
        return int(time.time())

    @staticmethod
    def urlEncode(v):
        return urllib.quote(v, safe='~')

    @staticmethod
    def urlDecode(v):
        return urllib.unquote(v)

    @staticmethod
    def urlParse(url_string):
        return urlparse(url_string)

    @staticmethod
    def getCookieExpirationDate():
        return datetime.utcnow() + timedelta(days=1)

    @staticmethod
    def getCurrentTimeAsIso8601Str():        
        return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def convertToInt(value):
        try:
            converted = int(value)
        except:
            converted = 0
        return converted
