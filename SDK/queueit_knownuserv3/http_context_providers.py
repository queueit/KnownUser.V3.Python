from queueit_helpers import QueueitHelpers


class HttpContextProvider:
    ERROR_MSG = "Please implement/use specific provider"

    def getProviderName(self):
        raise NotImplementedError(self.ERROR_MSG)

    def setCookie(self, name, value, expire, domain):
        raise NotImplementedError(self.ERROR_MSG)

    def getCookie(self, name):
        raise NotImplementedError(self.ERROR_MSG)

    def getHeader(self, name):
        raise NotImplementedError(self.ERROR_MSG)

    def getRequestIp(self, name):
        raise NotImplementedError(self.ERROR_MSG)

    def getOriginalRequestUrl(self):
        raise NotImplementedError(self.ERROR_MSG)


class Django_1_8_Provider(HttpContextProvider):
    def __init__(self, request, response):
        self.request = request
        self.response = response

    def getProviderName(self):
        return "django_1_8"

    def setCookie(self, name, value, expire, domain):
        if (str(domain) == ""):
            domain = None

        if (value is not None):
            value = QueueitHelpers.urlEncode(value)

        self.response.set_cookie(
            name,
            value,
            max_age=None,
            expires=expire,
            path='/',
            domain=domain,
            secure=None,
            httponly=False)

    def getCookie(self, name):
        value = self.request.COOKIES.get(name)
        if (value is not None):
            value = QueueitHelpers.urlDecode(value)
        return value

    def getHeader(self, name):
        if (name is None or name == ""):
            return None

        key = "HTTP_" + name.replace("-", "_").upper()
        return self.request.META.get(key)

    def getRequestIp(self):
        return self.request.META.get("REMOTE_ADDR")

    def getOriginalRequestUrl(self):
        return self.request.build_absolute_uri()