from queueit_helpers import QueueitHelpers


class Utils:
    @staticmethod
    def toString(v):
        if v is None:
            return ""
        if v is True:
            return "true"
        if v is False:
            return "false"
        return str(v)

    @staticmethod
    def isNilOrEmpty(v):
        return v is None or str(v) == ""


class RequestValidationResult:
    def __init__(self, action_type, event_id, queue_id, redirect_url, redirect_type, action_name):
        self.actionType = action_type
        self.eventId = event_id
        self.queueId = queue_id
        self.redirectUrl = redirect_url
        self.redirectType = redirect_type
        self.isAjaxResult = False
        self.actionName = action_name

    def doRedirect(self):
        return not Utils.isNilOrEmpty(self.redirectUrl)

    def getAjaxQueueRedirectHeaderKey(self):
        return "x-queueit-redirect"

    def getAjaxRedirectUrl(self):
        if not Utils.isNilOrEmpty(self.redirectUrl):
            return QueueitHelpers.urlEncode(self.redirectUrl)
        return ""


class QueueEventConfig:
    def __init__(self):
        self.eventId = None
        self.layoutName = None
        self.culture = None
        self.queueDomain = None
        self.extendCookieValidity = None
        self.cookieValidityMinute = None
        self.cookieDomain = None
        self.isCookieHttpOnly = False
        self.isCookieSecure = False
        self.version = -1
        self.actionName = 'unspecified'

    def toString(self):
        return ("EventId:" + Utils.toString(self.eventId) +
                "&Version:" + Utils.toString(self.version) +
                "&QueueDomain:" + Utils.toString(self.queueDomain) +
                "&CookieDomain:" + Utils.toString(self.cookieDomain) +
                "&IsCookieHttpOnly:" + Utils.toString(self.isCookieHttpOnly) +
                "&IsCookieSecure:" + Utils.toString(self.isCookieSecure) +
                "&ExtendCookieValidity:" + Utils.toString(self.extendCookieValidity) +
                "&CookieValidityMinute:" + Utils.toString(self.cookieValidityMinute) +
                "&LayoutName:" + Utils.toString(self.layoutName) +
                "&Culture:" + Utils.toString(self.culture)  +
                "&ActionName:" + Utils.toString(self.actionName))


class CancelEventConfig:
    def __init__(self):
        self.eventId = None
        self.queueDomain = None
        self.version = None
        self.cookieDomain = None
        self.isCookieHttpOnly = False
        self.isCookieSecure = False
        self.actionName = 'unspecified'

    def toString(self):
        return ("EventId:" + Utils.toString(self.eventId) +
                "&Version:" + Utils.toString(self.version) +
                "&QueueDomain:" + Utils.toString(self.queueDomain) +
                "&CookieDomain:" + Utils.toString(self.cookieDomain) +
                "&IsCookieHttpOnly:" + Utils.toString(self.isCookieHttpOnly) +
                "&IsCookieSecure:" + Utils.toString(self.isCookieSecure) +
                "&ActionName:" + Utils.toString(self.actionName))


class KnownUserError(StandardError):
    pass


class ActionTypes:
    CANCEL = "Cancel"
    QUEUE = "Queue"
    IGNORE = "Ignore"
