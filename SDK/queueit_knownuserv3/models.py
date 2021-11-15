from .queueit_helpers import QueueitHelpers


class Utils:
    @staticmethod
    def toString(v):
        if (v is None):
            return ""
        if (v is True):
            return "true"
        if (v is False):
            return "false"
        return str(v)

    @staticmethod
    def isNilOrEmpty(v):
        return v is None or str(v) == ""


class CancelEventConfig:
    def __init__(self):
        self.eventId = None
        self.queueDomain = None
        self.cookieDomain = None
        self.version = None
        self.actionName = 'unspecified'

    def toString(self):
        return "EventId:" + Utils.toString(
            self.eventId) + "&Version:" + Utils.toString(
                self.version) + "&QueueDomain:" + Utils.toString(
                    self.queueDomain) + "&CookieDomain:" + Utils.toString(
                        self.cookieDomain) + "&ActionName:" + Utils.toString(self.actionName)


class QueueEventConfig:
    def __init__(self):
        self.eventId = None
        self.layoutName = None
        self.culture = None
        self.queueDomain = None
        self.extendCookieValidity = None
        self.cookieValidityMinute = None
        self.cookieDomain = None
        self.version = None
        self.actionName = 'unspecified'

    def toString(self):
        return "EventId:" + Utils.toString(
            self.eventId) + "&Version:" + Utils.toString(
                self.version) + "&QueueDomain:" + Utils.toString(
                    self.queueDomain) + "&CookieDomain:" + Utils.toString(
                        self.cookieDomain
                    ) + "&ExtendCookieValidity:" + Utils.toString(
                        self.extendCookieValidity
                    ) + "&CookieValidityMinute:" + Utils.toString(
                        self.cookieValidityMinute
                    ) + "&LayoutName:" + Utils.toString(
                        self.layoutName) + "&Culture:" + Utils.toString(
                            self.culture)  + "&ActionName:" + Utils.toString(self.actionName)


class RequestValidationResult:
    def __init__(self, actionType, eventId, queueId, redirectUrl, redirectType, actionName):
        self.actionType = actionType
        self.eventId = eventId
        self.queueId = queueId
        self.redirectUrl = redirectUrl
        self.redirectType = redirectType
        self.isAjaxResult = False
        self.actionName = actionName

    def doRedirect(self):
        return not Utils.isNilOrEmpty(self.redirectUrl)

    def getAjaxQueueRedirectHeaderKey(self):
        return "x-queueit-redirect"

    def getAjaxRedirectUrl(self):
        if (not Utils.isNilOrEmpty(self.redirectUrl)):
            return QueueitHelpers.urlEncode(self.redirectUrl)
        return ""


class KnownUserError(StandardError):
    pass


class ActionTypes:
    CANCEL = "Cancel"
    QUEUE = "Queue"
    IGNORE = "Ignore"
