import unittest
import json
import sys
from datetime import datetime

from queueit_knownuserv3.queue_url_params import QueueUrlParams
from queueit_knownuserv3.models import RequestValidationResult, ActionTypes, QueueEventConfig, CancelEventConfig, KnownUserError
from queueit_knownuserv3.known_user import KnownUser
from queueit_knownuserv3.user_in_queue_service import UserInQueueService
from queueit_knownuserv3.http_context_providers import HttpContextProvider
from queueit_knownuserv3.queueit_helpers import QueueitHelpers


class HttpContextProviderMock(HttpContextProvider):
    def __init__(self):
        self.headers = {}
        self.setCookies = {}
        self.originalRequestUrl = ""
        self.remote_ip = ""

    def getHeader(self, headerName):
        if (not headerName in self.headers):
            return None
        return self.headers[headerName]

    def setCookie(self, name, value, expire, domain):
        self.setCookies[name] = {
            "value": value,
            "expire": expire,
            "domain": domain
        }

    def getRequestIp(self):
        return self.remote_ip

    def getOriginalRequestUrl(self):
        return self.originalRequestUrl

    def getProviderName(self):
        return "mock-connector"

class UserInQueueServiceMock(UserInQueueService):
    def __init__(self):
        self.extendQueueCookieCalls = {}
        self.validateQueueRequestCalls = {}
        self.validateCancelRequestCalls = {}
        self.getIgnoreActionResultCalls = {}
        self.validateCancelRequestRaiseException = False
        self.validateQueueRequestRaiseException = False
        self.validateQueueRequestResultObj = RequestValidationResult(
            ActionTypes.QUEUE, None, None, None, None, None)
        self.validateCancelRequestResultObj = RequestValidationResult(
            ActionTypes.CANCEL, None, None, None, None, None)
        self.getIgnoreActionResultObj = RequestValidationResult(
            ActionTypes.IGNORE, None, None, None, None, None)

    def extendQueueCookie(self, eventId, cookieValidityMinute, cookieDomain,
                          secretKey):
        self.extendQueueCookieCalls[len(self.extendQueueCookieCalls)] = {
            "eventId": eventId,
            "cookieValidityMinute": cookieValidityMinute,
            "cookieDomain": cookieDomain,
            "secretKey": secretKey
        }

    def validateQueueRequest(self, targetUrl, queueitToken, config, customerId,
                             secretKey):
        self.validateQueueRequestCalls[len(self.validateQueueRequestCalls)] = {
            "targetUrl": targetUrl,
            "queueitToken": queueitToken,
            "config": config,
            "customerId": customerId,
            "secretKey": secretKey
        }
        if(self.validateQueueRequestRaiseException):
            raise Exception("Exception")
        return self.validateQueueRequestResultObj

    def validateCancelRequest(self, targetUrl, config, customerId, secretKey):
        self.validateCancelRequestCalls[len(
            self.validateQueueRequestCalls)] = {
                "targetUrl": targetUrl,
                "config": config,
                "customerId": customerId,
                "secretKey": secretKey
            }

        if (self.validateCancelRequestRaiseException):
            raise Exception("Exception")
        return self.validateCancelRequestResultObj

    def getIgnoreActionResult(self, actionName):
        self.getIgnoreActionResultCalls[len(
            self.getIgnoreActionResultCalls)] = {
            "actionName" : actionName
        }
        return self.getIgnoreActionResultObj

class QueueITTokenGenerator:
    @staticmethod
    def generateDebugToken(eventId, secretKey, expiredToken = False):
        timeStamp = QueueitHelpers.getCurrentTime() + (3 * 60)
        if expiredToken:
            timeStamp = timeStamp - 1000
        tokenWithoutHash = (
            QueueUrlParams.EVENT_ID_KEY +
            QueueUrlParams.KEY_VALUE_SEPARATOR_CHAR +
            eventId) + QueueUrlParams.KEY_VALUE_SEPARATOR_GROUP_CHAR + (
            QueueUrlParams.REDIRECT_TYPE_KEY +
            QueueUrlParams.KEY_VALUE_SEPARATOR_CHAR + "debug") + QueueUrlParams.KEY_VALUE_SEPARATOR_GROUP_CHAR + (
            QueueUrlParams.TIMESTAMP_KEY +
            QueueUrlParams.KEY_VALUE_SEPARATOR_CHAR + str(timeStamp))

        hashValue = QueueitHelpers.hmacSha256Encode(
            tokenWithoutHash, secretKey)
        token = tokenWithoutHash + QueueUrlParams.KEY_VALUE_SEPARATOR_GROUP_CHAR + QueueUrlParams.HASH_KEY + QueueUrlParams.KEY_VALUE_SEPARATOR_CHAR + hashValue
        return token


class TestKnownUser(unittest.TestCase):
    def test_cancelRequestByLocalConfig(self):
        userInQueueService = UserInQueueServiceMock()
        KnownUser.userInQueueService = userInQueueService

        cancelConfig = CancelEventConfig()
        cancelConfig.eventId = "eventId"
        cancelConfig.queueDomain = "queueDomain"
        cancelConfig.version = 1
        cancelConfig.cookieDomain = "cookieDomain"
        cancelConfig.actionName = "cancelAction"

        result = KnownUser.cancelRequestByLocalConfig(
            "targetUrl", "token", cancelConfig, "customerId", "secretKey",
            HttpContextProviderMock())

        assert (userInQueueService.validateCancelRequestCalls[0]["targetUrl"]
                == "targetUrl")
        assert (userInQueueService.validateCancelRequestCalls[0]["config"] ==
                cancelConfig)
        assert (userInQueueService.validateCancelRequestCalls[0]["customerId"]
                == "customerId")
        assert (userInQueueService.validateCancelRequestCalls[0]["secretKey"]
                == "secretKey")
        assert (not result.isAjaxResult)

    def test_cancelRequestByLocalConfig_AjaxCall(self):
        userInQueueService = UserInQueueServiceMock()
        KnownUser.userInQueueService = userInQueueService

        cancelConfig = CancelEventConfig()
        cancelConfig.eventId = "eventId"
        cancelConfig.queueDomain = "queueDomain"
        cancelConfig.version = 1
        cancelConfig.cookieDomain = "cookieDomain"
        cancelConfig.actionName = "cancelAction"

        hcpMock = HttpContextProviderMock()
        hcpMock.headers = {"x-queueit-ajaxpageurl": "http%3a%2f%2furl"}
        userInQueueService.validateCancelRequestResultObj = RequestValidationResult(
            ActionTypes.CANCEL, "eventId", None, "http://q.qeuue-it.com", None, cancelConfig.actionName)

        result = KnownUser.cancelRequestByLocalConfig(
            "targetUrl", "token", cancelConfig, "customerId", "secretKey",
            hcpMock)

        assert (userInQueueService.validateCancelRequestCalls[0]["targetUrl"]
                == "http://url")
        assert (userInQueueService.validateCancelRequestCalls[0]["config"] ==
                cancelConfig)
        assert (userInQueueService.validateCancelRequestCalls[0]["customerId"]
                == "customerId")
        assert (userInQueueService.validateCancelRequestCalls[0]["secretKey"]
                == "secretKey")
        assert (result.isAjaxResult)
        assert (result.getAjaxRedirectUrl().lower() ==
                "http%3a%2f%2fq.qeuue-it.com")
        assert (result.actionName == cancelConfig.actionName )

    def test_cancelRequestByLocalConfig_setDebugCookie(self):
        userInQueueService = UserInQueueServiceMock()
        KnownUser.userInQueueService = userInQueueService

        cancelConfig = CancelEventConfig()
        cancelConfig.eventId = "eventId"
        cancelConfig.queueDomain = "queueDomain"
        cancelConfig.version = 1
        cancelConfig.cookieDomain = "cookieDomain"
        cancelConfig.actionName = "cancelAction"

        hcpMock = HttpContextProviderMock()
        hcpMock.originalRequestUrl = "http://localhost/original_url"
        hcpMock.remote_ip = "userIP"
        hcpMock.headers = {
            "via": "v",
            "forwarded": "f",
            "x-forwarded-for": "xff",
            "x-forwarded-host": "xfh",
            "x-forwarded-proto": "xfp"
        }

        secretKey = "secretKey"
        queueitToken = QueueITTokenGenerator.generateDebugToken(
            "eventId", secretKey)

        expectedServerTime = QueueitHelpers.getCurrentTimeAsIso8601Str(
        )
        KnownUser.cancelRequestByLocalConfig("url", queueitToken, cancelConfig,
                                             "customerId", secretKey,
                                             hcpMock)

        expectedCookieValue = "RequestHttpHeader_Via=v" + \
            "|SdkVersion=" + userInQueueService.SDK_VERSION + \
            "|Connector=mock-connector" + \
            "|Runtime=" + sys.version + \
            "|QueueitToken=" + queueitToken + \
            "|OriginalUrl=http://localhost/original_url" + \
            "|RequestIP=userIP" + \
            "|RequestHttpHeader_Forwarded=f" + \
            "|CancelConfig=EventId:eventId&Version:1&QueueDomain:queueDomain&CookieDomain:cookieDomain&ActionName:" + cancelConfig.actionName + \
            "|RequestHttpHeader_XForwardedFor=xff" + \
            "|TargetUrl=url" + \
            "|RequestHttpHeader_XForwardedHost=xfh" + \
            "|ServerUtcTime=" + expectedServerTime + \
            "|RequestHttpHeader_XForwardedProto=xfp"

        assert (len(hcpMock.setCookies) == 1)
        assert (KnownUser.QUEUEIT_DEBUG_KEY in hcpMock.setCookies)

        actualCookieValue = hcpMock.setCookies[KnownUser.QUEUEIT_DEBUG_KEY][
            "value"]
        for val in actualCookieValue.split('|'):
            assert (val in expectedCookieValue)

    def test_CancelRequestByLocalConfig_debug_nullconfig(self):
        userInQueueService = UserInQueueServiceMock()
        KnownUser.userInQueueService = userInQueueService

        hcpMock = HttpContextProviderMock()
        hcpMock.originalRequestUrl = "http://localhost/original_url"
        hcpMock.remote_ip = "userIP"
        hcpMock.headers = {
            "via": "v",
            "forwarded": "f",
            "x-forwarded-for": "xff",
            "x-forwarded-host": "xfh",
            "x-forwarded-proto": "xfp"
        }

        integrationConfigJson = "{'key': 'valu'e}"
        secretKey = "secretKey"
        queueitToken = QueueITTokenGenerator.generateDebugToken("eventId", secretKey)

        expectedServerTime = QueueitHelpers.getCurrentTimeAsIso8601Str()
        try:
            KnownUser.cancelRequestByLocalConfig("http://test.com?event1=true", queueitToken,
                                                         None, "customerId", secretKey, hcpMock)
        except KnownUserError as err:
            errorThrown = err.message.startswith("cancelConfig can not be none.")
            assert (errorThrown)

        expectedCookieValue = "RequestHttpHeader_Via=v" + \
            "|SdkVersion=" + userInQueueService.SDK_VERSION + \
            "|Connector=mock-connector" + \
            "|Runtime=" + sys.version + \
            "|QueueitToken=" + queueitToken + \
            "|OriginalUrl=http://localhost/original_url" + \
            "|RequestIP=userIP" + \
            "|RequestHttpHeader_Forwarded=f" + \
            "|CancelConfig=NULL" + \
            "|RequestHttpHeader_XForwardedFor=xff" + \
            "|TargetUrl=http://test.com?event1=true" + \
            "|RequestHttpHeader_XForwardedHost=xfh" + \
            "|ServerUtcTime=" + expectedServerTime + \
            "|RequestHttpHeader_XForwardedProto=xfp" + \
            "|Exception=cancelConfig can not be none."

        assert (len(hcpMock.setCookies) == 1)
        assert (KnownUser.QUEUEIT_DEBUG_KEY in hcpMock.setCookies)
        actualCookieValue = hcpMock.setCookies[KnownUser.QUEUEIT_DEBUG_KEY]["value"]
        for val in actualCookieValue.split('|'):
            assert (val in expectedCookieValue)

    def test_CancelRequestByLocalConfig_debug_missing_customerid(self):
        hcpMock = HttpContextProviderMock()
        hcpMock.originalRequestUrl = "http://localhost/original_url"
        queueitToken = QueueITTokenGenerator.generateDebugToken("eventId", "secretkey")
        queueConfig = QueueEventConfig()
        result = KnownUser.cancelRequestByLocalConfig("url", queueitToken, queueConfig, None, "secretkey",
                                                            hcpMock)
        assert (result.redirectUrl == "https://api2.queue-it.net/diagnostics/connector/error/?code=setup")
        assert (len(hcpMock.setCookies) == 0)

    def test_CancelRequestByLocalConfig_debug_missing_secretkey(self):
        hcpMock = HttpContextProviderMock()
        hcpMock.originalRequestUrl = "http://localhost/original_url"
        queueitToken = QueueITTokenGenerator.generateDebugToken("eventId", "secretkey")
        queueConfig = QueueEventConfig()
        result = KnownUser.cancelRequestByLocalConfig("url", queueitToken, queueConfig, "customerid", None,
                                                            hcpMock)
        assert (result.redirectUrl == "https://api2.queue-it.net/diagnostics/connector/error/?code=setup")
        assert (len(hcpMock.setCookies) == 0)

    def test_CancelRequestByLocalConfig_debug_expiredtoken(self):
        hcpMock = HttpContextProviderMock()
        hcpMock.originalRequestUrl = "http://localhost/original_url"
        queueitToken = QueueITTokenGenerator.generateDebugToken("eventId", "secretkey", True)
        queueConfig = QueueEventConfig()
        result = KnownUser.cancelRequestByLocalConfig("url", queueitToken, queueConfig, "customerid",
                                                            "secretkey", hcpMock)
        assert (result.redirectUrl ==
                "https://customerid.api2.queue-it.net/customerid/diagnostics/connector/error/?code=timestamp")
        assert (len(hcpMock.setCookies) == 0)

    def test_CancelRequestByLocalConfig_debug_modifiedtoken(self):
        hcpMock = HttpContextProviderMock()
        hcpMock.originalRequestUrl = "http://localhost/original_url"
        queueitToken = QueueITTokenGenerator.generateDebugToken("eventId", "secretkey") + "invalid-hash"
        queueConfig = QueueEventConfig()
        result = KnownUser.cancelRequestByLocalConfig("url", queueitToken, queueConfig, "customerid",
                                                            "secretkey", hcpMock)
        assert (result.redirectUrl ==
                "https://customerid.api2.queue-it.net/customerid/diagnostics/connector/error/?code=hash")
        assert (len(hcpMock.setCookies) == 0)

    def test_cancelRequestByLocalConfig_none_QueueDomain(self):
        errorThrown = False

        cancelConfig = CancelEventConfig()
        cancelConfig.eventId = "eventId"

        try:
            KnownUser.cancelRequestByLocalConfig(
                "targetUrl", "token", cancelConfig, "customerId", "secretKey",
                HttpContextProviderMock())
        except KnownUserError as err:
            errorThrown = err.message == "cancelConfig.queueDomain can not be none or empty."

        assert (errorThrown)

    def test_cancelRequestByLocalConfig_none_EventId(self):
        errorThrown = False

        cancelConfig = CancelEventConfig()
        cancelConfig.queueDomain = "queueDomain"

        try:
            KnownUser.cancelRequestByLocalConfig(
                "targetUrl", "token", cancelConfig, "customerId", "secretKey",
                HttpContextProviderMock())
        except KnownUserError as err:
            errorThrown = err.message == "cancelConfig.eventId can not be none or empty."

        assert (errorThrown)

    def test_cancelRequestByLocalConfig_none_CancelConfig(self):
        errorThrown = False

        try:
            KnownUser.cancelRequestByLocalConfig("targetUrl", "token", None,
                                                 "customerId", "secretKey",
                                                 HttpContextProviderMock())
        except KnownUserError as err:
            errorThrown = err.message == "cancelConfig can not be none."

        assert (errorThrown)

    def test_cancelRequestByLocalConfig_none_CustomerId(self):
        errorThrown = False

        try:
            KnownUser.cancelRequestByLocalConfig("targetUrl", "token",
                                                 CancelEventConfig(), None,
                                                 "secretKey",
                                                 HttpContextProviderMock())
        except KnownUserError as err:
            errorThrown = err.message == "customerId can not be none or empty."

        assert (errorThrown)

    def test_cancelRequestByLocalConfig_none_SeceretKey(self):
        errorThrown = False

        try:
            KnownUser.cancelRequestByLocalConfig("targetUrl", "token",
                                                 CancelEventConfig(),
                                                 "customerId", None,
                                                 HttpContextProviderMock())
        except KnownUserError as err:
            errorThrown = err.message == "secretKey can not be none or empty."

        assert (errorThrown)

    def test_cancelRequestByLocalConfig_none_TargetUrl(self):
        errorThrown = False

        try:
            KnownUser.cancelRequestByLocalConfig(None, "token",
                                                 CancelEventConfig(),
                                                 "customerId", None,
                                                 HttpContextProviderMock())
        except KnownUserError as err:
            errorThrown = err.message == "targetUrl can not be none or empty."

        assert (errorThrown)

    def test_extendQueueCookie_none_EventId(self):
        errorThrown = False

        try:
            KnownUser.extendQueueCookie(None, 10, "cookieDomain", "secretkey",
                                        {})
        except KnownUserError as err:
            errorThrown = err.message == "eventId can not be none or empty."

        assert (errorThrown)

    def test_extendQueueCookie_none_SecretKey(self):
        errorThrown = False

        try:
            KnownUser.extendQueueCookie("eventId", 10, "cookieDomain", None,
                                        {})
        except KnownUserError as err:
            errorThrown = err.message == "secretKey can not be none or empty."

        assert (errorThrown)

    def test_extendQueueCookie_Invalid_CookieValidityMinute(self):
        errorThrown = False

        try:
            KnownUser.extendQueueCookie("eventId", "invalidInt",
                                        "cookieDomain", "secrettKey", {})
        except KnownUserError as err:
            errorThrown = err.message == "cookieValidityMinute should be integer greater than 0."

        assert (errorThrown)

    def test_extendQueueCookie_Negative_CookieValidityMinute(self):
        errorThrown = False

        try:
            KnownUser.extendQueueCookie("eventId", -1, "cookieDomain",
                                        "secrettKey", {})
        except KnownUserError as err:
            errorThrown = err.message == "cookieValidityMinute should be integer greater than 0."

        assert (errorThrown)

    def test_extendQueueCookie(self):
        userInQueueService = UserInQueueServiceMock()
        KnownUser.userInQueueService = userInQueueService

        KnownUser.extendQueueCookie("evtId", 10, "domain", "key",
                                    HttpContextProviderMock())

        assert (
            userInQueueService.extendQueueCookieCalls[0]["eventId"] == "evtId")
        assert (userInQueueService.extendQueueCookieCalls[0][
            "cookieValidityMinute"] == 10)
        assert (userInQueueService.extendQueueCookieCalls[0]["cookieDomain"] ==
                "domain")
        assert (
            userInQueueService.extendQueueCookieCalls[0]["secretKey"] == "key")

    def test_resolveQueueRequestByLocalConfig_empty_eventId(self):
        queueConfig = QueueEventConfig()
        queueConfig.cookieDomain = "cookieDomain"
        queueConfig.layoutName = "layoutName"
        queueConfig.culture = "culture"
        #queueConfig.eventId = "eventId"
        queueConfig.queueDomain = "queueDomain"
        queueConfig.extendCookieValidity = True
        queueConfig.cookieValidityMinute = 10
        queueConfig.version = 12

        errorThrown = False

        try:
            KnownUser.resolveQueueRequestByLocalConfig(
                "targeturl", "queueIttoken", queueConfig, "customerid",
                "secretkey", HttpContextProviderMock())
        except KnownUserError as err:
            errorThrown = err.message == "queueConfig.eventId can not be none or empty."

        assert (errorThrown)

    def test_resolveQueueRequestByLocalConfig_empty_secretKey(self):
        queueConfig = QueueEventConfig()
        queueConfig.cookieDomain = "cookieDomain"
        queueConfig.layoutName = "layoutName"
        queueConfig.culture = "culture"
        queueConfig.eventId = "eventId"
        queueConfig.queueDomain = "queueDomain"
        queueConfig.extendCookieValidity = True
        queueConfig.cookieValidityMinute = 10
        queueConfig.version = 12

        errorThrown = False

        try:
            KnownUser.resolveQueueRequestByLocalConfig(
                "targeturl", "queueIttoken", queueConfig, "customerid", None,
                HttpContextProviderMock())
        except KnownUserError as err:
            errorThrown = err.message == "secretKey can not be none or empty."

        assert (errorThrown)

    def test_resolveQueueRequestByLocalConfig_empty_queueDomain(self):
        queueConfig = QueueEventConfig()
        queueConfig.cookieDomain = "cookieDomain"
        queueConfig.layoutName = "layoutName"
        queueConfig.culture = "culture"
        queueConfig.eventId = "eventId"
        #queueConfig.queueDomain = "queueDomain"
        queueConfig.extendCookieValidity = True
        queueConfig.cookieValidityMinute = 10
        queueConfig.version = 12

        errorThrown = False

        try:
            KnownUser.resolveQueueRequestByLocalConfig(
                "targeturl", "queueIttoken", queueConfig, "customerid",
                "secretkey", HttpContextProviderMock())
        except KnownUserError as err:
            errorThrown = err.message == "queueConfig.queueDomain can not be none or empty."

        assert (errorThrown)

    def test_resolveQueueRequestByLocalConfig_empty_customerId(self):
        queueConfig = QueueEventConfig()
        queueConfig.cookieDomain = "cookieDomain"
        queueConfig.layoutName = "layoutName"
        queueConfig.culture = "culture"
        queueConfig.eventId = "eventId"
        queueConfig.queueDomain = "queueDomain"
        queueConfig.extendCookieValidity = True
        queueConfig.cookieValidityMinute = 10
        queueConfig.version = 12

        errorThrown = False

        try:
            KnownUser.resolveQueueRequestByLocalConfig(
                "targeturl", "queueIttoken", queueConfig, None, "secretKey",
                HttpContextProviderMock())
        except KnownUserError as err:
            errorThrown = err.message == "customerId can not be none or empty."

        assert (errorThrown)

    def test_resolveQueueRequestByLocalConfig_Invalid_extendCookieValidity(
            self):
        queueConfig = QueueEventConfig()
        queueConfig.cookieDomain = "cookieDomain"
        queueConfig.layoutName = "layoutName"
        queueConfig.culture = "culture"
        queueConfig.eventId = "eventId"
        queueConfig.queueDomain = "queueDomain"
        queueConfig.extendCookieValidity = "not-a-boolean"
        queueConfig.cookieValidityMinute = 10
        queueConfig.version = 12

        errorThrown = False

        try:
            KnownUser.resolveQueueRequestByLocalConfig(
                "targeturl", "queueIttoken", queueConfig, "customerId",
                "secretKey", HttpContextProviderMock())
        except KnownUserError as err:
            errorThrown = err.message == "queueConfig.extendCookieValidity should be valid boolean."

        assert (errorThrown)

    def test_resolveQueueRequestByLocalConfig_Invalid_cookieValidityMinute(
            self):
        queueConfig = QueueEventConfig()
        queueConfig.cookieDomain = "cookieDomain"
        queueConfig.layoutName = "layoutName"
        queueConfig.culture = "culture"
        queueConfig.eventId = "eventId"
        queueConfig.queueDomain = "queueDomain"
        queueConfig.extendCookieValidity = True
        queueConfig.cookieValidityMinute = "test"
        queueConfig.version = 12

        errorThrown = False

        try:
            KnownUser.resolveQueueRequestByLocalConfig(
                "targeturl", "queueIttoken", queueConfig, "customerId",
                "secretKey", HttpContextProviderMock())
        except KnownUserError as err:
            errorThrown = err.message.startswith(
                "queueConfig.cookieValidityMinute should be integer greater than 0"
            )

        assert (errorThrown)

    def test_resolveQueueRequestByLocalConfig_zero_cookieValidityMinute(self):
        queueConfig = QueueEventConfig()
        queueConfig.cookieDomain = "cookieDomain"
        queueConfig.layoutName = "layoutName"
        queueConfig.culture = "culture"
        queueConfig.eventId = "eventId"
        queueConfig.queueDomain = "queueDomain"
        queueConfig.extendCookieValidity = True
        queueConfig.cookieValidityMinute = 0
        queueConfig.version = 12

        errorThrown = False

        try:
            KnownUser.resolveQueueRequestByLocalConfig(
                "targeturl", "queueIttoken", queueConfig, "customerId",
                "secretKey", HttpContextProviderMock())
        except KnownUserError as err:
            errorThrown = err.message.startswith(
                "queueConfig.cookieValidityMinute should be integer greater than 0"
            )

        assert (errorThrown)

    def test_resolveQueueRequestByLocalConfig_setDebugCookie(self):
        userInQueueService = UserInQueueServiceMock()
        KnownUser.userInQueueService = userInQueueService

        queueConfig = QueueEventConfig()
        queueConfig.cookieDomain = "cookieDomain"
        queueConfig.layoutName = "layoutName"
        queueConfig.culture = "culture"
        queueConfig.eventId = "eventId"
        queueConfig.queueDomain = "queueDomain"
        queueConfig.extendCookieValidity = True
        queueConfig.cookieValidityMinute = 10
        queueConfig.version = 12
        queueConfig.actionName = "queueAction"

        hcpMock = HttpContextProviderMock()
        hcpMock.originalRequestUrl = "http://localhost/original_url"
        hcpMock.remote_ip = "userIP"
        hcpMock.headers = {
            "via": "v",
            "forwarded": "f",
            "x-forwarded-for": "xff",
            "x-forwarded-host": "xfh",
            "x-forwarded-proto": "xfp"
        }

        secretKey = "secretKey"
        queueitToken = QueueITTokenGenerator.generateDebugToken(
            "eventId", secretKey)

        expectedServerTime = QueueitHelpers.getCurrentTimeAsIso8601Str(
        )
        KnownUser.resolveQueueRequestByLocalConfig("url", queueitToken,
                                                   queueConfig, "customerId",
                                                   secretKey, hcpMock)

        expectedCookieValue = "RequestHttpHeader_Via=v" + \
            "|SdkVersion=" + userInQueueService.SDK_VERSION + \
            "|Connector=mock-connector" + \
            "|Runtime=" + sys.version + \
            "|QueueitToken=" + queueitToken + \
            "|OriginalUrl=http://localhost/original_url" + \
            "|QueueConfig=EventId:eventId&Version:12&QueueDomain:queueDomain&CookieDomain:cookieDomain&ExtendCookieValidity:true&CookieValidityMinute:10&LayoutName:layoutName&Culture:culture&ActionName:" + queueConfig.actionName +\
            "|RequestIP=userIP" + \
            "|RequestHttpHeader_Forwarded=f" + \
            "|RequestHttpHeader_XForwardedFor=xff" + \
            "|TargetUrl=url" + \
            "|RequestHttpHeader_XForwardedHost=xfh" + \
            "|ServerUtcTime=" + expectedServerTime + \
            "|RequestHttpHeader_XForwardedProto=xfp"

        assert (len(hcpMock.setCookies) == 1)
        assert (KnownUser.QUEUEIT_DEBUG_KEY in hcpMock.setCookies)
        actualCookieValue = hcpMock.setCookies[KnownUser.QUEUEIT_DEBUG_KEY]["value"]
        for val in actualCookieValue.split('|'):
            assert (val in expectedCookieValue)

    def test_ResolveQueueRequestByLocalConfig_debug_nullconfig(self):
        userInQueueService = UserInQueueServiceMock()
        KnownUser.userInQueueService = userInQueueService

        hcpMock = HttpContextProviderMock()
        hcpMock.originalRequestUrl = "http://localhost/original_url"
        hcpMock.remote_ip = "userIP"
        hcpMock.headers = {
            "via": "v",
            "forwarded": "f",
            "x-forwarded-for": "xff",
            "x-forwarded-host": "xfh",
            "x-forwarded-proto": "xfp"
        }
        secretKey = "secretKey"
        queueitToken = QueueITTokenGenerator.generateDebugToken("eventId", secretKey)
        expectedServerTime = QueueitHelpers.getCurrentTimeAsIso8601Str()
        try:
            result = KnownUser.resolveQueueRequestByLocalConfig("url", queueitToken, None, "id", secretKey, hcpMock)
        except KnownUserError as err:
            errorThrown = err.message.startswith("queueConfig can not be none.")
            assert (errorThrown)

        expectedCookieValue = "RequestHttpHeader_Via=v" + \
            "|SdkVersion=" + userInQueueService.SDK_VERSION + \
            "|Connector=mock-connector" + \
            "|Runtime=" + sys.version + \
            "|QueueitToken=" + queueitToken + \
            "|OriginalUrl=http://localhost/original_url" + \
            "|QueueConfig=NULL" +\
            "|RequestIP=userIP" + \
            "|RequestHttpHeader_Forwarded=f" + \
            "|RequestHttpHeader_XForwardedFor=xff" + \
            "|TargetUrl=url" + \
            "|RequestHttpHeader_XForwardedHost=xfh" + \
            "|ServerUtcTime=" + expectedServerTime + \
            "|RequestHttpHeader_XForwardedProto=xfp" + \
            "|Exception=queueConfig can not be none."

        assert (len(hcpMock.setCookies) == 1)
        assert (KnownUser.QUEUEIT_DEBUG_KEY in hcpMock.setCookies)
        actualCookieValue = hcpMock.setCookies[KnownUser.QUEUEIT_DEBUG_KEY]["value"]
        for val in actualCookieValue.split('|'):
            assert (val in expectedCookieValue)

    def test_ResolveQueueRequestByLocalConfig_debug_missing_customerid(self):
        hcpMock = HttpContextProviderMock()
        hcpMock.originalRequestUrl = "http://localhost/original_url"
        queueitToken = QueueITTokenGenerator.generateDebugToken("eventId", "secretkey")
        queueConfig = QueueEventConfig()
        result = KnownUser.resolveQueueRequestByLocalConfig("url", queueitToken, queueConfig, None, "secretkey", hcpMock)
        assert (result.redirectUrl == "https://api2.queue-it.net/diagnostics/connector/error/?code=setup")
        assert (len(hcpMock.setCookies) == 0)

    def test_ResolveQueueRequestByLocalConfig_debug_missing_secretkey(self):
        hcpMock = HttpContextProviderMock()
        hcpMock.originalRequestUrl = "http://localhost/original_url"
        queueitToken = QueueITTokenGenerator.generateDebugToken("eventId", "secretkey")
        queueConfig = QueueEventConfig()
        result = KnownUser.resolveQueueRequestByLocalConfig("url", queueitToken, queueConfig, "customerid", None, hcpMock)
        assert (result.redirectUrl == "https://api2.queue-it.net/diagnostics/connector/error/?code=setup")
        assert (len(hcpMock.setCookies) == 0)

    def test_ResolveQueueRequestByLocalConfig_debug_expiredtoken(self):
        hcpMock = HttpContextProviderMock()
        hcpMock.originalRequestUrl = "http://localhost/original_url"
        queueitToken = QueueITTokenGenerator.generateDebugToken("eventId", "secretkey", True)
        queueConfig = QueueEventConfig()
        result = KnownUser.resolveQueueRequestByLocalConfig("url", queueitToken, queueConfig, "customerid",
                                                            "secretkey", hcpMock)
        assert (result.redirectUrl == "https://customerid.api2.queue-it.net/customerid/diagnostics/connector/error/?code=timestamp")
        assert (len(hcpMock.setCookies) == 0)

    def test_ResolveQueueRequestByLocalConfig_debug_modifiedtoken(self):
        hcpMock = HttpContextProviderMock()
        hcpMock.originalRequestUrl = "http://localhost/original_url"
        queueitToken = QueueITTokenGenerator.generateDebugToken("eventId", "secretkey") + "invalid-hash"
        queueConfig = QueueEventConfig()
        result = KnownUser.resolveQueueRequestByLocalConfig("url", queueitToken, queueConfig, "customerid",
                                                            "secretkey", hcpMock)
        assert (result.redirectUrl == "https://customerid.api2.queue-it.net/customerid/diagnostics/connector/error/?code=hash")
        assert (len(hcpMock.setCookies) == 0)

    def test_resolveQueueRequestByLocalConfig(self):
        userInQueueService = UserInQueueServiceMock()
        KnownUser.userInQueueService = userInQueueService

        queueConfig = QueueEventConfig()
        queueConfig.cookieDomain = "cookieDomain"
        queueConfig.layoutName = "layoutName"
        queueConfig.culture = "culture"
        queueConfig.eventId = "eventId"
        queueConfig.queueDomain = "queueDomain"
        queueConfig.extendCookieValidity = True
        queueConfig.cookieValidityMinute = 10
        queueConfig.version = 12
        queueConfig.actionName = "queueAction"

        result = KnownUser.resolveQueueRequestByLocalConfig(
            "target", "token", queueConfig, "id", "key",
            HttpContextProviderMock())

        assert (userInQueueService.validateQueueRequestCalls[0]["targetUrl"] ==
                "target")
        assert (userInQueueService.validateQueueRequestCalls[0]["queueitToken"]
                == "token")
        assert (userInQueueService.validateQueueRequestCalls[0]["config"] ==
                queueConfig)
        assert (userInQueueService.validateQueueRequestCalls[0]["customerId"]
                == "id")
        assert (userInQueueService.validateQueueRequestCalls[0]["secretKey"] ==
                "key")
        assert (not result.isAjaxResult)

    def test_resolveQueueRequestByLocalConfig_AjaxCall(self):
        userInQueueService = UserInQueueServiceMock()
        KnownUser.userInQueueService = userInQueueService

        queueConfig = QueueEventConfig()
        queueConfig.cookieDomain = "cookieDomain"
        queueConfig.layoutName = "layoutName"
        queueConfig.culture = "culture"
        queueConfig.eventId = "eventId"
        queueConfig.queueDomain = "queueDomain"
        queueConfig.extendCookieValidity = True
        queueConfig.cookieValidityMinute = 10
        queueConfig.version = 12
        queueConfig.actionName = "queueAction"

        hcpMock = HttpContextProviderMock()
        hcpMock.headers = {"x-queueit-ajaxpageurl": "http%3a%2f%2furl"}
        userInQueueService.validateQueueRequestResultObj = RequestValidationResult(
            ActionTypes.QUEUE, "eventId", None, "http://q.qeuue-it.com", None, queueConfig.actionName)

        result = KnownUser.resolveQueueRequestByLocalConfig(
            "targetUrl", "token", queueConfig, "customerId", "secretKey",
            hcpMock)

        assert (userInQueueService.validateQueueRequestCalls[0]["targetUrl"] ==
                "http://url")
        assert (userInQueueService.validateQueueRequestCalls[0]["config"] ==
                queueConfig)
        assert (userInQueueService.validateQueueRequestCalls[0]["customerId"]
                == "customerId")
        assert (userInQueueService.validateQueueRequestCalls[0]["secretKey"] ==
                "secretKey")
        assert (result.isAjaxResult)
        assert (result.getAjaxRedirectUrl().lower() ==
                "http%3a%2f%2fq.qeuue-it.com")
        assert (result.actionName == queueConfig.actionName)

    def test_validateRequestByIntegrationConfig_empty_currentUrlWithoutQueueITToken(
            self):
        errorThrown = False

        try:
            KnownUser.validateRequestByIntegrationConfig(
                "", "queueIttoken", "{}", "customerId", "secretKey",
                HttpContextProviderMock())
        except KnownUserError as err:
            errorThrown = err.message.startswith(
                "currentUrlWithoutQueueITToken can not be none or empty")

        assert (errorThrown)

    def test_validateRequestByIntegrationConfig_empty_integrationsConfigString(
            self):
        errorThrown = False

        try:
            KnownUser.validateRequestByIntegrationConfig(
                "currentUrlWithoutQueueITToken", "queueIttoken", "{}",
                "customerId", "secretKey", HttpContextProviderMock())
        except KnownUserError as err:
            errorThrown = err.message.startswith(
                "integrationsConfigString can not be none or empty")

        assert (errorThrown)

    def test_validateRequestByIntegrationConfig_invalid_integrationsConfigString(
            self):
        errorThrown = False

        try:
            KnownUser.validateRequestByIntegrationConfig(
                "currentUrlWithoutQueueITToken", "queueIttoken",
                "{}", "customerId", "secretKey",
                HttpContextProviderMock())
        except KnownUserError as err:
            errorThrown = err.message.startswith("integrationsConfigString can not be none or empty.")

        assert (errorThrown)

    def test_validateRequestByIntegrationConfig(self):
        userInQueueService = UserInQueueServiceMock()
        KnownUser.userInQueueService = userInQueueService

        integrationConfig = {
            "Description":
            "test",
            "Integrations": [{
                "Name":
                "event1action",
                "ActionType": "Queue",
                "EventId":
                "event1",
                "CookieDomain":
                ".test.com",
                "LayoutName":
                "Christmas Layout by Queue-it",
                "Culture":
                "",
                "ExtendCookieValidity":
                True,
                "CookieValidityMinute":
                20,
                "Triggers": [{
                    "TriggerParts": [{
                        "Operator": "Contains",
                        "ValueToCompare": "event1",
                        "UrlPart": "PageUrl",
                        "ValidatorType": "UrlValidator",
                        "IsNegative": False,
                        "IsIgnoreCase": True
                    }, {
                        "Operator": "Contains",
                        "ValueToCompare": "googlebot",
                        "ValidatorType": "UserAgentValidator",
                        "IsNegative": False,
                        "IsIgnoreCase": False
                    }],
                    "LogicalOperator":
                    "And"
                }],
                "QueueDomain":
                "knownusertest.queue-it.net",
                "RedirectLogic":
                "AllowTParameter"
            }],
            "CustomerId":
            "knownusertest",
            "AccountId":
            "knownusertest",
            "Version":
            3,
            "PublishDate":
            "2017-05-15T21:39:12.0076806Z",
            "ConfigDataVersion":
            "1.0.0.1"
        }
        hcpMock = HttpContextProviderMock()
        hcpMock.headers = {"user-agent": "googlebot"}
        integrationConfigJson = json.dumps(integrationConfig)
        result = KnownUser.validateRequestByIntegrationConfig(
            "http://test.com?event1=true", "token", integrationConfigJson,
            "id", "key", hcpMock)

        assert (userInQueueService.validateQueueRequestCalls[0]["targetUrl"] ==
                "http://test.com?event1=true")
        assert (userInQueueService.validateQueueRequestCalls[0]["queueitToken"]
                == "token")
        assert (userInQueueService.validateQueueRequestCalls[0]["customerId"]
                == "id")
        assert (userInQueueService.validateQueueRequestCalls[0]["secretKey"] ==
                "key")

        assert (userInQueueService.validateQueueRequestCalls[0]["config"]
                .queueDomain == "knownusertest.queue-it.net")
        assert (userInQueueService.validateQueueRequestCalls[0]["config"]
                .eventId == "event1")
        assert (userInQueueService.validateQueueRequestCalls[0]["config"]
                .culture == "")
        assert (userInQueueService.validateQueueRequestCalls[0]["config"]
                .layoutName == "Christmas Layout by Queue-it")
        assert (userInQueueService.validateQueueRequestCalls[0]["config"]
                .extendCookieValidity)
        assert (userInQueueService.validateQueueRequestCalls[0]["config"]
                .cookieValidityMinute == 20)
        assert (userInQueueService.validateQueueRequestCalls[0]["config"]
                .cookieDomain == ".test.com")
        assert (userInQueueService.validateQueueRequestCalls[0]["config"]
                .version == 3)
        assert (not result.isAjaxResult)
        assert (userInQueueService.validateQueueRequestCalls[0]["config"]
                .actionName == 'event1action')

    def test_validateRequestByIntegrationConfig_AjaxCall(self):
        userInQueueService = UserInQueueServiceMock()
        KnownUser.userInQueueService = userInQueueService

        integrationConfig = {
            "Description":
            "test",
            "Integrations": [{
                "Name":
                "event1action",
                "ActionType": "Queue",
                "EventId":
                "event1",
                "CookieDomain":
                ".test.com",
                "LayoutName":
                "Christmas Layout by Queue-it",
                "Culture":
                "",
                "ExtendCookieValidity":
                True,
                "CookieValidityMinute":
                20,
                "Triggers": [{
                    "TriggerParts": [{
                        "Operator": "Contains",
                        "ValueToCompare": "event1",
                        "UrlPart": "PageUrl",
                        "ValidatorType": "UrlValidator",
                        "IsNegative": False,
                        "IsIgnoreCase": True
                    }, {
                        "Operator": "Contains",
                        "ValueToCompare": "googlebot",
                        "ValidatorType": "UserAgentValidator",
                        "IsNegative": False,
                        "IsIgnoreCase": False
                    }],
                    "LogicalOperator":
                    "And"
                }],
                "QueueDomain":
                "knownusertest.queue-it.net",
                "RedirectLogic":
                "AllowTParameter"
            }],
            "CustomerId":
            "knownusertest",
            "AccountId":
            "knownusertest",
            "Version":
            3,
            "PublishDate":
            "2017-05-15T21:39:12.0076806Z",
            "ConfigDataVersion":
            "1.0.0.1"
        }
        hcpMock = HttpContextProviderMock()
        hcpMock.headers = {
            "user-agent": "googlebot",
            "x-queueit-ajaxpageurl": "http%3a%2f%2furl"
        }
        integrationConfigJson = json.dumps(integrationConfig)

        userInQueueService.validateQueueRequestResultObj = RequestValidationResult(
            ActionTypes.QUEUE, "eventId", None, "http://q.qeuue-it.com", None, "event1action")

        result = KnownUser.validateRequestByIntegrationConfig(
            "http://test.com?event1=true", "token", integrationConfigJson,
            "id", "key", hcpMock)

        assert (userInQueueService.validateQueueRequestCalls[0]["targetUrl"] ==
                "http://url")
        assert (userInQueueService.validateQueueRequestCalls[0]["queueitToken"]
                == "token")
        assert (userInQueueService.validateQueueRequestCalls[0]["customerId"]
                == "id")
        assert (userInQueueService.validateQueueRequestCalls[0]["secretKey"] ==
                "key")

        assert (userInQueueService.validateQueueRequestCalls[0]["config"]
                .queueDomain == "knownusertest.queue-it.net")
        assert (userInQueueService.validateQueueRequestCalls[0]["config"]
                .eventId == "event1")
        assert (userInQueueService.validateQueueRequestCalls[0]["config"]
                .culture == "")
        assert (userInQueueService.validateQueueRequestCalls[0]["config"]
                .layoutName == "Christmas Layout by Queue-it")
        assert (userInQueueService.validateQueueRequestCalls[0]["config"]
                .extendCookieValidity)
        assert (userInQueueService.validateQueueRequestCalls[0]["config"]
                .cookieValidityMinute == 20)
        assert (userInQueueService.validateQueueRequestCalls[0]["config"]
                .cookieDomain == ".test.com")
        assert (userInQueueService.validateQueueRequestCalls[0]["config"]
                .version == 3)
        assert (result.isAjaxResult)
        assert (result.getAjaxRedirectUrl().lower() ==
                "http%3a%2f%2fq.qeuue-it.com")
        assert (userInQueueService.validateQueueRequestCalls[0]["config"]
                .actionName == integrationConfig['Integrations'][0]['Name'])

    def test_validateRequestByIntegrationConfig_setDebugCookie(self):
        userInQueueService = UserInQueueServiceMock()
        KnownUser.userInQueueService = userInQueueService

        integrationConfig = {
            "Description":
            "test",
            "Integrations": [{
                "Name":
                "event1action",
                "ActionType": "Queue",
                "EventId":
                "event1",
                "CookieDomain":
                ".test.com",
                "LayoutName":
                "Christmas Layout by Queue-it",
                "Culture":
                "da-DK",
                "ExtendCookieValidity":
                True,
                "CookieValidityMinute":
                20,
                "Triggers": [{
                    "TriggerParts": [{
                        "Operator": "Contains",
                        "ValueToCompare": "event1",
                        "UrlPart": "PageUrl",
                        "ValidatorType": "UrlValidator",
                        "IsNegative": False,
                        "IsIgnoreCase": True
                    }, {
                        "Operator": "Contains",
                        "ValueToCompare": "googlebot",
                        "ValidatorType": "UserAgentValidator",
                        "IsNegative": False,
                        "IsIgnoreCase": False
                    }],
                    "LogicalOperator":
                    "And"
                }],
                "QueueDomain":
                "knownusertest.queue-it.net",
                "RedirectLogic":
                "AllowTParameter"
            }],
            "CustomerId":
            "knownusertest",
            "AccountId":
            "knownusertest",
            "Version":
            3,
            "PublishDate":
            "2017-05-15T21:39:12.0076806Z",
            "ConfigDataVersion":
            "1.0.0.1"
        }

        hcpMock = HttpContextProviderMock()
        hcpMock.originalRequestUrl = "http://localhost/original_url"
        hcpMock.remote_ip = "userIP"
        hcpMock.headers = {
            "user-agent": "googlebot",
            "via": "v",
            "forwarded": "f",
            "x-forwarded-for": "xff",
            "x-forwarded-host": "xfh",
            "x-forwarded-proto": "xfp"
        }
        integrationConfigJson = json.dumps(integrationConfig)

        secretKey = "secretKey"
        queueitToken = QueueITTokenGenerator.generateDebugToken(
            "eventId", secretKey)

        expectedServerTime = QueueitHelpers.getCurrentTimeAsIso8601Str(
        )
        KnownUser.validateRequestByIntegrationConfig(
            "http://test.com?event1=true", queueitToken, integrationConfigJson,
            "customerId", secretKey, hcpMock)

        expectedCookieValue = "RequestHttpHeader_Via=v" + \
            "|SdkVersion=" + userInQueueService.SDK_VERSION + \
            "|Connector=mock-connector" + \
            "|Runtime=" + sys.version + \
            "|QueueitToken=" + queueitToken + \
            "|OriginalUrl=http://localhost/original_url" + \
            "|QueueConfig=EventId:event1&Version:3&QueueDomain:knownusertest.queue-it.net&CookieDomain:.test.com&ExtendCookieValidity:true&CookieValidityMinute:20&LayoutName:Christmas Layout by Queue-it&Culture:da-DK&ActionName:" + integrationConfig['Integrations'][0]['Name']  + \
            "|RequestIP=userIP" + \
            "|ServerUtcTime=" + expectedServerTime + \
            "|MatchedConfig=event1action" + \
            "|RequestHttpHeader_XForwardedFor=xff" + \
            "|RequestHttpHeader_Forwarded=f" + \
            "|TargetUrl=http://test.com?event1=true" + \
            "|RequestHttpHeader_XForwardedHost=xfh" + \
            "|PureUrl=http://test.com?event1=true" + \
            "|ConfigVersion=3" + \
            "|RequestHttpHeader_XForwardedProto=xfp"

        assert (len(hcpMock.setCookies) == 1)
        assert (KnownUser.QUEUEIT_DEBUG_KEY in hcpMock.setCookies)

        actualCookieValue = hcpMock.setCookies[KnownUser.QUEUEIT_DEBUG_KEY][
            "value"]
        for val in actualCookieValue.split('|'):
            assert (val in expectedCookieValue)

    def test_validateRequestByIntegrationConfig_NotMatch(self):
        userInQueueService = UserInQueueServiceMock()
        KnownUser.userInQueueService = userInQueueService

        integrationConfig = {
            "Description": "test",
            "Integrations": [],
            "CustomerId": "knownusertest",
            "AccountId": "knownusertest",
            "Version": 3,
            "PublishDate": "2017-05-15T21:39:12.0076806Z",
            "ConfigDataVersion": "1.0.0.1"
        }

        integrationConfigJson = json.dumps(integrationConfig)
        result = KnownUser.validateRequestByIntegrationConfig(
            "http://test.com?event1=true", "queueIttoken",
            integrationConfigJson, "customerid", "secretkey",
            HttpContextProviderMock())

        assert (len(userInQueueService.validateQueueRequestCalls) == 0)
        assert (not result.doRedirect())

    def test_validateRequestByIntegrationConfig_setDebugCookie_NotMatch(self):
        userInQueueService = UserInQueueServiceMock()
        KnownUser.userInQueueService = userInQueueService

        hcpMock = HttpContextProviderMock()
        hcpMock.originalRequestUrl = "http://localhost/original_url"
        hcpMock.remote_ip = "userIP"
        hcpMock.headers = {
            "via": "v",
            "forwarded": "f",
            "x-forwarded-for": "xff",
            "x-forwarded-host": "xfh",
            "x-forwarded-proto": "xfp"
        }

        integrationConfig = {
            "Description": "test",
            "Integrations": [],
            "CustomerId": "knownusertest",
            "AccountId": "knownusertest",
            "Version": 3,
            "PublishDate": "2017-05-15T21:39:12.0076806Z",
            "ConfigDataVersion": "1.0.0.1"
        }

        secretKey = "secretKey"
        queueitToken = QueueITTokenGenerator.generateDebugToken(
            "eventId", secretKey)

        integrationConfigJson = json.dumps(integrationConfig)
        expectedServerTime = QueueitHelpers.getCurrentTimeAsIso8601Str(
        )
        KnownUser.validateRequestByIntegrationConfig(
            "http://test.com?event1=true", queueitToken, integrationConfigJson,
            "customerId", secretKey, hcpMock)

        expectedCookieValue = "RequestHttpHeader_Via=v" + \
            "|SdkVersion=" + userInQueueService.SDK_VERSION + \
            "|Connector=mock-connector" + \
            "|Runtime=" + sys.version + \
            "|QueueitToken=" + queueitToken + \
            "|OriginalUrl=http://localhost/original_url" + \
            "|RequestIP=userIP" + \
            "|ServerUtcTime=" + expectedServerTime + \
            "|MatchedConfig=NULL" + \
            "|RequestHttpHeader_XForwardedFor=xff" + \
            "|RequestHttpHeader_Forwarded=f" + \
            "|RequestHttpHeader_XForwardedHost=xfh" + \
            "|PureUrl=http://test.com?event1=true" + \
            "|ConfigVersion=3" + \
            "|RequestHttpHeader_XForwardedProto=xfp"

        assert (len(hcpMock.setCookies) == 1)
        assert (KnownUser.QUEUEIT_DEBUG_KEY in hcpMock.setCookies)
        actualCookieValue = hcpMock.setCookies[KnownUser.QUEUEIT_DEBUG_KEY][
            "value"]
        for val in actualCookieValue.split('|'):
            assert (val in expectedCookieValue)

    def test_validateRequestByIntegrationConfig_debug_invalid_config_json(self):
        userInQueueService = UserInQueueServiceMock()
        KnownUser.userInQueueService = userInQueueService

        hcpMock = HttpContextProviderMock()
        hcpMock.originalRequestUrl = "http://localhost/original_url"
        hcpMock.remote_ip = "userIP"
        hcpMock.headers = {
            "via": "v",
            "forwarded": "f",
            "x-forwarded-for": "xff",
            "x-forwarded-host": "xfh",
            "x-forwarded-proto": "xfp"
        }

        integrationConfigJson = "{}"
        secretKey = "secretKey"
        queueitToken = QueueITTokenGenerator.generateDebugToken("eventId", secretKey)

        expectedServerTime = QueueitHelpers.getCurrentTimeAsIso8601Str()
        try:
            KnownUser.validateRequestByIntegrationConfig("http://test.com?event1=true", queueitToken,
                                                         integrationConfigJson, "customerId", secretKey, hcpMock)
        except KnownUserError as err:
            errorThrown = err.message.startswith("integrationsConfigString can not be none or empty.")
            assert (errorThrown)

        expectedCookieValue = "RequestHttpHeader_Via=v" + \
                              "|SdkVersion=" + userInQueueService.SDK_VERSION + \
                              "|Connector=mock-connector" + \
                              "|Runtime=" + sys.version + \
                              "|QueueitToken=" + queueitToken + \
                              "|OriginalUrl=http://localhost/original_url" + \
                              "|RequestIP=userIP" + \
                              "|ServerUtcTime=" + expectedServerTime + \
                              "|MatchedConfig=NULL" + \
                              "|RequestHttpHeader_XForwardedFor=xff" + \
                              "|RequestHttpHeader_Forwarded=f" + \
                              "|RequestHttpHeader_XForwardedHost=xfh" + \
                              "|PureUrl=http://test.com?event1=true" + \
                              "|ConfigVersion=NULL" + \
                              "|RequestHttpHeader_XForwardedProto=xfp" + \
                              "|Exception=integrationsConfigString can not be none or empty."

        assert (len(hcpMock.setCookies) == 1)
        assert (KnownUser.QUEUEIT_DEBUG_KEY in hcpMock.setCookies)
        actualCookieValue = hcpMock.setCookies[KnownUser.QUEUEIT_DEBUG_KEY]["value"]
        for val in actualCookieValue.split('|'):
            assert (val in expectedCookieValue)

    def test_validateRequestByIntegrationConfig_debug_missing_customerId(self):
        integrationConfigString = "[[{}]]"

        hcpMock = HttpContextProviderMock()
        hcpMock.originalRequestUrl = "http://localhost/original_url"
        queueitToken = QueueITTokenGenerator.generateDebugToken("eventId", "secretkey")

        result = KnownUser.validateRequestByIntegrationConfig("http://test.com?event1=true", queueitToken,
                                                         integrationConfigString, None, "secretkey", hcpMock)

        assert (result.redirectUrl == "https://api2.queue-it.net/diagnostics/connector/error/?code=setup")
        assert (len(hcpMock.setCookies) == 0)

    def test_validateRequestByIntegrationConfig_debug_missing_secretkey(self):
        integrationConfigString = "[[{}]]"

        hcpMock = HttpContextProviderMock()
        hcpMock.originalRequestUrl = "http://localhost/original_url"
        queueitToken = QueueITTokenGenerator.generateDebugToken("eventId", "secretkey")

        result = KnownUser.validateRequestByIntegrationConfig("http://test.com?event1=true", queueitToken,
                                                         integrationConfigString, "customerid", None, hcpMock)

        assert (result.redirectUrl == "https://api2.queue-it.net/diagnostics/connector/error/?code=setup")
        assert (len(hcpMock.setCookies) == 0)

    def test_validateRequestByIntegrationConfig_debug_expiredtoken(self):
        integrationConfigString = "[[{}]]"

        hcpMock = HttpContextProviderMock()
        hcpMock.originalRequestUrl = "http://localhost/original_url"
        queueitToken = QueueITTokenGenerator.generateDebugToken("eventId", "secretkey", True)

        result = KnownUser.validateRequestByIntegrationConfig("http://test.com?event1=true", queueitToken,
                                                              integrationConfigString, "customerid", "secretkey", hcpMock)

        assert (result.redirectUrl == "https://customerid.api2.queue-it.net/customerid/diagnostics/connector/error/?code=timestamp")
        assert (len(hcpMock.setCookies) == 0)

    def test_validateRequestByIntegrationConfig_debug_modifiedtoken(self):
        integrationConfigString = "[[{}]]"

        hcpMock = HttpContextProviderMock()
        hcpMock.originalRequestUrl = "http://localhost/original_url"
        invalidDebugToken = QueueITTokenGenerator.generateDebugToken("eventId", "secretkey") + "invalid-hash"

        result = KnownUser.validateRequestByIntegrationConfig("http://test.com?event1=true", invalidDebugToken,
                                                              integrationConfigString, "customerid", "secretkey", hcpMock)

        assert (result.redirectUrl == "https://customerid.api2.queue-it.net/customerid/diagnostics/connector/error/?code=hash")
        assert (len(hcpMock.setCookies) == 0)

    def test_validateRequestByIntegrationConfig_ForcedTargetUrl(self):
        userInQueueService = UserInQueueServiceMock()
        KnownUser.userInQueueService = userInQueueService

        integrationConfig = {
            "Description":
            "test",
            "Integrations": [{
                "Name":
                "event1action",
                "ActionType":
                "Queue",
                "EventId":
                "event1",
                "CookieDomain":
                ".test.com",
                "LayoutName":
                "Christmas Layout by Queue-it",
                "Culture":
                "",
                "ExtendCookieValidity":
                True,
                "CookieValidityMinute":
                20,
                "Triggers": [{
                    "TriggerParts": [{
                        "Operator": "Contains",
                        "ValueToCompare": "event1",
                        "UrlPart": "PageUrl",
                        "ValidatorType": "UrlValidator",
                        "IsNegative": False,
                        "IsIgnoreCase": True
                    }],
                    "LogicalOperator":
                    "And"
                }],
                "QueueDomain":
                "knownusertest.queue-it.net",
                "RedirectLogic":
                "ForcedTargetUrl",
                "ForcedTargetUrl":
                "http://test.com"
            }],
            "CustomerId":
            "knownusertest",
            "AccountId":
            "knownusertest",
            "Version":
            3,
            "PublishDate":
            "2017-05-15T21:39:12.0076806Z",
            "ConfigDataVersion":
            "1.0.0.1"
        }

        integrationConfigJson = json.dumps(integrationConfig)
        result = KnownUser.validateRequestByIntegrationConfig(
            "http://test.com?event1=true", "queueIttoken",
            integrationConfigJson, "customerid", "secretkey",
            HttpContextProviderMock())

        assert (userInQueueService.validateQueueRequestCalls[0]['targetUrl'] ==
                "http://test.com")
        assert (not result.isAjaxResult)

    def test_validateRequestByIntegrationConfig_ForcedTargetUrl_AjaxCall(self):
        userInQueueService = UserInQueueServiceMock()
        KnownUser.userInQueueService = userInQueueService

        integrationConfig = {
            "Description":
            "test",
            "Integrations": [{
                "Name":
                "event1action",
                "ActionType":
                "Queue",
                "EventId":
                "event1",
                "CookieDomain":
                ".test.com",
                "LayoutName":
                "Christmas Layout by Queue-it",
                "Culture":
                "",
                "ExtendCookieValidity":
                True,
                "CookieValidityMinute":
                20,
                "Triggers": [{
                    "TriggerParts": [{
                        "Operator": "Contains",
                        "ValueToCompare": "event1",
                        "UrlPart": "PageUrl",
                        "ValidatorType": "UrlValidator",
                        "IsNegative": False,
                        "IsIgnoreCase": True
                    }],
                    "LogicalOperator":
                    "And"
                }],
                "QueueDomain":
                "knownusertest.queue-it.net",
                "RedirectLogic":
                "ForcedTargetUrl",
                "ForcedTargetUrl":
                "http://test.com"
            }],
            "CustomerId":
            "knownusertest",
            "AccountId":
            "knownusertest",
            "Version":
            3,
            "PublishDate":
            "2017-05-15T21:39:12.0076806Z",
            "ConfigDataVersion":
            "1.0.0.1"
        }

        hcpMock = HttpContextProviderMock()
        hcpMock.headers = {"x-queueit-ajaxpageurl": "http%3a%2f%2furl"}
        userInQueueService.validateQueueRequestResultObj = RequestValidationResult(
            ActionTypes.QUEUE, "eventId", None, "http://q.qeuue-it.com", None, "event1action")

        integrationConfigJson = json.dumps(integrationConfig)
        result = KnownUser.validateRequestByIntegrationConfig(
            "http://test.com?event1=true", "queueIttoken",
            integrationConfigJson, "customerid", "secretkey", hcpMock)

        assert (userInQueueService.validateQueueRequestCalls[0]['targetUrl'] ==
                "http://test.com")
        assert (result.isAjaxResult)
        assert (result.getAjaxRedirectUrl().lower() ==
                "http%3a%2f%2fq.qeuue-it.com")

    def test_validateRequestByIntegrationConfig_EventTargetUrl(self):
        userInQueueService = UserInQueueServiceMock()
        KnownUser.userInQueueService = userInQueueService

        integrationConfig = {
            "Description":
            "test",
            "Integrations": [{
                "Name":
                "event1action",
                "ActionType":
                "Queue",
                "EventId":
                "event1",
                "CookieDomain":
                ".test.com",
                "LayoutName":
                "Christmas Layout by Queue-it",
                "Culture":
                "",
                "ExtendCookieValidity":
                True,
                "CookieValidityMinute":
                20,
                "Triggers": [{
                    "TriggerParts": [{
                        "Operator": "Contains",
                        "ValueToCompare": "event1",
                        "UrlPart": "PageUrl",
                        "ValidatorType": "UrlValidator",
                        "IsNegative": False,
                        "IsIgnoreCase": True
                    }],
                    "LogicalOperator":
                    "And"
                }],
                "QueueDomain":
                "knownusertest.queue-it.net",
                "RedirectLogic":
                "EventTargetUrl"
            }],
            "CustomerId":
            "knownusertest",
            "AccountId":
            "knownusertest",
            "Version":
            3,
            "PublishDate":
            "2017-05-15T21:39:12.0076806Z",
            "ConfigDataVersion":
            "1.0.0.1"
        }

        integrationConfigJson = json.dumps(integrationConfig)
        result = KnownUser.validateRequestByIntegrationConfig(
            "http://test.com?event1=true", "queueIttoken",
            integrationConfigJson, "customerid", "secretkey",
            HttpContextProviderMock())

        assert (
            userInQueueService.validateQueueRequestCalls[0]['targetUrl'] == "")
        assert (not result.isAjaxResult)
        assert (userInQueueService.validateQueueRequestCalls[0]["config"]
                .actionName == integrationConfig['Integrations'][0]['Name'])

    def test_validateRequestByIntegrationConfig_EventTargetUrl_AjaxCall(self):
        userInQueueService = UserInQueueServiceMock()
        KnownUser.userInQueueService = userInQueueService

        integrationConfig = {
            "Description":
            "test",
            "Integrations": [{
                "Name":
                "event1action",
                "ActionType":
                "Queue",
                "EventId":
                "event1",
                "CookieDomain":
                ".test.com",
                "LayoutName":
                "Christmas Layout by Queue-it",
                "Culture":
                "",
                "ExtendCookieValidity":
                True,
                "CookieValidityMinute":
                20,
                "Triggers": [{
                    "TriggerParts": [{
                        "Operator": "Contains",
                        "ValueToCompare": "event1",
                        "UrlPart": "PageUrl",
                        "ValidatorType": "UrlValidator",
                        "IsNegative": False,
                        "IsIgnoreCase": True
                    }],
                    "LogicalOperator":
                    "And"
                }],
                "QueueDomain":
                "knownusertest.queue-it.net",
                "RedirectLogic":
                "EventTargetUrl"
            }],
            "CustomerId":
            "knownusertest",
            "AccountId":
            "knownusertest",
            "Version":
            3,
            "PublishDate":
            "2017-05-15T21:39:12.0076806Z",
            "ConfigDataVersion":
            "1.0.0.1"
        }

        hcpMock = HttpContextProviderMock()
        hcpMock.headers = {"x-queueit-ajaxpageurl": "http%3a%2f%2furl"}
        userInQueueService.validateQueueRequestResultObj = RequestValidationResult(
            ActionTypes.QUEUE, "eventId", None, "http://q.qeuue-it.com", None, "event1action")

        integrationConfigJson = json.dumps(integrationConfig)
        result = KnownUser.validateRequestByIntegrationConfig(
            "http://test.com?event1=true", "queueIttoken",
            integrationConfigJson, "customerid", "secretkey", hcpMock)

        assert (
            userInQueueService.validateQueueRequestCalls[0]['targetUrl'] == "")
        assert (result.isAjaxResult)
        assert (result.getAjaxRedirectUrl().lower() ==
                "http%3a%2f%2fq.qeuue-it.com")
        assert (userInQueueService.validateQueueRequestCalls[0]["config"]
                .actionName == integrationConfig['Integrations'][0]['Name'])

    def test_validateRequestByIntegrationConfig_CancelAction(self):
        userInQueueService = UserInQueueServiceMock()
        KnownUser.userInQueueService = userInQueueService

        integrationConfig = {
            "Description":
            "test",
            "Integrations": [{
                "Name":
                "event1action",
                "ActionType":
                "Cancel",
                "EventId":
                "event1",
                "CookieDomain":
                ".test.com",
                "Triggers": [{
                    "TriggerParts": [{
                        "Operator": "Contains",
                        "ValueToCompare": "event1",
                        "UrlPart": "PageUrl",
                        "ValidatorType": "UrlValidator",
                        "IsNegative": False,
                        "IsIgnoreCase": True
                    }],
                    "LogicalOperator":
                    "And"
                }],
                "QueueDomain":
                "knownusertest.queue-it.net",
            }],
            "CustomerId":
            "knownusertest",
            "AccountId":
            "knownusertest",
            "Version":
            3,
            "PublishDate":
            "2017-05-15T21:39:12.0076806Z",
            "ConfigDataVersion":
            "1.0.0.1"
        }

        integrationConfigJson = json.dumps(integrationConfig)
        result = KnownUser.validateRequestByIntegrationConfig(
            "http://test.com?event1=true", "queueIttoken",
            integrationConfigJson, "customerid", "secretkey",
            HttpContextProviderMock())

        assert (userInQueueService.validateCancelRequestCalls[0]["targetUrl"]
                == "http://test.com?event1=true")
        assert (userInQueueService.validateCancelRequestCalls[0]["customerId"]
                == "customerid")
        assert (userInQueueService.validateCancelRequestCalls[0]["secretKey"]
                == "secretkey")

        assert (userInQueueService.validateCancelRequestCalls[0]["config"]
                .queueDomain == "knownusertest.queue-it.net")
        assert (userInQueueService.validateCancelRequestCalls[0]["config"]
                .eventId == "event1")
        assert (userInQueueService.validateCancelRequestCalls[0]["config"]
                .cookieDomain == ".test.com")
        assert (userInQueueService.validateCancelRequestCalls[0]["config"]
                .version == 3)
        assert (not result.isAjaxResult)
        assert (userInQueueService.validateCancelRequestCalls[0]["config"]
                .actionName == integrationConfig['Integrations'][0]['Name'])

    def test_validateRequestByIntegrationConfig_CancelAction_AjaxCall(self):
        userInQueueService = UserInQueueServiceMock()
        KnownUser.userInQueueService = userInQueueService

        integrationConfig = {
            "Description":
            "test",
            "Integrations": [{
                "Name":
                "event1action",
                "ActionType":
                "Cancel",
                "EventId":
                "event1",
                "CookieDomain":
                ".test.com",
                "Triggers": [{
                    "TriggerParts": [{
                        "Operator": "Contains",
                        "ValueToCompare": "event1",
                        "UrlPart": "PageUrl",
                        "ValidatorType": "UrlValidator",
                        "IsNegative": False,
                        "IsIgnoreCase": True
                    }],
                    "LogicalOperator":
                    "And"
                }],
                "QueueDomain":
                "knownusertest.queue-it.net",
            }],
            "CustomerId":
            "knownusertest",
            "AccountId":
            "knownusertest",
            "Version":
            3,
            "PublishDate":
            "2017-05-15T21:39:12.0076806Z",
            "ConfigDataVersion":
            "1.0.0.1"
        }

        hcpMock = HttpContextProviderMock()
        hcpMock.headers = {"x-queueit-ajaxpageurl": "http%3a%2f%2furl"}
        userInQueueService.validateCancelRequestResultObj = RequestValidationResult(
            ActionTypes.CANCEL, "eventId", None, "http://q.qeuue-it.com", None, "event1action")

        integrationConfigJson = json.dumps(integrationConfig)
        result = KnownUser.validateRequestByIntegrationConfig(
            "http://test.com?event1=true", "queueIttoken",
            integrationConfigJson, "customerid", "secretkey", hcpMock)

        assert (userInQueueService.validateCancelRequestCalls[0]["targetUrl"]
                == "http://url")
        assert (userInQueueService.validateCancelRequestCalls[0]["customerId"]
                == "customerid")
        assert (userInQueueService.validateCancelRequestCalls[0]["secretKey"]
                == "secretkey")

        assert (userInQueueService.validateCancelRequestCalls[0]["config"]
                .queueDomain == "knownusertest.queue-it.net")
        assert (userInQueueService.validateCancelRequestCalls[0]["config"]
                .eventId == "event1")
        assert (userInQueueService.validateCancelRequestCalls[0]["config"]
                .cookieDomain == ".test.com")
        assert (userInQueueService.validateCancelRequestCalls[0]["config"]
                .version == 3)
        assert (result.isAjaxResult)
        assert (result.getAjaxRedirectUrl().lower() ==
                "http%3a%2f%2fq.qeuue-it.com")
        assert (userInQueueService.validateCancelRequestCalls[0]["config"]
                .actionName == integrationConfig['Integrations'][0]['Name'])

    def test_validateRequestByIntegrationConfig_ignoreAction(self):
        userInQueueService = UserInQueueServiceMock()
        KnownUser.userInQueueService = userInQueueService

        integrationConfig = {
            "Description":
            "test",
            "Integrations": [{
                "Name":
                "event1action",
                "ActionType":
                "Ignore",
                "EventId":
                "event1",
                "CookieDomain":
                ".test.com",                
                "Triggers": [{
                    "TriggerParts": [{
                        "Operator": "Contains",
                        "ValueToCompare": "event1",
                        "UrlPart": "PageUrl",
                        "ValidatorType": "UrlValidator",
                        "IsNegative": False,
                        "IsIgnoreCase": True
                    }],
                    "LogicalOperator":
                    "And"
                }],
                "QueueDomain":
                "knownusertest.queue-it.net",
            }],
            "CustomerId":
            "knownusertest",
            "AccountId":
            "knownusertest",
            "Version":
            3,
            "PublishDate":
            "2017-05-15T21:39:12.0076806Z",
            "ConfigDataVersion":
            "1.0.0.1"
        }

        integrationConfigJson = json.dumps(integrationConfig)
        result = KnownUser.validateRequestByIntegrationConfig(
            "http://test.com?event1=true", "queueIttoken",
            integrationConfigJson, "customerid", "secretkey",
            HttpContextProviderMock())

        assert (len(userInQueueService.getIgnoreActionResultCalls) == 1)
        assert (not result.isAjaxResult)
        assert (userInQueueService.getIgnoreActionResultCalls[0]["actionName"] == integrationConfig['Integrations'][0]['Name'])

    def test_validateRequestByIntegrationConfig_ignoreAction_AjaxCall(self):
        userInQueueService = UserInQueueServiceMock()
        KnownUser.userInQueueService = userInQueueService

        integrationConfig = {
            "Description":
            "test",
            "Integrations": [{
                "Name":
                "event1action",
                "ActionType":
                "Ignore",
                "EventId":
                "event1",
                "CookieDomain":
                ".test.com",
                "Triggers": [{
                    "TriggerParts": [{
                        "Operator": "Contains",
                        "ValueToCompare": "event1",
                        "UrlPart": "PageUrl",
                        "ValidatorType": "UrlValidator",
                        "IsNegative": False,
                        "IsIgnoreCase": True
                    }],
                    "LogicalOperator":
                    "And"
                }],
                "QueueDomain":
                "knownusertest.queue-it.net",
            }],
            "CustomerId":
            "knownusertest",
            "AccountId":
            "knownusertest",
            "Version":
            3,
            "PublishDate":
            "2017-05-15T21:39:12.0076806Z",
            "ConfigDataVersion":
            "1.0.0.1"
        }

        hcpMock = HttpContextProviderMock()
        hcpMock.headers = {"x-queueit-ajaxpageurl": "http%3a%2f%2furl"}

        integrationConfigJson = json.dumps(integrationConfig)
        result = KnownUser.validateRequestByIntegrationConfig(
            "http://test.com?event1=true", "queueIttoken",
            integrationConfigJson, "customerid", "secretkey", hcpMock)

        assert (len(userInQueueService.getIgnoreActionResultCalls) == 1)
        assert (result.isAjaxResult)
        assert (userInQueueService.getIgnoreActionResultCalls[0]["actionName"] == integrationConfig['Integrations'][0]['Name'])

    def test_validateRequestByIntegrationConfig_defaultsTo_ignoreAction(self):
        userInQueueService = UserInQueueServiceMock()
        KnownUser.userInQueueService = userInQueueService

        integrationConfig = {
            "Description":
            "test",
            "Integrations": [{
                "Name":
                "event1action",
                "ActionType":
                "some-future-action-type",
                "EventId":
                "event1",
                "CookieDomain":
                ".test.com",                
                "Triggers": [{
                    "TriggerParts": [{
                        "Operator": "Contains",
                        "ValueToCompare": "event1",
                        "UrlPart": "PageUrl",
                        "ValidatorType": "UrlValidator",
                        "IsNegative": False,
                        "IsIgnoreCase": True
                    }],
                    "LogicalOperator":
                    "And"
                }],
                "QueueDomain":
                "knownusertest.queue-it.net",
            }],
            "CustomerId":
            "knownusertest",
            "AccountId":
            "knownusertest",
            "Version":
            3,
            "PublishDate":
            "2017-05-15T21:39:12.0076806Z",
            "ConfigDataVersion":
            "1.0.0.1"
        }

        hcpMock = HttpContextProviderMock()
        integrationConfigJson = json.dumps(integrationConfig)
        result = KnownUser.validateRequestByIntegrationConfig(
            "http://test.com?event1=true", "queueIttoken",
            integrationConfigJson, "customerid", "secretkey", hcpMock)

        assert (len(userInQueueService.getIgnoreActionResultCalls) == 1)
        assert (userInQueueService.getIgnoreActionResultCalls[0]["actionName"] == integrationConfig['Integrations'][0]['Name'])

    def test_cancelRequestByLocalConfig_Exception_NoDebugToken_NoDebugCookie(self):
        userInQueueService = UserInQueueServiceMock()
        KnownUser.userInQueueService = userInQueueService
        hcpMock = HttpContextProviderMock()
        hcpMock.originalRequestUrl = "http://localhost/original_url"
        hcpMock.remote_ip = "userIP"
        hcpMock.headers = {
            "via": "v",
            "forwarded": "f",
            "x-forwarded-for": "xff",
            "x-forwarded-host": "xfh",
            "x-forwarded-proto": "xfp"
        }
        cancelConfig = CancelEventConfig()
        cancelConfig.eventId = "eventId"
        cancelConfig.queueDomain = "queueDomain"
        cancelConfig.version = 1
        cancelConfig.cookieDomain = "cookieDomain"
        cancelConfig.actionName = "cancelAction"
        userInQueueService.validateCancelRequestRaiseException = True
        try:
            KnownUser.cancelRequestByLocalConfig("targetUrl", "token", cancelConfig,
                                                          "customerId", "secretKey", HttpContextProviderMock())
        except Exception as e:
            assert (e.message == "Exception")

        assert (len(userInQueueService.validateCancelRequestCalls) > 0)
        assert (len(hcpMock.setCookies) == 0)

    def test_resolveQueueRequestByLocalConfig_Exception_NoDebugToken_NoDebugCookie(self):
        userInQueueService = UserInQueueServiceMock()
        KnownUser.userInQueueService = userInQueueService
        hcpMock = HttpContextProviderMock()
        hcpMock.originalRequestUrl = "http://localhost/original_url"
        hcpMock.remote_ip = "userIP"
        hcpMock.headers = {
            "via": "v",
            "forwarded": "f",
            "x-forwarded-for": "xff",
            "x-forwarded-host": "xfh",
            "x-forwarded-proto": "xfp"
        }
        queueConfig = QueueEventConfig()
        queueConfig.cookieDomain = "cookieDomain"
        queueConfig.layoutName = "layoutName"
        queueConfig.culture = "culture"
        queueConfig.eventId = "eventId"
        queueConfig.queueDomain = "queueDomain"
        queueConfig.extendCookieValidity = True
        queueConfig.cookieValidityMinute = 10
        queueConfig.version = 12
        queueConfig.actionName = "queueAction"
        userInQueueService.validateQueueRequestRaiseException = True
        try:
            KnownUser.resolveQueueRequestByLocalConfig("target", "token", queueConfig, "id", "key",
                                HttpContextProviderMock())
        except Exception as e:
            assert (e.message == "Exception")

        assert (len(userInQueueService.validateQueueRequestCalls) > 0)
        assert (len(hcpMock.setCookies) == 0)

    def test_validateRequestByIntegrationConfig_CancelAction_Exception_NoDebugToken_NoDebugCookie(self):
        userInQueueService = UserInQueueServiceMock()
        KnownUser.userInQueueService = userInQueueService
        hcpMock = HttpContextProviderMock()
        hcpMock.originalRequestUrl = "http://localhost/original_url"
        hcpMock.remote_ip = "userIP"
        hcpMock.headers = {
            "via": "v",
            "forwarded": "f",
            "x-forwarded-for": "xff",
            "x-forwarded-host": "xfh",
            "x-forwarded-proto": "xfp"
        }
        integrationConfig = {
            "Description":
            "test",
            "Integrations": [{
                "Name":
                "event1action",
                "ActionType":
                "Cancel",
                "EventId":
                "event1",
                "CookieDomain":
                ".test.com",
                "Triggers": [{
                    "TriggerParts": [{
                        "Operator": "Contains",
                        "ValueToCompare": "event1",
                        "UrlPart": "PageUrl",
                        "ValidatorType": "UrlValidator",
                        "IsNegative": False,
                        "IsIgnoreCase": True
                    }],
                    "LogicalOperator":
                    "And"
                }],
                "QueueDomain":
                "knownusertest.queue-it.net",
            }],
            "CustomerId":
            "knownusertest",
            "AccountId":
            "knownusertest",
            "Version":
            3,
            "PublishDate":
            "2017-05-15T21:39:12.0076806Z",
            "ConfigDataVersion":
            "1.0.0.1"
        }

        integrationConfigJson = json.dumps(integrationConfig)
        userInQueueService.validateCancelRequestRaiseException = True
        try:
            KnownUser.validateRequestByIntegrationConfig("http://test.com?event1=true", "queueIttoken",
                                    integrationConfigJson, "customerid", "secretkey", HttpContextProviderMock())
        except Exception as e:
            assert (e.message == "Exception")

        assert (len(userInQueueService.validateCancelRequestCalls) > 0)
        assert (len(hcpMock.setCookies) == 0)