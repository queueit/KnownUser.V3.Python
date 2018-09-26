import unittest
import json
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


class UserInQueueServiceMock(UserInQueueService):
    def __init__(self):
        self.extendQueueCookieCalls = {}
        self.validateQueueRequestCalls = {}
        self.validateCancelRequestCalls = {}
        self.getIgnoreActionResultCalls = {}
        self.validateQueueRequestResultObj = RequestValidationResult(
            ActionTypes.QUEUE, None, None, None, None)
        self.validateCancelRequestResultObj = RequestValidationResult(
            ActionTypes.CANCEL, None, None, None, None)
        self.getIgnoreActionResultObj = RequestValidationResult(
            ActionTypes.IGNORE, None, None, None, None)

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
        return self.validateQueueRequestResultObj

    def validateCancelRequest(self, targetUrl, config, customerId, secretKey):
        self.validateCancelRequestCalls[len(
            self.validateQueueRequestCalls)] = {
                "targetUrl": targetUrl,
                "config": config,
                "customerId": customerId,
                "secretKey": secretKey
            }
        return self.validateCancelRequestResultObj

    def getIgnoreActionResult(self):
        self.getIgnoreActionResultCalls[len(
            self.getIgnoreActionResultCalls)] = {}
        return self.getIgnoreActionResultObj


class QueueITTokenGenerator:
    @staticmethod
    def generateDebugToken(eventId, secretKey):
        tokenWithoutHash = (
            QueueUrlParams.EVENT_ID_KEY +
            QueueUrlParams.KEY_VALUE_SEPARATOR_CHAR +
            eventId) + QueueUrlParams.KEY_VALUE_SEPARATOR_GROUP_CHAR + (
                QueueUrlParams.REDIRECT_TYPE_KEY +
                QueueUrlParams.KEY_VALUE_SEPARATOR_CHAR + "debug")
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

        hcpMock = HttpContextProviderMock()
        hcpMock.headers = {"x-queueit-ajaxpageurl": "http%3a%2f%2furl"}
        userInQueueService.validateCancelRequestResultObj = RequestValidationResult(
            ActionTypes.CANCEL, "eventId", None, "http://q.qeuue-it.com", None)

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

    def test_cancelRequestByLocalConfig_setDebugCookie(self):
        userInQueueService = UserInQueueServiceMock()
        KnownUser.userInQueueService = userInQueueService

        cancelConfig = CancelEventConfig()
        cancelConfig.eventId = "eventId"
        cancelConfig.queueDomain = "queueDomain"
        cancelConfig.version = 1
        cancelConfig.cookieDomain = "cookieDomain"

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
            "|QueueitToken=" + queueitToken + \
            "|OriginalUrl=http://localhost/original_url" + \
            "|RequestIP=userIP" + \
            "|RequestHttpHeader_Forwarded=f" + \
            "|CancelConfig=EventId:eventId&Version:1&QueueDomain:queueDomain&CookieDomain:cookieDomain" + \
            "|RequestHttpHeader_XForwardedFor=xff" + \
            "|TargetUrl=url" + \
            "|RequestHttpHeader_XForwardedHost=xfh" + \
            "|ServerUtcTime=" + expectedServerTime + \
            "|RequestHttpHeader_XForwardedProto=xfp"

        assert (len(hcpMock.setCookies) == 1)
        assert (KnownUser.QUEUEIT_DEBUG_KEY in hcpMock.setCookies)

        actualCookieValue = hcpMock.setCookies[KnownUser.QUEUEIT_DEBUG_KEY][
            "value"]
        assert (expectedCookieValue == actualCookieValue)

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
            "|QueueitToken=" + queueitToken + \
            "|OriginalUrl=http://localhost/original_url" + \
            "|QueueConfig=EventId:eventId&Version:12&QueueDomain:queueDomain&CookieDomain:cookieDomain&ExtendCookieValidity:true&CookieValidityMinute:10&LayoutName:layoutName&Culture:culture" + \
            "|RequestIP=userIP" + \
            "|RequestHttpHeader_Forwarded=f" + \
            "|RequestHttpHeader_XForwardedFor=xff" + \
            "|TargetUrl=url" + \
            "|RequestHttpHeader_XForwardedHost=xfh" + \
            "|ServerUtcTime=" + expectedServerTime + \
            "|RequestHttpHeader_XForwardedProto=xfp"

        assert (len(hcpMock.setCookies) == 1)
        assert (KnownUser.QUEUEIT_DEBUG_KEY in hcpMock.setCookies)
        actualCookieValue = hcpMock.setCookies[KnownUser.QUEUEIT_DEBUG_KEY][
            "value"]
        assert (expectedCookieValue == actualCookieValue)

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

        hcpMock = HttpContextProviderMock()
        hcpMock.headers = {"x-queueit-ajaxpageurl": "http%3a%2f%2furl"}
        userInQueueService.validateQueueRequestResultObj = RequestValidationResult(
            ActionTypes.QUEUE, "eventId", None, "http://q.qeuue-it.com", None)

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

    def test_validateRequestByIntegrationConfig_empty_currentUrlWithoutQueueITToken(
            self):
        errorThrown = False

        try:
            KnownUser.validateRequestByIntegrationConfig(
                "", "queueIttoken", None, "customerId", "secretKey",
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
                "currentUrlWithoutQueueITToken", "queueIttoken", None,
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
                "not-valid-json", "customerId", "secretKey",
                HttpContextProviderMock())
        except KnownUserError as err:
            errorThrown = err.message.startswith(
                "integrationConfiguration text was not valid")

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
            ActionTypes.QUEUE, "eventId", None, "http://q.qeuue-it.com", None)

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
            "|QueueitToken=" + queueitToken + \
            "|OriginalUrl=http://localhost/original_url" + \
            "|QueueConfig=EventId:event1&Version:3&QueueDomain:knownusertest.queue-it.net&CookieDomain:.test.com&ExtendCookieValidity:true&CookieValidityMinute:20&LayoutName:Christmas Layout by Queue-it&Culture:da-DK" + \
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

        assert (expectedCookieValue == actualCookieValue)

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
        assert (expectedCookieValue == actualCookieValue)

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
            ActionTypes.QUEUE, "eventId", None, "http://q.qeuue-it.com", None)

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
            ActionTypes.QUEUE, "eventId", None, "http://q.qeuue-it.com", None)

        integrationConfigJson = json.dumps(integrationConfig)
        result = KnownUser.validateRequestByIntegrationConfig(
            "http://test.com?event1=true", "queueIttoken",
            integrationConfigJson, "customerid", "secretkey", hcpMock)

        assert (
            userInQueueService.validateQueueRequestCalls[0]['targetUrl'] == "")
        assert (result.isAjaxResult)
        assert (result.getAjaxRedirectUrl().lower() ==
                "http%3a%2f%2fq.qeuue-it.com")

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
            ActionTypes.CANCEL, "eventId", None, "http://q.qeuue-it.com", None)

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
        KnownUser.validateRequestByIntegrationConfig(
            "http://test.com?event1=true", "queueIttoken",
            integrationConfigJson, "customerid", "secretkey", hcpMock)

        assert (len(userInQueueService.getIgnoreActionResultCalls) == 1)
