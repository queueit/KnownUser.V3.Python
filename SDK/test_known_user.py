import unittest
import json
import sys

from queueit_knownuserv3.queue_url_params import QueueUrlParams
from queueit_knownuserv3.models import *
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

    def getHeader(self, header_name):
        if header_name not in self.headers:
            return None
        return self.headers[header_name]

    def setCookie(self, name, value, expire, domain, is_cookie_http_only, is_cookie_secure):
        self.setCookies[name] = {
            "value": value,
            "expire": expire,
            "domain": domain,
            "isCookieHttpOnly": is_cookie_http_only,
            "isCookieSecure": is_cookie_secure
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

    def extendQueueCookie(self, event_id, cookie_validity_minute, cookie_domain,
                          is_cookie_http_only, is_cookie_secure, secret_key):
        self.extendQueueCookieCalls[len(self.extendQueueCookieCalls)] = {
            "eventId": event_id,
            "cookieValidityMinute": cookie_validity_minute,
            "cookieDomain": cookie_domain,
            "isCookieHttpOnly": is_cookie_http_only,
            "isCookieSecure": is_cookie_secure,
            "secretKey": secret_key
        }

    def validateQueueRequest(self, target_url, queueit_token, config, customer_id,
                             secret_key):
        self.validateQueueRequestCalls[len(self.validateQueueRequestCalls)] = {
            "targetUrl": target_url,
            "queueitToken": queueit_token,
            "config": config,
            "customerId": customer_id,
            "secretKey": secret_key
        }
        if self.validateQueueRequestRaiseException:
            raise Exception("Exception")
        return self.validateQueueRequestResultObj

    def validateCancelRequest(self, target_url, config, customer_id, secret_key):
        self.validateCancelRequestCalls[len(
            self.validateQueueRequestCalls)] = {
            "targetUrl": target_url,
            "config": config,
            "customerId": customer_id,
            "secretKey": secret_key
        }

        if self.validateCancelRequestRaiseException:
            raise Exception("Exception")
        return self.validateCancelRequestResultObj

    def getIgnoreActionResult(self, action_name):
        self.getIgnoreActionResultCalls[len(
            self.getIgnoreActionResultCalls)] = {
            "actionName": action_name
        }
        return self.getIgnoreActionResultObj


class QueueITTokenGenerator:
    @staticmethod
    def generateDebugToken(event_id, secret_key, expired_token=False):
        time_stamp = QueueitHelpers.getCurrentTime() + (3 * 60)
        if expired_token:
            time_stamp = time_stamp - 1000
        token_without_hash = (
                                     QueueUrlParams.EVENT_ID_KEY +
                                     QueueUrlParams.KEY_VALUE_SEPARATOR_CHAR +
                                     event_id) + QueueUrlParams.KEY_VALUE_SEPARATOR_GROUP_CHAR + (
                                     QueueUrlParams.REDIRECT_TYPE_KEY +
                                     QueueUrlParams.KEY_VALUE_SEPARATOR_CHAR + "debug") + QueueUrlParams.KEY_VALUE_SEPARATOR_GROUP_CHAR + (
                                     QueueUrlParams.TIMESTAMP_KEY +
                                     QueueUrlParams.KEY_VALUE_SEPARATOR_CHAR + str(time_stamp))

        hash_value = QueueitHelpers.hmacSha256Encode(token_without_hash, secret_key)
        token = token_without_hash + QueueUrlParams.KEY_VALUE_SEPARATOR_GROUP_CHAR + QueueUrlParams.HASH_KEY + QueueUrlParams.KEY_VALUE_SEPARATOR_CHAR + hash_value
        return token


class TestKnownUser(unittest.TestCase):
    def test_cancelRequestByLocalConfig(self):
        user_in_queue_service = UserInQueueServiceMock()
        KnownUser.userInQueueService = user_in_queue_service

        cancel_config = CancelEventConfig()
        cancel_config.eventId = "eventId"
        cancel_config.queueDomain = "queueDomain"
        cancel_config.version = 1
        cancel_config.cookieDomain = "cookieDomain"
        cancel_config.actionName = "cancelAction"

        result = KnownUser.cancelRequestByLocalConfig(
            "targetUrl", "token", cancel_config, "customerId", "secretKey",
            HttpContextProviderMock())

        assert (user_in_queue_service.validateCancelRequestCalls[0]["targetUrl"]
                == "targetUrl")
        assert (user_in_queue_service.validateCancelRequestCalls[0]["config"] ==
                cancel_config)
        assert (user_in_queue_service.validateCancelRequestCalls[0]["customerId"]
                == "customerId")
        assert (user_in_queue_service.validateCancelRequestCalls[0]["secretKey"]
                == "secretKey")
        assert (not result.isAjaxResult)

    def test_cancelRequestByLocalConfig_AjaxCall(self):
        user_in_queue_service = UserInQueueServiceMock()
        KnownUser.userInQueueService = user_in_queue_service

        cancel_config = CancelEventConfig()
        cancel_config.eventId = "eventId"
        cancel_config.queueDomain = "queueDomain"
        cancel_config.version = 1
        cancel_config.cookieDomain = "cookieDomain"
        cancel_config.actionName = "cancelAction"

        hcp_mock = HttpContextProviderMock()
        hcp_mock.headers = {"x-queueit-ajaxpageurl": "http%3a%2f%2furl"}
        user_in_queue_service.validateCancelRequestResultObj = RequestValidationResult(
            ActionTypes.CANCEL, "eventId", None, "http://q.qeuue-it.com", None, cancel_config.actionName)

        result = KnownUser.cancelRequestByLocalConfig(
            "targetUrl", "token", cancel_config, "customerId", "secretKey",
            hcp_mock)

        assert (user_in_queue_service.validateCancelRequestCalls[0]["targetUrl"]
                == "http://url")
        assert (user_in_queue_service.validateCancelRequestCalls[0]["config"] ==
                cancel_config)
        assert (user_in_queue_service.validateCancelRequestCalls[0]["customerId"]
                == "customerId")
        assert (user_in_queue_service.validateCancelRequestCalls[0]["secretKey"]
                == "secretKey")
        assert (result.isAjaxResult)
        assert (result.getAjaxRedirectUrl().lower() ==
                "http%3a%2f%2fq.qeuue-it.com")
        assert (result.actionName == cancel_config.actionName)

    def test_cancelRequestByLocalConfig_setDebugCookie(self):
        user_in_queue_service = UserInQueueServiceMock()
        KnownUser.userInQueueService = user_in_queue_service

        cancel_config = CancelEventConfig()
        cancel_config.eventId = "eventId"
        cancel_config.queueDomain = "queueDomain"
        cancel_config.version = 1
        cancel_config.cookieDomain = "cookieDomain"
        cancel_config.actionName = "cancelAction"

        hcp_mock = HttpContextProviderMock()
        hcp_mock.originalRequestUrl = "http://localhost/original_url"
        hcp_mock.remote_ip = "userIP"
        hcp_mock.headers = {
            "via": "v",
            "forwarded": "f",
            "x-forwarded-for": "xff",
            "x-forwarded-host": "xfh",
            "x-forwarded-proto": "xfp"
        }

        secret_key = "secretKey"
        queueit_token = QueueITTokenGenerator.generateDebugToken("eventId", secret_key)
        expected_server_time = QueueitHelpers.getCurrentTimeAsIso8601Str()

        KnownUser.cancelRequestByLocalConfig(
            "url",
            queueit_token,
            cancel_config,
            "customerId",
            secret_key,
            hcp_mock)

        expected_cookie_value = "RequestHttpHeader_Via=v" + \
                                "|SdkVersion=" + user_in_queue_service.SDK_VERSION + \
                                "|Connector=mock-connector" + \
                                "|Runtime=" + sys.version + \
                                "|QueueitToken=" + queueit_token + \
                                "|OriginalUrl=http://localhost/original_url" + \
                                "|RequestIP=userIP" + \
                                "|RequestHttpHeader_Forwarded=f" + \
                                "|CancelConfig=EventId:eventId&Version:1&QueueDomain:queueDomain&CookieDomain:cookieDomain&IsCookieHttpOnly:false&IsCookieSecure:false&ActionName:" + cancel_config.actionName + \
                                "|RequestHttpHeader_XForwardedFor=xff" + \
                                "|TargetUrl=url" + \
                                "|RequestHttpHeader_XForwardedHost=xfh" + \
                                "|ServerUtcTime=" + expected_server_time + \
                                "|RequestHttpHeader_XForwardedProto=xfp"

        assert (len(hcp_mock.setCookies) == 1)
        assert (KnownUser.QUEUEIT_DEBUG_KEY in hcp_mock.setCookies)

        actual_cookie_value = hcp_mock.setCookies[KnownUser.QUEUEIT_DEBUG_KEY][
            "value"]
        for val in actual_cookie_value.split('|'):
            assert (val in expected_cookie_value)

    def test_CancelRequestByLocalConfig_debug_nullconfig(self):
        user_in_queue_service = UserInQueueServiceMock()
        KnownUser.userInQueueService = user_in_queue_service

        hcp_mock = HttpContextProviderMock()
        hcp_mock.originalRequestUrl = "http://localhost/original_url"
        hcp_mock.remote_ip = "userIP"
        hcp_mock.headers = {
            "via": "v",
            "forwarded": "f",
            "x-forwarded-for": "xff",
            "x-forwarded-host": "xfh",
            "x-forwarded-proto": "xfp"
        }

        integrationConfigJson = "{'key': 'valu'e}"
        secret_key = "secretKey"
        queueit_token = QueueITTokenGenerator.generateDebugToken("eventId", secret_key)

        expected_server_time = QueueitHelpers.getCurrentTimeAsIso8601Str()
        try:
            KnownUser.cancelRequestByLocalConfig("http://test.com?event1=true", queueit_token,
                                                 None, "customerId", secret_key, hcp_mock)
        except KnownUserError as err:
            error_thrown = err.message.startswith("cancelConfig can not be none.")
            assert error_thrown

        expected_cookie_value = "RequestHttpHeader_Via=v" + \
                                "|SdkVersion=" + user_in_queue_service.SDK_VERSION + \
                                "|Connector=mock-connector" + \
                                "|Runtime=" + sys.version + \
                                "|QueueitToken=" + queueit_token + \
                                "|OriginalUrl=http://localhost/original_url" + \
                                "|RequestIP=userIP" + \
                                "|RequestHttpHeader_Forwarded=f" + \
                                "|CancelConfig=NULL" + \
                                "|RequestHttpHeader_XForwardedFor=xff" + \
                                "|TargetUrl=http://test.com?event1=true" + \
                                "|RequestHttpHeader_XForwardedHost=xfh" + \
                                "|ServerUtcTime=" + expected_server_time + \
                                "|RequestHttpHeader_XForwardedProto=xfp" + \
                                "|Exception=cancelConfig can not be none."

        assert (len(hcp_mock.setCookies) == 1)
        assert (KnownUser.QUEUEIT_DEBUG_KEY in hcp_mock.setCookies)
        actual_cookie_value = hcp_mock.setCookies[KnownUser.QUEUEIT_DEBUG_KEY]["value"]
        for val in actual_cookie_value.split('|'):
            assert (val in expected_cookie_value)

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
        error_thrown = False

        cancelConfig = CancelEventConfig()
        cancelConfig.eventId = "eventId"

        try:
            KnownUser.cancelRequestByLocalConfig(
                "targetUrl", "token", cancelConfig, "customerId", "secretKey",
                HttpContextProviderMock())
        except KnownUserError as err:
            error_thrown = err.message == "cancelConfig.queueDomain can not be none or empty."

        assert error_thrown

    def test_cancelRequestByLocalConfig_none_EventId(self):
        error_thrown = False

        cancelConfig = CancelEventConfig()
        cancelConfig.queueDomain = "queueDomain"

        try:
            KnownUser.cancelRequestByLocalConfig(
                "targetUrl", "token", cancelConfig, "customerId", "secretKey",
                HttpContextProviderMock())
        except KnownUserError as err:
            error_thrown = err.message == "cancelConfig.eventId can not be none or empty."

        assert error_thrown

    def test_cancelRequestByLocalConfig_none_CancelConfig(self):
        error_thrown = False

        try:
            KnownUser.cancelRequestByLocalConfig("targetUrl", "token", None,
                                                 "customerId", "secretKey",
                                                 HttpContextProviderMock())
        except KnownUserError as err:
            error_thrown = err.message == "cancelConfig can not be none."

        assert error_thrown

    def test_cancelRequestByLocalConfig_none_CustomerId(self):
        error_thrown = False

        try:
            KnownUser.cancelRequestByLocalConfig("targetUrl", "token",
                                                 CancelEventConfig(), None,
                                                 "secretKey",
                                                 HttpContextProviderMock())
        except KnownUserError as err:
            error_thrown = err.message == "customerId can not be none or empty."

        assert error_thrown

    def test_cancelRequestByLocalConfig_none_SeceretKey(self):
        error_thrown = False

        try:
            KnownUser.cancelRequestByLocalConfig("targetUrl", "token",
                                                 CancelEventConfig(),
                                                 "customerId", None,
                                                 HttpContextProviderMock())
        except KnownUserError as err:
            error_thrown = err.message == "secretKey can not be none or empty."

        assert error_thrown

    def test_cancelRequestByLocalConfig_none_TargetUrl(self):
        error_thrown = False

        try:
            KnownUser.cancelRequestByLocalConfig(None, "token",
                                                 CancelEventConfig(),
                                                 "customerId", None,
                                                 HttpContextProviderMock())
        except KnownUserError as err:
            error_thrown = err.message == "targetUrl can not be none or empty."

        assert error_thrown

    def test_extendQueueCookie_none_EventId(self):
        error_thrown = False

        try:
            KnownUser.extendQueueCookie(None, 10, "cookieDomain", False, False, "secretkey", {})
        except KnownUserError as err:
            error_thrown = err.message == "eventId can not be none or empty."

        assert error_thrown

    def test_extendQueueCookie_none_SecretKey(self):
        error_thrown = False

        try:
            KnownUser.extendQueueCookie("eventId", 10, "cookieDomain", False, False, None, {})
        except KnownUserError as err:
            error_thrown = err.message == "secretKey can not be none or empty."

        assert error_thrown

    def test_extendQueueCookie_Invalid_CookieValidityMinute(self):
        error_thrown = False

        try:
            KnownUser.extendQueueCookie("eventId", "invalidInt", "cookieDomain", False, False, "secrettKey", {})
        except KnownUserError as err:
            error_thrown = err.message == "cookieValidityMinute should be integer greater than 0."

        assert error_thrown

    def test_extendQueueCookie_Negative_CookieValidityMinute(self):
        error_thrown = False

        try:
            KnownUser.extendQueueCookie("eventId", -1, "cookieDomain", False, False, "secrettKey", {})
        except KnownUserError as err:
            error_thrown = err.message == "cookieValidityMinute should be integer greater than 0."

        assert error_thrown

    def test_extendQueueCookie(self):
        user_in_queue_service_mock = UserInQueueServiceMock()
        KnownUser.userInQueueService = user_in_queue_service_mock

        KnownUser.extendQueueCookie("evtId", 10, "domain", True, True, "key", HttpContextProviderMock())

        assert (user_in_queue_service_mock.extendQueueCookieCalls[0]["eventId"] == "evtId")
        assert (user_in_queue_service_mock.extendQueueCookieCalls[0]["cookieValidityMinute"] == 10)
        assert (user_in_queue_service_mock.extendQueueCookieCalls[0]["cookieDomain"] == "domain")
        assert (user_in_queue_service_mock.extendQueueCookieCalls[0]["isCookieHttpOnly"])
        assert (user_in_queue_service_mock.extendQueueCookieCalls[0]["isCookieSecure"])
        assert (user_in_queue_service_mock.extendQueueCookieCalls[0]["secretKey"] == "key")

    def test_resolveQueueRequestByLocalConfig_empty_eventId(self):
        queue_config = QueueEventConfig()
        queue_config.cookieDomain = "cookieDomain"
        queue_config.layoutName = "layoutName"
        queue_config.culture = "culture"
        # queueConfig.eventId = "eventId"
        queue_config.queueDomain = "queueDomain"
        queue_config.extendCookieValidity = True
        queue_config.cookieValidityMinute = 10
        queue_config.version = 12

        error_thrown = False

        try:
            KnownUser.resolveQueueRequestByLocalConfig(
                "targeturl", "queueIttoken", queue_config, "customerid",
                "secretkey", HttpContextProviderMock())
        except KnownUserError as err:
            error_thrown = err.message == "queueConfig.eventId can not be none or empty."

        assert error_thrown

    def test_resolveQueueRequestByLocalConfig_empty_secretKey(self):
        queue_config = QueueEventConfig()
        queue_config.cookieDomain = "cookieDomain"
        queue_config.layoutName = "layoutName"
        queue_config.culture = "culture"
        queue_config.eventId = "eventId"
        queue_config.queueDomain = "queueDomain"
        queue_config.extendCookieValidity = True
        queue_config.cookieValidityMinute = 10
        queue_config.version = 12

        error_thrown = False

        try:
            KnownUser.resolveQueueRequestByLocalConfig(
                "targeturl", "queueIttoken", queue_config, "customerid", None,
                HttpContextProviderMock())
        except KnownUserError as err:
            error_thrown = err.message == "secretKey can not be none or empty."

        assert error_thrown

    def test_resolveQueueRequestByLocalConfig_empty_queueDomain(self):
        queueConfig = QueueEventConfig()
        queueConfig.cookieDomain = "cookieDomain"
        queueConfig.layoutName = "layoutName"
        queueConfig.culture = "culture"
        queueConfig.eventId = "eventId"
        # queueConfig.queueDomain = "queueDomain"
        queueConfig.extendCookieValidity = True
        queueConfig.cookieValidityMinute = 10
        queueConfig.version = 12

        error_thrown = False

        try:
            KnownUser.resolveQueueRequestByLocalConfig(
                "targeturl", "queueIttoken", queueConfig, "customerid",
                "secretkey", HttpContextProviderMock())
        except KnownUserError as err:
            error_thrown = err.message == "queueConfig.queueDomain can not be none or empty."

        assert error_thrown

    def test_resolveQueueRequestByLocalConfig_empty_customerId(self):
        queue_config = QueueEventConfig()
        queue_config.cookieDomain = "cookieDomain"
        queue_config.layoutName = "layoutName"
        queue_config.culture = "culture"
        queue_config.eventId = "eventId"
        queue_config.queueDomain = "queueDomain"
        queue_config.extendCookieValidity = True
        queue_config.cookieValidityMinute = 10
        queue_config.version = 12

        error_thrown = False

        try:
            KnownUser.resolveQueueRequestByLocalConfig(
                "targeturl", "queueIttoken", queue_config, None, "secretKey",
                HttpContextProviderMock())
        except KnownUserError as err:
            error_thrown = err.message == "customerId can not be none or empty."

        assert error_thrown

    def test_resolveQueueRequestByLocalConfig_Invalid_extendCookieValidity(self):
        queue_config = QueueEventConfig()
        queue_config.cookieDomain = "cookieDomain"
        queue_config.layoutName = "layoutName"
        queue_config.culture = "culture"
        queue_config.eventId = "eventId"
        queue_config.queueDomain = "queueDomain"
        queue_config.extendCookieValidity = "not-a-boolean"
        queue_config.cookieValidityMinute = 10
        queue_config.version = 12

        error_thrown = False

        try:
            KnownUser.resolveQueueRequestByLocalConfig("targeturl", "queueIttoken", queue_config, "customerId",
                                                       "secretKey", HttpContextProviderMock())
        except KnownUserError as err:
            error_thrown = err.message == "queueConfig.extendCookieValidity should be valid boolean."

        assert error_thrown

    def test_resolveQueueRequestByLocalConfig_Invalid_cookieValidityMinute(self):
        queue_config = QueueEventConfig()
        queue_config.cookieDomain = "cookieDomain"
        queue_config.layoutName = "layoutName"
        queue_config.culture = "culture"
        queue_config.eventId = "eventId"
        queue_config.queueDomain = "queueDomain"
        queue_config.extendCookieValidity = True
        queue_config.cookieValidityMinute = "test"
        queue_config.version = 12

        error_thrown = False

        try:
            KnownUser.resolveQueueRequestByLocalConfig(
                "targeturl", "queueIttoken", queue_config, "customerId",
                "secretKey", HttpContextProviderMock())
        except KnownUserError as err:
            error_thrown = err.message.startswith(
                "queueConfig.cookieValidityMinute should be integer greater than 0"
            )

        assert error_thrown

    def test_resolveQueueRequestByLocalConfig_zero_cookieValidityMinute(self):
        queue_config = QueueEventConfig()
        queue_config.cookieDomain = "cookieDomain"
        queue_config.layoutName = "layoutName"
        queue_config.culture = "culture"
        queue_config.eventId = "eventId"
        queue_config.queueDomain = "queueDomain"
        queue_config.extendCookieValidity = True
        queue_config.cookieValidityMinute = 0
        queue_config.version = 12

        error_thrown = False

        try:
            KnownUser.resolveQueueRequestByLocalConfig(
                "targeturl", "queueIttoken", queue_config, "customerId",
                "secretKey", HttpContextProviderMock())
        except KnownUserError as err:
            error_thrown = err.message.startswith(
                "queueConfig.cookieValidityMinute should be integer greater than 0"
            )

        assert error_thrown

    def test_resolveQueueRequestByLocalConfig_setDebugCookie(self):
        user_in_queue_service = UserInQueueServiceMock()
        KnownUser.userInQueueService = user_in_queue_service

        queue_config = QueueEventConfig()
        queue_config.cookieDomain = "cookieDomain"
        queue_config.layoutName = "layoutName"
        queue_config.culture = "culture"
        queue_config.eventId = "eventId"
        queue_config.queueDomain = "queueDomain"
        queue_config.isCookieHttpOnly = False
        queue_config.isCookieSecure = False
        queue_config.extendCookieValidity = True
        queue_config.cookieValidityMinute = 10
        queue_config.version = 12
        queue_config.actionName = "queueAction"

        hcp_mock = HttpContextProviderMock()
        hcp_mock.originalRequestUrl = "http://localhost/original_url"
        hcp_mock.remote_ip = "userIP"
        hcp_mock.headers = {
            "via": "v",
            "forwarded": "f",
            "x-forwarded-for": "xff",
            "x-forwarded-host": "xfh",
            "x-forwarded-proto": "xfp"
        }

        secret_key = "secretKey"
        queueit_token = QueueITTokenGenerator.generateDebugToken(
            "eventId", secret_key)

        expected_server_time = QueueitHelpers.getCurrentTimeAsIso8601Str()
        KnownUser.resolveQueueRequestByLocalConfig("url", queueit_token,
                                                   queue_config, "customerId",
                                                   secret_key, hcp_mock)

        expected_cookie_value = "RequestHttpHeader_Via=v" + \
                                "|SdkVersion=" + user_in_queue_service.SDK_VERSION + \
                                "|Connector=mock-connector" + \
                                "|Runtime=" + sys.version + \
                                "|QueueitToken=" + queueit_token + \
                                "|OriginalUrl=http://localhost/original_url" + \
                                "|QueueConfig=EventId:eventId&Version:12&QueueDomain:queueDomain&CookieDomain:cookieDomain&IsCookieHttpOnly:false&IsCookieSecure:false&ExtendCookieValidity:true&CookieValidityMinute:10&LayoutName:layoutName&Culture:culture&ActionName:" + queue_config.actionName + \
                                "|RequestIP=userIP" + \
                                "|RequestHttpHeader_Forwarded=f" + \
                                "|RequestHttpHeader_XForwardedFor=xff" + \
                                "|TargetUrl=url" + \
                                "|RequestHttpHeader_XForwardedHost=xfh" + \
                                "|ServerUtcTime=" + expected_server_time + \
                                "|RequestHttpHeader_XForwardedProto=xfp"

        assert (len(hcp_mock.setCookies) == 1)
        assert (KnownUser.QUEUEIT_DEBUG_KEY in hcp_mock.setCookies)
        actual_cookie_value = hcp_mock.setCookies[KnownUser.QUEUEIT_DEBUG_KEY]["value"]
        for val in actual_cookie_value.split('|'):
            assert (val in expected_cookie_value)

    def test_ResolveQueueRequestByLocalConfig_debug_nullconfig(self):
        user_in_queue_service = UserInQueueServiceMock()
        KnownUser.userInQueueService = user_in_queue_service

        hcp_mock = HttpContextProviderMock()
        hcp_mock.originalRequestUrl = "http://localhost/original_url"
        hcp_mock.remote_ip = "userIP"
        hcp_mock.headers = {
            "via": "v",
            "forwarded": "f",
            "x-forwarded-for": "xff",
            "x-forwarded-host": "xfh",
            "x-forwarded-proto": "xfp"
        }
        secret_key = "secret_key"
        queueit_token = QueueITTokenGenerator.generateDebugToken("eventId", secret_key)
        expected_server_time = QueueitHelpers.getCurrentTimeAsIso8601Str()
        try:
            result = KnownUser.resolveQueueRequestByLocalConfig("url", queueit_token, None, "id", secret_key, hcp_mock)
        except KnownUserError as err:
            error_thrown = err.message.startswith("queueConfig can not be none.")
            assert error_thrown

        expected_cookie_value = "RequestHttpHeader_Via=v" + \
                                "|SdkVersion=" + user_in_queue_service.SDK_VERSION + \
                                "|Connector=mock-connector" + \
                                "|Runtime=" + sys.version + \
                                "|QueueitToken=" + queueit_token + \
                                "|OriginalUrl=http://localhost/original_url" + \
                                "|QueueConfig=NULL" + \
                                "|RequestIP=userIP" + \
                                "|RequestHttpHeader_Forwarded=f" + \
                                "|RequestHttpHeader_XForwardedFor=xff" + \
                                "|TargetUrl=url" + \
                                "|RequestHttpHeader_XForwardedHost=xfh" + \
                                "|ServerUtcTime=" + expected_server_time + \
                                "|RequestHttpHeader_XForwardedProto=xfp" + \
                                "|Exception=queueConfig can not be none."

        assert (len(hcp_mock.setCookies) == 1)
        assert (KnownUser.QUEUEIT_DEBUG_KEY in hcp_mock.setCookies)
        actual_cookie_value = hcp_mock.setCookies[KnownUser.QUEUEIT_DEBUG_KEY]["value"]
        for val in actual_cookie_value.split('|'):
            assert (val in expected_cookie_value)

    def test_ResolveQueueRequestByLocalConfig_debug_missing_customerid(self):
        hcpMock = HttpContextProviderMock()
        hcpMock.originalRequestUrl = "http://localhost/original_url"
        queueitToken = QueueITTokenGenerator.generateDebugToken("eventId", "secretkey")
        queueConfig = QueueEventConfig()
        result = KnownUser.resolveQueueRequestByLocalConfig("url", queueitToken, queueConfig, None, "secretkey",
                                                            hcpMock)
        assert (result.redirectUrl == "https://api2.queue-it.net/diagnostics/connector/error/?code=setup")
        assert (len(hcpMock.setCookies) == 0)

    def test_ResolveQueueRequestByLocalConfig_debug_missing_secretkey(self):
        hcp_mock = HttpContextProviderMock()
        hcp_mock.originalRequestUrl = "http://localhost/original_url"
        queueit_token = QueueITTokenGenerator.generateDebugToken("eventId", "secretkey")
        queue_config = QueueEventConfig()
        result = KnownUser.resolveQueueRequestByLocalConfig("url", queueit_token, queue_config, "customerid", None,
                                                            hcp_mock)
        assert (result.redirectUrl == "https://api2.queue-it.net/diagnostics/connector/error/?code=setup")
        assert (len(hcp_mock.setCookies) == 0)

    def test_ResolveQueueRequestByLocalConfig_debug_expiredtoken(self):
        hcp_mock = HttpContextProviderMock()
        hcp_mock.originalRequestUrl = "http://localhost/original_url"
        queueit_token = QueueITTokenGenerator.generateDebugToken("eventId", "secretkey", True)
        queue_config = QueueEventConfig()
        result = KnownUser.resolveQueueRequestByLocalConfig("url", queueit_token, queue_config, "customerid",
                                                            "secretkey", hcp_mock)
        assert (
                result.redirectUrl == "https://customerid.api2.queue-it.net/customerid/diagnostics/connector/error/?code=timestamp")
        assert (len(hcp_mock.setCookies) == 0)

    def test_ResolveQueueRequestByLocalConfig_debug_modifiedtoken(self):
        hcp_mock = HttpContextProviderMock()
        hcp_mock.originalRequestUrl = "http://localhost/original_url"
        queueit_token = QueueITTokenGenerator.generateDebugToken("eventId", "secretkey") + "invalid-hash"
        queue_config = QueueEventConfig()
        result = KnownUser.resolveQueueRequestByLocalConfig("url", queueit_token, queue_config, "customerid",
                                                            "secretkey", hcp_mock)
        assert (
                result.redirectUrl == "https://customerid.api2.queue-it.net/customerid/diagnostics/connector/error/?code=hash")
        assert (len(hcp_mock.setCookies) == 0)

    def test_resolveQueueRequestByLocalConfig(self):
        user_in_queue_service = UserInQueueServiceMock()
        KnownUser.userInQueueService = user_in_queue_service

        queue_config = QueueEventConfig()
        queue_config.cookieDomain = "cookieDomain"
        queue_config.layoutName = "layoutName"
        queue_config.culture = "culture"
        queue_config.eventId = "eventId"
        queue_config.queueDomain = "queueDomain"
        queue_config.extendCookieValidity = True
        queue_config.cookieValidityMinute = 10
        queue_config.version = 12
        queue_config.actionName = "queueAction"

        result = KnownUser.resolveQueueRequestByLocalConfig(
            "target", "token", queue_config, "id", "key",
            HttpContextProviderMock())

        assert (user_in_queue_service.validateQueueRequestCalls[0]["targetUrl"] ==
                "target")
        assert (user_in_queue_service.validateQueueRequestCalls[0]["queueitToken"]
                == "token")
        assert (user_in_queue_service.validateQueueRequestCalls[0]["config"] ==
                queue_config)
        assert (user_in_queue_service.validateQueueRequestCalls[0]["customerId"]
                == "id")
        assert (user_in_queue_service.validateQueueRequestCalls[0]["secretKey"] ==
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
        error_thrown = False

        try:
            KnownUser.validateRequestByIntegrationConfig(
                "", "queueIttoken", "{}", "customerId", "secretKey",
                HttpContextProviderMock())
        except KnownUserError as err:
            error_thrown = err.message.startswith(
                "currentUrlWithoutQueueITToken can not be none or empty")

        assert error_thrown

    def test_validateRequestByIntegrationConfig_empty_integrationsConfigString(
            self):
        error_thrown = False

        try:
            KnownUser.validateRequestByIntegrationConfig(
                "currentUrlWithoutQueueITToken", "queueIttoken", "{}",
                "customerId", "secretKey", HttpContextProviderMock())
        except KnownUserError as err:
            error_thrown = err.message.startswith(
                "integrationsConfigString can not be none or empty")

        assert error_thrown

    def test_validateRequestByIntegrationConfig_invalid_integrationsConfigString(
            self):
        error_thrown = False

        try:
            KnownUser.validateRequestByIntegrationConfig(
                "currentUrlWithoutQueueITToken", "queueIttoken",
                "{}", "customerId", "secretKey",
                HttpContextProviderMock())
        except KnownUserError as err:
            error_thrown = err.message.startswith("integrationsConfigString can not be none or empty.")

        assert error_thrown

    def test_validateRequestByIntegrationConfig(self):
        user_in_queue_service = UserInQueueServiceMock()
        KnownUser.userInQueueService = user_in_queue_service

        integration_config = {
            "Description": "test",
            "Integrations": [{
                "Name": "event1action",
                "ActionType": "Queue",
                "EventId": "event1",
                "CookieDomain": ".test.com",
                "IsCookieHttpOnly": False,
                "IsCookieSecure": False,
                "LayoutName": "Christmas Layout by Queue-it",
                "Culture": "",
                "ExtendCookieValidity": True,
                "CookieValidityMinute": 20,
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
                    "LogicalOperator": "And"
                }],
                "QueueDomain": "knownusertest.queue-it.net",
                "RedirectLogic": "AllowTParameter"
            }],
            "CustomerId": "knownusertest",
            "AccountId": "knownusertest",
            "Version": 3,
            "PublishDate": "2017-05-15T21:39:12.0076806Z",
            "ConfigDataVersion": "1.0.0.1"
        }
        hcp_mock = HttpContextProviderMock()
        hcp_mock.headers = {"user-agent": "googlebot"}
        integration_config_json = json.dumps(integration_config)
        result = KnownUser.validateRequestByIntegrationConfig(
            "http://test.com?event1=true", "token", integration_config_json,
            "id", "key", hcp_mock)

        assert (user_in_queue_service.validateQueueRequestCalls[0]["targetUrl"] ==
                "http://test.com?event1=true")
        assert (user_in_queue_service.validateQueueRequestCalls[0]["queueitToken"]
                == "token")
        assert (user_in_queue_service.validateQueueRequestCalls[0]["customerId"]
                == "id")
        assert (user_in_queue_service.validateQueueRequestCalls[0]["secretKey"] ==
                "key")

        assert (user_in_queue_service.validateQueueRequestCalls[0]["config"]
                .queueDomain == "knownusertest.queue-it.net")
        assert (user_in_queue_service.validateQueueRequestCalls[0]["config"]
                .eventId == "event1")
        assert (user_in_queue_service.validateQueueRequestCalls[0]["config"]
                .culture == "")
        assert (user_in_queue_service.validateQueueRequestCalls[0]["config"]
                .layoutName == "Christmas Layout by Queue-it")
        assert (user_in_queue_service.validateQueueRequestCalls[0]["config"]
                .extendCookieValidity)
        assert (user_in_queue_service.validateQueueRequestCalls[0]["config"]
                .cookieValidityMinute == 20)
        assert (user_in_queue_service.validateQueueRequestCalls[0]["config"]
                .cookieDomain == ".test.com")
        assert (user_in_queue_service.validateQueueRequestCalls[0]["config"]
                .version == 3)
        assert (not result.isAjaxResult)
        assert (user_in_queue_service.validateQueueRequestCalls[0]["config"]
                .actionName == 'event1action')

    def test_validateRequestByIntegrationConfig_AjaxCall(self):
        user_in_queue_service = UserInQueueServiceMock()
        KnownUser.userInQueueService = user_in_queue_service

        integration_config = {
            "Description": "test",
            "Integrations": [{
                "Name": "event1action",
                "ActionType": "Queue",
                "EventId": "event1",
                "CookieDomain": ".test.com",
                "IsCookieHttpOnly": False,
                "IsCookieSecure": False,
                "LayoutName": "Christmas Layout by Queue-it",
                "Culture": "",
                "ExtendCookieValidity": True,
                "CookieValidityMinute": 20,
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
                    "LogicalOperator": "And"
                }],
                "QueueDomain": "knownusertest.queue-it.net",
                "RedirectLogic": "AllowTParameter"
            }],
            "CustomerId": "knownusertest",
            "AccountId": "knownusertest",
            "Version": 3,
            "PublishDate": "2017-05-15T21:39:12.0076806Z",
            "ConfigDataVersion": "1.0.0.1"
        }
        hcp_mock = HttpContextProviderMock()
        hcp_mock.headers = {
            "user-agent": "googlebot",
            "x-queueit-ajaxpageurl": "http%3a%2f%2furl"
        }
        integration_config_json = json.dumps(integration_config)

        user_in_queue_service.validateQueueRequestResultObj = RequestValidationResult(
            ActionTypes.QUEUE, "eventId", None, "http://q.qeuue-it.com", None, "event1action")

        result = KnownUser.validateRequestByIntegrationConfig(
            "http://test.com?event1=true", "token", integration_config_json,
            "id", "key", hcp_mock)

        assert (user_in_queue_service.validateQueueRequestCalls[0]["targetUrl"] ==
                "http://url")
        assert (user_in_queue_service.validateQueueRequestCalls[0]["queueitToken"]
                == "token")
        assert (user_in_queue_service.validateQueueRequestCalls[0]["customerId"]
                == "id")
        assert (user_in_queue_service.validateQueueRequestCalls[0]["secretKey"] ==
                "key")

        assert (user_in_queue_service.validateQueueRequestCalls[0]["config"]
                .queueDomain == "knownusertest.queue-it.net")
        assert (user_in_queue_service.validateQueueRequestCalls[0]["config"]
                .eventId == "event1")
        assert (user_in_queue_service.validateQueueRequestCalls[0]["config"]
                .culture == "")
        assert (user_in_queue_service.validateQueueRequestCalls[0]["config"]
                .layoutName == "Christmas Layout by Queue-it")
        assert (user_in_queue_service.validateQueueRequestCalls[0]["config"]
                .extendCookieValidity)
        assert (user_in_queue_service.validateQueueRequestCalls[0]["config"]
                .cookieValidityMinute == 20)
        assert (user_in_queue_service.validateQueueRequestCalls[0]["config"]
                .cookieDomain == ".test.com")
        assert (user_in_queue_service.validateQueueRequestCalls[0]["config"]
                .version == 3)
        assert (result.isAjaxResult)
        assert (result.getAjaxRedirectUrl().lower() ==
                "http%3a%2f%2fq.qeuue-it.com")
        assert (user_in_queue_service.validateQueueRequestCalls[0]["config"]
                .actionName == integration_config['Integrations'][0]['Name'])

    def test_validateRequestByIntegrationConfig_setDebugCookie(self):
        user_in_queue_service = UserInQueueServiceMock()
        KnownUser.userInQueueService = user_in_queue_service

        integration_config = {
            "Description": "test",
            "Integrations": [{
                "Name": "event1action",
                "ActionType": "Queue",
                "EventId": "event1",
                "CookieDomain": ".test.com",
                "IsCookieHttpOnly": False,
                "IsCookieSecure": False,
                "LayoutName": "Christmas Layout by Queue-it",
                "Culture": "da-DK",
                "ExtendCookieValidity": True,
                "CookieValidityMinute": 20,
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
                    "LogicalOperator": "And"
                }],
                "QueueDomain": "knownusertest.queue-it.net",
                "RedirectLogic": "AllowTParameter"
            }],
            "CustomerId": "knownusertest",
            "AccountId": "knownusertest",
            "Version": 3,
            "PublishDate": "2017-05-15T21:39:12.0076806Z",
            "ConfigDataVersion": "1.0.0.1"
        }

        hcp_mock = HttpContextProviderMock()
        hcp_mock.originalRequestUrl = "http://localhost/original_url"
        hcp_mock.remote_ip = "userIP"
        hcp_mock.headers = {
            "user-agent": "googlebot",
            "via": "v",
            "forwarded": "f",
            "x-forwarded-for": "xff",
            "x-forwarded-host": "xfh",
            "x-forwarded-proto": "xfp"
        }
        integration_config_json = json.dumps(integration_config)

        secret_key = "secretKey"
        queueit_token = QueueITTokenGenerator.generateDebugToken(            "eventId", secret_key)

        expected_server_time = QueueitHelpers.getCurrentTimeAsIso8601Str(        )
        KnownUser.validateRequestByIntegrationConfig(
            "http://test.com?event1=true", queueit_token, integration_config_json,
            "customerId", secret_key, hcp_mock)

        expected_cookie_value = "RequestHttpHeader_Via=v" + \
                              "|SdkVersion=" + user_in_queue_service.SDK_VERSION + \
                              "|Connector=mock-connector" + \
                              "|Runtime=" + sys.version + \
                              "|QueueitToken=" + queueit_token + \
                              "|OriginalUrl=http://localhost/original_url" + \
                              "|QueueConfig=EventId:event1&Version:3&QueueDomain:knownusertest.queue-it.net&CookieDomain:.test.com&IsCookieHttpOnly:false&IsCookieSecure:false&ExtendCookieValidity:true&CookieValidityMinute:20&LayoutName:Christmas Layout by Queue-it&Culture:da-DK&ActionName:" + \
                              integration_config['Integrations'][0]['Name'] + \
                              "|RequestIP=userIP" + \
                              "|ServerUtcTime=" + expected_server_time + \
                              "|MatchedConfig=event1action" + \
                              "|RequestHttpHeader_XForwardedFor=xff" + \
                              "|RequestHttpHeader_Forwarded=f" + \
                              "|TargetUrl=http://test.com?event1=true" + \
                              "|RequestHttpHeader_XForwardedHost=xfh" + \
                              "|PureUrl=http://test.com?event1=true" + \
                              "|ConfigVersion=3" + \
                              "|RequestHttpHeader_XForwardedProto=xfp"

        assert (len(hcp_mock.setCookies) == 1)
        assert (KnownUser.QUEUEIT_DEBUG_KEY in hcp_mock.setCookies)

        actual_cookie_value = hcp_mock.setCookies[KnownUser.QUEUEIT_DEBUG_KEY][
            "value"]
        for val in actual_cookie_value.split('|'):
            assert (val in expected_cookie_value)

    def test_validateRequestByIntegrationConfig_NotMatch(self):
        user_in_queue_service = UserInQueueServiceMock()
        KnownUser.userInQueueService = user_in_queue_service

        integration_config = {
            "Description": "test",
            "Integrations": [],
            "CustomerId": "knownusertest",
            "AccountId": "knownusertest",
            "Version": 3,
            "PublishDate": "2017-05-15T21:39:12.0076806Z",
            "ConfigDataVersion": "1.0.0.1"
        }

        integration_config_json = json.dumps(integration_config)
        result = KnownUser.validateRequestByIntegrationConfig(
            "http://test.com?event1=true", "queueIttoken",
            integration_config_json, "customerid", "secretkey",
            HttpContextProviderMock())

        assert (len(user_in_queue_service.validateQueueRequestCalls) == 0)
        assert (not result.doRedirect())

    def test_validateRequestByIntegrationConfig_setDebugCookie_NotMatch(self):
        user_in_queue_service = UserInQueueServiceMock()
        KnownUser.userInQueueService = user_in_queue_service

        hcp_mock = HttpContextProviderMock()
        hcp_mock.originalRequestUrl = "http://localhost/original_url"
        hcp_mock.remote_ip = "userIP"
        hcp_mock.headers = {
            "via": "v",
            "forwarded": "f",
            "x-forwarded-for": "xff",
            "x-forwarded-host": "xfh",
            "x-forwarded-proto": "xfp"
        }

        integration_config = {
            "Description": "test",
            "Integrations": [],
            "CustomerId": "knownusertest",
            "AccountId": "knownusertest",
            "Version": 3,
            "PublishDate": "2017-05-15T21:39:12.0076806Z",
            "ConfigDataVersion": "1.0.0.1"
        }

        secret_key = "secretKey"
        queueit_token = QueueITTokenGenerator.generateDebugToken(
            "eventId", secret_key)

        integration_config_json = json.dumps(integration_config)
        expected_server_time = QueueitHelpers.getCurrentTimeAsIso8601Str(        )
        KnownUser.validateRequestByIntegrationConfig(
            "http://test.com?event1=true", queueit_token, integration_config_json,
            "customerId", secret_key, hcp_mock)

        expected_cookie_value = "RequestHttpHeader_Via=v" + \
                              "|SdkVersion=" + user_in_queue_service.SDK_VERSION + \
                              "|Connector=mock-connector" + \
                              "|Runtime=" + sys.version + \
                              "|QueueitToken=" + queueit_token + \
                              "|OriginalUrl=http://localhost/original_url" + \
                              "|RequestIP=userIP" + \
                              "|ServerUtcTime=" + expected_server_time + \
                              "|MatchedConfig=NULL" + \
                              "|RequestHttpHeader_XForwardedFor=xff" + \
                              "|RequestHttpHeader_Forwarded=f" + \
                              "|RequestHttpHeader_XForwardedHost=xfh" + \
                              "|PureUrl=http://test.com?event1=true" + \
                              "|ConfigVersion=3" + \
                              "|RequestHttpHeader_XForwardedProto=xfp"

        assert (len(hcp_mock.setCookies) == 1)
        assert (KnownUser.QUEUEIT_DEBUG_KEY in hcp_mock.setCookies)
        actual_cookie_value = hcp_mock.setCookies[KnownUser.QUEUEIT_DEBUG_KEY]["value"]
        for val in actual_cookie_value.split('|'):
            assert (val in expected_cookie_value)

    def test_validateRequestByIntegrationConfig_debug_invalid_config_json(self):
        user_in_queue_service = UserInQueueServiceMock()
        KnownUser.userInQueueService = user_in_queue_service

        hcp_mock = HttpContextProviderMock()
        hcp_mock.originalRequestUrl = "http://localhost/original_url"
        hcp_mock.remote_ip = "userIP"
        hcp_mock.headers = {
            "via": "v",
            "forwarded": "f",
            "x-forwarded-for": "xff",
            "x-forwarded-host": "xfh",
            "x-forwarded-proto": "xfp"
        }

        integration_config_json = "{}"
        secret_key = "secretKey"
        queueit_token = QueueITTokenGenerator.generateDebugToken("eventId", secret_key)

        expected_server_time = QueueitHelpers.getCurrentTimeAsIso8601Str()
        try:
            KnownUser.validateRequestByIntegrationConfig("http://test.com?event1=true", queueit_token,
                                                         integration_config_json, "customerId", secret_key, hcp_mock)
        except KnownUserError as err:
            error_thrown = err.message.startswith("integrationsConfigString can not be none or empty.")
            assert error_thrown

        expected_cookie_value = "RequestHttpHeader_Via=v" + \
                                "|SdkVersion=" + user_in_queue_service.SDK_VERSION + \
                                "|Connector=mock-connector" + \
                                "|Runtime=" + sys.version + \
                                "|QueueitToken=" + queueit_token + \
                                "|OriginalUrl=http://localhost/original_url" + \
                                "|RequestIP=userIP" + \
                                "|ServerUtcTime=" + expected_server_time + \
                                "|MatchedConfig=NULL" + \
                                "|RequestHttpHeader_XForwardedFor=xff" + \
                                "|RequestHttpHeader_Forwarded=f" + \
                                "|RequestHttpHeader_XForwardedHost=xfh" + \
                                "|PureUrl=http://test.com?event1=true" + \
                                "|ConfigVersion=NULL" + \
                                "|RequestHttpHeader_XForwardedProto=xfp" + \
                                "|Exception=integrationsConfigString can not be none or empty."

        assert (len(hcp_mock.setCookies) == 1)
        assert (KnownUser.QUEUEIT_DEBUG_KEY in hcp_mock.setCookies)
        actualCookieValue = hcp_mock.setCookies[KnownUser.QUEUEIT_DEBUG_KEY]["value"]
        for val in actualCookieValue.split('|'):
            assert (val in expected_cookie_value)

    def test_validateRequestByIntegrationConfig_debug_missing_customerId(self):
        integration_config_string = "[[{}]]"

        hcp_mock = HttpContextProviderMock()
        hcp_mock.originalRequestUrl = "http://localhost/original_url"
        queueit_token = QueueITTokenGenerator.generateDebugToken("eventId", "secretkey")

        result = KnownUser.validateRequestByIntegrationConfig("http://test.com?event1=true", queueit_token,
                                                              integration_config_string, None, "secretkey", hcp_mock)

        assert (result.redirectUrl == "https://api2.queue-it.net/diagnostics/connector/error/?code=setup")
        assert (len(hcp_mock.setCookies) == 0)

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
        integration_config_string = "[[{}]]"

        hcp_mock = HttpContextProviderMock()
        hcp_mock.originalRequestUrl = "http://localhost/original_url"
        queueit_token = QueueITTokenGenerator.generateDebugToken("eventId", "secretkey", True)

        result = KnownUser.validateRequestByIntegrationConfig("http://test.com?event1=true", queueit_token,
                                                              integration_config_string, "customerid", "secretkey",
                                                              hcp_mock)

        assert (
                result.redirectUrl == "https://customerid.api2.queue-it.net/customerid/diagnostics/connector/error/?code=timestamp")
        assert (len(hcp_mock.setCookies) == 0)

    def test_validateRequestByIntegrationConfig_debug_modifiedtoken(self):
        integration_config_string = "[[{}]]"

        hcp_mock = HttpContextProviderMock()
        hcp_mock.originalRequestUrl = "http://localhost/original_url"
        invalid_debug_token = QueueITTokenGenerator.generateDebugToken("eventId", "secretkey") + "invalid-hash"

        result = KnownUser.validateRequestByIntegrationConfig("http://test.com?event1=true", invalid_debug_token,
                                                              integration_config_string, "customerid", "secretkey",
                                                              hcp_mock)

        assert (
                result.redirectUrl == "https://customerid.api2.queue-it.net/customerid/diagnostics/connector/error/?code=hash")
        assert (len(hcp_mock.setCookies) == 0)

    def test_validateRequestByIntegrationConfig_ForcedTargetUrl(self):
        user_in_queue_service = UserInQueueServiceMock()
        KnownUser.userInQueueService = user_in_queue_service

        integration_config = {
            "Description": "test",
            "Integrations": [{
                "Name": "event1action",
                "ActionType": "Queue",
                "EventId": "event1",
                "CookieDomain": ".test.com",
                "IsCookieHttpOnly": False,
                "IsCookieSecure": False,
                "LayoutName": "Christmas Layout by Queue-it",
                "Culture": "",
                "ExtendCookieValidity": True,
                "CookieValidityMinute": 20,
                "Triggers": [{
                    "TriggerParts": [{
                        "Operator": "Contains",
                        "ValueToCompare": "event1",
                        "UrlPart": "PageUrl",
                        "ValidatorType": "UrlValidator",
                        "IsNegative": False,
                        "IsIgnoreCase": True
                    }],
                    "LogicalOperator": "And"
                }],
                "QueueDomain": "knownusertest.queue-it.net",
                "RedirectLogic": "ForcedTargetUrl",
                "ForcedTargetUrl": "http://test.com"
            }],
            "CustomerId": "knownusertest",
            "AccountId": "knownusertest",
            "Version": 3,
            "PublishDate": "2017-05-15T21:39:12.0076806Z",
            "ConfigDataVersion": "1.0.0.1"
        }

        integration_config_json = json.dumps(integration_config)
        result = KnownUser.validateRequestByIntegrationConfig(
            "http://test.com?event1=true", "queueIttoken",
            integration_config_json, "customerid", "secretkey",
            HttpContextProviderMock())

        assert (user_in_queue_service.validateQueueRequestCalls[0]['targetUrl'] ==
                "http://test.com")
        assert (not result.isAjaxResult)

    def test_validateRequestByIntegrationConfig_ForcedTargetUrl_AjaxCall(self):
        user_in_queue_service = UserInQueueServiceMock()
        KnownUser.userInQueueService = user_in_queue_service

        integration_config = {
            "Description": "test",
            "Integrations": [{
                "Name": "event1action",
                "ActionType": "Queue",
                "EventId": "event1",
                "CookieDomain": ".test.com",
                "IsCookieHttpOnly": False,
                "IsCookieSecure": False,
                "LayoutName": "Christmas Layout by Queue-it",
                "Culture": "",
                "ExtendCookieValidity": True,
                "CookieValidityMinute": 20,
                "Triggers": [{
                    "TriggerParts": [{
                        "Operator": "Contains",
                        "ValueToCompare": "event1",
                        "UrlPart": "PageUrl",
                        "ValidatorType": "UrlValidator",
                        "IsNegative": False,
                        "IsIgnoreCase": True
                    }],
                    "LogicalOperator": "And"
                }],
                "QueueDomain": "knownusertest.queue-it.net",
                "RedirectLogic": "ForcedTargetUrl",
                "ForcedTargetUrl": "http://test.com"
            }],
            "CustomerId": "knownusertest",
            "AccountId": "knownusertest",
            "Version": 3,
            "PublishDate": "2017-05-15T21:39:12.0076806Z",
            "ConfigDataVersion": "1.0.0.1"
        }

        hcp_mock = HttpContextProviderMock()
        hcp_mock.headers = {"x-queueit-ajaxpageurl": "http%3a%2f%2furl"}
        user_in_queue_service.validateQueueRequestResultObj = RequestValidationResult(
            ActionTypes.QUEUE, "eventId", None, "http://q.qeuue-it.com", None, "event1action")

        integration_config_json = json.dumps(integration_config)
        result = KnownUser.validateRequestByIntegrationConfig(
            "http://test.com?event1=true", "queueIttoken",
            integration_config_json, "customerid", "secretkey", hcp_mock)

        assert (user_in_queue_service.validateQueueRequestCalls[0]['targetUrl'] ==
                "http://test.com")
        assert (result.isAjaxResult)
        assert (result.getAjaxRedirectUrl().lower() ==
                "http%3a%2f%2fq.qeuue-it.com")

    def test_validateRequestByIntegrationConfig_EventTargetUrl(self):
        user_in_queue_service = UserInQueueServiceMock()
        KnownUser.userInQueueService = user_in_queue_service

        integration_config = {
            "Description": "test",
            "Integrations": [{
                "Name": "event1action",
                "ActionType": "Queue",
                "EventId": "event1",
                "CookieDomain": ".test.com",
                "IsCookieHttpOnly": False,
                "IsCookieSecure": False,
                "LayoutName": "Christmas Layout by Queue-it",
                "Culture": "",
                "ExtendCookieValidity": True,
                "CookieValidityMinute": 20,
                "Triggers": [{
                    "TriggerParts": [{
                        "Operator": "Contains",
                        "ValueToCompare": "event1",
                        "UrlPart": "PageUrl",
                        "ValidatorType": "UrlValidator",
                        "IsNegative": False,
                        "IsIgnoreCase": True
                    }],
                    "LogicalOperator": "And"
                }],
                "QueueDomain": "knownusertest.queue-it.net",
                "RedirectLogic": "EventTargetUrl"
            }],
            "CustomerId": "knownusertest",
            "AccountId": "knownusertest",
            "Version": 3,
            "PublishDate": "2017-05-15T21:39:12.0076806Z",
            "ConfigDataVersion": "1.0.0.1"
        }

        integration_config_json = json.dumps(integration_config)
        result = KnownUser.validateRequestByIntegrationConfig(
            "http://test.com?event1=true", "queueIttoken",
            integration_config_json, "customerid", "secretkey",
            HttpContextProviderMock())

        assert (
                user_in_queue_service.validateQueueRequestCalls[0]['targetUrl'] == "")
        assert (not result.isAjaxResult)
        assert (user_in_queue_service.validateQueueRequestCalls[0]["config"]
                .actionName == integration_config['Integrations'][0]['Name'])

    def test_validateRequestByIntegrationConfig_EventTargetUrl_AjaxCall(self):
        user_in_queue_service = UserInQueueServiceMock()
        KnownUser.userInQueueService = user_in_queue_service

        integration_config = {
            "Description": "test",
            "Integrations": [{
                "Name": "event1action",
                "ActionType": "Queue",
                "EventId": "event1",
                "CookieDomain": ".test.com",
                "IsCookieHttpOnly": False,
                "IsCookieSecure": False,
                "LayoutName": "Christmas Layout by Queue-it",
                "Culture": "",
                "ExtendCookieValidity": True,
                "CookieValidityMinute": 20,
                "Triggers": [{
                    "TriggerParts": [{
                        "Operator": "Contains",
                        "ValueToCompare": "event1",
                        "UrlPart": "PageUrl",
                        "ValidatorType": "UrlValidator",
                        "IsNegative": False,
                        "IsIgnoreCase": True
                    }],
                    "LogicalOperator": "And"
                }],
                "QueueDomain": "knownusertest.queue-it.net",
                "RedirectLogic": "EventTargetUrl"
            }],
            "CustomerId": "knownusertest",
            "AccountId": "knownusertest",
            "Version": 3,
            "PublishDate": "2017-05-15T21:39:12.0076806Z",
            "ConfigDataVersion": "1.0.0.1"
        }

        hcp_mock = HttpContextProviderMock()
        hcp_mock.headers = {"x-queueit-ajaxpageurl": "http%3a%2f%2furl"}
        user_in_queue_service.validateQueueRequestResultObj = RequestValidationResult(
            ActionTypes.QUEUE, "eventId", None, "http://q.qeuue-it.com", None, "event1action")

        integration_config_json = json.dumps(integration_config)
        result = KnownUser.validateRequestByIntegrationConfig(
            "http://test.com?event1=true", "queueIttoken",
            integration_config_json, "customerid", "secretkey", hcp_mock)

        assert (
                user_in_queue_service.validateQueueRequestCalls[0]['targetUrl'] == "")
        assert (result.isAjaxResult)
        assert (result.getAjaxRedirectUrl().lower() ==
                "http%3a%2f%2fq.qeuue-it.com")
        assert (user_in_queue_service.validateQueueRequestCalls[0]["config"]
                .actionName == integration_config['Integrations'][0]['Name'])

    def test_validateRequestByIntegrationConfig_CancelAction(self):
        user_in_queue_service = UserInQueueServiceMock()
        KnownUser.userInQueueService = user_in_queue_service

        integration_config = {
            "Description": "test",
            "Integrations": [{
                "Name": "event1action",
                "ActionType": "Cancel",
                "EventId": "event1",
                "CookieDomain": ".test.com",
                "IsCookieHttpOnly": False,
                "IsCookieSecure": False,
                "Triggers": [{
                    "TriggerParts": [{
                        "Operator": "Contains",
                        "ValueToCompare": "event1",
                        "UrlPart": "PageUrl",
                        "ValidatorType": "UrlValidator",
                        "IsNegative": False,
                        "IsIgnoreCase": True
                    }],
                    "LogicalOperator": "And"
                }],
                "QueueDomain": "knownusertest.queue-it.net",
            }],
            "CustomerId": "knownusertest",
            "AccountId": "knownusertest",
            "Version": 3,
            "PublishDate": "2017-05-15T21:39:12.0076806Z",
            "ConfigDataVersion": "1.0.0.1"
        }

        integration_config_json = json.dumps(integration_config)
        result = KnownUser.validateRequestByIntegrationConfig(
            "http://test.com?event1=true", "queueIttoken",
            integration_config_json, "customerid", "secretkey",
            HttpContextProviderMock())

        assert (user_in_queue_service.validateCancelRequestCalls[0]["targetUrl"]
                == "http://test.com?event1=true")
        assert (user_in_queue_service.validateCancelRequestCalls[0]["customerId"]
                == "customerid")
        assert (user_in_queue_service.validateCancelRequestCalls[0]["secretKey"]
                == "secretkey")

        assert (user_in_queue_service.validateCancelRequestCalls[0]["config"]
                .queueDomain == "knownusertest.queue-it.net")
        assert (user_in_queue_service.validateCancelRequestCalls[0]["config"]
                .eventId == "event1")
        assert (user_in_queue_service.validateCancelRequestCalls[0]["config"]
                .cookieDomain == ".test.com")
        assert (user_in_queue_service.validateCancelRequestCalls[0]["config"]
                .version == 3)
        assert (not result.isAjaxResult)
        assert (user_in_queue_service.validateCancelRequestCalls[0]["config"]
                .actionName == integration_config['Integrations'][0]['Name'])

    def test_validateRequestByIntegrationConfig_CancelAction_AjaxCall(self):
        user_in_queue_service = UserInQueueServiceMock()
        KnownUser.userInQueueService = user_in_queue_service

        integration_config = {
            "Description": "test",
            "Integrations": [{
                "Name": "event1action",
                "ActionType": "Cancel",
                "EventId": "event1",
                "CookieDomain": ".test.com",
                "IsCookieHttpOnly": False,
                "IsCookieSecure": False,
                "Triggers": [{
                    "TriggerParts": [{
                        "Operator": "Contains",
                        "ValueToCompare": "event1",
                        "UrlPart": "PageUrl",
                        "ValidatorType": "UrlValidator",
                        "IsNegative": False,
                        "IsIgnoreCase": True
                    }],
                    "LogicalOperator": "And"
                }],
                "QueueDomain": "knownusertest.queue-it.net",
            }],
            "CustomerId": "knownusertest",
            "AccountId": "knownusertest",
            "Version": 3,
            "PublishDate": "2017-05-15T21:39:12.0076806Z",
            "ConfigDataVersion": "1.0.0.1"
        }

        hcp_mock = HttpContextProviderMock()
        hcp_mock.headers = {"x-queueit-ajaxpageurl": "http%3a%2f%2furl"}
        user_in_queue_service.validateCancelRequestResultObj = RequestValidationResult(
            ActionTypes.CANCEL, "eventId", None, "http://q.qeuue-it.com", None, "event1action")

        integration_config_json = json.dumps(integration_config)
        result = KnownUser.validateRequestByIntegrationConfig(
            "http://test.com?event1=true", "queueIttoken",
            integration_config_json, "customerid", "secretkey", hcp_mock)

        assert (user_in_queue_service.validateCancelRequestCalls[0]["targetUrl"]
                == "http://url")
        assert (user_in_queue_service.validateCancelRequestCalls[0]["customerId"]
                == "customerid")
        assert (user_in_queue_service.validateCancelRequestCalls[0]["secretKey"]
                == "secretkey")

        assert (user_in_queue_service.validateCancelRequestCalls[0]["config"]
                .queueDomain == "knownusertest.queue-it.net")
        assert (user_in_queue_service.validateCancelRequestCalls[0]["config"]
                .eventId == "event1")
        assert (user_in_queue_service.validateCancelRequestCalls[0]["config"]
                .cookieDomain == ".test.com")
        assert (user_in_queue_service.validateCancelRequestCalls[0]["config"]
                .version == 3)
        assert (result.isAjaxResult)
        assert (result.getAjaxRedirectUrl().lower() ==
                "http%3a%2f%2fq.qeuue-it.com")
        assert (user_in_queue_service.validateCancelRequestCalls[0]["config"]
                .actionName == integration_config['Integrations'][0]['Name'])

    def test_validateRequestByIntegrationConfig_ignoreAction(self):
        user_in_queue_service = UserInQueueServiceMock()
        KnownUser.userInQueueService = user_in_queue_service

        integration_config = {
            "Description": "test",
            "Integrations": [{
                "Name": "event1action",
                "ActionType": "Ignore",
                "EventId": "event1",
                "CookieDomain": ".test.com",
                "IsCookieHttpOnly": False,
                "IsCookieSecure": False,
                "Triggers": [{
                    "TriggerParts": [{
                        "Operator": "Contains",
                        "ValueToCompare": "event1",
                        "UrlPart": "PageUrl",
                        "ValidatorType": "UrlValidator",
                        "IsNegative": False,
                        "IsIgnoreCase": True
                    }],
                    "LogicalOperator": "And"
                }],
                "QueueDomain": "knownusertest.queue-it.net",
            }],
            "CustomerId": "knownusertest",
            "AccountId": "knownusertest",
            "Version": 3,
            "PublishDate": "2017-05-15T21:39:12.0076806Z",
            "ConfigDataVersion": "1.0.0.1"
        }

        integration_config_json = json.dumps(integration_config)
        result = KnownUser.validateRequestByIntegrationConfig(
            "http://test.com?event1=true", "queueIttoken",
            integration_config_json, "customerid", "secretkey",
            HttpContextProviderMock())

        assert (len(user_in_queue_service.getIgnoreActionResultCalls) == 1)
        assert (not result.isAjaxResult)
        assert (user_in_queue_service.getIgnoreActionResultCalls[0]
                ["actionName"] == integration_config['Integrations'][0]['Name'])

    def test_validateRequestByIntegrationConfig_ignoreAction_AjaxCall(self):
        user_in_queue_service = UserInQueueServiceMock()
        KnownUser.userInQueueService = user_in_queue_service

        integration_config = {
            "Description": "test",
            "Integrations": [{
                "Name": "event1action",
                "ActionType": "Ignore",
                "EventId": "event1",
                "CookieDomain": ".test.com",
                "IsCookieHttpOnly": False,
                "IsCookieSecure": False,
                "Triggers": [{
                    "TriggerParts": [{
                        "Operator": "Contains",
                        "ValueToCompare": "event1",
                        "UrlPart": "PageUrl",
                        "ValidatorType": "UrlValidator",
                        "IsNegative": False,
                        "IsIgnoreCase": True
                    }],
                    "LogicalOperator": "And"
                }],
                "QueueDomain": "knownusertest.queue-it.net",
            }],
            "CustomerId": "knownusertest",
            "AccountId": "knownusertest",
            "Version": 3,
            "PublishDate": "2017-05-15T21:39:12.0076806Z",
            "ConfigDataVersion": "1.0.0.1"
        }

        hcp_mock = HttpContextProviderMock()
        hcp_mock.headers = {"x-queueit-ajaxpageurl": "http%3a%2f%2furl"}

        integration_config_json = json.dumps(integration_config)
        result = KnownUser.validateRequestByIntegrationConfig(
            "http://test.com?event1=true", "queueIttoken",
            integration_config_json, "customerid", "secretkey", hcp_mock)

        assert (len(user_in_queue_service.getIgnoreActionResultCalls) == 1)
        assert (result.isAjaxResult)
        assert (user_in_queue_service.getIgnoreActionResultCalls[0]
                ["actionName"] == integration_config['Integrations'][0]['Name'])

    def test_validateRequestByIntegrationConfig_defaultsTo_ignoreAction(self):
        user_in_queue_service = UserInQueueServiceMock()
        KnownUser.userInQueueService = user_in_queue_service

        integration_config = {
            "Description": "test",
            "Integrations": [{
                "Name": "event1action",
                "ActionType": "some-future-action-type",
                "EventId": "event1",
                "CookieDomain": ".test.com",
                "IsCookieHttpOnly": False,
                "IsCookieSecure": False,
                "Triggers": [{
                    "TriggerParts": [{
                        "Operator": "Contains",
                        "ValueToCompare": "event1",
                        "UrlPart": "PageUrl",
                        "ValidatorType": "UrlValidator",
                        "IsNegative": False,
                        "IsIgnoreCase": True
                    }],
                    "LogicalOperator": "And"
                }],
                "QueueDomain": "knownusertest.queue-it.net",
            }],
            "CustomerId": "knownusertest",
            "AccountId": "knownusertest",
            "Version": 3,
            "PublishDate": "2017-05-15T21:39:12.0076806Z",
            "ConfigDataVersion": "1.0.0.1"
        }

        hcp_mock = HttpContextProviderMock()
        integration_config_json = json.dumps(integration_config)
        result = KnownUser.validateRequestByIntegrationConfig(
            "http://test.com?event1=true", "queueIttoken",
            integration_config_json, "customerid", "secretkey", hcp_mock)

        assert (len(user_in_queue_service.getIgnoreActionResultCalls) == 1)
        assert (user_in_queue_service.getIgnoreActionResultCalls[0]["actionName"] ==
                integration_config['Integrations'][0][
                    'Name'])

    def test_cancelRequestByLocalConfig_Exception_NoDebugToken_NoDebugCookie(self):
        user_in_queue_service = UserInQueueServiceMock()
        KnownUser.userInQueueService = user_in_queue_service
        hcp_mock = HttpContextProviderMock()
        hcp_mock.originalRequestUrl = "http://localhost/original_url"
        hcp_mock.remote_ip = "userIP"
        hcp_mock.headers = {
            "via": "v",
            "forwarded": "f",
            "x-forwarded-for": "xff",
            "x-forwarded-host": "xfh",
            "x-forwarded-proto": "xfp"
        }
        cancel_config = CancelEventConfig()
        cancel_config.eventId = "eventId"
        cancel_config.queueDomain = "queueDomain"
        cancel_config.version = 1
        cancel_config.cookieDomain = "cookieDomain"
        cancel_config.actionName = "cancelAction"
        user_in_queue_service.validateCancelRequestRaiseException = True
        try:
            KnownUser.cancelRequestByLocalConfig("targetUrl", "token", cancel_config,
                                                 "customerId", "secretKey", HttpContextProviderMock())
        except Exception as e:
            assert (e.message == "Exception")

        assert (len(user_in_queue_service.validateCancelRequestCalls) > 0)
        assert (len(hcp_mock.setCookies) == 0)

    def test_resolveQueueRequestByLocalConfig_Exception_NoDebugToken_NoDebugCookie(self):
        user_in_queue_service = UserInQueueServiceMock()
        KnownUser.userInQueueService = user_in_queue_service
        hcp_mock = HttpContextProviderMock()
        hcp_mock.originalRequestUrl = "http://localhost/original_url"
        hcp_mock.remote_ip = "userIP"
        hcp_mock.headers = {
            "via": "v",
            "forwarded": "f",
            "x-forwarded-for": "xff",
            "x-forwarded-host": "xfh",
            "x-forwarded-proto": "xfp"
        }
        queue_config = QueueEventConfig()
        queue_config.cookieDomain = "cookieDomain"
        queue_config.layoutName = "layoutName"
        queue_config.culture = "culture"
        queue_config.eventId = "eventId"
        queue_config.queueDomain = "queueDomain"
        queue_config.extendCookieValidity = True
        queue_config.cookieValidityMinute = 10
        queue_config.version = 12
        queue_config.actionName = "queueAction"
        user_in_queue_service.validateQueueRequestRaiseException = True
        try:
            KnownUser.resolveQueueRequestByLocalConfig("target", "token", queue_config, "id", "key",
                                                       HttpContextProviderMock())
        except Exception as e:
            assert (e.message == "Exception")

        assert (len(user_in_queue_service.validateQueueRequestCalls) > 0)
        assert (len(hcp_mock.setCookies) == 0)

    def test_validateRequestByIntegrationConfig_CancelAction_Exception_NoDebugToken_NoDebugCookie(self):
        user_in_queue_service = UserInQueueServiceMock()
        KnownUser.userInQueueService = user_in_queue_service
        hcp_mock = HttpContextProviderMock()
        hcp_mock.originalRequestUrl = "http://localhost/original_url"
        hcp_mock.remote_ip = "userIP"
        hcp_mock.headers = {
            "via": "v",
            "forwarded": "f",
            "x-forwarded-for": "xff",
            "x-forwarded-host": "xfh",
            "x-forwarded-proto": "xfp"
        }
        integration_config = {
            "Description": "test",
            "Integrations": [{
                "Name": "event1action",
                "ActionType": "Cancel",
                "EventId": "event1",
                "CookieDomain": ".test.com",
                "Triggers": [{
                    "TriggerParts": [{
                        "Operator": "Contains",
                        "ValueToCompare": "event1",
                        "UrlPart": "PageUrl",
                        "ValidatorType": "UrlValidator",
                        "IsNegative": False,
                        "IsIgnoreCase": True
                    }],
                    "LogicalOperator": "And"
                }],
                "QueueDomain": "knownusertest.queue-it.net",
            }],
            "CustomerId": "knownusertest",
            "AccountId": "knownusertest",
            "Version": 3,
            "PublishDate": "2017-05-15T21:39:12.0076806Z",
            "ConfigDataVersion": "1.0.0.1"
        }

        integration_config_json = json.dumps(integration_config)
        user_in_queue_service.validateCancelRequestRaiseException = True
        try:
            KnownUser.validateRequestByIntegrationConfig("http://test.com?event1=true", "queueIttoken",
                                                         integration_config_json, "customerid", "secretkey",
                                                         HttpContextProviderMock())
        except Exception as e:
            assert (e.message == "Exception")

        assert (len(user_in_queue_service.validateCancelRequestCalls) > 0)
        assert (len(hcp_mock.setCookies) == 0)
