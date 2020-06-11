import unittest
import re

from queueit_knownuserv3.models import QueueEventConfig, CancelEventConfig
from queueit_knownuserv3.user_in_queue_service import UserInQueueService
from queueit_knownuserv3.queueit_helpers import QueueitHelpers
from queueit_knownuserv3.user_in_queue_state_cookie_repository import UserInQueueStateCookieRepository
from queueit_knownuserv3.user_in_queue_state_cookie_repository import StateInfo
from queueit_knownuserv3.http_context_providers import HttpContextProvider


class HttpContextProviderMock(HttpContextProvider):
    def __init__(self):
        pass

    def getProviderName(self):
        return "mock"

    def setCookie(self, name, value, expire, domain):
        pass


class UserInQueueStateCookieRepositoryMock(UserInQueueStateCookieRepository):
    def __init__(self, httpContextProvider):
        self.httpContextProvider = httpContextProvider
        self.arrayFunctionCallsArgs = {
            'store': [],
            'getState': [],
            'cancelQueueCookie': [],
            'extendQueueCookie': []
        }

        self.arrayReturns = {
            'store': [],
            'getState': [],
            'cancelQueueCookie': [],
            'extendQueueCookie': []
        }

    def getState(self, eventId, cookieValidityMinutes, secretKey,
                 validateTime):
        self.arrayFunctionCallsArgs['getState'].append(
            [eventId, cookieValidityMinutes, secretKey, validateTime])

        return self.arrayReturns['getState'][
            len(self.arrayFunctionCallsArgs['getState']) - 1]

    def store(self, eventId, queueId, fixedCookieValidityMinutes, cookieDomain,
              redirectType, secretKey):
        self.arrayFunctionCallsArgs['store'].append([
            eventId, queueId, fixedCookieValidityMinutes, cookieDomain,
            redirectType, secretKey
        ])

    def cancelQueueCookie(self, eventId, cookieDomain):
        self.arrayFunctionCallsArgs['cancelQueueCookie'].append(
            [eventId, cookieDomain])

    def reissueQueueCookie(self, eventId, cookieValidityMinutes, cookieDomain,
                           secretKey):
        self.arrayFunctionCallsArgs['store'].append(
            [eventId, cookieValidityMinutes, cookieDomain, secretKey])

    def expectCall(self, functionName, secquenceNo, argument):
        if (len(self.arrayFunctionCallsArgs[functionName]) >= secquenceNo):
            argArr = self.arrayFunctionCallsArgs[functionName][secquenceNo - 1]
            if (len(argument) != len(argArr)):
                return False
            c = range(len(argArr) - 1)
            for i in c:
                if (argArr[i] != argument[i]):
                    return False
            return True
        return False

    def expectCallAny(self, functionName):
        if (len(self.arrayFunctionCallsArgs[functionName]) >= 1):
            return True
        return False


class TestHelper():
    @staticmethod
    def generateHash(eventId, queueId, timestamp, extendableCookie,
                     cookieValidityMinutes, redirectType, secretKey):
        token = 'e_' + eventId + '~ts_' + timestamp + '~ce_' + extendableCookie + '~q_' + queueId
        if (cookieValidityMinutes is not None):
            token = token + '~cv_' + str(cookieValidityMinutes)
        if (redirectType is not None):
            token = token + '~rt_' + redirectType
        return token + '~h_' + QueueitHelpers.hmacSha256Encode(
            token, secretKey)


class TestUserInQueueService(unittest.TestCase):
    def test_ValidateQueueRequest_ValidState_ExtendableCookie_NoCookieExtensionFromConfig_DoNotRedirectDoNotStoreCookieWithExtension(
            self):
        queueConfig = QueueEventConfig()
        queueConfig.eventId = "e1"
        queueConfig.queueDomain = "testDomain"
        queueConfig.cookieDomain = "testDomain"
        queueConfig.cookieValidityMinute = 10
        queueConfig.extendCookieValidity = False
        queueConfig.actionName = "QueueAction"
        httpContextProviderMock = HttpContextProviderMock()
        userInQueueStateCookieRepositoryMock = UserInQueueStateCookieRepositoryMock(
            httpContextProviderMock)
        userInQueueStateCookieRepositoryMock.arrayReturns['getState'].append(
            StateInfo(True, True, "queueId", None, "idle"))
        testObject = UserInQueueService(httpContextProviderMock,
                                        userInQueueStateCookieRepositoryMock)
        result = testObject.validateQueueRequest("url", "token", queueConfig,
                                                 "customerid", "key")
        assert (not result.doRedirect())
        assert (result.queueId == "queueId")
        assert (
            not userInQueueStateCookieRepositoryMock.expectCallAny('store'))
        assert (userInQueueStateCookieRepositoryMock.expectCall(
            'getState', 1, ["e1", 10, 'key', True]))
        assert (queueConfig.actionName == result.actionName)
        assert (not userInQueueStateCookieRepositoryMock.expectCallAny('cancelQueueCookie'))

    def test_ValidateQueueRequest_ValidState_ExtendableCookie_CookieExtensionFromConfig_DoNotRedirectDoStoreCookieWithExtension(
            self):
        queueConfig = QueueEventConfig()
        queueConfig.eventId = "e1"
        queueConfig.queueDomain = "testDomain.com"
        queueConfig.cookieDomain = "testDomain"
        queueConfig.cookieValidityMinute = 10
        queueConfig.extendCookieValidity = True
        queueConfig.actionName = "QueueAction"
        httpContextProviderMock = HttpContextProviderMock()
        userInQueueStateCookieRepositoryMock = UserInQueueStateCookieRepositoryMock(
            httpContextProviderMock)
        userInQueueStateCookieRepositoryMock.arrayReturns['getState'].append(
            StateInfo(True, True, "queueId", None, "disabled"))
        testObject = UserInQueueService(httpContextProviderMock,
                                        userInQueueStateCookieRepositoryMock)
        result = testObject.validateQueueRequest("url", "token", queueConfig,
                                                 "customerid", "key")
        assert (not result.doRedirect())
        assert (result.eventId == 'e1')
        assert (result.queueId == "queueId")
        assert (userInQueueStateCookieRepositoryMock.expectCall(
            'store', 1,
            ["e1", 'queueId', None, 'testDomain', "disabled", "key"]))
        assert (queueConfig.actionName == result.actionName)
        assert (not userInQueueStateCookieRepositoryMock.expectCallAny('cancelQueueCookie'))

    def test_ValidateQueueRequest_ValidState_NoExtendableCookie_DoNotRedirectDoNotStoreCookieWithExtension(
            self):
        queueConfig = QueueEventConfig()
        queueConfig.eventId = "e1"
        queueConfig.queueDomain = "testDomain"
        queueConfig.cookieValidityMinute = 10
        queueConfig.extendCookieValidity = True
        queueConfig.actionName = "QueueAction"
        httpContextProviderMock = HttpContextProviderMock()
        userInQueueStateCookieRepositoryMock = UserInQueueStateCookieRepositoryMock(
            httpContextProviderMock)
        userInQueueStateCookieRepositoryMock.arrayReturns['getState'].append(
            StateInfo(True, True, "queueId", 3, "idle"))
        testObject = UserInQueueService(httpContextProviderMock,
                                        userInQueueStateCookieRepositoryMock)
        result = testObject.validateQueueRequest("url", "token", queueConfig,
                                                 "customerid", "key")
        assert (not result.doRedirect())
        assert (result.eventId == 'e1')
        assert (result.queueId == "queueId")
        assert (not userInQueueStateCookieRepositoryMock.expectCallAny('store'))
        assert (queueConfig.actionName == result.actionName)
        assert (not userInQueueStateCookieRepositoryMock.expectCallAny('cancelQueueCookie'))

    def test_ValidateQueueRequest_NoCookie_TampredToken_RedirectToErrorPageWithHashError_DoNotStoreCookie(
            self):
        key = "4e1db821-a825-49da-acd0-5d376f2068db"
        queueConfig = QueueEventConfig()
        queueConfig.eventId = "e1"
        queueConfig.queueDomain = "testDomain.com"
        queueConfig.cookieValidityMinute = 10
        queueConfig.extendCookieValidity = True
        queueConfig.version = 11
        queueConfig.actionName = "Queue Action (._~-) !*|'\""
        url = "http://test.test.com?b=h"
        httpContextProviderMock = HttpContextProviderMock()
        userInQueueStateCookieRepositoryMock = UserInQueueStateCookieRepositoryMock(
            httpContextProviderMock)
        userInQueueStateCookieRepositoryMock.arrayReturns['getState'].append(
            StateInfo(False, False, None, None, None))
        token = TestHelper.generateHash(
            'e1', 'queueId',
            str((QueueitHelpers.getCurrentTime() + (3 * 60))),
            'False', None, 'idle', key)
        token = token.replace("False", 'True')
        expectedErrorUrl = "https://testDomain.com/error/hash/?c=testCustomer&e=e1" + \
                "&ver=" + UserInQueueService.SDK_VERSION + \
                "&kupver=mock" + \
                "&cver=11" + \
                "&man=" + QueueitHelpers.urlEncode(queueConfig.actionName) + \
                "&queueittoken=" + token + \
                "&t=" + QueueitHelpers.urlEncode(url)
        testObject = UserInQueueService(httpContextProviderMock,
                                        userInQueueStateCookieRepositoryMock)
        result = testObject.validateQueueRequest(url, token, queueConfig,
                                                 "testCustomer", key)
        assert (
            not userInQueueStateCookieRepositoryMock.expectCallAny('store'))
        assert (result.doRedirect())
        assert (result.eventId == 'e1')
        matches = re.search("&ts=[^&]*", result.redirectUrl)
        timestamp = matches.group(0).replace("&ts=", "")
        timestamp = timestamp.replace("&", "")
        assert (QueueitHelpers.getCurrentTime() - int(timestamp)
                < 100)
        urlWithoutTimeStamp = re.sub("&ts=[^&]*", "", result.redirectUrl)
        assert (urlWithoutTimeStamp.upper() == expectedErrorUrl.upper())
        assert (queueConfig.actionName == result.actionName)
        assert (queueConfig.actionName == result.actionName)
        assert (not userInQueueStateCookieRepositoryMock.expectCallAny('cancelQueueCookie'))
        assert (not userInQueueStateCookieRepositoryMock.expectCallAny('store'))

    def test_ValidateQueueRequest_NoCookie_ExpiredTimeStampInToken_RedirectToErrorPageWithTimeStampError_DoNotStoreCookie(
            self):
        key = "4e1db821-a825-49da-acd0-5d376f2068db"
        queueConfig = QueueEventConfig()
        queueConfig.eventId = "e1"
        queueConfig.queueDomain = "testDomain.com"
        queueConfig.cookieValidityMinute = 10
        queueConfig.extendCookieValidity = True
        queueConfig.version = 11
        queueConfig.actionName = "Queue Action (._~-) !*|'\""
        url = "http://test.test.com?b=h"
        httpContextProviderMock = HttpContextProviderMock()
        userInQueueStateCookieRepositoryMock = UserInQueueStateCookieRepositoryMock(
            httpContextProviderMock)
        userInQueueStateCookieRepositoryMock.arrayReturns['getState'].append(
            StateInfo(False, False, None, None, None))
        token = TestHelper.generateHash(
            'e1', 'queueId',
            str((QueueitHelpers.getCurrentTime() - (3 * 60))),
            'False', None, 'queue', key)
        expectedErrorUrl = "https://testDomain.com/error/timestamp/?c=testCustomer&e=e1" + \
                    "&ver=" + UserInQueueService.SDK_VERSION + \
                    "&kupver=mock" + \
                    "&cver=11" + \
                    "&man=" + QueueitHelpers.urlEncode(queueConfig.actionName) + \
                    "&queueittoken=" + token + \
                    "&t=" + QueueitHelpers.urlEncode(url)
        testObject = UserInQueueService(httpContextProviderMock,
                                        userInQueueStateCookieRepositoryMock)
        result = testObject.validateQueueRequest(url, token, queueConfig,
                                                 "testCustomer", key)
        assert (
            not userInQueueStateCookieRepositoryMock.expectCallAny('store'))
        assert (result.doRedirect())
        assert (result.eventId == 'e1')
        matches = re.search("&ts=[^&]*", result.redirectUrl)
        timestamp = matches.group(0).replace("&ts=", "")
        timestamp = timestamp.replace("&", "")
        assert (QueueitHelpers.getCurrentTime() - int(timestamp)
                < 100)
        urlWithoutTimeStamp = re.sub("&ts=[^&]*", "", result.redirectUrl)
        assert (urlWithoutTimeStamp.upper() == expectedErrorUrl.upper())
        assert (not userInQueueStateCookieRepositoryMock.expectCallAny('cancelQueueCookie'))
        assert (queueConfig.actionName == result.actionName)
        assert (not userInQueueStateCookieRepositoryMock.expectCallAny('store'))

    def test_ValidateQueueRequest_NoCookie_EventIdMismatch_RedirectToErrorPageWithEventIdMissMatchError_DoNotStoreCookie(
            self):
        key = "4e1db821-a825-49da-acd0-5d376f2068db"
        queueConfig = QueueEventConfig()
        queueConfig.eventId = "e2"
        queueConfig.queueDomain = "testDomain.com"
        queueConfig.cookieValidityMinute = 10
        queueConfig.extendCookieValidity = True
        queueConfig.version = 11
        queueConfig.actionName = "Queue Action (._~-) !*|'\""
        url = "http://test.test.com?b=h"
        httpContextProviderMock = HttpContextProviderMock()
        userInQueueStateCookieRepositoryMock = UserInQueueStateCookieRepositoryMock(
            httpContextProviderMock)
        userInQueueStateCookieRepositoryMock.arrayReturns['getState'].append(
            StateInfo(False, False, None, None, None))
        token = TestHelper.generateHash(
            'e1', 'queueId',
            str((QueueitHelpers.getCurrentTime() - (3 * 60))),
            'False', None, 'queue', key)
        expectedErrorUrl = "https://testDomain.com/error/eventid/?c=testCustomer&e=e2" + \
                "&ver=" + UserInQueueService.SDK_VERSION + \
                "&kupver=mock" + \
                "&cver=11" + \
                "&man=" + QueueitHelpers.urlEncode(queueConfig.actionName) + \
                "&queueittoken=" + token + \
                "&t=" + QueueitHelpers.urlEncode(url)
        testObject = UserInQueueService(httpContextProviderMock,
                                        userInQueueStateCookieRepositoryMock)
        result = testObject.validateQueueRequest(url, token, queueConfig,
                                                 "testCustomer", key)
        assert (
            not userInQueueStateCookieRepositoryMock.expectCallAny('store'))
        assert (result.doRedirect())
        assert (result.eventId == 'e2')
        matches = re.search("&ts=[^&]*", result.redirectUrl)
        timestamp = matches.group(0).replace("&ts=", "")
        timestamp = timestamp.replace("&", "")
        assert (QueueitHelpers.getCurrentTime() - int(timestamp)
                < 100)
        urlWithoutTimeStamp = re.sub("&ts=[^&]*", "", result.redirectUrl)
        assert (urlWithoutTimeStamp.upper() == expectedErrorUrl.upper())
        assert (not userInQueueStateCookieRepositoryMock.expectCallAny('cancelQueueCookie'))
        assert (queueConfig.actionName == result.actionName)
        assert (not userInQueueStateCookieRepositoryMock.expectCallAny('store'))


    def test_ValidateQueueRequest_NoCookie_ValidToken_ExtendableCookie_DoNotRedirect_StoreExtendableCookie(
            self):
        key = "4e1db821-a825-49da-acd0-5d376f2068db"
        queueConfig = QueueEventConfig()
        queueConfig.eventId = "e1"
        queueConfig.queueDomain = "testDomain.com"
        queueConfig.cookieValidityMinute = 10
        queueConfig.cookieDomain = "testDomain"
        queueConfig.extendCookieValidity = True
        queueConfig.version = 11
        queueConfig.actionName = "QueueAction"
        url = "http://test.test.com?b=h"
        httpContextProviderMock = HttpContextProviderMock()
        userInQueueStateCookieRepositoryMock = UserInQueueStateCookieRepositoryMock(
            httpContextProviderMock)
        userInQueueStateCookieRepositoryMock.arrayReturns['getState'].append(
            StateInfo(False, False, None, None, None))
        token = TestHelper.generateHash(
            'e1', 'queueId',
            str((QueueitHelpers.getCurrentTime() + (3 * 60))),
            'true', None, 'queue', key)
        testObject = UserInQueueService(httpContextProviderMock,
                                        userInQueueStateCookieRepositoryMock)
        result = testObject.validateQueueRequest(url, token, queueConfig,
                                                 "testCustomer", key)
        assert (not result.doRedirect())
        assert (result.eventId == 'e1')
        assert (result.queueId == 'queueId')
        assert (result.redirectType == 'queue')
        assert (userInQueueStateCookieRepositoryMock.expectCall(
            'store', 1, ["e1", 'queueId', None, 'testDomain', 'queue', key]))
        assert (queueConfig.actionName == result.actionName)
        assert (not userInQueueStateCookieRepositoryMock.expectCallAny('cancelQueueCookie'))

    def test_ValidateQueueRequest_NoCookie_ValidToken_CookieValidityMinuteFromToken_DoNotRedirect_StoreNonExtendableCookie(
            self):
        key = "4e1db821-a825-49da-acd0-5d376f2068db"
        queueConfig = QueueEventConfig()
        queueConfig.eventId = "e1"
        queueConfig.queueDomain = "testDomain.com"
        queueConfig.cookieValidityMinute = 30
        queueConfig.cookieDomain = "testDomain"
        queueConfig.extendCookieValidity = True
        queueConfig.actionName = "QueueAction"
        queueConfig.version = 11
        url = "http://test.test.com?b=h"
        httpContextProviderMock = HttpContextProviderMock()
        userInQueueStateCookieRepositoryMock = UserInQueueStateCookieRepositoryMock(
            httpContextProviderMock)
        userInQueueStateCookieRepositoryMock.arrayReturns['getState'].append(
            StateInfo(False, False, None, None, None))
        token = TestHelper.generateHash(
            'e1', 'queueId',
            str(QueueitHelpers.getCurrentTime() + (3 * 60)),
            'false', 3, 'DirectLink', key)
        testObject = UserInQueueService(httpContextProviderMock,
                                        userInQueueStateCookieRepositoryMock)
        result = testObject.validateQueueRequest(url, token, queueConfig,
                                                 "testCustomer", key)
        self.assertFalse(result.doRedirect())
        self.assertEqual(result.eventId, 'e1')
        self.assertEqual(result.queueId, 'queueId')
        self.assertEqual(result.redirectType, 'DirectLink')
        self.assertTrue(
            userInQueueStateCookieRepositoryMock.expectCall(
                'store', 1,
                ["e1", 'queueId', 3, 'testDomain', 'DirectLink', key]))
        self.assertEquals(queueConfig.actionName, result.actionName)
        assert (not userInQueueStateCookieRepositoryMock.expectCallAny('cancelQueueCookie'))

    def test_NoCookie_NoValidToken_WithoutToken_RedirectToQueue(self):
        key = "4e1db821-a825-49da-acd0-5d376f2068db"
        queueConfig = QueueEventConfig()
        queueConfig.eventId = "e1"
        queueConfig.queueDomain = "testDomain.com"
        queueConfig.cookieValidityMinute = 10
        queueConfig.extendCookieValidity = True
        queueConfig.version = 11
        queueConfig.culture = 'en-US'
        queueConfig.layoutName = 'testlayout'
        queueConfig.actionName = "Queue Action (._~-) !*|'\""
        url = "http://test.test.com?b=h"
        httpContextProviderMock = HttpContextProviderMock()
        userInQueueStateCookieRepositoryMock = UserInQueueStateCookieRepositoryMock(
            httpContextProviderMock)
        userInQueueStateCookieRepositoryMock.arrayReturns['getState'].append(
            StateInfo(False, False, None, None, None))
        token = ""
        expectedRedirectUrl = "https://testDomain.com/?c=testCustomer&e=e1" + \
                "&ver=" + UserInQueueService.SDK_VERSION + \
                "&kupver=mock" + \
                "&cver=11"  + \
                "&man=" + QueueitHelpers.urlEncode(queueConfig.actionName) + \
                "&cid=en-US" + \
                "&l=testlayout"+"&t=" + QueueitHelpers.urlEncode(url)
        testObject = UserInQueueService(httpContextProviderMock,
                                        userInQueueStateCookieRepositoryMock)
        result = testObject.validateQueueRequest(url, token, queueConfig,
                                                 "testCustomer", key)
        assert (
            not userInQueueStateCookieRepositoryMock.expectCallAny('store'))
        assert (result.doRedirect())
        assert (result.eventId == 'e1')
        assert (result.queueId == None)
        assert (result.redirectUrl.upper() == expectedRedirectUrl.upper())
        assert (queueConfig.actionName == result.actionName)
        assert (not userInQueueStateCookieRepositoryMock.expectCallAny('cancelQueueCookie'))

    def test_ValidateRequest_NoCookie_WithoutToken_RedirectToQueue_NotargetUrl(
            self):
        key = "4e1db821-a825-49da-acd0-5d376f2068db"
        queueConfig = QueueEventConfig()
        queueConfig.eventId = "e1"
        queueConfig.queueDomain = "testDomain.com"
        queueConfig.cookieValidityMinute = 10
        queueConfig.extendCookieValidity = True
        queueConfig.version = 11
        queueConfig.culture = 'en-US'
        queueConfig.layoutName = 'testlayout'
        queueConfig.actionName = "Queue Action (._~-) !*|'\""
        httpContextProviderMock = HttpContextProviderMock()
        userInQueueStateCookieRepositoryMock = UserInQueueStateCookieRepositoryMock(
            httpContextProviderMock)
        userInQueueStateCookieRepositoryMock.arrayReturns['getState'].append(
            StateInfo(False, False, None, None, None))
        token = ""
        expectedRedirectUrl = "https://testDomain.com/?c=testCustomer&e=e1" + \
                "&ver=" + UserInQueueService.SDK_VERSION + \
                "&kupver=mock" + \
                "&cver=11" + \
                "&man=" + QueueitHelpers.urlEncode(queueConfig.actionName) + \
                "&cid=en-US" + \
                "&l=testlayout"
        testObject = UserInQueueService(httpContextProviderMock,
                                        userInQueueStateCookieRepositoryMock)
        result = testObject.validateQueueRequest(None, token, queueConfig,
                                                 "testCustomer", key)
        assert (
            not userInQueueStateCookieRepositoryMock.expectCallAny('store'))
        assert (result.doRedirect())
        assert (result.eventId == 'e1')
        assert (result.queueId == None)
        assert (result.redirectUrl.upper() == expectedRedirectUrl.upper())
        assert (queueConfig.actionName == result.actionName)
        assert (not userInQueueStateCookieRepositoryMock.expectCallAny('cancelQueueCookie'))

    def test_validateRequest_InvalidCookie_WithoutToken_RedirectToQueue_CancelCookie(self):
        config = QueueEventConfig()
        config.eventId = "e1"
        config.queueDomain = "testDomain.com"
        config.cookieValidityMinute = 10
        config.extendCookieValidity = False
        config.version = 11
        config.culture = None
        config.layoutName = 'testlayout'
        config.actionName = "QueueAction"
        expectedUrl = "https://testDomain.com/?c=testCustomer&e=e1" + \
                "&ver=" + UserInQueueService.SDK_VERSION + \
                "&kupver=mock" + \
                "&cver=11" + \
                "&man=" + QueueitHelpers.urlEncode(config.actionName) + \
                "&l=testlayout"

        httpContextProviderMock = HttpContextProviderMock()
        userInQueueStateCookieRepositoryMock = UserInQueueStateCookieRepositoryMock(
            httpContextProviderMock)
        userInQueueStateCookieRepositoryMock.arrayReturns['getState'].append(
            StateInfo(True, False, None, None, None))
        testObject = UserInQueueService(httpContextProviderMock,
                                        userInQueueStateCookieRepositoryMock)

        result = testObject.validateQueueRequest(None, "", config, "testCustomer", "key")
        assert(result.doRedirect())
        assert (result.redirectUrl.upper() == expectedUrl.upper())
        assert (not userInQueueStateCookieRepositoryMock.expectCallAny('store'))
        assert (result.eventId == config.eventId)
        assert (result.actionName == config.actionName)
        assert (userInQueueStateCookieRepositoryMock.expectCallAny('cancelQueueCookie'))

    def test_ValidateQueueRequest_NoCookie_InValidToken(self):
        key = "4e1db821-a825-49da-acd0-5d376f2068db"
        queueConfig = QueueEventConfig()
        queueConfig.eventId = "e1"
        queueConfig.queueDomain = "testDomain.com"
        queueConfig.cookieValidityMinute = 10
        queueConfig.extendCookieValidity = True
        queueConfig.version = 11
        queueConfig.culture = 'en-US'
        queueConfig.layoutName = 'testlayout'
        queueConfig.actionName = "QueueAction"
        url = "http://test.test.com?b=h"
        httpContextProviderMock = HttpContextProviderMock()
        userInQueueStateCookieRepositoryMock = UserInQueueStateCookieRepositoryMock(
            httpContextProviderMock)
        userInQueueStateCookieRepositoryMock.arrayReturns['getState'].append(
            StateInfo(False, False, None, None, None))
        testObject = UserInQueueService(httpContextProviderMock,
                                        userInQueueStateCookieRepositoryMock)
        result = testObject.validateQueueRequest(
            url,
            "ts_sasa~cv_adsasa~ce_falwwwse~q_944c1f44-60dd-4e37-aabc-f3e4bb1c8895",
            queueConfig, "testCustomer", key)
        assert (
            not userInQueueStateCookieRepositoryMock.expectCallAny('store'))
        assert (result.doRedirect())
        assert (result.eventId == 'e1')
        assert (result.queueId == None)
        assert (result.redirectUrl.startswith(
            "https://testDomain.com/error/hash/?c=testCustomer&e=e1"))
        assert (queueConfig.actionName == result.actionName)
        assert (not userInQueueStateCookieRepositoryMock.expectCallAny('cancelQueueCookie'))

    def test_validateRequest_InvalidCookie_InvalidToken_CancelCookie(self):
        config = QueueEventConfig()
        config.eventId = "e1"
        config.queueDomain = "testDomain.com"
        config.cookieValidityMinute = 10
        config.extendCookieValidity = False
        config.version = 10
        config.culture = None
        config.layoutName = 'testlayout'
        config.actionName = "QueueAction"
        targetUrl = "http://test.test.com?b=h"
        knownUserVersion = UserInQueueService.SDK_VERSION
        httpContextProviderMock = HttpContextProviderMock()
        userInQueueStateCookieRepositoryMock = UserInQueueStateCookieRepositoryMock(
            httpContextProviderMock)
        userInQueueStateCookieRepositoryMock.arrayReturns['getState'].append(
            StateInfo(True, False, None, None, None))
        testObject = UserInQueueService(httpContextProviderMock,
                                        userInQueueStateCookieRepositoryMock)

        result = testObject.validateQueueRequest(targetUrl,
            "ts_sasa~cv_adsasa~ce_falwwwse~q_944c1f44-60dd-4e37-aabc-f3e4bb1c8895",
            config, "testCustomer", "key")
        assert(result.doRedirect())
        assert (result.redirectUrl.startswith(
            "https://testDomain.com/error/hash/?c=testCustomer&e=e1&ver={0}&kupver=mock&cver=10&man=QueueAction&l=testlayout&queueittoken=ts_sasa~cv_adsasa~ce_falwwwse~q_944c1f44-60dd-4e37-aabc-f3e4bb1c8895&".format(knownUserVersion)))
        assert (not userInQueueStateCookieRepositoryMock.expectCallAny('store'))
        assert (result.eventId == config.eventId)
        assert (result.actionName == config.actionName)
        assert (userInQueueStateCookieRepositoryMock.expectCallAny('cancelQueueCookie'))

    def test_validateCancelRequest(self):
        cancelConfig = CancelEventConfig()
        cancelConfig.eventId = "e1"
        cancelConfig.queueDomain = "testDomain.com"
        cancelConfig.cookieDomain = "my-cookie-domain"
        cancelConfig.version = 10
        cancelConfig.actionName = "TestCancelAction"
        url = "http://test.test.com?b=h"
        httpContextProviderMock = HttpContextProviderMock()
        userInQueueStateCookieRepositoryMock = UserInQueueStateCookieRepositoryMock(
            httpContextProviderMock)
        userInQueueStateCookieRepositoryMock.arrayReturns['getState'].append(
            StateInfo(True, True, "queueId", 3, "idle"))
        expectedUrl = "https://testDomain.com/cancel/testCustomer/e1/?c=testCustomer&e=e1&ver=" + UserInQueueService.SDK_VERSION + "&kupver=mock&cver=10&man=" + cancelConfig.actionName + "&r=" + QueueitHelpers.urlEncode(
            url)
        testObject = UserInQueueService(httpContextProviderMock,
                                        userInQueueStateCookieRepositoryMock)
        result = testObject.validateCancelRequest(url, cancelConfig,
                                                  "testCustomer", "key")

        assert (userInQueueStateCookieRepositoryMock.expectCall(
            'cancelQueueCookie', 1, ["e1", 'my-cookie-domain']))
        assert (result.doRedirect())
        assert (result.queueId == "queueId")
        assert (result.eventId == 'e1')
        assert (expectedUrl == result.redirectUrl)
        assert (cancelConfig.actionName == result.actionName)

    def test_getIgnoreActionResult(self):
        httpContextProviderMock = HttpContextProviderMock()
        userInQueueStateCookieRepositoryMock = UserInQueueStateCookieRepositoryMock(
            httpContextProviderMock)

        testObject = UserInQueueService(httpContextProviderMock,
                                        userInQueueStateCookieRepositoryMock)
        result = testObject.getIgnoreActionResult("TestIgnoreAction")

        assert (not result.doRedirect())
        assert (result.eventId == None)
        assert (result.queueId == None)
        assert (result.redirectUrl == None)
        assert (result.actionType == 'Ignore')
        assert (result.actionName == 'TestIgnoreAction')
