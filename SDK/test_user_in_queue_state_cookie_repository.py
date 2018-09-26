import unittest

from queueit_knownuserv3.user_in_queue_state_cookie_repository import UserInQueueStateCookieRepository
from queueit_knownuserv3.queueit_helpers import QueueitHelpers
from queueit_knownuserv3.http_context_providers import HttpContextProvider
from queueit_knownuserv3.models import Utils


class HttpContextProviderMock(HttpContextProvider):
    def __init__(self):
        self.cookieList = {}
        self.setCookieCalls = {}
        self.getCookieCalls = {}

    def setCookie(self, cookieName, value, expire, domain):
        self.cookieList[cookieName] = {
            "name": cookieName,
            "value": value,
            "expiration": expire,
            "cookieDomain": domain
        }
        self.setCookieCalls[len(self.setCookieCalls)] = {
            "name": cookieName,
            "value": value,
            "expiration": expire,
            "cookieDomain": domain
        }

    def getCookie(self, cookieName):
        self.getCookieCalls[len(self.getCookieCalls)] = cookieName
        if (not cookieName in self.cookieList):
            return None
        return self.cookieList[cookieName]["value"]


class UnitTestHelper:
    @staticmethod
    def generateHash(eventId, queueId, fixedCookieValidityMinutes,
                     redirectType, issueTime, secretKey):
        return QueueitHelpers.hmacSha256Encode(
            eventId + queueId + Utils.toString(fixedCookieValidityMinutes) +
            redirectType + issueTime, secretKey)


class TestUserInQueueStateCookieRepository(unittest.TestCase):
    def test_store_hasValidState_ExtendableCookie_CookieIsSaved(self):
        eventId = "event1"
        secretKey = "4e1deweb821-a82ew5-49da-acdqq0-5d3476f2068db"
        cookieDomain = ".test.com"
        queueId = "queueId"
        cookieValidity = 10
        cookieKey = UserInQueueStateCookieRepository.getCookieKey(eventId)
        wfHandler = HttpContextProviderMock()
        testObject = UserInQueueStateCookieRepository(wfHandler)
        testObject.store(eventId, queueId, None, cookieDomain, "Queue",
                         secretKey)
        state = testObject.getState(eventId, cookieValidity, secretKey, True)
        self.assertTrue(state.isValid)
        self.assertEqual(state.queueId, queueId)
        self.assertTrue(state.isStateExtendable())
        self.assertEqual(state.redirectType, 'Queue')
        expirationTimeDelta = wfHandler.cookieList[cookieKey]["expiration"] - QueueitHelpers.getCookieExpirationDate(
        )
        assert (str(expirationTimeDelta) == "0:00:00")
        self.assertEqual(wfHandler.cookieList[cookieKey]["cookieDomain"],
                         cookieDomain)

    def test_store_hasValidState_nonExtendableCookie_CookieIsSaved(self):
        eventId = "event1"
        secretKey = "4e1deweb821-a82ew5-49da-acdqq0-5d3476f2068db"
        cookieDomain = ".test.com"
        queueId = "queueId"
        cookieValidity = 3
        cookieKey = UserInQueueStateCookieRepository.getCookieKey(eventId)
        wfHandler = HttpContextProviderMock()
        testObject = UserInQueueStateCookieRepository(wfHandler)
        testObject.store(eventId, queueId, cookieValidity, cookieDomain,
                         "Idle", secretKey)
        state = testObject.getState(eventId, cookieValidity, secretKey, True)
        assert (state.isValid)
        assert (state.queueId == queueId)
        assert (state.isStateExtendable() == False)
        assert (state.redirectType == 'Idle')
        assert (state.fixedCookieValidityMinutes == 3)
        expirationTimeDelta = wfHandler.cookieList[cookieKey]["expiration"] - QueueitHelpers.getCookieExpirationDate(
        )
        assert (str(expirationTimeDelta) == "0:00:00")
        self.assertEqual(wfHandler.cookieList[cookieKey]["cookieDomain"],
                         cookieDomain)

    def test_store_hasValidState_tamperedCookie_stateIsNotValid_isCookieExtendable(
            self):
        eventId = "event1"
        secretKey = "4e1deweb821-a82ew5-49da-acdqq0-5d3476f2068db"
        cookieDomain = ".test.com"
        queueId = "queueId"
        cookieValidity = 10
        cookieKey = UserInQueueStateCookieRepository.getCookieKey(eventId)
        wfHandler = HttpContextProviderMock()
        testObject = UserInQueueStateCookieRepository(wfHandler)
        testObject.store(eventId, queueId, 3, cookieDomain, "Idle", secretKey)
        state = testObject.getState(eventId, cookieValidity, secretKey, True)
        assert (state.isValid)
        oldCookieValue = wfHandler.cookieList[cookieKey]["value"]
        wfHandler.cookieList[cookieKey]["value"] = oldCookieValue.replace(
            "FixedValidityMins=3", "FixedValidityMins=10")
        state2 = testObject.getState(eventId, cookieValidity, secretKey, True)
        assert (not state2.isValid)
        assert (not state2.isStateExtendable())

    def test_store_hasValidState_tamperedCookie_stateIsNotValid_eventId(self):
        eventId = "event1"
        secretKey = "4e1deweb821-a82ew5-49da-acdqq0-5d3476f2068db"
        cookieDomain = ".test.com"
        queueId = "queueId"
        cookieValidity = 10
        cookieKey = UserInQueueStateCookieRepository.getCookieKey(eventId)
        wfHandler = HttpContextProviderMock()
        testObject = UserInQueueStateCookieRepository(wfHandler)
        testObject.store(eventId, queueId, 3, cookieDomain, "Idle", secretKey)
        state = testObject.getState(eventId, cookieValidity, secretKey, True)
        assert (state.isValid)

        oldCookieValue = wfHandler.cookieList[cookieKey]["value"]
        wfHandler.cookieList[cookieKey]["value"] = oldCookieValue.replace(
            "EventId=event1", "EventId=event2")
        state2 = testObject.getState(eventId, cookieValidity, secretKey, True)
        assert (not state2.isValid)
        assert (not state2.isStateExtendable())

    def test_store_hasValidState_expiredCookie_stateIsNotValid(self):
        eventId = "event1"
        secretKey = "4e1deweb821-a82ew5-49da-acdqq0-5d3476f2068db"
        cookieDomain = ".test.com"
        queueId = "queueId"
        cookieValidity = -1
        wfHandler = HttpContextProviderMock()
        testObject = UserInQueueStateCookieRepository(wfHandler)
        testObject.store(eventId, queueId, None, cookieDomain, "Idle",
                         secretKey)
        state = testObject.getState(eventId, cookieValidity, secretKey, True)
        assert (not state.isValid)

    def test_store_hasValidState_differentEventId_stateIsNotValid(self):
        eventId = "event1"
        secretKey = "4e1deweb821-a82ew5-49da-acdqq0-5d3476f2068db"
        cookieDomain = ".test.com"
        queueId = "queueId"
        cookieValidity = 10
        wfHandler = HttpContextProviderMock()
        testObject = UserInQueueStateCookieRepository(wfHandler)
        testObject.store(eventId, queueId, None, cookieDomain, "Queue",
                         secretKey)
        state = testObject.getState(eventId, cookieValidity, secretKey, True)
        assert (state.isValid)
        state2 = testObject.getState("event2", cookieValidity, secretKey, True)
        assert (not state2.isValid)

    def test_hasValidState_noCookie_stateIsNotValid(self):
        eventId = "event1"
        secretKey = "4e1deweb821-a82ew5-49da-acdqq0-5d3476f2068db"
        cookieValidity = 10
        wfHandler = HttpContextProviderMock()
        testObject = UserInQueueStateCookieRepository(wfHandler)
        state = testObject.getState(eventId, cookieValidity, secretKey, True)
        assert (not state.isValid)

    def test_hasValidState_invalidCookie_stateIsNotValid(self):
        eventId = "event1"
        secretKey = "4e1deweb821-a82ew5-49da-acdqq0-5d3476f2068db"
        cookieDomain = ".test.com"
        queueId = "queueId"
        cookieKey = UserInQueueStateCookieRepository.getCookieKey(eventId)
        cookieValidity = 10
        wfHandler = HttpContextProviderMock()
        testObject = UserInQueueStateCookieRepository(wfHandler)
        testObject.store(eventId, queueId, 20, cookieDomain, "Queue",
                         secretKey)
        state = testObject.getState(eventId, cookieValidity, secretKey, True)
        assert (state.isValid)
        wfHandler.cookieList[cookieKey][
            "value"] = "IsCookieExtendable=ooOOO&Expires=|||&QueueId=000&Hash=23232"
        state2 = testObject.getState(eventId, cookieValidity, secretKey, True)
        assert (not state2.isValid)

    def test_cancelQueueCookie(self):
        eventId = "event1"
        secretKey = "4e1deweb821-a82ew5-49da-acdqq0-5d3476f2068db"
        cookieDomain = ".test.com"
        queueId = "queueId"
        cookieValidity = 20
        wfHandler = HttpContextProviderMock()
        testObject = UserInQueueStateCookieRepository(wfHandler)
        testObject.store(eventId, queueId, 20, cookieDomain, "Queue",
                         secretKey)
        state = testObject.getState(eventId, cookieValidity, secretKey, True)
        assert (state.isValid)
        testObject.cancelQueueCookie(eventId, cookieDomain)
        state2 = testObject.getState(eventId, cookieValidity, secretKey, True)
        assert (not state2.isValid)
        assert (int(wfHandler.setCookieCalls[1]["expiration"]) == -1)
        assert (wfHandler.setCookieCalls[1]["cookieDomain"] == cookieDomain)
        assert (wfHandler.setCookieCalls[1]["value"] == None)

    def test_extendQueueCookie_cookieExist(self):
        eventId = "event1"
        secretKey = "4e1deweb821-a82ew5-49da-acdqq0-5d3476f2068db"
        cookieDomain = ".test.com"
        queueId = "queueId"
        cookieKey = UserInQueueStateCookieRepository.getCookieKey(eventId)
        wfHandler = HttpContextProviderMock()
        testObject = UserInQueueStateCookieRepository(wfHandler)
        testObject.store(eventId, queueId, None, cookieDomain, "Queue",
                         secretKey)
        testObject.reissueQueueCookie(eventId, 12, cookieDomain, secretKey)
        state = testObject.getState(eventId, 5, secretKey, True)
        assert (state.isValid)
        assert (state.queueId == queueId)
        assert (state.isStateExtendable())

        expirationTimeDelta = wfHandler.cookieList[cookieKey]["expiration"] - QueueitHelpers.getCookieExpirationDate(
        )
        assert (str(expirationTimeDelta) == "0:00:00")
        assert (
            wfHandler.cookieList[cookieKey]["cookieDomain"] == cookieDomain)

    def test_extendQueueCookie_cookieDoesNotExist(self):
        eventId = "event1"
        secretKey = "4e1deweb821-a82ew5-49da-acdqq0-5d3476f2068db"
        cookieDomain = ".test.com"
        queueId = "queueId"
        wfHandler = HttpContextProviderMock()
        testObject = UserInQueueStateCookieRepository(wfHandler)
        testObject.store("event2", queueId, 20, cookieDomain, "Queue",
                         secretKey)
        testObject.reissueQueueCookie(eventId, 12, cookieDomain, secretKey)
        assert (len(wfHandler.setCookieCalls) == 1)

    def test_getState_validCookieFormat_extendable(self):
        eventId = "event1"
        secretKey = "4e1deweb821-a82ew5-49da-acdqq0-5d3476f2068db"
        cookieDomain = ".test.com"
        queueId = "queueId"
        cookieKey = UserInQueueStateCookieRepository.getCookieKey(eventId)
        wfHandler = HttpContextProviderMock()
        testObject = UserInQueueStateCookieRepository(wfHandler)
        issueTime = str(QueueitHelpers.getCurrentTime())
        hashValue = UnitTestHelper.generateHash(eventId, queueId, None,
                                                "queue", issueTime, secretKey)
        wfHandler.setCookie(
            cookieKey, "EventId=" + eventId + "&QueueId=" + queueId +
            "&RedirectType=queue&IssueTime=" + issueTime + "&Hash=" +
            hashValue, QueueitHelpers.getCookieExpirationDate(),
            cookieDomain)
        state = testObject.getState(eventId, 10, secretKey, True)
        assert (state.isStateExtendable())
        assert (state.isValid)
        assert (state.queueId == queueId)
        assert (state.redirectType == "queue")

    def test_getState_oldCookie_invalid_expiredCookie_extendable(self):
        eventId = "event1"
        secretKey = "4e1deweb821-a82ew5-49da-acdqq0-5d3476f2068db"
        cookieDomain = ".test.com"
        queueId = "queueId"
        cookieKey = UserInQueueStateCookieRepository.getCookieKey(eventId)
        wfHandler = HttpContextProviderMock()
        testObject = UserInQueueStateCookieRepository(wfHandler)
        issueTime = str(
            (QueueitHelpers.getCurrentTime() - (11 * 60)))
        hashValue = UnitTestHelper.generateHash(eventId, queueId, None,
                                                "queue", issueTime, secretKey)
        wfHandler.setCookie(
            cookieKey, "EventId=" + eventId + "&QueueId=" + queueId +
            "&RedirectType=queue&IssueTime=" + issueTime + "&Hash=" +
            hashValue, QueueitHelpers.getCookieExpirationDate(),
            cookieDomain)
        state = testObject.getState(eventId, 10, secretKey, True)
        assert (not state.isValid)

    def test_getState_oldCookie_invalid_expiredCookie_nonExtendable(self):
        eventId = "event1"
        secretKey = "4e1deweb821-a82ew5-49da-acdqq0-5d3476f2068db"
        cookieDomain = ".test.com"
        queueId = "queueId"
        cookieKey = UserInQueueStateCookieRepository.getCookieKey(eventId)
        wfHandler = HttpContextProviderMock()
        testObject = UserInQueueStateCookieRepository(wfHandler)
        issueTime = str(
            (QueueitHelpers.getCurrentTime() - (4 * 60)))
        hashValue = UnitTestHelper.generateHash(eventId, queueId, 3, "idle",
                                                issueTime, secretKey)
        wfHandler.setCookie(
            cookieKey, "EventId=" + eventId + "&QueueId=" + queueId +
            "&FixedValidityMins=3&RedirectType=idle&IssueTime=" + issueTime +
            "&Hash=" + hashValue,
            QueueitHelpers.getCookieExpirationDate(),
            cookieDomain)
        state = testObject.getState(eventId, 10, secretKey, True)
        assert (not state.isValid)

    def test_getState_validCookieFormat_nonExtendable(self):
        eventId = "event1"
        secretKey = "4e1deweb821-a82ew5-49da-acdqq0-5d3476f2068db"
        cookieDomain = ".test.com"
        queueId = "queueId"
        cookieKey = UserInQueueStateCookieRepository.getCookieKey(eventId)
        wfHandler = HttpContextProviderMock()
        testObject = UserInQueueStateCookieRepository(wfHandler)
        issueTime = str(QueueitHelpers.getCurrentTime())
        hashValue = UnitTestHelper.generateHash(eventId, queueId, 3, "idle",
                                                issueTime, secretKey)
        wfHandler.setCookie(
            cookieKey, "EventId=" + eventId + "&QueueId=" + queueId +
            "&FixedValidityMins=3&RedirectType=idle&IssueTime=" + issueTime +
            "&Hash=" + hashValue,
            QueueitHelpers.getCookieExpirationDate(),
            cookieDomain)
        state = testObject.getState(eventId, 10, secretKey, True)
        assert (not state.isStateExtendable())
        assert (state.isValid)
        assert (state.queueId == queueId)
        assert (state.redirectType == "idle")
