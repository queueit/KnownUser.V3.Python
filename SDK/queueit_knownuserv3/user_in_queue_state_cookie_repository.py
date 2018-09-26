from queueit_helpers import QueueitHelpers
from models import Utils


class UserInQueueStateCookieRepository:
    QUEUEIT_DATA_KEY = "QueueITAccepted-SDFrts345E-V3"

    def __init__(self, httpContextProvider):
        self.httpContextProvider = httpContextProvider

    @staticmethod
    def getCookieKey(eventId):
        return UserInQueueStateCookieRepository.QUEUEIT_DATA_KEY + '_' + eventId

    @staticmethod
    def __generateHash(eventId, queueId, fixedCookieValidityMinutes,
                       redirectType, issueTime, secretKey):
        return QueueitHelpers.hmacSha256Encode(
            eventId + queueId + fixedCookieValidityMinutes + redirectType +
            issueTime, secretKey)

    @staticmethod
    def __createCookieValue(eventId, queueId, fixedCookieValidityMinutes,
                            redirectType, secretKey):
        issueTime = Utils.toString(
            QueueitHelpers.getCurrentTime())
        hashValue = UserInQueueStateCookieRepository.__generateHash(
            eventId, queueId, fixedCookieValidityMinutes, redirectType,
            issueTime, secretKey)

        fixedCookieValidityMinutesPart = ""
        if (not Utils.isNilOrEmpty(fixedCookieValidityMinutes)):
            fixedCookieValidityMinutesPart = "&FixedValidityMins=" + fixedCookieValidityMinutes

        cookieValue = "EventId=" + eventId + "&QueueId=" + queueId + fixedCookieValidityMinutesPart + "&RedirectType=" + redirectType + "&IssueTime=" + issueTime + "&Hash=" + hashValue
        return cookieValue

    @staticmethod
    def __getCookieNameValueMap(cookieValue):
        result = {}
        cookieNameValues = cookieValue.split("&")
        for item in cookieNameValues:
            arr = item.split("=")
            if (len(arr) == 2):
                result[arr[0]] = arr[1]
        return result

    @staticmethod
    def __isCookieValid(secretKey, cookieNameValueMap, eventId,
                        cookieValidityMinutes, validateTime):
        try:
            if ("EventId" not in cookieNameValueMap):
                return False

            if ("QueueId" not in cookieNameValueMap):
                return False

            if ("RedirectType" not in cookieNameValueMap):
                return False

            if ("IssueTime" not in cookieNameValueMap):
                return False

            if ("Hash" not in cookieNameValueMap):
                return False

            fixedCookieValidityMinutes = ""
            if ("FixedValidityMins" in cookieNameValueMap):
                fixedCookieValidityMinutes = cookieNameValueMap[
                    "FixedValidityMins"]

            hashValue = UserInQueueStateCookieRepository.__generateHash(
                cookieNameValueMap["EventId"], cookieNameValueMap["QueueId"],
                fixedCookieValidityMinutes, cookieNameValueMap["RedirectType"],
                cookieNameValueMap["IssueTime"], secretKey)

            if (hashValue != cookieNameValueMap["Hash"]):
                return False

            if (eventId.upper() != cookieNameValueMap["EventId"].upper()):
                return False

            if (validateTime):
                validity = cookieValidityMinutes
                if (not Utils.isNilOrEmpty(fixedCookieValidityMinutes)):
                    validity = int(fixedCookieValidityMinutes)

                expirationTime = int(
                    cookieNameValueMap["IssueTime"]) + (validity * 60)
                if (expirationTime <
                        QueueitHelpers.getCurrentTime()):
                    return False

            return True
        except:
            return False

    def store(self, eventId, queueId, fixedCookieValidityMinutes, cookieDomain,
              redirectType, secretKey):
        cookieKey = UserInQueueStateCookieRepository.getCookieKey(eventId)
        cookieValue = UserInQueueStateCookieRepository.__createCookieValue(
            eventId, queueId, Utils.toString(fixedCookieValidityMinutes),
            redirectType, secretKey)
        self.httpContextProvider.setCookie(
            cookieKey, cookieValue,
            QueueitHelpers.getCookieExpirationDate(),
            cookieDomain)

    def getState(self, eventId, cookieValidityMinutes, secretKey,
                 validateTime):
        cookieKey = UserInQueueStateCookieRepository.getCookieKey(eventId)

        if (self.httpContextProvider.getCookie(cookieKey) is None):
            return StateInfo(False, None, None, None)

        cookieNameValueMap = UserInQueueStateCookieRepository.__getCookieNameValueMap(
            self.httpContextProvider.getCookie(cookieKey))
        if (not UserInQueueStateCookieRepository.__isCookieValid(
                secretKey, cookieNameValueMap, eventId, cookieValidityMinutes,
                validateTime)):
            return StateInfo(False, None, None, None)

        fixedCookieValidityMinutes = None
        if ("FixedValidityMins" in cookieNameValueMap):
            fixedCookieValidityMinutes = int(
                cookieNameValueMap["FixedValidityMins"])

        return StateInfo(True, cookieNameValueMap["QueueId"],
                         fixedCookieValidityMinutes,
                         cookieNameValueMap["RedirectType"])

    def cancelQueueCookie(self, eventId, cookieDomain):
        cookieKey = UserInQueueStateCookieRepository.getCookieKey(eventId)
        self.httpContextProvider.setCookie(cookieKey, None, -1, cookieDomain)

    def reissueQueueCookie(self, eventId, cookieValidityMinutes, cookieDomain,
                           secretKey):
        cookieKey = UserInQueueStateCookieRepository.getCookieKey(eventId)
        cookieValue = self.httpContextProvider.getCookie(cookieKey)
        if (cookieValue == None):
            return

        cookieNameValueMap = UserInQueueStateCookieRepository.__getCookieNameValueMap(
            cookieValue)
        if (not UserInQueueStateCookieRepository.__isCookieValid(
                secretKey, cookieNameValueMap, eventId, cookieValidityMinutes,
                True)):
            return

        fixedCookieValidityMinutes = ""
        if ("FixedValidityMins" in cookieNameValueMap):
            fixedCookieValidityMinutes = cookieNameValueMap[
                "FixedValidityMins"]

        cookieValue = UserInQueueStateCookieRepository.__createCookieValue(
            eventId, cookieNameValueMap["QueueId"], fixedCookieValidityMinutes,
            cookieNameValueMap["RedirectType"], secretKey)

        self.httpContextProvider.setCookie(
            cookieKey, cookieValue,
            QueueitHelpers.getCookieExpirationDate(),
            cookieDomain)


class StateInfo:
    def __init__(self, isValid, queueId, fixedCookieValidityMinutes,
                 redirectType):
        self.isValid = isValid
        self.queueId = queueId
        self.fixedCookieValidityMinutes = fixedCookieValidityMinutes
        self.redirectType = redirectType

    def isStateExtendable(self):
        return self.isValid and Utils.isNilOrEmpty(
            self.fixedCookieValidityMinutes)
