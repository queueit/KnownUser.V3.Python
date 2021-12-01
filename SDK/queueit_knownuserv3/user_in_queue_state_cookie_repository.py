from queueit_helpers import QueueitHelpers
from models import Utils


class UserInQueueStateCookieRepository:
    QUEUEIT_DATA_KEY = "QueueITAccepted-SDFrts345E-V3"

    def __init__(self, http_context_provider):
        self.httpContextProvider = http_context_provider

    @staticmethod
    def getCookieKey(event_id):
        return UserInQueueStateCookieRepository.QUEUEIT_DATA_KEY + '_' + event_id

    @staticmethod
    def __generateHash(event_id, queue_id, fixed_cookie_validity_minutes,
                       redirect_type, issue_time, secret_key):
        return QueueitHelpers.hmacSha256Encode(
            event_id + queue_id + fixed_cookie_validity_minutes + redirect_type +
            issue_time, secret_key)

    @staticmethod
    def __createCookieValue(event_id, queue_id, fixed_cookie_validity_minutes,
                            redirect_type, secret_key):
        issue_time = Utils.toString(
            QueueitHelpers.getCurrentTime())
        hash_value = UserInQueueStateCookieRepository.__generateHash(
            event_id, queue_id, fixed_cookie_validity_minutes, redirect_type,
            issue_time, secret_key)

        fixed_cookie_validity_minutes_part = ""
        if not Utils.isNilOrEmpty(fixed_cookie_validity_minutes):
            fixed_cookie_validity_minutes_part = "&FixedValidityMins=" + fixed_cookie_validity_minutes

        cookie_value = "EventId=" + event_id + "&QueueId=" + queue_id + fixed_cookie_validity_minutes_part \
                       + "&RedirectType=" + redirect_type + "&IssueTime=" + issue_time + "&Hash=" + hash_value
        return cookie_value

    @staticmethod
    def __getCookieNameValueMap(cookie_value):
        result = {}
        cookie_name_values = cookie_value.split("&")
        for item in cookie_name_values:
            arr = item.split("=")
            if len(arr) == 2:
                result[arr[0]] = arr[1]
        return result

    @staticmethod
    def __isCookieValid(secret_key, cookie_name_value_map, event_id,
                        cookie_validity_minutes, validate_time):
        try:
            if "EventId" not in cookie_name_value_map:
                return False

            if "QueueId" not in cookie_name_value_map:
                return False

            if "RedirectType" not in cookie_name_value_map:
                return False

            if "IssueTime" not in cookie_name_value_map:
                return False

            if "Hash" not in cookie_name_value_map:
                return False

            fixed_cookie_validity_minutes = ""
            if "FixedValidityMins" in cookie_name_value_map:
                fixed_cookie_validity_minutes = cookie_name_value_map["FixedValidityMins"]

            hash_value = UserInQueueStateCookieRepository.__generateHash(
                cookie_name_value_map["EventId"], cookie_name_value_map["QueueId"],
                fixed_cookie_validity_minutes, cookie_name_value_map["RedirectType"],
                cookie_name_value_map["IssueTime"], secret_key)

            if hash_value != cookie_name_value_map["Hash"]:
                return False

            if event_id.upper() != cookie_name_value_map["EventId"].upper():
                return False

            if validate_time:
                validity = cookie_validity_minutes
                if not Utils.isNilOrEmpty(fixed_cookie_validity_minutes):
                    validity = int(fixed_cookie_validity_minutes)

                expiration_time = int(cookie_name_value_map["IssueTime"]) + (validity * 60)
                if expiration_time < QueueitHelpers.getCurrentTime():
                    return False

            return True
        except:
            return False

    def store(self, event_id, queue_id, fixed_cookie_validity_minutes, cookie_domain,
              is_cookie_http_only, is_cookie_secure, redirect_type, secret_key):
        cookie_key = UserInQueueStateCookieRepository.getCookieKey(event_id)
        cookie_value = UserInQueueStateCookieRepository.__createCookieValue(
            event_id, queue_id, Utils.toString(fixed_cookie_validity_minutes),
            redirect_type, secret_key)
        self.httpContextProvider.setCookie(
            cookie_key,
            cookie_value,
            QueueitHelpers.getCookieExpirationDate(),
            cookie_domain,
            is_cookie_http_only,
            is_cookie_secure)

    def getState(self, event_id, cookie_validity_minutes, secret_key, validate_time):
        try:
            cookie_key = UserInQueueStateCookieRepository.getCookieKey(event_id)

            if self.httpContextProvider.getCookie(cookie_key) is None:
                return StateInfo(False, False, None, None, None)

            cookie_name_value_map = UserInQueueStateCookieRepository.__getCookieNameValueMap(
                self.httpContextProvider.getCookie(cookie_key))
            if (not UserInQueueStateCookieRepository.__isCookieValid(
                    secret_key, cookie_name_value_map, event_id, cookie_validity_minutes,
                    validate_time)):
                return StateInfo(True, False, None, None, None)

            fixed_cookie_validity_minutes = None
            if "FixedValidityMins" in cookie_name_value_map:
                fixed_cookie_validity_minutes = int(
                    cookie_name_value_map["FixedValidityMins"])

            return StateInfo(True, True, cookie_name_value_map["QueueId"],
                             fixed_cookie_validity_minutes,
                             cookie_name_value_map["RedirectType"])
        except:
            return StateInfo(True, False, None, None, None)

    def cancelQueueCookie(self, event_id, cookie_domain, is_cookie_http_only, is_cookie_secure):
        cookie_key = UserInQueueStateCookieRepository.getCookieKey(event_id)
        self.httpContextProvider.setCookie(cookie_key, None, -1, cookie_domain, is_cookie_http_only, is_cookie_secure)

    def reissueQueueCookie(self, event_id, cookie_validity_minutes, cookie_domain,
                           is_cookie_http_only, is_cookie_secure, secret_key):
        cookie_key = UserInQueueStateCookieRepository.getCookieKey(event_id)
        cookie_value = self.httpContextProvider.getCookie(cookie_key)
        if cookie_value is None:
            return

        cookie_name_value_map = UserInQueueStateCookieRepository.__getCookieNameValueMap(cookie_value)
        if (not UserInQueueStateCookieRepository.__isCookieValid(
                secret_key, cookie_name_value_map, event_id, cookie_validity_minutes,
                True)):
            return

        fixed_cookie_validity_minutes = ""
        if "FixedValidityMins" in cookie_name_value_map:
            fixed_cookie_validity_minutes = cookie_name_value_map[
                "FixedValidityMins"]

        cookie_value = UserInQueueStateCookieRepository.__createCookieValue(
            event_id, cookie_name_value_map["QueueId"], fixed_cookie_validity_minutes,
            cookie_name_value_map["RedirectType"], secret_key)

        self.httpContextProvider.setCookie(
            cookie_key,
            cookie_value,
            QueueitHelpers.getCookieExpirationDate(),
            cookie_domain,
            is_cookie_http_only,
            is_cookie_secure)


class StateInfo:
    def __init__(self, is_found, is_valid, queue_id, fixed_cookie_validity_minutes, redirect_type):
        self.isFound = is_found
        self.isValid = is_valid
        self.queueId = queue_id
        self.fixedCookieValidityMinutes = fixed_cookie_validity_minutes
        self.redirectType = redirect_type

    def isStateExtendable(self):
        return self.isValid and Utils.isNilOrEmpty(
            self.fixedCookieValidityMinutes)
