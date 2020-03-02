from models import Utils as Utils


class QueueUrlParams:
    KEY_VALUE_SEPARATOR_GROUP_CHAR = '~'
    KEY_VALUE_SEPARATOR_CHAR = '_'
    TIMESTAMP_KEY = "ts"
    COOKIE_VALIDITY_MINUTES_KEY = "cv"
    EVENT_ID_KEY = "e"
    EXTENDABLE_COOKIE_KEY = "ce"
    HASH_KEY = "h"
    QUEUE_ID_KEY = "q"
    REDIRECT_TYPE_KEY = "rt"

    def __init__(self):
        self.timeStamp = 0
        self.eventId = ""
        self.hashCode = ""
        self.extendableCookie = False
        self.cookieValidityMinutes = None
        self.queueITToken = ""
        self.queueITTokenWithoutHash = ""
        self.queueId = ""
        self.redirectType = None

    @staticmethod
    def extractQueueParams(queueitToken):
        result = QueueUrlParams()
        if (Utils.isNilOrEmpty(queueitToken)):
            return None
        result.queueITToken = queueitToken
        paramsNameValueList = result.queueITToken.split(QueueUrlParams.KEY_VALUE_SEPARATOR_GROUP_CHAR)
        for pNameValue in paramsNameValueList:
            paramNameValueArr = pNameValue.split(QueueUrlParams.KEY_VALUE_SEPARATOR_CHAR)
            if(len(paramNameValueArr) != 2):
                continue
            if (paramNameValueArr[0] == QueueUrlParams.HASH_KEY):
                result.hashCode = paramNameValueArr[1]
            elif (paramNameValueArr[0] == QueueUrlParams.TIMESTAMP_KEY):
                if(not paramNameValueArr[1].isdigit()):
                    continue
                result.timeStamp = int(paramNameValueArr[1])
            elif (paramNameValueArr[0] == QueueUrlParams.COOKIE_VALIDITY_MINUTES_KEY):
                if (not paramNameValueArr[1].isdigit()):
                    continue
                result.cookieValidityMinutes = int(paramNameValueArr[1])
            elif (paramNameValueArr[0] == QueueUrlParams.EVENT_ID_KEY):
                result.eventId = paramNameValueArr[1]
            elif (paramNameValueArr[0] == QueueUrlParams.EXTENDABLE_COOKIE_KEY):
                if (paramNameValueArr[1].upper() == 'TRUE'):
                    result.extendableCookie = True
            elif (paramNameValueArr[0] == QueueUrlParams.QUEUE_ID_KEY):
                result.queueId = paramNameValueArr[1]
            elif (paramNameValueArr[0] == QueueUrlParams.REDIRECT_TYPE_KEY):
                result.redirectType = paramNameValueArr[1]

        hashValue = QueueUrlParams.KEY_VALUE_SEPARATOR_GROUP_CHAR + QueueUrlParams.HASH_KEY \
        + QueueUrlParams.KEY_VALUE_SEPARATOR_CHAR \
        + result.hashCode
        result.queueITTokenWithoutHash = result.queueITToken.replace(hashValue, "")
        return result
