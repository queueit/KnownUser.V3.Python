from models import RequestValidationResult, ActionTypes, Utils
from queue_url_params import QueueUrlParams
from user_in_queue_state_cookie_repository import UserInQueueStateCookieRepository
from queueit_helpers import QueueitHelpers


class UserInQueueService:
    SDK_VERSION = "3.5.1"

    def __init__(self, httpContextProvider, userInQueueStateRepository):
        self.httpContextProvider = httpContextProvider
        self.userInQueueStateRepository = userInQueueStateRepository

    def __getQueueITTokenValidationResult(self, targetUrl, eventId, config,
                                          queueParams, customerId, secretKey):
        calculatedHash = QueueitHelpers.hmacSha256Encode(
            queueParams.queueITTokenWithoutHash, secretKey)

        if (calculatedHash.upper() != queueParams.hashCode.upper()):
            return self.__getVaidationErrorResult(customerId, targetUrl,
                                                  config, queueParams, "hash")

        if (queueParams.eventId.upper() != eventId.upper()):
            return self.__getVaidationErrorResult(
                customerId, targetUrl, config, queueParams, "eventid")

        if (queueParams.timeStamp <
                QueueitHelpers.getCurrentTime()):
            return self.__getVaidationErrorResult(
                customerId, targetUrl, config, queueParams, "timestamp")

        cookieDomain = ""
        if (not Utils.isNilOrEmpty(config.cookieDomain)):
            cookieDomain = config.cookieDomain

        self.userInQueueStateRepository.store(
            config.eventId, queueParams.queueId,
            queueParams.cookieValidityMinutes, cookieDomain,
            queueParams.redirectType, secretKey)
        return RequestValidationResult(ActionTypes.QUEUE, config.eventId,
                                       queueParams.queueId, None,
                                       queueParams.redirectType)

    def __getVaidationErrorResult(self, customerId, targetUrl, config, qParams,
                                  errorCode):
        targetUrlParam = ""
        if (not Utils.isNilOrEmpty(targetUrl)):
            targetUrlParam = "&t=" + QueueitHelpers.urlEncode(
                targetUrl)

        query = self.__getQueryString(
            customerId, config.eventId, config.version, config.culture,
            config.layoutName
        ) + "&queueittoken=" + qParams.queueITToken + "&ts=" + str(
            QueueitHelpers.getCurrentTime()) + targetUrlParam

        domainAlias = config.queueDomain
        if (not domainAlias.endswith("/")):
            domainAlias = domainAlias + "/"

        redirectUrl = "https://" + domainAlias + "error/" + errorCode + "/?" + query
        return RequestValidationResult(ActionTypes.QUEUE, config.eventId, None,
                                       redirectUrl, None)

    def __getInQueueRedirectResult(self, targetUrl, config, customerId):
        targetUrlParam = ""
        if (not Utils.isNilOrEmpty(targetUrl)):
            targetUrlParam = "&t=" + QueueitHelpers.urlEncode(
                targetUrl)

        domainAlias = config.queueDomain
        if (not domainAlias.endswith("/")):
            domainAlias = domainAlias + "/"

        qs = self.__getQueryString(customerId, config.eventId, config.version,
                                   config.culture, config.layoutName)
        redirectUrl = "https://" + domainAlias + "?" + qs + targetUrlParam

        return RequestValidationResult(ActionTypes.QUEUE, config.eventId, None,
                                       redirectUrl, None)

    def __getQueryString(self, customerId, eventId, configVersion, culture,
                         layoutName):
        queryStringList = []
        queryStringList.append(
            "c=" + QueueitHelpers.urlEncode(customerId))
        queryStringList.append(
            "e=" + QueueitHelpers.urlEncode(eventId))
        queryStringList.append("ver=v3-py_" +
                               self.httpContextProvider.getProviderName() +
                               "-" + self.SDK_VERSION)

        if (configVersion is None):
            configVersion = "-1"
        queryStringList.append("cver=" + str(configVersion))

        if (not Utils.isNilOrEmpty(culture)):
            queryStringList.append(
                "cid=" + QueueitHelpers.urlEncode(culture))

        if (not Utils.isNilOrEmpty(layoutName)):
            queryStringList.append(
                "l=" + QueueitHelpers.urlEncode(layoutName))

        return "&".join(queryStringList)

    def validateQueueRequest(self, targetUrl, queueitToken, config, customerId,
                             secretKey):
        state = self.userInQueueStateRepository.getState(
            config.eventId, config.cookieValidityMinute, secretKey, True)

        if (state.isValid):
            if (state.isStateExtendable() and config.extendCookieValidity):
                self.userInQueueStateRepository.store(
                    config.eventId, state.queueId, None,
                    Utils.toString(config.cookieDomain), state.redirectType,
                    secretKey)
            result = RequestValidationResult(ActionTypes.QUEUE, config.eventId,
                                             state.queueId, None,
                                             state.redirectType)
            return result

        queueParams = QueueUrlParams.extractQueueParams(queueitToken)
        if (queueParams is not None):
            return self.__getQueueITTokenValidationResult(
                targetUrl, config.eventId, config, queueParams, customerId,
                secretKey)
        else:
            return self.__getInQueueRedirectResult(targetUrl, config,
                                                   customerId)

    def validateCancelRequest(self, targetUrl, cancelConfig, customerId,
                              secretKey):
        state = self.userInQueueStateRepository.getState(
            cancelConfig.eventId, -1, secretKey, False)
        if (state.isValid):
            self.userInQueueStateRepository.cancelQueueCookie(
                cancelConfig.eventId, cancelConfig.cookieDomain)

            targetUrlParam = ""
            if (not Utils.isNilOrEmpty(targetUrl)):
                targetUrlParam = "&r=" + QueueitHelpers.urlEncode(
                    targetUrl)

            query = self.__getQueryString(customerId, cancelConfig.eventId,
                                          cancelConfig.version, None,
                                          None) + targetUrlParam

            domainAlias = cancelConfig.queueDomain
            if (not domainAlias.endswith("/")):
                domainAlias = domainAlias + "/"

            redirectUrl = "https://" + domainAlias + "cancel/" + customerId + "/" + cancelConfig.eventId + "/?" + query
            return RequestValidationResult(ActionTypes.CANCEL,
                                           cancelConfig.eventId, state.queueId,
                                           redirectUrl, state.redirectType)
        else:
            return RequestValidationResult(
                ActionTypes.CANCEL, cancelConfig.eventId, None, None, None)

    def extendQueueCookie(self, eventId, cookieValidityMinutes, cookieDomain,
                          secretKey):
        self.userInQueueStateRepository.reissueQueueCookie(
            eventId, cookieValidityMinutes, cookieDomain, secretKey)

    def getIgnoreActionResult(self):
        return RequestValidationResult(ActionTypes.IGNORE, None, None, None,
                                       None)
