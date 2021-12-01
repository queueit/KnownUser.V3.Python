from models import RequestValidationResult, ActionTypes, Utils
from queue_url_params import QueueUrlParams
from queueit_helpers import QueueitHelpers


class UserInQueueService:
    SDK_VERSION = "v3-python-" + "3.7.0"

    def __init__(self, http_context_provider, user_in_queue_state_repository):
        self.httpContextProvider = http_context_provider
        self.userInQueueStateRepository = user_in_queue_state_repository

    def __getValidTokenResult(self, config, queue_params, secret_key):

        cookie_domain = ""
        if not Utils.isNilOrEmpty(config.cookieDomain):
            cookie_domain = config.cookieDomain

        self.userInQueueStateRepository.store(
            config.eventId,
            queue_params.queueId,
            queue_params.cookieValidityMinutes,
            cookie_domain,
            config.isCookieHttpOnly,
            config.isCookieSecure,
            queue_params.redirectType,
            secret_key)

        return RequestValidationResult(ActionTypes.QUEUE, config.eventId,
                                       queue_params.queueId, None,
                                       queue_params.redirectType, config.actionName)

    def __getErrorResult(self, customer_id, target_url, config, q_params, error_code):
        time_stamp = str(QueueitHelpers.getCurrentTime())
        target_url_param = ""
        if not Utils.isNilOrEmpty(target_url):
            target_url_param = "&t={}".format(QueueitHelpers.urlEncode(target_url))

        query_string = self.__getQueryString(customer_id, config.eventId, config.version, config.actionName,
                                             config.culture, config.layoutName)
        query = "{}&queueittoken={}&ts={}{}".format(query_string, q_params.queueITToken, time_stamp, target_url_param)
        redirect_url = self.__generateRedirectUrl(config.queueDomain, "error/{}/".format(error_code), query)

        return RequestValidationResult(ActionTypes.QUEUE, config.eventId, None, redirect_url, None, config.actionName)

    def __getQueueResult(self, target_url, config, customer_id):
        target_url_param = ""
        if not Utils.isNilOrEmpty(target_url):
            target_url_param = "&t={}".format(QueueitHelpers.urlEncode(target_url))
        query_string = self.__getQueryString(customer_id, config.eventId, config.version, config.actionName,
                                             config.culture, config.layoutName)
        query = "{}{}".format(query_string, target_url_param)
        redirect_url = self.__generateRedirectUrl(config.queueDomain, "", query)

        return RequestValidationResult(ActionTypes.QUEUE, config.eventId, None, redirect_url, None, config.actionName)

    def __generateRedirectUrl(self, queue_domain, uri_path, query):
        if not queue_domain.endswith("/"):
            queue_domain = queue_domain + "/"

        return "https://{}{}?{}".format(queue_domain, uri_path, query)

    def __getQueryString(self, customer_id, event_id, config_version, action_name, culture,
                         layout_name):
        query_string_list = [
            "c=" + QueueitHelpers.urlEncode(customer_id),
            "e=" + QueueitHelpers.urlEncode(event_id),
            "ver=" + self.SDK_VERSION,
            "kupver=" + QueueitHelpers.urlEncode(self.httpContextProvider.getProviderName())
        ]
        if config_version is None:
            config_version = "-1"
        query_string_list.append("cver=" + str(config_version))
        query_string_list.append("man=" + QueueitHelpers.urlEncode(action_name))

        if not Utils.isNilOrEmpty(culture):
            query_string_list.append("cid=" + QueueitHelpers.urlEncode(culture))

        if not Utils.isNilOrEmpty(layout_name):
            query_string_list.append("l=" + QueueitHelpers.urlEncode(layout_name))

        return "&".join(query_string_list)

    def __validateToken(self, config, queue_params, secret_key):
        calculated_hash = QueueitHelpers.hmacSha256Encode(
            queue_params.queueITTokenWithoutHash, secret_key)

        if calculated_hash.upper() != queue_params.hashCode.upper():
            return TokenValidationResult(False, "hash")

        if queue_params.eventId.upper() != config.eventId.upper():
            return TokenValidationResult(False, "eventid")

        if queue_params.timeStamp < QueueitHelpers.getCurrentTime():
            return TokenValidationResult(False, "timestamp")

        return TokenValidationResult(True, None)

    def validateQueueRequest(self, target_url, queueit_token, config, customer_id, secret_key):
        state = self.userInQueueStateRepository.getState(
            config.eventId, config.cookieValidityMinute, secret_key, True)

        if state.isValid:
            if state.isStateExtendable() and config.extendCookieValidity:
                self.userInQueueStateRepository.store(
                    config.eventId,
                    state.queueId, None,
                    Utils.toString(config.cookieDomain),
                    config.isCookieHttpOnly,
                    config.isCookieSecure,
                    state.redirectType, secret_key)

            result = RequestValidationResult(ActionTypes.QUEUE, config.eventId,
                                             state.queueId, None,
                                             state.redirectType, config.actionName)
            return result

        queue_params = QueueUrlParams.extractQueueParams(queueit_token)
        request_validation_result = RequestValidationResult(None, None, None, None, None, None)
        is_token_valid = False

        if queue_params is not None:
            token_validation_result = self.__validateToken(config, queue_params, secret_key)
            is_token_valid = token_validation_result.isValid
            if is_token_valid:
                request_validation_result = self.__getValidTokenResult(config, queue_params, secret_key)
            else:
                request_validation_result = self.__getErrorResult(customer_id, target_url, config, queue_params,
                                                                  token_validation_result.errorCode)
        else:
            request_validation_result = self.__getQueueResult(target_url, config, customer_id)

        if state.isFound and not is_token_valid:
            self.userInQueueStateRepository.cancelQueueCookie(
                config.eventId,
                config.cookieDomain,
                config.isCookieHttpOnly,
                config.isCookieSecure)

        return request_validation_result

    def validateCancelRequest(self, target_url, cancel_config, customer_id, secret_key):

        state = self.userInQueueStateRepository.getState(cancel_config.eventId, -1, secret_key, False)

        if state.isValid:
            self.userInQueueStateRepository.cancelQueueCookie(
                cancel_config.eventId,
                cancel_config.cookieDomain,
                cancel_config.isCookieHttpOnly,
                cancel_config.isCookieSecure)

            target_url_param = ""
            if not Utils.isNilOrEmpty(target_url):
                target_url_param = "&r={}".format(QueueitHelpers.urlEncode(target_url))

            query_string = self.__getQueryString(customer_id, cancel_config.eventId, cancel_config.version,
                                                 cancel_config.actionName, None, None)

            query = "{}{}".format(query_string, target_url_param)

            uri_path = "cancel/{}/{}".format(customer_id, cancel_config.eventId)

            if state.queueId:
                uri_path = "{}/{}".format(uri_path, state.queueId)

            redirect_url = self.__generateRedirectUrl(cancel_config.queueDomain, uri_path, query)

            return RequestValidationResult(ActionTypes.CANCEL,
                                           cancel_config.eventId, state.queueId,
                                           redirect_url, state.redirectType, cancel_config.actionName)
        else:
            return RequestValidationResult(
                ActionTypes.CANCEL, cancel_config.eventId, None, None, None, cancel_config.actionName)

    def extendQueueCookie(self, event_id, cookie_validity_minutes, cookie_domain,
                          is_cookie_http_only, is_cookie_secure, secret_key):
        self.userInQueueStateRepository.reissueQueueCookie(
            event_id, cookie_validity_minutes, cookie_domain, is_cookie_http_only, is_cookie_secure, secret_key)

    def getIgnoreActionResult(self, action_name):
        return RequestValidationResult(ActionTypes.IGNORE, None, None, None, None, action_name)


class TokenValidationResult:
    def __init__(self, is_valid, error_code):
        self.isValid = is_valid
        self.errorCode = error_code
