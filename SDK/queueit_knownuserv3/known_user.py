from user_in_queue_service import UserInQueueService
from user_in_queue_state_cookie_repository import UserInQueueStateCookieRepository
from queueit_helpers import QueueitHelpers
from models import Utils, KnownUserError, ActionTypes, RequestValidationResult, QueueEventConfig, CancelEventConfig
from integration_config_helpers import IntegrationEvaluator
from connector_diagnostics import ConnectorDiagnostics
import json
import sys


class KnownUser:
    def __init__(self):
        pass

    QUEUEIT_TOKEN_KEY = "queueittoken"
    QUEUEIT_DEBUG_KEY = "queueitdebug"
    QUEUEIT_AJAX_HEADER_KEY = "x-queueit-ajaxpageurl"

    userInQueueService = None

    @staticmethod
    def __getUserInQueueService(http_context_provider):
        if KnownUser.userInQueueService is None:
            return UserInQueueService(
                http_context_provider,
                UserInQueueStateCookieRepository(http_context_provider))
        return KnownUser.userInQueueService

    @staticmethod
    def __isQueueAjaxCall(http_context_provider):
        return http_context_provider.getHeader(
            KnownUser.QUEUEIT_AJAX_HEADER_KEY) is not None

    @staticmethod
    def __generateTargetUrl(original_target_url, http_context_provider):
        if KnownUser.__isQueueAjaxCall(http_context_provider):
            return QueueitHelpers.urlDecode(
                http_context_provider.getHeader(
                    KnownUser.QUEUEIT_AJAX_HEADER_KEY))
        return original_target_url

    @staticmethod
    def __logMoreRequestDetails(debug_entries, http_context_provider):
        debug_entries["ServerUtcTime"] = QueueitHelpers.getCurrentTimeAsIso8601Str()
        debug_entries["RequestIP"] = http_context_provider.getRequestIp()
        debug_entries["RequestHttpHeader_Via"] = http_context_provider.getHeader("via")
        debug_entries["RequestHttpHeader_Forwarded"] = http_context_provider.getHeader("forwarded")
        debug_entries["RequestHttpHeader_XForwardedFor"] = http_context_provider.getHeader("x-forwarded-for")
        debug_entries["RequestHttpHeader_XForwardedHost"] = http_context_provider.getHeader("x-forwarded-host")
        debug_entries["RequestHttpHeader_XForwardedProto"] = http_context_provider.getHeader("x-forwarded-proto")

    @staticmethod
    def __setDebugCookie(debug_entries, http_context_provider):
        if debug_entries is None or len(debug_entries) == 0:
            return

        cookie_value = ''
        for k, v in debug_entries.iteritems():
            cookie_value += (k + '=' + str(v) + '|')

        cookie_value = cookie_value.strip('|')
        http_context_provider.setCookie(KnownUser.QUEUEIT_DEBUG_KEY, cookie_value, None, None, False, False)

    @staticmethod
    def __getRunTime():
        return sys.version

    @staticmethod
    def __resolveQueueRequestByLocalConfig(target_url, queueit_token, queue_config, customer_id, secret_key,
                                           http_context_provider, debug_entries, is_debug):
        if is_debug:
            debug_entries["SdkVersion"] = UserInQueueService.SDK_VERSION
            debug_entries["Connector"] = http_context_provider.getProviderName()
            debug_entries["Runtime"] = KnownUser.__getRunTime()
            debug_entries["TargetUrl"] = target_url
            debug_entries["QueueitToken"] = queueit_token
            debug_entries[
                "OriginalUrl"] = http_context_provider.getOriginalRequestUrl()
            if queue_config is None:
                debug_entries["QueueConfig"] = "NULL"
            else:
                debug_entries["QueueConfig"] = queue_config.toString()
            KnownUser.__logMoreRequestDetails(debug_entries,
                                              http_context_provider)

        if Utils.isNilOrEmpty(customer_id):
            raise KnownUserError("customerId can not be none or empty.")

        if Utils.isNilOrEmpty(secret_key):
            raise KnownUserError("secretKey can not be none or empty.")

        if queue_config is None:
            raise KnownUserError("queueConfig can not be none.")

        if Utils.isNilOrEmpty(queue_config.eventId):
            raise KnownUserError(
                "queueConfig.eventId can not be none or empty.")

        if Utils.isNilOrEmpty(queue_config.queueDomain):
            raise KnownUserError(
                "queueConfig.queueDomain can not be none or empty.")

        minutes = QueueitHelpers.convertToInt(queue_config.cookieValidityMinute)
        if minutes <= 0:
            raise KnownUserError(
                "queueConfig.cookieValidityMinute should be integer greater than 0."
            )

        if not isinstance(queue_config.extendCookieValidity, bool):
            raise KnownUserError(
                "queueConfig.extendCookieValidity should be valid boolean.")

        user_in_queue_service = KnownUser.__getUserInQueueService(http_context_provider)
        result = user_in_queue_service.validateQueueRequest(target_url, queueit_token, queue_config, customer_id,
                                                            secret_key)
        result.isAjaxResult = KnownUser.__isQueueAjaxCall(http_context_provider)
        return result

    @staticmethod
    def __cancelRequestByLocalConfig(target_url, queueit_token, cancel_config, customer_id, secret_key,
                                     http_context_provider, debug_entries, is_debug):
        target_url = KnownUser.__generateTargetUrl(target_url, http_context_provider)

        if is_debug:
            debug_entries["SdkVersion"] = UserInQueueService.SDK_VERSION
            debug_entries["Connector"] = http_context_provider.getProviderName()
            debug_entries["Runtime"] = KnownUser.__getRunTime()
            debug_entries["TargetUrl"] = target_url
            debug_entries["QueueitToken"] = queueit_token
            debug_entries["OriginalUrl"] = http_context_provider.getOriginalRequestUrl()
            if cancel_config is None:
                debug_entries["CancelConfig"] = "NULL"
            else:
                debug_entries["CancelConfig"] = cancel_config.toString()
            KnownUser.__logMoreRequestDetails(debug_entries,
                                              http_context_provider)

        if Utils.isNilOrEmpty(target_url):
            raise KnownUserError("targetUrl can not be none or empty.")

        if Utils.isNilOrEmpty(customer_id):
            raise KnownUserError("customerId can not be none or empty.")

        if Utils.isNilOrEmpty(secret_key):
            raise KnownUserError("secretKey can not be none or empty.")

        if cancel_config is None:
            raise KnownUserError("cancelConfig can not be none.")

        if Utils.isNilOrEmpty(cancel_config.eventId):
            raise KnownUserError(
                "cancelConfig.eventId can not be none or empty.")

        if Utils.isNilOrEmpty(cancel_config.queueDomain):
            raise KnownUserError(
                "cancelConfig.queueDomain can not be none or empty.")

        user_in_queue_service = KnownUser.__getUserInQueueService(http_context_provider)
        result = user_in_queue_service.validateCancelRequest(target_url, cancel_config, customer_id, secret_key)
        result.isAjaxResult = KnownUser.__isQueueAjaxCall(http_context_provider)

        return result

    @staticmethod
    def __handleQueueAction(current_url_without_queueit_token, queueit_token,
                            customer_integration, customer_id, secret_key,
                            matched_config, http_context_provider, debug_entries, is_debug):
        queue_config = QueueEventConfig()
        queue_config.eventId = matched_config["EventId"]
        queue_config.layoutName = matched_config["LayoutName"]
        queue_config.culture = matched_config["Culture"]
        queue_config.queueDomain = matched_config["QueueDomain"]
        queue_config.extendCookieValidity = matched_config["ExtendCookieValidity"]
        queue_config.cookieValidityMinute = matched_config["CookieValidityMinute"]
        queue_config.cookieDomain = matched_config["CookieDomain"]
        queue_config.isCookieHttpOnly = matched_config[
            "IsCookieHttpOnly"] if "IsCookieHttpOnly" in matched_config else False
        queue_config.isCookieSecure = matched_config["IsCookieSecure"] if "IsCookieSecure" in matched_config else False
        queue_config.version = customer_integration["Version"]
        queue_config.actionName = matched_config["Name"]

        redirect_logic = matched_config["RedirectLogic"]

        if redirect_logic == "ForcedTargetUrl":
            target_url = matched_config["ForcedTargetUrl"]
        elif redirect_logic == "EventTargetUrl":
            target_url = ""
        else:
            target_url = KnownUser.__generateTargetUrl(
                current_url_without_queueit_token, http_context_provider)

        return KnownUser.__resolveQueueRequestByLocalConfig(
            target_url, queueit_token, queue_config, customer_id, secret_key,
            http_context_provider, debug_entries, is_debug)

    @staticmethod
    def __handleCancelAction(current_url_without_queueit_token, queueit_token,
                             customer_integration, customer_id, secret_key,
                             matched_config, http_context_provider, debug_entries, is_debug):
        cancel_config = CancelEventConfig()
        cancel_config.eventId = matched_config["EventId"]
        cancel_config.queueDomain = matched_config["QueueDomain"]
        cancel_config.version = customer_integration["Version"]
        cancel_config.cookieDomain = matched_config["CookieDomain"]
        cancel_config.isCookieHttpOnly = matched_config[
            "IsCookieHttpOnly"] if "IsCookieHttpOnly" in matched_config else False
        cancel_config.isCookieSecure = matched_config["IsCookieSecure"] if "IsCookieSecure" in matched_config else False
        cancel_config.actionName = matched_config["Name"]

        return KnownUser.__cancelRequestByLocalConfig(
            current_url_without_queueit_token, queueit_token, cancel_config,
            customer_id, secret_key, http_context_provider, debug_entries, is_debug)

    @staticmethod
    def extendQueueCookie(event_id, cookie_validity_minute, cookie_domain,
                          is_cookie_http_only, is_cookie_secure, secret_key, http_context_provider):
        if Utils.isNilOrEmpty(event_id):
            raise KnownUserError("eventId can not be none or empty.")

        if Utils.isNilOrEmpty(secret_key):
            raise KnownUserError("secretKey can not be none or empty.")

        minutes = QueueitHelpers.convertToInt(cookie_validity_minute)
        if minutes <= 0:
            raise KnownUserError(
                "cookieValidityMinute should be integer greater than 0.")

        user_in_queue_service = KnownUser.__getUserInQueueService(
            http_context_provider)

        user_in_queue_service.extendQueueCookie(
            event_id,
            cookie_validity_minute,
            cookie_domain,
            is_cookie_http_only,
            is_cookie_secure,
            secret_key)

    @staticmethod
    def resolveQueueRequestByLocalConfig(target_url, queueit_token, queue_config,
                                         customer_id, secret_key,
                                         http_context_provider):
        debug_entries = {}
        connector_diagnostics = ConnectorDiagnostics.verify(customer_id, secret_key, queueit_token)
        if connector_diagnostics.hasError:
            return connector_diagnostics.validationResult
        try:
            target_url = KnownUser.__generateTargetUrl(target_url,
                                                       http_context_provider)
            return KnownUser.__resolveQueueRequestByLocalConfig(
                target_url, queueit_token, queue_config, customer_id, secret_key,
                http_context_provider, debug_entries, connector_diagnostics.isEnabled)
        except Exception as e:
            if connector_diagnostics.isEnabled:
                debug_entries["Exception"] = e.message
            raise e
        finally:
            KnownUser.__setDebugCookie(debug_entries, http_context_provider)

    @staticmethod
    def validateRequestByIntegrationConfig(
            current_url_without_queueit_token, queueit_token,
            integration_config_string, customer_id, secret_key,
            http_context_provider):

        debug_entries = {}
        connector_diagnostics = ConnectorDiagnostics.verify(customer_id, secret_key, queueit_token)
        if connector_diagnostics.hasError:
            return connector_diagnostics.validationResult
        try:
            if connector_diagnostics.isEnabled:
                debug_entries["SdkVersion"] = UserInQueueService.SDK_VERSION
                debug_entries["Connector"] = http_context_provider.getProviderName()
                debug_entries["Runtime"] = KnownUser.__getRunTime()
                debug_entries["PureUrl"] = current_url_without_queueit_token
                debug_entries["QueueitToken"] = queueit_token
                debug_entries["OriginalUrl"] = http_context_provider.getOriginalRequestUrl()
                KnownUser.__logMoreRequestDetails(debug_entries, http_context_provider)

            customer_integration = json.loads(integration_config_string)
            if connector_diagnostics.isEnabled:
                debug_entries["ConfigVersion"] = "NULL"
                if customer_integration and "Version" in customer_integration:
                    debug_entries["ConfigVersion"] = customer_integration["Version"]

            if Utils.isNilOrEmpty(current_url_without_queueit_token):
                raise KnownUserError(
                    "currentUrlWithoutQueueITToken can not be none or empty.")

            if not customer_integration or not customer_integration["Version"]:
                raise KnownUserError(
                    "integrationsConfigString can not be none or empty.")

            matched_config = IntegrationEvaluator().getMatchedIntegrationConfig(
                customer_integration, current_url_without_queueit_token,
                http_context_provider)

            if connector_diagnostics.isEnabled:
                if matched_config is None:
                    debug_entries["MatchedConfig"] = "NULL"
                else:
                    debug_entries["MatchedConfig"] = matched_config["Name"]

            if matched_config is None:
                return RequestValidationResult(None, None, None, None, None, None)

            if matched_config["ActionType"] == ActionTypes.QUEUE:
                return KnownUser.__handleQueueAction(
                    current_url_without_queueit_token, queueit_token,
                    customer_integration, customer_id, secret_key, matched_config,
                    http_context_provider, debug_entries, connector_diagnostics.isEnabled)
            elif matched_config["ActionType"] == ActionTypes.CANCEL:
                return KnownUser.__handleCancelAction(
                    current_url_without_queueit_token, queueit_token,
                    customer_integration, customer_id, secret_key, matched_config,
                    http_context_provider, debug_entries, connector_diagnostics.isEnabled)
            else:  # for all unknown types default to 'Ignore'
                user_in_queue_service = KnownUser.__getUserInQueueService(
                    http_context_provider)
                result = user_in_queue_service.getIgnoreActionResult(matched_config['Name'])
                result.isAjaxResult = KnownUser.__isQueueAjaxCall(
                    http_context_provider)
                return result
        except Exception as e:
            if connector_diagnostics.isEnabled:
                debug_entries["Exception"] = e.message
            raise e
        finally:
            KnownUser.__setDebugCookie(debug_entries, http_context_provider)
            pass

    @staticmethod
    def cancelRequestByLocalConfig(target_url, queueit_token, cancel_config,
                                   customer_id, secret_key, http_context_provider):
        debug_entries = {}
        connector_diagnostics = ConnectorDiagnostics.verify(customer_id, secret_key, queueit_token)
        if connector_diagnostics.hasError:
            return connector_diagnostics.validationResult
        try:
            return KnownUser.__cancelRequestByLocalConfig(
                target_url, queueit_token, cancel_config, customer_id, secret_key,
                http_context_provider, debug_entries, connector_diagnostics.isEnabled)
        except Exception as e:
            if connector_diagnostics.isEnabled:
                debug_entries["Exception"] = e.message
            raise e
        finally:
            KnownUser.__setDebugCookie(debug_entries, http_context_provider)
