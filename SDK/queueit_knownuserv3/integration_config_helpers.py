from queueit_helpers import QueueitHelpers


class ValidatorType:
    def __init__(self):
        pass

    UrlValidator = 'UrlValidator'
    CookieValidator = 'CookieValidator'
    UserAgentValidator = 'UserAgentValidator'
    HttpHeaderValidator = 'HttpHeaderValidator'
    RequestBodyValidator = 'RequestBodyValidator'


class IntegrationEvaluator:
    def getMatchedIntegrationConfig(self, customer_integration, current_page_url,
                                    http_context_provider):
        if (not isinstance(customer_integration, dict)
                or "Integrations" not in customer_integration
                or customer_integration.get("Integrations") is None
                or not isinstance(customer_integration["Integrations"], list)):
            return None

        for integrationConfig in customer_integration["Integrations"]:
            if (not isinstance(integrationConfig, dict)
                    or "Triggers" not in integrationConfig
                    or integrationConfig.get("Triggers") is None or
                    not isinstance(integrationConfig.get("Triggers"), list)):
                continue

            for trigger in integrationConfig["Triggers"]:
                if not isinstance(trigger, dict):
                    return False
                if (self.evaluateTrigger(trigger, current_page_url,
                                         http_context_provider)):
                    return integrationConfig

        return None

    def evaluateTrigger(self, trigger, current_page_url, http_context_provider):
        if (trigger.get("LogicalOperator") is None
                or "TriggerParts" not in trigger
                or trigger.get("TriggerParts") is None
                or not isinstance(trigger.get("TriggerParts"), list)):
            return False

        if trigger.get("LogicalOperator") == "Or":
            for triggerPart in trigger["TriggerParts"]:
                if not isinstance(triggerPart, dict):
                    return False
                if (self.evaluateTriggerPart(triggerPart, current_page_url,
                                             http_context_provider)):
                    return True
            return False
        else:
            for triggerPart in trigger["TriggerParts"]:
                if not isinstance(triggerPart, dict):
                    return False
                if (not self.evaluateTriggerPart(triggerPart, current_page_url,
                                                 http_context_provider)):
                    return False
            return True

    def evaluateTriggerPart(self, trigger_part, current_page_url,
                            http_context_provider):
        validator_type = trigger_part.get("ValidatorType")
        if validator_type is None:
            return False

        if validator_type == ValidatorType.UrlValidator:
            return UrlValidatorHelper.evaluate(trigger_part, current_page_url)
        elif validator_type == ValidatorType.CookieValidator:
            return CookieValidatorHelper.evaluate(trigger_part,
                                                  http_context_provider)
        elif validator_type == ValidatorType.UserAgentValidator:
            return UserAgentValidatorHelper.evaluate(trigger_part,
                                                     http_context_provider)
        elif validator_type == ValidatorType.HttpHeaderValidator:
            return HttpHeaderValidatorHelper.evaluate(trigger_part,
                                                      http_context_provider)
        elif validator_type == ValidatorType.RequestBodyValidator:
            return RequestBodyValidatorHelper.evaluate(trigger_part,
                                                       http_context_provider)

        return False


class UrlValidatorHelper:
    @staticmethod
    def evaluate(trigger_part, url):
        try:
            if (trigger_part is None
                    or "Operator" not in trigger_part
                    or "IsNegative" not in trigger_part
                    or "IsIgnoreCase" not in trigger_part
                    or "UrlPart" not in trigger_part):
                return False

            urlPart = UrlValidatorHelper.getUrlPart(trigger_part['UrlPart'],
                                                    url)

            return ComparisonOperatorHelper.evaluate(
                trigger_part["Operator"], trigger_part["IsNegative"],
                trigger_part["IsIgnoreCase"], urlPart,
                trigger_part.get("ValueToCompare"),
                trigger_part.get("ValuesToCompare"))
        except:
            return False

    @staticmethod
    def getUrlPart(url_part, url):
        try:
            uri = QueueitHelpers.urlParse(url)

            if url_part == "PagePath":
                return uri.path
            elif url_part == "PageUrl":
                return url
            elif url_part == "HostName":
                return uri.hostname
            return ''
        except:
            return ''


class CookieValidatorHelper:
    @staticmethod
    def evaluate(trigger_part, http_context_provider):
        try:
            if (trigger_part is None
                    or "Operator" not in trigger_part
                    or "IsNegative" not in trigger_part
                    or "IsIgnoreCase" not in trigger_part
                    or "CookieName" not in trigger_part):
                return False

            cookie_value = http_context_provider.getCookie(
                trigger_part['CookieName'])

            return ComparisonOperatorHelper.evaluate(
                trigger_part["Operator"], trigger_part["IsNegative"],
                trigger_part["IsIgnoreCase"], cookie_value,
                trigger_part.get("ValueToCompare"),
                trigger_part.get("ValuesToCompare"))
        except:
            return False


class UserAgentValidatorHelper:
    @staticmethod
    def evaluate(trigger_part, http_context_provider):
        try:
            if (trigger_part is None or "Operator" not in trigger_part
                    or "IsNegative" not in trigger_part
                    or "IsIgnoreCase" not in trigger_part):
                return False

            user_agent = http_context_provider.getHeader("user-agent")

            return ComparisonOperatorHelper.evaluate(
                trigger_part["Operator"], trigger_part["IsNegative"],
                trigger_part["IsIgnoreCase"], user_agent,
                trigger_part.get("ValueToCompare"),
                trigger_part.get("ValuesToCompare"))
        except:
            return False


class RequestBodyValidatorHelper:
    def __init__(self):
        pass

    @staticmethod
    def evaluate(trigger_part, http_context_provider):
        try:
            if (trigger_part is None
                    or "Operator" not in trigger_part
                    or "IsNegative" not in trigger_part
                    or "IsIgnoreCase" not in trigger_part):
                return False

            request_body = http_context_provider.getRequestBodyAsString()
            return ComparisonOperatorHelper.evaluate(
                trigger_part["Operator"], trigger_part["IsNegative"],
                trigger_part["IsIgnoreCase"], request_body,
                trigger_part.get("ValueToCompare"),
                trigger_part.get("ValuesToCompare"))
        except:
            return False


class HttpHeaderValidatorHelper:
    @staticmethod
    def evaluate(trigger_part, http_context_provider):
        try:
            if (trigger_part is None
                    or "Operator" not in trigger_part
                    or "IsNegative" not in trigger_part
                    or "IsIgnoreCase" not in trigger_part
                    or "HttpHeaderName" not in trigger_part):
                return False

            header_value = http_context_provider.getHeader(
                trigger_part['HttpHeaderName'])

            return ComparisonOperatorHelper.evaluate(
                trigger_part["Operator"], trigger_part["IsNegative"],
                trigger_part["IsIgnoreCase"], header_value,
                trigger_part.get("ValueToCompare"),
                trigger_part.get("ValuesToCompare"))
        except:
            return False


class ComparisonOperatorHelper:
    @staticmethod
    def evaluate(opt, is_negative, ignore_case, value, value_to_compare,
                 values_to_compare):
        if value is None:
            value = ''

        if value_to_compare is None:
            value_to_compare = ''

        if values_to_compare is None:
            values_to_compare = []

        if opt == "Equals":
            return ComparisonOperatorHelper.equals(value, value_to_compare,
                                                   is_negative, ignore_case)
        if opt == "Contains":
            return ComparisonOperatorHelper.contains(value, value_to_compare,
                                                     is_negative, ignore_case)
        if opt == "EqualsAny":
            return ComparisonOperatorHelper.equalsAny(value, values_to_compare,
                                                      is_negative, ignore_case)
        if opt == "ContainsAny":
            return ComparisonOperatorHelper.containsAny(
                value, values_to_compare, is_negative, ignore_case)

        return False

    @staticmethod
    def equals(value, value_to_compare, is_negative, ignore_case):
        if ignore_case:
            evaluation = value.upper() == value_to_compare.upper()
        else:
            evaluation = value == value_to_compare

        if is_negative:
            return not evaluation
        else:
            return evaluation

    @staticmethod
    def contains(value, value_to_compare, is_negative, ignore_case):
        if value_to_compare == "*" and value != '':
            return True

        if ignore_case:
            value = value.upper()
            value_to_compare = value_to_compare.upper()

        evaluation = value_to_compare in value
        if is_negative:
            return not evaluation
        else:
            return evaluation

    @staticmethod
    def equalsAny(value, values_to_compare, is_negative, ignore_case):
        for valueToCompare in values_to_compare:
            if (ComparisonOperatorHelper.equals(value, valueToCompare, False,
                                                ignore_case)):
                return not is_negative
        return is_negative

    @staticmethod
    def containsAny(value, values_to_compare, is_negative, ignore_case):
        for valueToCompare in values_to_compare:
            if (ComparisonOperatorHelper.contains(value, valueToCompare, False,
                                                  ignore_case)):
                return not is_negative
        return is_negative
