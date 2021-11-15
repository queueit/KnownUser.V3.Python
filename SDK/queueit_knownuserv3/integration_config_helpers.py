from .queueit_helpers import QueueitHelpers


class IntegrationEvaluator:
    def getMatchedIntegrationConfig(self, customerIntegration, currentPageUrl,
                                    httpContextProvider):
        if (not isinstance(customerIntegration, dict)
                or customerIntegration.get("Integrations") == None
                or not isinstance(customerIntegration["Integrations"], list)):
            return None

        for integrationConfig in customerIntegration["Integrations"]:
            if (not isinstance(integrationConfig, dict)
                    or integrationConfig.get("Triggers") == None or
                    not isinstance(integrationConfig.get("Triggers"), list)):
                continue

            for trigger in integrationConfig["Triggers"]:
                if (not isinstance(trigger, dict)):
                    return False
                if (self.evaluateTrigger(trigger, currentPageUrl,
                                         httpContextProvider)):
                    return integrationConfig

        return None

    def evaluateTrigger(self, trigger, currentPageUrl, httpContextProvider):
        if (trigger.get("LogicalOperator") == None
                or trigger.get("TriggerParts") == None
                or not isinstance(trigger.get("TriggerParts"), list)):
            return False

        if (trigger.get("LogicalOperator") == "Or"):
            for triggerPart in trigger["TriggerParts"]:
                if (not isinstance(triggerPart, dict)):
                    return False
                if (self.evaluateTriggerPart(triggerPart, currentPageUrl,
                                             httpContextProvider)):
                    return True
            return False
        else:
            for triggerPart in trigger["TriggerParts"]:
                if (not isinstance(triggerPart, dict)):
                    return False
                if (not self.evaluateTriggerPart(triggerPart, currentPageUrl,
                                                 httpContextProvider)):
                    return False
            return True

    def evaluateTriggerPart(self, triggerPart, currentPageUrl,
                            httpContextProvider):
        validatorType = triggerPart.get("ValidatorType")
        if (validatorType == None):
            return False

        if (validatorType == "UrlValidator"):
            return UrlValidatorHelper.evaluate(triggerPart, currentPageUrl)
        if (validatorType == "CookieValidator"):
            return CookieValidatorHelper.evaluate(triggerPart,
                                                  httpContextProvider)
        if (validatorType == "UserAgentValidator"):
            return UserAgentValidatorHelper.evaluate(triggerPart,
                                                     httpContextProvider)
        if (validatorType == "HttpHeaderValidator"):
            return HttpHeaderValidatorHelper.evaluate(triggerPart,
                                                      httpContextProvider)

        return False


class UrlValidatorHelper:
    @staticmethod
    def evaluate(triggerPart, url):
        try:
            if (triggerPart == None or "Operator" not in triggerPart
                    or "IsNegative" not in triggerPart
                    or "IsIgnoreCase" not in triggerPart
                    or "UrlPart" not in triggerPart):
                return False

            urlPart = UrlValidatorHelper.getUrlPart(triggerPart['UrlPart'],
                                                    url)

            return ComparisonOperatorHelper.evaluate(
                triggerPart["Operator"], triggerPart["IsNegative"],
                triggerPart["IsIgnoreCase"], urlPart,
                triggerPart.get("ValueToCompare"),
                triggerPart.get("ValuesToCompare"))
        except:
            return False

    @staticmethod
    def getUrlPart(urlPart, url):
        try:
            uri = QueueitHelpers.urlParse(url)

            if (urlPart == "PagePath"):
                return uri.path
            if (urlPart == "PageUrl"):
                return url
            if (urlPart == "HostName"):
                return uri.hostname
            return ''
        except:
            return ''


class CookieValidatorHelper:
    @staticmethod
    def evaluate(triggerPart, httpContextProvider):
        try:
            if (triggerPart == None or "Operator" not in triggerPart
                    or "IsNegative" not in triggerPart
                    or "IsIgnoreCase" not in triggerPart
                    or "CookieName" not in triggerPart):
                return False

            cookieValue = httpContextProvider.getCookie(
                triggerPart['CookieName'])

            return ComparisonOperatorHelper.evaluate(
                triggerPart["Operator"], triggerPart["IsNegative"],
                triggerPart["IsIgnoreCase"], cookieValue,
                triggerPart.get("ValueToCompare"),
                triggerPart.get("ValuesToCompare"))
        except:
            return False


class UserAgentValidatorHelper:
    @staticmethod
    def evaluate(triggerPart, httpContextProvider):
        try:
            if (triggerPart == None or "Operator" not in triggerPart
                    or "IsNegative" not in triggerPart
                    or "IsIgnoreCase" not in triggerPart):
                return False

            userAgent = httpContextProvider.getHeader("user-agent")

            return ComparisonOperatorHelper.evaluate(
                triggerPart["Operator"], triggerPart["IsNegative"],
                triggerPart["IsIgnoreCase"], userAgent,
                triggerPart.get("ValueToCompare"),
                triggerPart.get("ValuesToCompare"))
        except:
            return False


class HttpHeaderValidatorHelper:
    @staticmethod
    def evaluate(triggerPart, httpContextProvider):
        try:
            if (triggerPart == None or "Operator" not in triggerPart
                    or "IsNegative" not in triggerPart
                    or "IsIgnoreCase" not in triggerPart
                    or "HttpHeaderName" not in triggerPart):
                return False

            headerValue = httpContextProvider.getHeader(
                triggerPart['HttpHeaderName'])

            return ComparisonOperatorHelper.evaluate(
                triggerPart["Operator"], triggerPart["IsNegative"],
                triggerPart["IsIgnoreCase"], headerValue,
                triggerPart.get("ValueToCompare"),
                triggerPart.get("ValuesToCompare"))
        except:
            return False


class ComparisonOperatorHelper:
    @staticmethod
    def evaluate(opt, isNegative, ignoreCase, value, valueToCompare,
                 valuesToCompare):
        if (value is None):
            value = ''

        if (valueToCompare is None):
            valueToCompare = ''

        if (valuesToCompare is None):
            valuesToCompare = []

        if (opt == "Equals"):
            return ComparisonOperatorHelper.equals(value, valueToCompare,
                                                   isNegative, ignoreCase)
        if (opt == "Contains"):
            return ComparisonOperatorHelper.contains(value, valueToCompare,
                                                     isNegative, ignoreCase)
        if (opt == "EqualsAny"):
            return ComparisonOperatorHelper.equalsAny(value, valuesToCompare,
                                                      isNegative, ignoreCase)
        if (opt == "ContainsAny"):
            return ComparisonOperatorHelper.containsAny(
                value, valuesToCompare, isNegative, ignoreCase)

        return False

    @staticmethod
    def equals(value, valueToCompare, isNegative, ignoreCase):
        if (ignoreCase):
            evaluation = value.upper() == valueToCompare.upper()
        else:
            evaluation = value == valueToCompare

        if (isNegative):
            return not evaluation
        else:
            return evaluation

    @staticmethod
    def contains(value, valueToCompare, isNegative, ignoreCase):
        if (valueToCompare == "*" and value != ''):
            return True

        if (ignoreCase):
            value = value.upper()
            valueToCompare = valueToCompare.upper()

        evaluation = valueToCompare in value
        if (isNegative):
            return not evaluation
        else:
            return evaluation

    @staticmethod
    def equalsAny(value, valuesToCompare, isNegative, ignoreCase):
        for valueToCompare in valuesToCompare:
            if (ComparisonOperatorHelper.equals(value, valueToCompare, False,
                                                ignoreCase)):
                return not isNegative
        return isNegative

    @staticmethod
    def containsAny(value, valuesToCompare, isNegative, ignoreCase):
        for valueToCompare in valuesToCompare:
            if (ComparisonOperatorHelper.contains(value, valueToCompare, False,
                                                  ignoreCase)):
                return not isNegative
        return isNegative
