import unittest

from queueit_knownuserv3.integration_config_helpers import IntegrationEvaluator
from queueit_knownuserv3.integration_config_helpers import UrlValidatorHelper, CookieValidatorHelper
from queueit_knownuserv3.integration_config_helpers import UserAgentValidatorHelper, HttpHeaderValidatorHelper
from queueit_knownuserv3.integration_config_helpers import ComparisonOperatorHelper
from queueit_knownuserv3.http_context_providers import HttpContextProvider


class HttpContextProviderMock(HttpContextProvider):
    def __init__(self):
        self.headers = {}
        self.cookies = {}

    def getHeader(self, headerName):
        if (not headerName in self.headers):
            return None
        return self.headers[headerName]

    def getCookie(self, cookieName):
        if (not cookieName in self.cookies):
            return None
        return self.cookies[cookieName]


class TestIntegrationEvaluator(unittest.TestCase):
    def test_getMatchedIntegrationConfig_oneTrigger_and_notMatched(self):
        integrationConfig = {
            "Integrations": [{
                "Triggers": [{
                    "LogicalOperator":
                    "And",
                    "TriggerParts": [{
                        "CookieName": "c1",
                        "Operator": "Equals",
                        "ValueToCompare": "value1",
                        "ValidatorType": "CookieValidator",
                        "IsIgnoreCase": False,
                        "IsNegative": False
                    }, {
                        "UrlPart": "PageUrl",
                        "ValidatorType": "UrlValidator",
                        "ValueToCompare": "test",
                        "Operator": "Contains",
                        "IsIgnoreCase": False,
                        "IsNegative": False
                    }]
                }]
            }]
        }

        url = "http://test.testdomain.com:8080/test?q=2"
        testObject = IntegrationEvaluator()
        matchedConfig = testObject.getMatchedIntegrationConfig(
            integrationConfig, url, HttpContextProviderMock())
        assert (matchedConfig == None)

    def test_getMatchedIntegrationConfig_oneTrigger_and_matched(self):
        integrationConfig = {
            "Integrations": [{
                "Name":
                "integration1",
                "Triggers": [{
                    "LogicalOperator":
                    "And",
                    "TriggerParts": [{
                        "CookieName": "c1",
                        "Operator": "Equals",
                        "ValueToCompare": "value1",
                        "ValidatorType": "CookieValidator",
                        "IsIgnoreCase": True,
                        "IsNegative": False
                    }, {
                        "UrlPart": "PageUrl",
                        "ValidatorType": "UrlValidator",
                        "ValueToCompare": "test",
                        "Operator": "Contains",
                        "IsIgnoreCase": False,
                        "IsNegative": False
                    }]
                }]
            }]
        }

        url = "http://test.testdomain.com:8080/test?q=2"
        hcpMock = HttpContextProviderMock()
        hcpMock.cookies = {"c2": "ddd", "c1": "Value1"}
        testObject = IntegrationEvaluator()
        matchedConfig = testObject.getMatchedIntegrationConfig(
            integrationConfig, url, hcpMock)
        assert (matchedConfig["Name"] == "integration1")

    def test_getMatchedIntegrationConfig_oneTrigger_and_notmatched_UserAgent(
            self):
        integrationConfig = {
            "Integrations": [{
                "Name":
                "integration1",
                "Triggers": [{
                    "LogicalOperator":
                    "And",
                    "TriggerParts": [{
                        "CookieName": "c1",
                        "Operator": "Equals",
                        "ValueToCompare": "value1",
                        "ValidatorType": "CookieValidator",
                        "IsIgnoreCase": True,
                        "IsNegative": False
                    }, {
                        "UrlPart": "PageUrl",
                        "ValidatorType": "UrlValidator",
                        "ValueToCompare": "test",
                        "Operator": "Contains",
                        "IsIgnoreCase": False,
                        "IsNegative": False
                    }, {
                        "ValidatorType": "userAgentValidator",
                        "ValueToCompare": "Googlebot",
                        "Operator": "Contains",
                        "IsIgnoreCase": True,
                        "IsNegative": True
                    }]
                }]
            }]
        }

        url = "http://test.testdomain.com:8080/test?q=2"
        hcpMock = HttpContextProviderMock()
        hcpMock.headers = {"user-agent": "bot.html google.com googlebot test"}
        hcpMock.cookies = {"c2": "ddd", "c1": "Value1"}
        testObject = IntegrationEvaluator()
        matchedConfig = testObject.getMatchedIntegrationConfig(
            integrationConfig, url, hcpMock)
        assert (matchedConfig == None)

    def test_getMatchedIntegrationConfig_oneTrigger_or_notMatched(self):
        integrationConfig = {
            "Integrations": [{
                "Name":
                "integration1",
                "Triggers": [{
                    "LogicalOperator":
                    "Or",
                    "TriggerParts": [{
                        "CookieName": "c1",
                        "Operator": "Equals",
                        "ValueToCompare": "value1",
                        "ValidatorType": "CookieValidator",
                        "IsIgnoreCase": True,
                        "IsNegative": True
                    }, {
                        "UrlPart": "PageUrl",
                        "ValidatorType": "UrlValidator",
                        "ValueToCompare": "test",
                        "Operator": "Equals",
                        "IsIgnoreCase": False,
                        "IsNegative": False
                    }]
                }]
            }]
        }

        url = "http://test.testdomain.com:8080/test?q=2"
        hcpMock = HttpContextProviderMock()
        hcpMock.cookies = {"c2": "ddd", "c1": "Value1"}
        testObject = IntegrationEvaluator()
        matchedConfig = testObject.getMatchedIntegrationConfig(
            integrationConfig, url, hcpMock)
        assert (matchedConfig == None)

    def test_getMatchedIntegrationConfig_oneTrigger_or_matched(self):
        integrationConfig = {
            "Integrations": [{
                "Name":
                "integration1",
                "Triggers": [{
                    "LogicalOperator":
                    "Or",
                    "TriggerParts": [{
                        "CookieName": "c1",
                        "Operator": "Equals",
                        "ValueToCompare": "value1",
                        "ValidatorType": "CookieValidator",
                        "IsIgnoreCase": True,
                        "IsNegative": True
                    }, {
                        "UrlPart": "PageUrl",
                        "ValidatorType": "UrlValidator",
                        "ValueToCompare": "test",
                        "Operator": "Equals",
                        "IsIgnoreCase": False,
                        "IsNegative": True
                    }]
                }]
            }]
        }

        url = "http://test.testdomain.com:8080/test?q=2"
        hcpMock = HttpContextProviderMock()
        hcpMock.cookies = {"c2": "ddd", "c1": "Value1"}
        testObject = IntegrationEvaluator()
        matchedConfig = testObject.getMatchedIntegrationConfig(
            integrationConfig, url, hcpMock)
        assert (matchedConfig["Name"] == "integration1")

    def test_getMatchedIntegrationConfig_twoTriggers_matched(self):
        integrationConfig = {
            "Integrations": [{
                "Name":
                "integration1",
                "Triggers": [{
                    "LogicalOperator":
                    "And",
                    "TriggerParts": [{
                        "CookieName": "c1",
                        "Operator": "Equals",
                        "ValueToCompare": "value1",
                        "ValidatorType": "CookieValidator",
                        "IsIgnoreCase": True,
                        "IsNegative": True
                    }]
                }, {
                    "LogicalOperator":
                    "And",
                    "TriggerParts": [{
                        "CookieName": "c1",
                        "Operator": "Equals",
                        "ValueToCompare": "Value1",
                        "ValidatorType": "CookieValidator",
                        "IsIgnoreCase": False,
                        "IsNegative": False
                    }, {
                        "UrlPart": "PageUrl",
                        "ValidatorType": "UrlValidator",
                        "ValueToCompare": "test",
                        "Operator": "Contains",
                        "IsIgnoreCase": False,
                        "IsNegative": False
                    }]
                }]
            }]
        }

        url = "http://test.testdomain.com:8080/test?q=2"
        hcpMock = HttpContextProviderMock()
        hcpMock.cookies = {"c2": "ddd", "c1": "Value1"}
        testObject = IntegrationEvaluator()
        matchedConfig = testObject.getMatchedIntegrationConfig(
            integrationConfig, url, hcpMock)
        assert (matchedConfig["Name"] == "integration1")

    def test_getMatchedIntegrationConfig_threeIntegrationsInOrder_secondMatched(
            self):
        integrationConfig = {
            "Integrations": [{
                "Name":
                "integration0",
                "Triggers": [{
                    "LogicalOperator":
                    "And",
                    "TriggerParts": [{
                        "UrlPart": "PageUrl",
                        "ValidatorType": "UrlValidator",
                        "ValueToCompare": "Test",
                        "Operator": "Contains",
                        "IsIgnoreCase": False,
                        "IsNegative": False
                    }]
                }]
            }, {
                "Name":
                "integration1",
                "Triggers": [{
                    "LogicalOperator":
                    "And",
                    "TriggerParts": [{
                        "UrlPart": "PageUrl",
                        "ValidatorType": "UrlValidator",
                        "ValueToCompare": "test",
                        "Operator": "Contains",
                        "IsIgnoreCase": False,
                        "IsNegative": False
                    }]
                }]
            }, {
                "Name":
                "integration2",
                "Triggers": [{
                    "LogicalOperator":
                    "And",
                    "TriggerParts": [{
                        "CookieName": "c1",
                        "ValidatorType": "CookieValidator",
                        "ValueToCompare": "c1",
                        "Operator": "Equals",
                        "IsIgnoreCase": True,
                        "IsNegative": False
                    }]
                }]
            }]
        }

        url = "http://test.testdomain.com:8080/test?q=2"
        hcpMock = HttpContextProviderMock()
        hcpMock.cookies = {"c2": "ddd", "c1": "Value1"}
        testObject = IntegrationEvaluator()
        matchedConfig = testObject.getMatchedIntegrationConfig(
            integrationConfig, url, hcpMock)
        assert (matchedConfig["Name"] == "integration1")


class TestUrlValidatorHelper(unittest.TestCase):
    def test_evaluate(self):
        assert (not UrlValidatorHelper.evaluate(None, "notimportant"))
        assert (not UrlValidatorHelper.evaluate({}, "notimportant"))

        triggerPart = {
            "UrlPart": "PageUrl",
            "Operator": "Contains",
            "IsIgnoreCase": True,
            "IsNegative": False,
            "ValueToCompare": "http://test.testdomain.com:8080/test?q=1"
        }
        assert (not UrlValidatorHelper.evaluate(
            triggerPart, "http://test.testdomain.com:8080/test?q=2"))

        triggerPart = {
            "UrlPart": "PagePath",
            "Operator": "Equals",
            "IsIgnoreCase": True,
            "IsNegative": False,
            "ValueToCompare": "/Test/t1"
        }
        assert (UrlValidatorHelper.evaluate(
            triggerPart, "http://test.testdomain.com:8080/test/t1?q=2&y02"))

        triggerPart = {
            "UrlPart": "HostName",
            "Operator": "Contains",
            "IsIgnoreCase": True,
            "IsNegative": False,
            "ValueToCompare": "test.testdomain.com"
        }
        assert (UrlValidatorHelper.evaluate(
            triggerPart, "http://m.test.testdomain.com:8080/test?q=2"))

        triggerPart = {
            "UrlPart": "HostName",
            "Operator": "Contains",
            "IsIgnoreCase": True,
            "IsNegative": True,
            "ValueToCompare": "test.testdomain.com"
        }
        assert (not UrlValidatorHelper.evaluate(
            triggerPart, "http://m.test.testdomain.com:8080/test?q=2"))


class TestCookieValidatorHelper(unittest.TestCase):
    def test_evaluate(self):

        hcpMock = HttpContextProviderMock()
        assert (not CookieValidatorHelper.evaluate(None, hcpMock))
        assert (not CookieValidatorHelper.evaluate({}, hcpMock))

        triggerPart = {
            "CookieName": "c1",
            "Operator": "Contains",
            "IsIgnoreCase": True,
            "IsNegative": False,
            "ValueToCompare": "1"
        }
        hcpMock.cookies = {"c1": "hhh"}
        assert (not CookieValidatorHelper.evaluate(triggerPart, hcpMock))

        triggerPart = {
            "CookieName": "c1",
            "Operator": "Contains",
            "ValueToCompare": "1"
        }
        hcpMock.cookies = {"c2": "ddd", "c1": "3"}
        assert (not CookieValidatorHelper.evaluate(triggerPart, hcpMock))

        triggerPart = {
            "CookieName": "c1",
            "Operator": "Contains",
            "IsIgnoreCase": True,
            "IsNegative": False,
            "ValueToCompare": "1"
        }
        hcpMock.cookies = {"c2": "ddd", "c1": "1"}
        assert (CookieValidatorHelper.evaluate(triggerPart, hcpMock))

        triggerPart = {
            "CookieName": "c1",
            "Operator": "Contains",
            "IsIgnoreCase": True,
            "IsNegative": True,
            "ValueToCompare": "1"
        }
        hcpMock.cookies = {"c2": "ddd", "c1": "1"}
        assert (not CookieValidatorHelper.evaluate(triggerPart, hcpMock))


class TestUserAgentValidatorHelper(unittest.TestCase):
    def test_evaluate(self):
        hcpMock = HttpContextProviderMock()
        assert (not UserAgentValidatorHelper.evaluate(None, hcpMock))
        assert (not UserAgentValidatorHelper.evaluate({}, hcpMock))

        triggerPart = {
            "Operator": "Contains",
            "IsIgnoreCase": False,
            "IsNegative": False,
            "ValueToCompare": "googlebot"
        }
        hcpMock.headers = {"user-agent": "Googlebot sample useraagent"}
        assert (not UserAgentValidatorHelper.evaluate(triggerPart, hcpMock))

        triggerPart = {
            "Operator": "Equals",
            "IsIgnoreCase": True,
            "IsNegative": True,
            "ValueToCompare": "googlebot"
        }
        hcpMock.headers = {"user-agent": "ooglebot sample useraagent"}
        assert (UserAgentValidatorHelper.evaluate(triggerPart, hcpMock))

        triggerPart = {
            "Operator": "Contains",
            "IsIgnoreCase": False,
            "IsNegative": True,
            "ValueToCompare": "googlebot"
        }
        hcpMock.headers = {"user-agent": "googlebot"}
        assert (not UserAgentValidatorHelper.evaluate(triggerPart, hcpMock))

        triggerPart = {
            "Operator": "Contains",
            "IsIgnoreCase": True,
            "IsNegative": False,
            "ValueToCompare": "googlebot"
        }
        hcpMock.headers = {"user-agent": "Googlebot"}
        assert (UserAgentValidatorHelper.evaluate(triggerPart, hcpMock))


class TestHttpHeaderValidatorHelper(unittest.TestCase):
    def test_evaluate(self):
        hcpMock = HttpContextProviderMock()
        assert (not HttpHeaderValidatorHelper.evaluate(None, hcpMock))
        assert (not HttpHeaderValidatorHelper.evaluate({}, hcpMock))

        triggerPart = {
            "HttpHeaderName": "a-header",
            "Operator": "Contains",
            "IsIgnoreCase": True,
            "IsNegative": False,
            "ValueToCompare": "value"
        }
        hcpMock.headers = {'a-header': "VaLuE"}
        assert (HttpHeaderValidatorHelper.evaluate(triggerPart, hcpMock))

        triggerPart = {
            "HttpHeaderName": "a-header",
            "Operator": "Contains",
            "IsIgnoreCase": True,
            "IsNegative": False,
            "ValueToCompare": "value"
        }
        hcpMock.headers = {'a-header': "not"}
        assert (not HttpHeaderValidatorHelper.evaluate(triggerPart, hcpMock))

        triggerPart = {
            "HttpHeaderName": "a-header",
            "Operator": "Contains",
            "IsNegative": True,
            "IsIgnoreCase": False,
            "ValueToCompare": "value"
        }
        hcpMock.headers = {'a-header': "not"}
        assert (HttpHeaderValidatorHelper.evaluate(triggerPart, hcpMock))


class TestComparisonOperatorHelper(unittest.TestCase):
    def test_evaluate_equals_operator(self):
        assert (ComparisonOperatorHelper.evaluate("Equals", False, False, None,
                                                  None, None))
        assert (ComparisonOperatorHelper.evaluate("Equals", False, False,
                                                  "test1", "test1", None))
        assert (not ComparisonOperatorHelper.evaluate("Equals", False, False,
                                                      "test1", "Test1", None))
        assert (ComparisonOperatorHelper.evaluate("Equals", False, True,
                                                  "test1", "Test1", None))
        assert (ComparisonOperatorHelper.evaluate("Equals", True, False,
                                                  "test1", "Test1", None))
        assert (not ComparisonOperatorHelper.evaluate("Equals", True, False,
                                                      "test1", "test1", None))
        assert (not ComparisonOperatorHelper.evaluate("Equals", True, True,
                                                      "test1", "Test1", None))

    def test_evaluate_contains_operator(self):
        assert (ComparisonOperatorHelper.evaluate("Contains", False, False,
                                                  None, None, None))
        assert (ComparisonOperatorHelper.evaluate(
            "Contains", False, False, "test_test1_test", "test1", None))
        assert (not ComparisonOperatorHelper.evaluate(
            "Contains", False, False, "test_test1_test", "Test1", None))
        assert (ComparisonOperatorHelper.evaluate(
            "Contains", False, True, "test_test1_test", "Test1", None))
        assert (ComparisonOperatorHelper.evaluate(
            "Contains", True, False, "test_test1_test", "Test1", None))
        assert (not ComparisonOperatorHelper.evaluate(
            "Contains", True, True, "test_test1", "Test1", None))
        assert (not ComparisonOperatorHelper.evaluate(
            "Contains", True, False, "test_test1", "test1", None))
        assert (ComparisonOperatorHelper.evaluate(
            "Contains", False, False, "test_dsdsdsdtest1", "*", None))
        assert (not ComparisonOperatorHelper.evaluate(
            "Contains", False, False, "", "*", None))

    def test_evaluate_equalsAny_operator(self):
        assert (ComparisonOperatorHelper.evaluate("EqualsAny", False, False,
                                                  "test1", None, ["test1"]))
        assert (not ComparisonOperatorHelper.evaluate(
            "EqualsAny", False, False, "test1", None, ["Test1"]))
        assert (ComparisonOperatorHelper.evaluate("EqualsAny", False, True,
                                                  "test1", None, ["Test1"]))
        assert (ComparisonOperatorHelper.evaluate("EqualsAny", True, False,
                                                  "test1", None, ["Test1"]))
        assert (not ComparisonOperatorHelper.evaluate(
            "EqualsAny", True, False, "test1", None, ["test1"]))
        assert (not ComparisonOperatorHelper.evaluate(
            "EqualsAny", True, True, "test1", None, ["Test1"]))

    def test_evaluate_containsAny_operator(self):
        assert (ComparisonOperatorHelper.evaluate(
            "ContainsAny", False, False, "test_test1_test", None, ["test1"]))
        assert (not ComparisonOperatorHelper.evaluate(
            "ContainsAny", False, False, "test_test1_test", None, ["Test1"]))
        assert (ComparisonOperatorHelper.evaluate(
            "ContainsAny", False, True, "test_test1_test", None, ["Test1"]))
        assert (ComparisonOperatorHelper.evaluate(
            "ContainsAny", True, False, "test_test1_test", None, ["Test1"]))
        assert (not ComparisonOperatorHelper.evaluate(
            "ContainsAny", True, True, "test_test1", None, ["Test1"]))
        assert (not ComparisonOperatorHelper.evaluate(
            "ContainsAny", True, False, "test_test1", None, ["test1"]))
        assert (ComparisonOperatorHelper.evaluate(
            "ContainsAny", False, False, "test_dsdsdsdtest1", None, ["*"]))

    def test_evaluate_unsupported_operator(self):
        assert (not ComparisonOperatorHelper.evaluate("-not-supported-", False,
                                                      False, None, None, None))
