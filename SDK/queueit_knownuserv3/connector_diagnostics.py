from .queue_url_params import QueueUrlParams
from .models import RequestValidationResult, Utils
from .queueit_helpers import QueueitHelpers

class ConnectorDiagnostics:
    def __init__(self):
        self.isEnabled = False
        self.hasError = False
        self.validationResult = RequestValidationResult(None, None, None, None, None, None)

    def __setStateWithTokenError(self, customerId, errorCode):
        self.hasError = True
        redirectUrl = "https://{0}.api2.queue-it.net/{0}/diagnostics/connector/error/?code={1}".format(customerId, errorCode)
        self.validationResult = RequestValidationResult("ConnectorDiagnosticsRedirect",
                                                        None, None, redirectUrl, None, None)

    def __setStateWithSetupError(self):
        self.hasError = True
        redirectUrl = "https://api2.queue-it.net/diagnostics/connector/error/?code=setup"
        self.validationResult = RequestValidationResult("ConnectorDiagnosticsRedirect",
                                                        None, None, redirectUrl, None, None)

    @staticmethod
    def verify(customerId, secretKey, queueitToken):
        diagnostics = ConnectorDiagnostics()
        qParams = QueueUrlParams.extractQueueParams(queueitToken)

        if(qParams == None):
            return diagnostics

        if(qParams.redirectType == None):
            return diagnostics

        if(qParams.redirectType != "debug"):
            return diagnostics

        if(Utils.isNilOrEmpty(customerId) or Utils.isNilOrEmpty(secretKey)):
            diagnostics.__setStateWithSetupError()
            return diagnostics

        calculatedHash = QueueitHelpers.hmacSha256Encode(qParams.queueITTokenWithoutHash, secretKey)
        if(qParams.hashCode != calculatedHash):
            diagnostics.__setStateWithTokenError(customerId, "hash")
            return diagnostics

        if(qParams.timeStamp < QueueitHelpers.getCurrentTime()):
            diagnostics.__setStateWithTokenError(customerId, "timestamp")
            return diagnostics

        diagnostics.isEnabled = True
        return diagnostics

