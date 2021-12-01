from queue_url_params import QueueUrlParams
from models import RequestValidationResult, Utils
from queueit_helpers import QueueitHelpers


class ConnectorDiagnostics:
    def __init__(self):
        self.isEnabled = False
        self.hasError = False
        self.validationResult = RequestValidationResult(None, None, None, None, None, None)

    def __setStateWithTokenError(self, customer_id, error_code):
        self.hasError = True
        redirect_url_template = "https://{0}.api2.queue-it.net/{0}/diagnostics/connector/error/?code={1}"
        redirect_url = redirect_url_template.format(customer_id, error_code)
        self.validationResult = RequestValidationResult("ConnectorDiagnosticsRedirect",
                                                        None, None, redirect_url, None, None)

    def __setStateWithSetupError(self):
        self.hasError = True
        redirect_url = "https://api2.queue-it.net/diagnostics/connector/error/?code=setup"
        self.validationResult = RequestValidationResult("ConnectorDiagnosticsRedirect",
                                                        None, None, redirect_url, None, None)

    @staticmethod
    def verify(customer_id, secret_key, queueit_token):
        diagnostics = ConnectorDiagnostics()
        q_params = QueueUrlParams.extractQueueParams(queueit_token)

        if q_params is None:
            return diagnostics

        if q_params.redirectType is None:
            return diagnostics

        if q_params.redirectType != "debug":
            return diagnostics

        if Utils.isNilOrEmpty(customer_id) or Utils.isNilOrEmpty(secret_key):
            diagnostics.__setStateWithSetupError()
            return diagnostics

        expected_hash = QueueitHelpers.hmacSha256Encode(q_params.queueITTokenWithoutHash, secret_key)
        if q_params.hashCode != expected_hash:
            diagnostics.__setStateWithTokenError(customer_id, "hash")
            return diagnostics

        if q_params.timeStamp < QueueitHelpers.getCurrentTime():
            diagnostics.__setStateWithTokenError(customer_id, "timestamp")
            return diagnostics

        diagnostics.isEnabled = True
        return diagnostics
