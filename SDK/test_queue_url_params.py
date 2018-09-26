import unittest

from queueit_knownuserv3.queue_url_params import QueueUrlParams


class TestQueueUrlParams(unittest.TestCase):
    def test_extractQueueParams(self):
        queueITToken = "e_testevent1~q_6cf23f10-aca7-4fa2-840e-e10f56aecb44~ts_1486645251~ce_True~cv_3~rt_Queue~h_cb7b7b53fa20e708cb59a5a2696f248cba3b2905d92e12ee5523c298adbef298"
        result = QueueUrlParams.extractQueueParams(queueITToken)
        self.assertEqual(result.eventId, "testevent1")
        self.assertEqual(result.timeStamp, 1486645251)
        self.assertEqual(result.extendableCookie, True)
        self.assertEqual(result.queueITToken, queueITToken)
        self.assertEqual(result.cookieValidityMinutes, 3)
        self.assertEqual(result.queueId,
                         "6cf23f10-aca7-4fa2-840e-e10f56aecb44")
        self.assertEqual(
            result.hashCode,
            "cb7b7b53fa20e708cb59a5a2696f248cba3b2905d92e12ee5523c298adbef298")
        self.assertEqual(
            result.queueITTokenWithoutHash,
            "e_testevent1~q_6cf23f10-aca7-4fa2-840e-e10f56aecb44~ts_1486645251~ce_True~cv_3~rt_Queue"
        )

    def test_extractQueueParams_notValidToken(self):
        queueITToken = "ts_sasa~cv_adsasa~ce_falwwwse~q_944c1f44-60dd-4e37-aabc-f3e4bb1c8895"
        result = QueueUrlParams.extractQueueParams(queueITToken)
        self.assertEqual(result.eventId, "")
        self.assertEqual(result.timeStamp, 0)
        self.assertEqual(result.extendableCookie, False)
        self.assertEqual(result.queueITToken, queueITToken)
        self.assertEqual(result.cookieValidityMinutes, None)
        self.assertEqual(result.queueId,
                         "944c1f44-60dd-4e37-aabc-f3e4bb1c8895")
        self.assertEqual(result.hashCode, "")
        self.assertEqual(
            result.queueITTokenWithoutHash,
            "ts_sasa~cv_adsasa~ce_falwwwse~q_944c1f44-60dd-4e37-aabc-f3e4bb1c8895"
        )
