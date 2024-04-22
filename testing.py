import unittest
from ids import prediction_logic


class TestPredictionLogic(unittest.TestCase):

    def test_normal_packet_prediction(self):
        result = prediction_logic(mc_prediction="NORMAL", b_prediction="NORMAL")
        self.assertEqual(result, "NORMAL")

    def test_abnormal_packet_prediction(self):
        result = prediction_logic(mc_prediction="NORMAL", b_prediction="ABNORMAL")
        self.assertEqual(result, "SUSPICIOUS ACTIVITY")

    def test_dos_mc_normal_b_prediction(self):
        result = prediction_logic(mc_prediction="DOS", b_prediction="NORMAL")
        self.assertEqual(result, "DOS")

    def test_dos_mc_abnormal_b_prediction(self):
        result = prediction_logic(mc_prediction="DOS", b_prediction="ABNORMAL")
        self.assertEqual(result, "DOS")

    def test_probe_mc_normal_b_prediction(self):
        result = prediction_logic(mc_prediction="PROBE", b_prediction="NORMAL")
        self.assertEqual(result, "PROBE")

    def test_probe_mc_abnormal_b_prediction(self):
        result = prediction_logic(mc_prediction="PROBE", b_prediction="ABNORMAL")
        self.assertEqual(result, "PROBE")

    def test_r2l_mc_normal_b_prediction(self):
        result = prediction_logic(mc_prediction="R2L", b_prediction="NORMAL")
        self.assertEqual(result, "R2L")

    def test_r2l_mc_abnormal_b_prediction(self):
        result = prediction_logic(mc_prediction="R2L", b_prediction="ABNORMAL")
        self.assertEqual(result, "R2L")

    def test_u2r_mc_normal_b_prediction(self):
        result = prediction_logic(mc_prediction="U2R", b_prediction="NORMAL")
        self.assertEqual(result, "U2R")

    def test_u2r_mc_abnormal_b_prediction(self):
        result = prediction_logic(mc_prediction="U2R", b_prediction="ABNORMAL")
        self.assertEqual(result, "U2R")
