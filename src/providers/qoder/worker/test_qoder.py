import unittest
from unittest import mock
from signup import encode_bx_ua, TMD_IN_URL, is_tmd_punish

class TestHelpers(unittest.TestCase):
    def test_bx_ua_nonempty(self):
        self.assertGreater(len(encode_bx_ua()), 10)

    def test_tmd_detect(self):
        self.assertTrue(is_tmd_punish({"x5secdata":"xx"} ))
        self.assertFalse(is_tmd_punish({"errorCode":"BadRequest"}))
        self.assertFalse(is_tmd_punish({"errorMessage":"Code required"}))

if __name__ == "__main__":
    unittest.main()
