import unittest

from retrywise.packages.razorpay import ReferenceIdError, make_recovery_reference_id


class RecoveryReferenceTests(unittest.TestCase):
    def test_reference_is_stable_safe_and_within_provider_limit(self):
        first = make_recovery_reference_id("01J8Z4KFXA5YQW9D4P3", provider_account_id="acc_A")
        second = make_recovery_reference_id("01J8Z4KFXA5YQW9D4P3", provider_account_id="acc_A")
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("rtw_01j8z4kf_"))
        self.assertLessEqual(len(first), 40)

    def test_provider_account_is_part_of_identity(self):
        left = make_recovery_reference_id("case-1", provider_account_id="acc_A")
        right = make_recovery_reference_id("case-1", provider_account_id="acc_B")
        self.assertNotEqual(left, right)

    def test_unicode_case_id_still_has_deterministic_ascii_reference(self):
        reference = make_recovery_reference_id("मामला-१", provider_account_id="acc_A")
        self.assertRegex(reference, r"^rtw_[a-z0-9]+_[a-z2-7]+$")
        self.assertLessEqual(len(reference), 40)

    def test_surrounding_whitespace_is_rejected(self):
        with self.assertRaises(ReferenceIdError):
            make_recovery_reference_id(" case-1 ", provider_account_id="acc_A")


if __name__ == "__main__":
    unittest.main()
