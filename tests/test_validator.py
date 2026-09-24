"""Tests for the device-side CommandValidator and frame signing.

Standard library only. Run with either:
    python -m unittest discover -s tests -v
    python -m pytest tests
"""
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "edge"))

from edge_node import (  # noqa: E402
    CFG,
    ROGUE_ALARM_TEXT,
    CommandValidator,
    Forwarder,
    LineSimulator,
    sign,
)

KEY = b"test-key"
DEVICE = "JET-B"


class ValidatorTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.nonce_file = os.path.join(self._tmp.name, f"{DEVICE}.nonces")
        self.sim = LineSimulator("B", CFG["lines"]["B"]["batch_id"])
        self.validator = self.new_validator()
        self._n = 0

    def tearDown(self):
        self._tmp.cleanup()

    def new_validator(self, key=KEY):
        return CommandValidator(DEVICE, key, CFG["command_allowlist"], CFG["command_max_age_s"],
                                nonce_file=self.nonce_file)

    def body(self, command="set_agitation_setpoint", params=None, **overrides):
        self._n += 1
        b = dict(command_id=f"CMD-{self._n}", device_id=DEVICE, command=command,
                 params={"setpoint_rpm": 110} if params is None else params,
                 nonce=f"n-{time.time()}-{self._n}", exp=time.time() + 30)
        b.update(overrides)
        return b

    @staticmethod
    def signed(body, key=KEY):
        return dict(body, signature=sign(key, body))

    def assertRejected(self, result, reason_fragment):
        ok, verdict = result
        self.assertFalse(ok, verdict)
        self.assertTrue(verdict.startswith("REJECTED:"), verdict)
        self.assertIn(reason_fragment, verdict)


class TestAccept(ValidatorTestCase):
    def test_valid_command_is_accepted_and_applied(self):
        ok, verdict = self.validator.validate(self.signed(self.body()), self.sim)
        self.assertTrue(ok, verdict)
        self.assertIn("agitation setpoint 110 rpm", verdict)
        self.assertEqual(self.sim.setpoints["agitation_rpm"], 110.0)

    def test_range_bounds_are_inclusive(self):
        for rpm in (80, 120):
            ok, verdict = self.validator.validate(self.signed(self.body(params={"setpoint_rpm": rpm})), self.sim)
            self.assertTrue(ok, verdict)

    def test_batch_hold_and_alarm_ack(self):
        alarm = self.sim.raise_alarm("temp_c", "high", "test alarm", time.time())
        ok, verdict = self.validator.validate(
            self.signed(self.body("acknowledge_alarm", {"alarm_id": alarm["alarm_id"]})), self.sim)
        self.assertTrue(ok, verdict)
        self.assertTrue(self.sim.alarms[0]["acknowledged"])
        ok, verdict = self.validator.validate(
            self.signed(self.body("request_batch_hold", {"reason": "QA review"})), self.sim)
        self.assertTrue(ok, verdict)
        self.assertEqual(self.sim.status, "hold")


class TestOutOfRange(ValidatorTestCase):
    def test_above_range_rejected(self):
        self.assertRejected(self.validator.validate(self.signed(self.body(params={"setpoint_rpm": 500})), self.sim),
                            "outside validated range")
        self.assertEqual(self.sim.setpoints["agitation_rpm"], CFG["setpoint"]["agitation_rpm"])

    def test_below_range_rejected(self):
        self.assertRejected(self.validator.validate(self.signed(self.body(params={"setpoint_rpm": 79.9})), self.sim),
                            "outside validated range")

    def test_non_numeric_rejected_without_crashing(self):
        for bad in ("110", True, None, [110]):
            self.assertRejected(
                self.validator.validate(self.signed(self.body(params={"setpoint_rpm": bad})), self.sim),
                "not a number")

    def test_missing_and_unknown_params_rejected(self):
        self.assertRejected(self.validator.validate(self.signed(self.body(params={})), self.sim), "missing")
        self.assertRejected(
            self.validator.validate(self.signed(self.body(params={"setpoint_rpm": 100, "extra": 1})), self.sim),
            "not allowed")

    def test_pattern_and_length_rules_enforced(self):
        self.assertRejected(
            self.validator.validate(self.signed(self.body("acknowledge_alarm", {"alarm_id": "ALM-C-1"})), self.sim),
            "does not match pattern")
        self.assertRejected(
            self.validator.validate(self.signed(self.body("request_batch_hold", {"reason": "x" * 201})), self.sim),
            "at most 200 characters")

    def test_command_not_allowlisted(self):
        self.assertRejected(self.validator.validate(self.signed(self.body("open_valve", {})), self.sim),
                            "not allowlisted")


class TestReplay(ValidatorTestCase):
    def test_identical_command_twice_is_rejected(self):
        cmd = self.signed(self.body())
        self.assertTrue(self.validator.validate(cmd, self.sim)[0])
        self.assertRejected(self.validator.validate(cmd, self.sim), "replay")

    def test_replay_window_survives_restart(self):
        cmd = self.signed(self.body())
        self.assertTrue(self.validator.validate(cmd, self.sim)[0])
        restarted = self.new_validator()
        self.assertRejected(restarted.validate(cmd, self.sim), "replay")

    def test_rejected_command_does_not_burn_its_nonce(self):
        b = self.body(params={"setpoint_rpm": 500})
        self.assertRejected(self.validator.validate(self.signed(b), self.sim), "outside validated range")
        self.assertNotIn(b["nonce"], self.validator.seen)

    def test_expired_and_far_future_commands_rejected(self):
        self.assertRejected(self.validator.validate(self.signed(self.body(exp=time.time() - 1)), self.sim),
                            "expired")
        self.assertRejected(self.validator.validate(self.signed(self.body(exp=time.time() + 3600)), self.sim),
                            "expired")


class TestSignature(ValidatorTestCase):
    def test_zeroed_signature_rejected(self):
        cmd = dict(self.body(), signature="hmac-sha256:" + "0" * 64)
        self.assertRejected(self.validator.validate(cmd, self.sim), "signature invalid")

    def test_wrong_key_rejected(self):
        self.assertRejected(self.validator.validate(self.signed(self.body(), key=b"other-key"), self.sim),
                            "signature invalid")

    def test_tampered_body_rejected(self):
        cmd = self.signed(self.body())
        cmd["params"] = {"setpoint_rpm": 90}
        self.assertRejected(self.validator.validate(cmd, self.sim), "signature invalid")

    def test_missing_or_non_string_signature_rejected(self):
        for sig in (None, 123, "", "hmac-sha256:é"):
            cmd = dict(self.body(), signature=sig)
            self.assertRejected(self.validator.validate(cmd, self.sim), "signature invalid")

    def test_command_for_other_device_rejected(self):
        self.assertRejected(self.validator.validate(self.signed(self.body(device_id="JET-A")), self.sim),
                            "another device")

    def test_malformed_command_rejected(self):
        self.assertRejected(self.validator.validate(["not", "a", "dict"], self.sim), "malformed")


class TestTelemetryFrames(unittest.TestCase):
    def test_frame_signature_roundtrip(self):
        sim = LineSimulator("A", CFG["lines"]["A"]["batch_id"])
        fwd = Forwarder("JET-A", "A", sim.batch_id, KEY, sink=None)
        now = time.time()
        for i in range(5):
            sim.step(now + i)
            fwd.observe(sim.tags)
        f1, f2 = fwd.frame(sim, now), fwd.frame(sim, now + 30)
        self.assertEqual((f1["seq_no"], f2["seq_no"]), (1, 2))
        self.assertTrue(Forwarder.verify(KEY, f1))
        self.assertFalse(Forwarder.verify(b"other-key", f1))
        self.assertFalse(Forwarder.verify(KEY, dict(f1, status="hold")))

    def test_rogue_mode_overrides_alarm_text(self):
        sim = LineSimulator("B", CFG["lines"]["B"]["batch_id"], rogue=True)
        alarm = sim.raise_alarm("do_pct", "high", "DO low", time.time())
        self.assertEqual(alarm["alarm_message"], ROGUE_ALARM_TEXT)


if __name__ == "__main__":
    unittest.main()
