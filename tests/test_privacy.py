from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from agent_xray.classifier import classify_request_payload
from agent_xray.privacy import (
    audit_and_prepare_headers,
    redact_secrets_in_text,
    scan_body_for_secrets,
    scan_payload_for_secrets,
)
from agent_xray.store import TraceStore


class PrivacyAndRedactionTests(unittest.TestCase):
    def test_expanded_secret_patterns_and_zero_false_positives(self) -> None:
        ant = "sk-ant-api03-" + ("A1b2C3d4E5" * 3)
        proj = "sk-proj-" + ("Z9y8X7w6V5" * 3)
        or_key = "sk-or-v1-" + ("ab12cd34" * 6)
        legacy_sk = "sk-" + ("mN3pQ4rS5t" * 4)
        ghp = "ghp_" + ("kL9mN8pQ7r" * 3)
        ghpat = "github_pat_" + ("uV6wX5yZ4a" * 3)
        akia = "AKIA12345678ABCDEFGH"
        slack = "xoxb-1234567890-0987654321-AbCdEfGhIjKlMn"
        aiza = "AIzaSyA1b2c3d4e5f6g7h8i9j0kLmNoPqRsTuVw"
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        pem_closed = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEAv3rySecretBodyLine1\n"
            "SuperSecretPrivateKeyLine2==\n"
            "-----END RSA PRIVATE KEY-----"
        )
        pem_enc_unclosed = (
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
            "MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQISecretUnclosed"
        )

        all_secrets = [
            ("glued ant", f"ANTHROPIC_API_KEY={ant}", ant),
            ("underscore ant", f"X_{ant}", ant),
            ("proj", f"token:{proj}", proj),
            ("openrouter", f"OPENROUTER={or_key}", or_key),
            ("glued legacy sk", f"key={legacy_sk}", legacy_sk),
            ("underscore legacy sk", f"OPENAI_{legacy_sk}", legacy_sk),
            ("ghp", ghp, ghp),
            ("github_pat", ghpat, ghpat),
            ("akia", f"aws={akia}", akia),
            ("slack", slack, slack),
            ("google aiza", aiza, aiza),
            ("jwt", f"Bearer {jwt}", jwt),
            ("pem closed", f"Here is key:\n{pem_closed}\ndone", "MIIEowIBAAKCAQEAv3rySecretBodyLine1"),
            ("pem unclosed", f"Leaked:\n{pem_enc_unclosed}", "MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQISecretUnclosed"),
        ]

        for label, sample, forbidden_substr in all_secrets:
            with self.subTest(secret=label):
                findings = scan_body_for_secrets(sample)
                self.assertGreaterEqual(len(findings), 1, f"Expected secret match for {label}")
                findings_json = json.dumps([f.to_dict() for f in findings])
                self.assertNotIn(forbidden_substr[:10], findings_json)
                scrubbed = redact_secrets_in_text(sample)
                self.assertNotIn(forbidden_substr[:10], scrubbed)
                self.assertNotIn("-----BEGIN", scrubbed)

        benign = [
            "key type sk-ssh-ed25519@openssh.com and sk-ecdsa-sha2-nistp256",
            "AWS docs placeholder AKIAIOSFODNN7EXAMPLE in manual",
            "set token to ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "use sk-ant-xxxxxxxxxxxxxxxxxxxxxxxx in config",
            "commit 3f786850e387550fdab836ed7e6dc881de23001b id 123e4567-e89b-12d3-a456-426614174000",
            "install flask-sqlalchemy-extension-helper-package",
        ]
        for text in benign:
            with self.subTest(benign=text):
                self.assertEqual(scan_body_for_secrets(text), [])

    def test_default_zero_preview_and_redact_before_truncate_and_blocked_metadata(self) -> None:
        ant = "sk-ant-api03-" + ("SecretTail99" * 3)
        pem = (
            "-----BEGIN PRIVATE KEY-----\n"
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7BodyLeak\n"
            "-----END PRIVATE KEY-----"
        )
        # Place secret starting at char 132 so naive [:140] truncation cuts `sk-ant-api03-` to 8 chars!
        boundary_prompt = ("A" * 132) + ant + "\n" + pem
        payload = {
            "model": "claude-sonnet-4-5",
            "messages": [{"role": "user", "content": boundary_prompt}],
        }

        # 1. Default: prompt_preview must be empty
        cls_default = classify_request_payload("/anthropic/v1/messages", payload)
        self.assertEqual(cls_default.prompt_preview, "")

        # 2. Explicit store_previews=True: must redact BEFORE truncating to 140 chars
        cls_preview = classify_request_payload("/anthropic/v1/messages", payload, store_previews=True)
        self.assertNotIn("sk-ant", cls_preview.prompt_preview)
        self.assertNotIn("SecretTail", cls_preview.prompt_preview)
        self.assertNotIn("MIIEvQ", cls_preview.prompt_preview)
        self.assertLessEqual(len(cls_preview.prompt_preview), 140)

        # 3. Payload field path tracking + SQLite storage invariants
        findings = scan_payload_for_secrets(payload)
        self.assertGreaterEqual(len(findings), 2)
        fields = {f.field for f in findings}
        self.assertIn("messages[0].content", fields)

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "traces.db"
            store = TraceStore(db_path)
            # Default record_turn drops preview even if caller passes one unless store_previews=True
            store.record_turn(
                provider="anthropic",
                model="claude-sonnet-4-5",
                path="/anthropic/v1/messages",
                status_code=200,
                latency_ms=50,
                blocked=False,
                buckets=cls_default.buckets.to_dict(),
                tool_namespaces=[],
                usage={"input_tokens": 100, "output_tokens": 10, "cache_read_tokens": 0, "cache_write_tokens": 0},
                header_audit=[],
                secret_findings=[],
                prompt_preview=boundary_prompt,
            )
            # With store_previews=True on non-blocked turn: redacts full text BEFORE truncating
            store.record_turn(
                provider="anthropic",
                model="claude-sonnet-4-5",
                path="/anthropic/v1/messages",
                status_code=200,
                latency_ms=50,
                blocked=False,
                buckets=cls_preview.buckets.to_dict(),
                tool_namespaces=[],
                usage={"input_tokens": 100, "output_tokens": 10, "cache_read_tokens": 0, "cache_write_tokens": 0},
                header_audit=[],
                secret_findings=[f.to_dict() for f in findings],
                prompt_preview=boundary_prompt,
                store_previews=True,
            )
            # Blocked turn: NEVER stores prompt_preview even when store_previews=True
            store.record_turn(
                provider="anthropic",
                model="claude-sonnet-4-5",
                path="/anthropic/v1/messages",
                status_code=400,
                latency_ms=5,
                blocked=True,
                buckets=cls_preview.buckets.to_dict(),
                tool_namespaces=[],
                usage={"input_tokens": 0, "output_tokens": 0, "cache_read_tokens": 0, "cache_write_tokens": 0},
                header_audit=[],
                secret_findings=[f.to_dict() for f in findings],
                prompt_preview="Normal prefix before secret " + ant,
                store_previews=True,
            )
            store.close()

            conn = sqlite3.connect(db_path)
            rows = conn.execute("SELECT blocked, prompt_preview, secrets_json FROM traces ORDER BY id ASC").fetchall()
            dump_sql = "\n".join(conn.iterdump())
            conn.close()

            self.assertEqual(rows[0][1], "")
            self.assertNotEqual(rows[1][1], "")
            self.assertEqual(rows[2][0], 1)
            self.assertEqual(rows[2][1], "")  # Blocked turn must have empty prompt_preview!

            for forbidden in ("sk-ant", "SecretTail", "MIIEvQ", "BodyLeak", "Normal prefix before secret"):
                self.assertNotIn(forbidden, dump_sql)

            blocked_secrets = json.loads(rows[2][2])
            self.assertTrue(any(s.get("field") == "messages[0].content" for s in blocked_secrets))

    def test_headers_persist_only_name_and_value_length(self) -> None:
        custom_secret = "custom-super-secret-value-987654321"
        api_secret = "sk-ant-api03-" + ("H" * 30)
        inbound = [
            ("x-api-key", api_secret),
            ("X-Custom-Token", custom_secret),
            ("User-Agent", "claude-cli/2.1.4 (Darwin arm64)"),
            ("x-stainless-os", "MacOS"),
        ]
        outbound, audit = audit_and_prepare_headers(inbound, strip_telemetry=True)
        # Forwarded headers remain intact for upstream
        self.assertEqual(outbound["x-api-key"], api_secret)
        self.assertEqual(outbound["X-Custom-Token"], custom_secret)
        self.assertNotIn("x-stainless-os", outbound)

        # Persisted audit entries contain ONLY name, value_length, category, action — zero values!
        audit_dicts = [a.to_dict() for a in audit]
        audit_json = json.dumps(audit_dicts)
        self.assertNotIn(custom_secret, audit_json)
        self.assertNotIn("custom-super", audit_json)
        self.assertNotIn(api_secret, audit_json)
        self.assertNotIn("sk-ant", audit_json)
        self.assertNotIn("MacOS", audit_json)
        self.assertNotIn("Darwin", audit_json)

        by_name = {d["name"]: d for d in audit_dicts}
        self.assertEqual(by_name["X-Custom-Token"]["value_length"], len(custom_secret))
        self.assertEqual(by_name["x-api-key"]["value_length"], len(api_secret))
        self.assertNotIn("display_value", by_name["X-Custom-Token"])
        self.assertNotIn("value", by_name["X-Custom-Token"])


if __name__ == "__main__":
    unittest.main()
