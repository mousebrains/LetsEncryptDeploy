"""Tests for cyberpower.mousebrains.com.py deploy hook."""

import contextlib
import json
import os
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest


def load_cyberpower():
    """Import the cyberpower module dynamically."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "cyberpower_mousebrains", "cyberpower.mousebrains.com.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestRedactTokens:
    """Tests for the redact_tokens log-sanitizing helper."""

    def test_redacts_token_values(self):
        mod = load_cyberpower()
        body = '{"result": "success", "token": "SECRET123", "temp_token": "TMP456"}'
        out = mod.redact_tokens(body)
        assert "SECRET123" not in out
        assert "TMP456" not in out
        assert '"token"' in out
        assert '"temp_token"' in out

    def test_leaves_other_fields_alone(self):
        mod = load_cyberpower()
        body = '{"result": "success", "expires_in": 180}'
        assert mod.redact_tokens(body) == body

    def test_curl_request_log_redacts_tokens(self, caplog):
        """Session tokens in response bodies must not reach the log."""
        import logging as _logging

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b'{"result": "success", "token": "SESSION456"}'
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result), \
             caplog.at_level(_logging.INFO):
            mod = load_cyberpower()
            mod.curl_request("/usr/bin/curl", "GET", "https://example.com/api")
        assert "SESSION456" not in caplog.text
        assert "REDACTED" in caplog.text


class TestCurlRequest:
    """Tests for the curl_request helper."""

    def test_successful_request(self):
        """Should return CompletedProcess on success."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b'{"result": "success"}'
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result):
            mod = load_cyberpower()
            result = mod.curl_request("/usr/bin/curl", "GET", "https://example.com/api")
            assert result.returncode == 0

    def test_failed_request(self):
        """Should raise RuntimeError on non-zero return code."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = b""
        mock_result.stderr = b"Connection refused"

        with patch("subprocess.run", return_value=mock_result):
            mod = load_cyberpower()
            with pytest.raises(RuntimeError, match="curl GET"):
                mod.curl_request("/usr/bin/curl", "GET", "https://example.com/api")

    def test_data_file_arg(self, tmp_path):
        """Should pass data file with @prefix."""
        data = tmp_path / "data.json"
        data.write_text('{"test": true}')

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b""
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            mod = load_cyberpower()
            mod.curl_request("/usr/bin/curl", "POST", "https://example.com/api",
                             data_file=str(data))
            cmd = mock_run.call_args[0][0]
            assert f"@{data}" in cmd

    def test_form_file_arg(self, tmp_path):
        """Should pass form file with upfile= prefix."""
        cert = tmp_path / "combined.pem"
        cert.write_text("FAKE CERT")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b""
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            mod = load_cyberpower()
            mod.curl_request("/usr/bin/curl", "POST", "https://example.com/api",
                             form_file=str(cert))
            cmd = mock_run.call_args[0][0]
            assert any(f"upfile=@{cert}" in arg for arg in cmd)

    def test_token_header(self):
        """Should add Authorization Bearer header."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b""
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            mod = load_cyberpower()
            mod.curl_request("/usr/bin/curl", "GET", "https://example.com/api",
                             token="mytoken123")
            cmd = mock_run.call_args[0][0]
            assert "Authorization: Bearer mytoken123" in cmd

    def test_verbose_flag(self):
        """Should add -v flag when verbose=True."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b""
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            mod = load_cyberpower()
            mod.curl_request("/usr/bin/curl", "GET", "https://example.com/api",
                             verbose=True)
            cmd = mock_run.call_args[0][0]
            assert "-v" in cmd


class TestParseResponse:
    """Tests for the parse_response helper."""

    def test_valid_json(self):
        """Should return parsed dict."""
        sp = MagicMock()
        sp.stdout = b'{"result": "success", "token": "abc"}'
        mod = load_cyberpower()
        result = mod.parse_response(sp, "test")
        assert result["result"] == "success"

    def test_invalid_json(self):
        """Should raise RuntimeError on non-JSON."""
        sp = MagicMock()
        sp.stdout = b"<html>Error</html>"
        mod = load_cyberpower()
        with pytest.raises(RuntimeError, match="not valid JSON"):
            mod.parse_response(sp, "test")


class TestLogin:
    """Tests for the two-step login flow."""

    def test_successful_login(self, tmp_path):
        """Should return session token."""
        call_count = 0

        def mock_subprocess(cmd, **kwargs):
            nonlocal call_count
            call_count += 1
            result = MagicMock()
            result.returncode = 0
            result.stderr = b""
            if call_count == 1:
                result.stdout = json.dumps({"temp_token": "TEMP123"}).encode()
            else:
                result.stdout = json.dumps({
                    "result": "success",
                    "token": "SESSION456",
                    "expires_in": 180,
                }).encode()
            return result

        with patch("subprocess.run", side_effect=mock_subprocess):
            mod = load_cyberpower()
            token = mod.login("/usr/bin/curl", "ups.example.com",
                              "admin", "pass", str(tmp_path))
            assert token == "SESSION456"
            assert call_count == 2

    def test_login_no_temp_token(self, tmp_path):
        """Should raise RuntimeError when no temp_token returned."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps({"error": "bad credentials"}).encode()
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result):
            mod = load_cyberpower()
            with pytest.raises(RuntimeError, match="no temp_token"):
                mod.login("/usr/bin/curl", "ups.example.com",
                          "admin", "wrong", str(tmp_path))

    def test_login_verify_failure(self, tmp_path):
        """Should raise RuntimeError when verification fails."""
        call_count = 0

        def mock_subprocess(cmd, **kwargs):
            nonlocal call_count
            call_count += 1
            result = MagicMock()
            result.returncode = 0
            result.stderr = b""
            if call_count == 1:
                result.stdout = json.dumps({"temp_token": "TEMP123"}).encode()
            else:
                result.stdout = json.dumps({"result": "fail"}).encode()
            return result

        with patch("subprocess.run", side_effect=mock_subprocess):
            mod = load_cyberpower()
            with pytest.raises(RuntimeError, match="Login verification failed"):
                mod.login("/usr/bin/curl", "ups.example.com",
                          "admin", "pass", str(tmp_path))

    def test_credentials_written_to_tmpdir(self, tmp_path):
        """Should write credentials to a file in tmpdir, not on command line."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps({"temp_token": "T"}).encode()
        mock_result.stderr = b""

        # Only check the first call (login POST)
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            mod = load_cyberpower()
            with contextlib.suppress(RuntimeError, KeyError):
                mod.login("/usr/bin/curl", "ups.example.com",
                          "admin", "secret", str(tmp_path))
            cmd = mock_run.call_args_list[0][0][0]
            # Password should not appear in the command
            assert "secret" not in " ".join(cmd)
            # Data file should reference tmpdir
            data_args = [a for a in cmd if a.startswith("@")]
            assert len(data_args) == 1
            assert data_args[0].startswith(f"@{tmp_path}")


class TestUploadCertificate:
    """Tests for certificate upload."""

    def test_successful_upload(self, tmp_path):
        """Should not raise on success."""
        cert = tmp_path / "combined.pem"
        cert.write_text("FAKE CERT AND KEY")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps({
            "result": "success",
            "msg": "Please logout to set network",
        }).encode()
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result):
            mod = load_cyberpower()
            mod.upload_certificate("/usr/bin/curl", "ups.example.com",
                                   str(cert), "token123")

    def test_upload_failure(self, tmp_path):
        """Should raise RuntimeError on failure response."""
        cert = tmp_path / "combined.pem"
        cert.write_text("FAKE CERT")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps({"result": "fail"}).encode()
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result):
            mod = load_cyberpower()
            with pytest.raises(RuntimeError, match="Certificate upload failed"):
                mod.upload_certificate("/usr/bin/curl", "ups.example.com",
                                       str(cert), "token123")


class TestCyberpowerMain:
    """Tests for the cyberpower main function."""

    def test_missing_env_vars(self, clean_env):
        """Should exit 1 when env vars not set."""
        with patch.object(sys, "argv", ["cyberpower.mousebrains.com.py"]):
            mod = load_cyberpower()
            with pytest.raises(SystemExit, match="1"):
                mod.main()

    def test_hostname_mismatch(self, cert_dir):
        """Should exit 0 when hostname doesn't match."""
        os.environ["RENEWED_DOMAINS"] = "other.example.com"
        os.environ["RENEWED_LINEAGE"] = str(cert_dir)
        with patch.object(sys, "argv", ["cyberpower.mousebrains.com.py"]):
            mod = load_cyberpower()
            with pytest.raises(SystemExit) as exc_info:
                mod.main()
            assert exc_info.value.code == 0

    def test_missing_config_file(self, cert_dir):
        """Should exit 1 when config file doesn't exist."""
        hostname = cert_dir.name
        os.environ["RENEWED_DOMAINS"] = hostname
        os.environ["RENEWED_LINEAGE"] = str(cert_dir)
        with patch.object(sys, "argv",
                          [f"{hostname}.py", "--logfile", "",
                           "--configFile", "/nonexistent/config.json"]):
            mod = load_cyberpower()
            with pytest.raises(SystemExit, match="1"):
                mod.main()

    def test_empty_admin_password(self, cert_dir, config_file):
        """Should exit 1 when admin_password is empty."""
        hostname = cert_dir.name
        os.environ["RENEWED_DOMAINS"] = hostname
        os.environ["RENEWED_LINEAGE"] = str(cert_dir)
        config_file.write_text('{"admin_user": "admin", "admin_password": ""}')
        with patch.object(sys, "argv",
                          [f"{hostname}.py", "--logfile", "",
                           "--configFile", str(config_file)]):
            mod = load_cyberpower()
            with pytest.raises(SystemExit, match="1"):
                mod.main()

    def test_combined_pem_created(self, cert_dir, config_file):
        """Should concatenate fullchain and privkey into combined PEM."""
        hostname = cert_dir.name
        os.environ["RENEWED_DOMAINS"] = hostname
        os.environ["RENEWED_LINEAGE"] = str(cert_dir)

        call_count = 0

        def mock_subprocess(cmd, **kwargs):
            nonlocal call_count
            call_count += 1
            result = MagicMock()
            result.returncode = 0
            result.stderr = b""
            if call_count == 1:
                result.stdout = json.dumps({"temp_token": "T"}).encode()
            elif call_count == 2:
                result.stdout = json.dumps({
                    "result": "success", "token": "S", "expires_in": 180,
                }).encode()
            elif call_count == 3:
                # Upload call — check that the form file contains both cert and key
                form_args = [a for a in cmd if "upfile=@" in a]
                assert len(form_args) == 1
                combined_path = form_args[0].split("@")[1]
                with open(combined_path) as f:
                    content = f.read()
                assert "FAKE CERT DATA" in content
                assert "FAKE KEY DATA" in content
                result.stdout = json.dumps({
                    "result": "success", "msg": "Please logout to set network",
                }).encode()
            else:
                result.stdout = json.dumps({"result": "success"}).encode()
            return result

        with patch.object(sys, "argv",
                          [f"{hostname}.py", "--logfile", "", "--no-verify",
                           "--configFile", str(config_file)]), \
             patch("subprocess.run", side_effect=mock_subprocess):
            mod = load_cyberpower()
            mod.main()

    def test_full_successful_flow(self, cert_dir, config_file):
        """Should complete login, upload, logout flow."""
        hostname = cert_dir.name
        os.environ["RENEWED_DOMAINS"] = hostname
        os.environ["RENEWED_LINEAGE"] = str(cert_dir)

        call_count = 0

        def mock_subprocess(cmd, **kwargs):
            nonlocal call_count
            call_count += 1
            result = MagicMock()
            result.returncode = 0
            result.stderr = b""
            if call_count == 1:
                result.stdout = json.dumps({"temp_token": "TEMP"}).encode()
            elif call_count == 2:
                result.stdout = json.dumps({
                    "result": "success", "token": "SESS", "expires_in": 180,
                }).encode()
            elif call_count == 3:
                result.stdout = json.dumps({
                    "result": "success", "msg": "Please logout to set network",
                }).encode()
            else:
                result.stdout = json.dumps({"result": "success"}).encode()
            return result

        with patch.object(sys, "argv",
                          [f"{hostname}.py", "--logfile", "", "--no-verify",
                           "--configFile", str(config_file)]), \
             patch("subprocess.run", side_effect=mock_subprocess):
            mod = load_cyberpower()
            mod.main()

        # login POST + login verify GET + upload POST + logout PUT = 4
        assert call_count == 4

    def test_timeout_handling(self, cert_dir, config_file):
        """Should exit 1 on timeout."""
        hostname = cert_dir.name
        os.environ["RENEWED_DOMAINS"] = hostname
        os.environ["RENEWED_LINEAGE"] = str(cert_dir)

        with patch.object(sys, "argv",
                          [f"{hostname}.py", "--logfile", "",
                           "--configFile", str(config_file)]), \
             patch("subprocess.run",
                   side_effect=subprocess.TimeoutExpired("curl", 180)):
            mod = load_cyberpower()
            with pytest.raises(SystemExit, match="1"):
                mod.main()


class TestVerify:
    """Tests for the post-deploy certificate verification helpers."""

    def _write_pem(self, path, der):
        import base64
        b64 = base64.b64encode(der).decode()
        path.write_text(
            f"-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n")

    def test_leaf_cert_der_roundtrip(self, tmp_path):
        """Should decode the first PEM certificate back to its DER bytes."""
        mod = load_cyberpower()
        der = b"\x30\x82\x01\x02 fake der bytes"
        pem = tmp_path / "c.pem"
        self._write_pem(pem, der)
        assert mod.leaf_cert_der(str(pem)) == der

    def test_verify_matches(self, tmp_path):
        """Should return quietly when the served cert matches the deployed one."""
        mod = load_cyberpower()
        der = b"matching der"
        pem = tmp_path / "c.pem"
        self._write_pem(pem, der)
        with patch.object(mod, "served_cert_der", return_value=der):
            mod.verify_served_certificate("h", str(pem), attempts=1, delay=0)

    def test_verify_mismatch_raises(self, tmp_path):
        """Should raise after retrying when the served cert never matches."""
        mod = load_cyberpower()
        pem = tmp_path / "c.pem"
        self._write_pem(pem, b"deployed der")
        with patch.object(mod, "served_cert_der", return_value=b"other der"), \
             patch.object(mod.time, "sleep") as mock_sleep:
            with pytest.raises(RuntimeError, match="Verification failed"):
                mod.verify_served_certificate("h", str(pem), attempts=3, delay=0)
            assert mock_sleep.call_count == 2

    def test_verify_deadline(self, tmp_path):
        """Should stop at the absolute deadline even if attempts remain."""
        mod = load_cyberpower()
        pem = tmp_path / "c.pem"
        self._write_pem(pem, b"deployed der")
        with patch.object(mod, "served_cert_der", return_value=b"other der"), \
             patch.object(mod.time, "monotonic", side_effect=[0.0, 1000.0]), \
             patch.object(mod.time, "sleep") as mock_sleep:
            with pytest.raises(RuntimeError, match="deadline"):
                mod.verify_served_certificate("h", str(pem), attempts=100,
                                              delay=10, deadline=50)
            assert mock_sleep.call_count == 0
