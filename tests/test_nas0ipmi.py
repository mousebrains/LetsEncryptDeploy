"""Tests for nas0ipmi.mousebrains.com.py deploy hook."""

import os
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest


def load_nas0ipmi():
    """Import the nas0ipmi module dynamically."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "nas0ipmi_mousebrains", "nas0ipmi.mousebrains.com.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CSRF_HTML = '''<html><body>
<script>SmcCsrfInsert ("CSRF-TOKEN", "testtoken123abc");
/*SmcCsrfInsert ("CSRF_TOKEN", "testtoken123abc");*/</script>
</body></html>'''

VALIDATE_OK = '<?xml version="1.0"?><IPMI><SSL_INFO VALIDATE="1"/></IPMI>'
VALIDATE_FAIL = '<?xml version="1.0"?><IPMI><SSL_INFO VALIDATE="0"/></IPMI>'


class TestCurlRequest:
    """Tests for the curl_request helper."""

    def test_successful_get(self):
        """Should return CompletedProcess on success."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b"OK"
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result):
            mod = load_nas0ipmi()
            result = mod.curl_request("/usr/bin/curl", "https://example.com/",
                                      "/tmp/cookies")
            assert result.returncode == 0

    def test_failed_request(self):
        """Should raise RuntimeError on non-zero return code."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = b""
        mock_result.stderr = b"Connection refused"

        with patch("subprocess.run", return_value=mock_result):
            mod = load_nas0ipmi()
            with pytest.raises(RuntimeError, match="curl GET"):
                mod.curl_request("/usr/bin/curl", "https://example.com/",
                                 "/tmp/cookies")

    def test_form_fields(self):
        """Should add -F flags for each form field."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b""
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            mod = load_nas0ipmi()
            mod.curl_request("/usr/bin/curl", "https://example.com/upload",
                             "/tmp/cookies", method="POST",
                             form_fields=[("file", "@cert.pem"), ("token", "abc")])
            cmd = mock_run.call_args[0][0]
            f_indices = [i for i, v in enumerate(cmd) if v == "-F"]
            assert len(f_indices) == 2
            assert cmd[f_indices[0] + 1] == "file=@cert.pem"
            assert cmd[f_indices[1] + 1] == "token=abc"

    def test_headers(self):
        """Should add -H flags for each header."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b""
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            mod = load_nas0ipmi()
            mod.curl_request("/usr/bin/curl", "https://example.com/",
                             "/tmp/cookies",
                             headers={"CSRF-TOKEN": "abc123"})
            cmd = mock_run.call_args[0][0]
            assert "CSRF-TOKEN: abc123" in cmd

    def test_post_data(self):
        """Should add -d flag for post data."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b""
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            mod = load_nas0ipmi()
            mod.curl_request("/usr/bin/curl", "https://example.com/",
                             "/tmp/cookies", post_data="op=test&r=(0,0)")
            cmd = mock_run.call_args[0][0]
            assert "op=test&r=(0,0)" in cmd

    def test_verbose_flag(self):
        """Should add -v flag when verbose=True."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b""
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            mod = load_nas0ipmi()
            mod.curl_request("/usr/bin/curl", "https://example.com/",
                             "/tmp/cookies", verbose=True)
            cmd = mock_run.call_args[0][0]
            assert "-v" in cmd

    def test_cookies_file(self):
        """Should pass -b with cookies file."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b""
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            mod = load_nas0ipmi()
            mod.curl_request("/usr/bin/curl", "https://example.com/",
                             "/tmp/my_cookies")
            cmd = mock_run.call_args[0][0]
            b_idx = cmd.index("-b")
            assert cmd[b_idx + 1] == "/tmp/my_cookies"


class TestBmcLogin:
    """Tests for BMC login."""

    def test_successful_login(self, tmp_path):
        """Should not raise on success."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b"<html>redirect</html>"
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result):
            mod = load_nas0ipmi()
            mod.bmc_login("/usr/bin/curl", "bmc.example.com",
                          "admin", "pass", str(tmp_path / "cookies"))

    def test_login_failure(self, tmp_path):
        """Should raise RuntimeError on curl failure."""
        mock_result = MagicMock()
        mock_result.returncode = 7
        mock_result.stdout = b""
        mock_result.stderr = b"Connection refused"

        with patch("subprocess.run", return_value=mock_result):
            mod = load_nas0ipmi()
            with pytest.raises(RuntimeError, match="BMC login failed"):
                mod.bmc_login("/usr/bin/curl", "bmc.example.com",
                              "admin", "pass", str(tmp_path / "cookies"))

    def test_password_url_encoded(self, tmp_path):
        """Should URL-encode the password in the POST data."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b""
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            mod = load_nas0ipmi()
            mod.bmc_login("/usr/bin/curl", "bmc.example.com",
                          "admin", "p@ss&word=1", str(tmp_path / "cookies"))
            cmd = mock_run.call_args[0][0]
            d_idx = cmd.index("-d")
            post_data = cmd[d_idx + 1]
            assert "p%40ss%26word%3D1" in post_data


class TestGetCsrfToken:
    """Tests for CSRF token extraction."""

    def test_extracts_token(self):
        """Should extract CSRF token from HTML."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = CSRF_HTML.encode()
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result):
            mod = load_nas0ipmi()
            token = mod.get_csrf_token("/usr/bin/curl", "bmc.example.com",
                                       "/tmp/cookies")
            assert token == "testtoken123abc"

    def test_missing_token(self):
        """Should raise RuntimeError when token not found."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b"<html>no token here</html>"
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result):
            mod = load_nas0ipmi()
            with pytest.raises(RuntimeError, match="Could not extract CSRF"):
                mod.get_csrf_token("/usr/bin/curl", "bmc.example.com",
                                   "/tmp/cookies")


class TestUploadCertificate:
    """Tests for certificate upload."""

    def test_upload_form_fields(self, tmp_path):
        """Should upload cert and key with correct content-type and CSRF token."""
        cert = tmp_path / "fullchain.pem"
        cert.write_text("CERT DATA")
        key = tmp_path / "privkey.pem"
        key.write_text("KEY DATA")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b"<html>uploaded</html>"
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            mod = load_nas0ipmi()
            mod.upload_certificate("/usr/bin/curl", "bmc.example.com",
                                   str(cert), str(key),
                                   "/tmp/cookies", "csrf_tok")
            cmd = mock_run.call_args[0][0]
            f_args = [cmd[i + 1] for i, v in enumerate(cmd) if v == "-F"]
            assert len(f_args) == 3
            assert any("cert_file=" in a and "x-x509-ca-cert" in a for a in f_args)
            assert any("key_file=" in a and "x-x509-ca-cert" in a for a in f_args)
            assert any("CSRF-TOKEN=csrf_tok" in a for a in f_args)


class TestValidateCertificate:
    """Tests for certificate validation."""

    def test_validation_success(self):
        """Should not raise when VALIDATE=1."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = VALIDATE_OK.encode()
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result):
            mod = load_nas0ipmi()
            mod.validate_certificate("/usr/bin/curl", "bmc.example.com",
                                     "/tmp/cookies", "csrf_tok")

    def test_validation_failure(self):
        """Should raise RuntimeError when VALIDATE=0."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = VALIDATE_FAIL.encode()
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result):
            mod = load_nas0ipmi()
            with pytest.raises(RuntimeError, match="Certificate validation failed"):
                mod.validate_certificate("/usr/bin/curl", "bmc.example.com",
                                         "/tmp/cookies", "csrf_tok")

    def test_csrf_sent_as_header(self):
        """Should send CSRF token as a header for ipmi.cgi."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = VALIDATE_OK.encode()
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            mod = load_nas0ipmi()
            mod.validate_certificate("/usr/bin/curl", "bmc.example.com",
                                     "/tmp/cookies", "my_csrf")
            cmd = mock_run.call_args[0][0]
            assert "CSRF-TOKEN: my_csrf" in cmd


class TestNas0ipmiMain:
    """Tests for the nas0ipmi main function."""

    def test_missing_env_vars(self, clean_env):
        """Should exit 1 when env vars not set."""
        with patch.object(sys, "argv", ["nas0ipmi.mousebrains.com.py"]):
            mod = load_nas0ipmi()
            with pytest.raises(SystemExit, match="1"):
                mod.main()

    def test_hostname_mismatch(self, cert_dir):
        """Should exit 0 when hostname doesn't match."""
        os.environ["RENEWED_DOMAINS"] = "other.example.com"
        os.environ["RENEWED_LINEAGE"] = str(cert_dir)
        with patch.object(sys, "argv", ["nas0ipmi.mousebrains.com.py"]):
            mod = load_nas0ipmi()
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
            mod = load_nas0ipmi()
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
            mod = load_nas0ipmi()
            with pytest.raises(SystemExit, match="1"):
                mod.main()

    def test_full_successful_flow(self, cert_dir, config_file):
        """Should complete login, CSRF, upload, validate, reset flow."""
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
                # bmc_login
                result.stdout = b"<html>redirect</html>"
            elif call_count == 2:
                # get_csrf_token
                result.stdout = CSRF_HTML.encode()
            elif call_count == 3:
                # upload_certificate
                result.stdout = b"<html>uploaded</html>"
            elif call_count == 4:
                # validate_certificate
                result.stdout = VALIDATE_OK.encode()
            elif call_count == 5:
                # bmc_reset
                result.stdout = b""
            return result

        with patch.object(sys, "argv",
                          [f"{hostname}.py", "--logfile", "",
                           "--configFile", str(config_file)]), \
             patch("subprocess.run", side_effect=mock_subprocess):
            mod = load_nas0ipmi()
            mod.main()

        # login + csrf + upload + validate + reset = 5
        assert call_count == 5

    def test_no_reset_flag(self, cert_dir, config_file):
        """Should skip BMC reset when --no-reset is passed."""
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
                result.stdout = b"<html>redirect</html>"
            elif call_count == 2:
                result.stdout = CSRF_HTML.encode()
            elif call_count == 3:
                result.stdout = b"<html>uploaded</html>"
            elif call_count == 4:
                result.stdout = VALIDATE_OK.encode()
            return result

        with patch.object(sys, "argv",
                          [f"{hostname}.py", "--logfile", "",
                           "--configFile", str(config_file), "--no-reset"]), \
             patch("subprocess.run", side_effect=mock_subprocess):
            mod = load_nas0ipmi()
            mod.main()

        # login + csrf + upload + validate = 4 (no reset)
        assert call_count == 4

    def test_validation_failure_exits(self, cert_dir, config_file):
        """Should exit 1 when certificate validation fails."""
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
                result.stdout = b"<html>redirect</html>"
            elif call_count == 2:
                result.stdout = CSRF_HTML.encode()
            elif call_count == 3:
                result.stdout = b"<html>uploaded</html>"
            elif call_count == 4:
                result.stdout = VALIDATE_FAIL.encode()
            return result

        with patch.object(sys, "argv",
                          [f"{hostname}.py", "--logfile", "",
                           "--configFile", str(config_file)]), \
             patch("subprocess.run", side_effect=mock_subprocess):
            mod = load_nas0ipmi()
            with pytest.raises(SystemExit, match="1"):
                mod.main()

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
            mod = load_nas0ipmi()
            with pytest.raises(SystemExit, match="1"):
                mod.main()
