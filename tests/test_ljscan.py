"""Tests for ljscan.mousebrains.com.py deploy hook."""

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest


def load_ljscan():
    """Import the ljscan module dynamically."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "ljscan_mousebrains", "ljscan.mousebrains.com.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestCurlPost:
    """Tests for the curl_post helper function."""

    def test_successful_post(self, tmp_path):
        """Should return CompletedProcess on success."""
        data_file = tmp_path / "data.txt"
        data_file.write_text("test=data")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b'{"ok": true}'
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result):
            mod = load_ljscan()
            result = mod.curl_post("/usr/bin/curl", "https://example.com/api",
                                   data_file=str(data_file))
            assert result.returncode == 0

    def test_failed_post(self):
        """Should raise RuntimeError on non-zero return code."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = b""
        mock_result.stderr = b"Connection refused"

        with patch("subprocess.run", return_value=mock_result):
            mod = load_ljscan()
            with pytest.raises(RuntimeError, match="curl POST"):
                mod.curl_post("/usr/bin/curl", "https://example.com/api")

    def test_verbose_flag(self):
        """Should add -v flag when verbose=True."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b""
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            mod = load_ljscan()
            mod.curl_post("/usr/bin/curl", "https://example.com/api", verbose=True)
            cmd = mock_run.call_args[0][0]
            assert "-v" in cmd

    def test_user_agent_set(self):
        """Should set User-Agent to AppleWebKit."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b""
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            mod = load_ljscan()
            mod.curl_post("/usr/bin/curl", "https://example.com/api")
            cmd = mock_run.call_args[0][0]
            ua_idx = cmd.index("User-Agent: AppleWebKit")
            assert cmd[ua_idx - 1] == "-H"

    def test_header_file(self, tmp_path):
        """Should pass header file with @prefix."""
        header = tmp_path / "header.txt"
        header.write_text("Authorization: Bearer token123")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b""
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            mod = load_ljscan()
            mod.curl_post("/usr/bin/curl", "https://example.com/api",
                          header_file=str(header))
            cmd = mock_run.call_args[0][0]
            assert f"@{header}" in cmd


class TestAuthenticate:
    """Tests for the authenticate function."""

    def test_successful_auth(self, tmp_path):
        """Should return access token on success."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps({
            "access_token": "test-token-123",
            "token_type": "bearer",
            "scope": "deviceAdmin",
        }).encode()
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result):
            mod = load_ljscan()
            token = mod.authenticate("/usr/bin/curl", "printer.example.com",
                                     "admin", "pass", str(tmp_path))
            assert token == "test-token-123"

    def test_auth_failure(self, tmp_path):
        """Should raise RuntimeError when no access_token."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps({
            "error": "invalid_grant",
            "error_description": "Bad credentials",
        }).encode()
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result):
            mod = load_ljscan()
            with pytest.raises(RuntimeError, match="Authentication failed"):
                mod.authenticate("/usr/bin/curl", "printer.example.com",
                                 "admin", "wrongpass", str(tmp_path))

    def test_invalid_json_response(self, tmp_path):
        """Should raise RuntimeError on non-JSON response."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b"<html>Error</html>"
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result):
            mod = load_ljscan()
            with pytest.raises(RuntimeError, match="not valid JSON"):
                mod.authenticate("/usr/bin/curl", "printer.example.com",
                                 "admin", "pass", str(tmp_path))

    def test_auth_data_written_to_tmpdir(self, tmp_path):
        """Should write auth POST data to a file in tmpdir."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps({"access_token": "tok"}).encode()
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            mod = load_ljscan()
            mod.authenticate("/usr/bin/curl", "printer.example.com",
                             "admin", "pass", str(tmp_path))
            cmd = mock_run.call_args[0][0]
            # Find the data file reference
            data_args = [a for a in cmd if a.startswith("@")]
            assert len(data_args) == 1
            data_file = data_args[0][1:]  # Strip @
            assert data_file.startswith(str(tmp_path))


class TestLjscanMain:
    """Tests for the ljscan main function."""

    def test_missing_env_vars(self, clean_env):
        """Should exit 1 when env vars not set."""
        with patch.object(sys, "argv", ["ljscan.mousebrains.com.py"]):
            mod = load_ljscan()
            with pytest.raises(SystemExit, match="1"):
                mod.main()

    def test_hostname_mismatch(self, cert_dir):
        """Should exit 0 when hostname doesn't match."""
        os.environ["RENEWED_DOMAINS"] = "other.example.com"
        os.environ["RENEWED_LINEAGE"] = str(cert_dir)
        with patch.object(sys, "argv", ["ljscan.mousebrains.com.py"]):
            mod = load_ljscan()
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
            mod = load_ljscan()
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
            mod = load_ljscan()
            with pytest.raises(SystemExit, match="1"):
                mod.main()

    def test_openssl_failure(self, cert_dir, config_file):
        """Should exit 1 when openssl fails."""
        hostname = cert_dir.name
        os.environ["RENEWED_DOMAINS"] = hostname
        os.environ["RENEWED_LINEAGE"] = str(cert_dir)

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = b""
        mock_result.stderr = b"openssl error"

        with patch.object(sys, "argv",
                          [f"{hostname}.py", "--logfile", "",
                           "--configFile", str(config_file)]), \
             patch("subprocess.run", return_value=mock_result):
            mod = load_ljscan()
            with pytest.raises(SystemExit, match="1"):
                mod.main()

    def test_full_successful_flow(self, cert_dir, config_file):
        """Should complete the full auth + upload flow."""
        hostname = cert_dir.name
        os.environ["RENEWED_DOMAINS"] = hostname
        os.environ["RENEWED_LINEAGE"] = str(cert_dir)

        # openssl succeeds, write a dummy pfx file
        def mock_subprocess(cmd, **kwargs):
            result = MagicMock()
            result.returncode = 0
            result.stderr = b""
            if "pkcs12" in cmd:
                # Write dummy pfx data to the output file
                out_idx = list(cmd).index("-out") + 1
                with open(cmd[out_idx], "wb") as f:
                    f.write(b"FAKE PFX DATA")
                result.stdout = b""
            else:
                # curl calls — auth returns token, upload returns success
                result.stdout = json.dumps({
                    "access_token": "test-token",
                    "token_type": "bearer",
                }).encode()
            return result

        with patch.object(sys, "argv",
                          [f"{hostname}.py", "--logfile", "",
                           "--configFile", str(config_file)]), \
             patch("subprocess.run", side_effect=mock_subprocess):
            mod = load_ljscan()
            mod.main()  # Should not raise
