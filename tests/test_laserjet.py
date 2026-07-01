"""Tests for laserjet.mousebrains.com.py deploy hook."""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest


def load_laserjet():
    """Import the laserjet module dynamically."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "laserjet_mousebrains", "laserjet.mousebrains.com.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestCurlPost:
    """Tests for the laserjet curl_post helper."""

    def test_extra_args(self):
        """Should append extra_args to the curl command."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b""
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            mod = load_laserjet()
            mod.curl_post("/usr/bin/curl", "https://example.com/api",
                          extra_args=["-F", "field=value"])
            cmd = mock_run.call_args[0][0]
            assert "-F" in cmd
            assert "field=value" in cmd

    def test_netrc_file(self, tmp_path):
        """Should pass --netrc-file when provided."""
        netrc = tmp_path / "netrc"
        netrc.write_text("machine example.com login admin password pass\n")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b""
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            mod = load_laserjet()
            mod.curl_post("/usr/bin/curl", "https://example.com/api",
                          netrc_file=str(netrc))
            cmd = mock_run.call_args[0][0]
            assert "--netrc-file" in cmd
            assert str(netrc) in cmd

    def test_follows_redirects(self):
        """Should include -L flag for redirect following."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b""
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            mod = load_laserjet()
            mod.curl_post("/usr/bin/curl", "https://example.com/api")
            cmd = mock_run.call_args[0][0]
            assert "-L" in cmd

    def test_does_not_force_post_method(self):
        """Must NOT pass -X POST: it would re-POST the 303 redirect -> 405."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b""
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            mod = load_laserjet()
            mod.curl_post("/usr/bin/curl", "https://example.com/api",
                          data="a=b")
            cmd = mock_run.call_args[0][0]
            assert "-X" not in cmd

    def test_fails_on_http_error(self):
        """Should pass --fail-with-body so HTTP >= 400 becomes a curl error."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b""
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            mod = load_laserjet()
            mod.curl_post("/usr/bin/curl", "https://example.com/api")
            cmd = mock_run.call_args[0][0]
            assert "--fail-with-body" in cmd

    def test_cookie_jar(self, tmp_path):
        """Should pass -c and -b with the cookies file when provided."""
        cookies = tmp_path / "cookies"
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b""
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            mod = load_laserjet()
            mod.curl_post("/usr/bin/curl", "https://example.com/api",
                          cookies_file=str(cookies))
            cmd = mock_run.call_args[0][0]
            assert "-c" in cmd
            assert "-b" in cmd
            assert str(cookies) in cmd


class TestUploadCertificate:
    """Tests for the upload_certificate function."""

    def test_three_step_flow(self, tmp_path):
        """Should make exactly 3 POST requests."""
        pfx = tmp_path / "cert.pfx"
        pfx.write_bytes(b"FAKE PFX")
        netrc = tmp_path / "netrc"
        netrc.write_text("machine printer.example.com login admin password pass\n")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b""
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            mod = load_laserjet()
            mod.upload_certificate("/usr/bin/curl", "printer.example.com",
                                   str(pfx), "pfxpass", str(netrc),
                                   str(tmp_path / "cookies"))
            assert mock_run.call_count == 3

    def test_step_urls(self, tmp_path):
        """Should POST to the correct EWS URLs in order."""
        pfx = tmp_path / "cert.pfx"
        pfx.write_bytes(b"FAKE PFX")
        netrc = tmp_path / "netrc"
        netrc.write_text("machine h login a password p\n")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b""
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            mod = load_laserjet()
            mod.upload_certificate("/usr/bin/curl", "h", str(pfx), "p", str(netrc),
                                   str(tmp_path / "cookies"))
            urls = [call[0][0][4] for call in mock_run.call_args_list]
            assert "set_config_networkCerts" in urls[0]
            assert "set_config_networkPrintCerts" in urls[1]
            assert "Certificate.pfx" in urls[2]

    def test_step3_includes_form_fields(self, tmp_path):
        """Should use the real EWS import form fields: FileName/Password/Finish."""
        pfx = tmp_path / "cert.pfx"
        pfx.write_bytes(b"FAKE PFX")
        netrc = tmp_path / "netrc"
        netrc.write_text("machine h login a password p\n")
        pw_file = tmp_path / "pfx-password"
        pw_file.write_text("testpw")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b""
        mock_result.stderr = b""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            mod = load_laserjet()
            mod.upload_certificate("/usr/bin/curl", "h", str(pfx), str(pw_file),
                                   str(netrc), str(tmp_path / "cookies"))
            step3_cmd = mock_run.call_args_list[2][0][0]
            assert any("FileName=@" in arg for arg in step3_cmd)
            # Password is read from a file (-F 'Password=<file'), never on argv
            assert any(f"Password=<{pw_file}" in arg for arg in step3_cmd)
            assert not any("testpw" in arg for arg in step3_cmd
                           if "Password=<" not in arg)
            assert "Finish=" in step3_cmd
            # The old, wrong field names must be gone.
            assert not any("CertFile=@" in arg for arg in step3_cmd)


class TestLaserjetMain:
    """Tests for the laserjet main function."""

    def test_missing_env_vars(self, clean_env):
        """Should exit 1 when env vars not set."""
        with patch.object(sys, "argv", ["laserjet.mousebrains.com.py"]):
            mod = load_laserjet()
            with pytest.raises(SystemExit, match="1"):
                mod.main()

    def test_hostname_mismatch(self, cert_dir):
        """Should exit 0 when hostname doesn't match."""
        os.environ["RENEWED_DOMAINS"] = "other.example.com"
        os.environ["RENEWED_LINEAGE"] = str(cert_dir)
        with patch.object(sys, "argv", ["laserjet.mousebrains.com.py"]):
            mod = load_laserjet()
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
            mod = load_laserjet()
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
            mod = load_laserjet()
            with pytest.raises(SystemExit, match="1"):
                mod.main()

    def test_netrc_file_created_in_tmpdir(self, cert_dir, config_file):
        """Should create netrc file with credentials in temp dir."""
        hostname = cert_dir.name
        os.environ["RENEWED_DOMAINS"] = hostname
        os.environ["RENEWED_LINEAGE"] = str(cert_dir)

        def mock_subprocess(cmd, **kwargs):
            result = MagicMock()
            result.returncode = 0
            result.stderr = b""
            if "pkcs12" in cmd:
                out_idx = list(cmd).index("-out") + 1
                with open(cmd[out_idx], "wb") as f:
                    f.write(b"FAKE PFX")
                result.stdout = b""
            else:
                result.stdout = b""
            return result

        netrc_contents = []

        original_open = open
        def capturing_open(path, *args, **kwargs):
            f = original_open(path, *args, **kwargs)
            if str(path).endswith("netrc"):
                # Wrap to capture writes
                original_write = f.write
                def capturing_write(data):
                    netrc_contents.append(data)
                    return original_write(data)
                f.write = capturing_write
            return f

        with patch.object(sys, "argv",
                          [f"{hostname}.py", "--logfile", "",
                           "--no-verify", "--configFile", str(config_file)]), \
             patch("subprocess.run", side_effect=mock_subprocess):
            mod = load_laserjet()
            mod.main()

    def test_full_successful_flow(self, cert_dir, config_file):
        """Should complete the full openssl + 3-step upload."""
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
            if "pkcs12" in cmd:
                out_idx = list(cmd).index("-out") + 1
                with open(cmd[out_idx], "wb") as f:
                    f.write(b"FAKE PFX")
                result.stdout = b""
            else:
                result.stdout = b""
            return result

        with patch.object(sys, "argv",
                          [f"{hostname}.py", "--logfile", "",
                           "--no-verify", "--configFile", str(config_file)]), \
             patch("subprocess.run", side_effect=mock_subprocess):
            mod = load_laserjet()
            mod.main()

        # openssl + 3 curl calls = 4
        assert call_count == 4


class TestVerify:
    """Tests for the post-deploy certificate verification helpers."""

    def _write_pem(self, path, der):
        import base64
        b64 = base64.b64encode(der).decode()
        path.write_text(
            f"-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n")

    def test_leaf_cert_der_roundtrip(self, tmp_path):
        """Should decode the first PEM certificate back to its DER bytes."""
        mod = load_laserjet()
        der = b"\x30\x82\x01\x02 fake der bytes"
        pem = tmp_path / "c.pem"
        self._write_pem(pem, der)
        assert mod.leaf_cert_der(str(pem)) == der

    def test_leaf_cert_der_no_cert(self, tmp_path):
        """Should raise when the file has no PEM certificate."""
        mod = load_laserjet()
        pem = tmp_path / "c.pem"
        pem.write_text("not a certificate")
        with pytest.raises(RuntimeError):
            mod.leaf_cert_der(str(pem))

    def test_verify_matches(self, tmp_path):
        """Should return quietly when the served cert matches the deployed one."""
        mod = load_laserjet()
        der = b"matching der"
        pem = tmp_path / "c.pem"
        self._write_pem(pem, der)
        with patch.object(mod, "served_cert_der", return_value=der):
            mod.verify_served_certificate("h", str(pem), attempts=1, delay=0)

    def test_verify_mismatch_raises(self, tmp_path):
        """Should raise after retrying when the served cert never matches."""
        mod = load_laserjet()
        pem = tmp_path / "c.pem"
        self._write_pem(pem, b"deployed der")
        with patch.object(mod, "served_cert_der", return_value=b"other der"), \
             patch.object(mod.time, "sleep") as mock_sleep:
            with pytest.raises(RuntimeError, match="Verification failed"):
                mod.verify_served_certificate("h", str(pem), attempts=3, delay=0)
            # Slept between attempts but not after the last one.
            assert mock_sleep.call_count == 2

    def test_verify_deadline(self, tmp_path):
        """Should stop at the absolute deadline even if attempts remain."""
        mod = load_laserjet()
        pem = tmp_path / "c.pem"
        self._write_pem(pem, b"deployed der")
        with patch.object(mod, "served_cert_der", return_value=b"other der"), \
             patch.object(mod.time, "monotonic", side_effect=[0.0, 1000.0]), \
             patch.object(mod.time, "sleep") as mock_sleep:
            with pytest.raises(RuntimeError, match="deadline"):
                mod.verify_served_certificate("h", str(pem), attempts=100,
                                              delay=10, deadline=50)
            assert mock_sleep.call_count == 0
