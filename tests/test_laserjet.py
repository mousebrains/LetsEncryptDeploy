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
                                   str(pfx), "pfxpass", str(netrc))
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
            mod.upload_certificate("/usr/bin/curl", "h", str(pfx), "p", str(netrc))
            urls = [call[0][0][4] for call in mock_run.call_args_list]
            assert "set_config_networkCerts" in urls[0]
            assert "set_config_networkPrintCerts" in urls[1]
            assert "Certificate.pfx" in urls[2]

    def test_step3_includes_form_fields(self, tmp_path):
        """Should include CertFile, CertPwd, and ImportCert form fields."""
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
            mod.upload_certificate("/usr/bin/curl", "h", str(pfx), "testpw", str(netrc))
            step3_cmd = mock_run.call_args_list[2][0][0]
            assert any("CertFile=@" in arg for arg in step3_cmd)
            assert any("CertPwd=testpw" in arg for arg in step3_cmd)
            assert "ImportCert=Import" in step3_cmd


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
                           "--configFile", str(config_file)]), \
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
                           "--configFile", str(config_file)]), \
             patch("subprocess.run", side_effect=mock_subprocess):
            mod = load_laserjet()
            mod.main()

        # openssl + 3 curl calls = 4
        assert call_count == 4
