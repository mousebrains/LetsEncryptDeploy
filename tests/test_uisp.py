"""Tests for uisp.mousebrains.com.py deploy hook."""

import os
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest


def load_uisp():
    """Import the UISP module dynamically."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "uisp_mousebrains", "uisp.mousebrains.com.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestUISPMain:
    """Tests for the UISP deploy hook main function."""

    def test_missing_env_vars(self, clean_env):
        """Should exit 1 when RENEWED_DOMAINS is not set."""
        with patch.object(sys, "argv", ["uisp.mousebrains.com.py"]):
            mod = load_uisp()
            with pytest.raises(SystemExit, match="1"):
                mod.main()

    def test_hostname_mismatch(self, cert_dir):
        """Should exit 0 when hostname doesn't match."""
        os.environ["RENEWED_DOMAINS"] = "other.example.com"
        os.environ["RENEWED_LINEAGE"] = str(cert_dir)
        with patch.object(sys, "argv", ["uisp.mousebrains.com.py"]):
            mod = load_uisp()
            with pytest.raises(SystemExit) as exc_info:
                mod.main()
            assert exc_info.value.code == 0

    def test_successful_deployment(self, cert_dir):
        """Should SCP to certDir and SSH reload."""
        hostname = cert_dir.name
        os.environ["RENEWED_DOMAINS"] = hostname
        os.environ["RENEWED_LINEAGE"] = str(cert_dir)

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b""
        mock_result.stderr = b""

        with patch.object(sys, "argv",
                          [f"{hostname}.py", "--logfile", "", "--no-verify"]), \
             patch("subprocess.run", return_value=mock_result) as mock_run:
            mod = load_uisp()
            mod.main()

            assert mock_run.call_count == 2
            scp_call = mock_run.call_args_list[0]
            # SCP target should include the certDir
            scp_target = scp_call[0][0][-1]
            assert hostname in scp_target
            assert "/etc/certificates/" in scp_target

    def test_reload_timeout_configurable(self, cert_dir):
        """Should use --reloadTimeout for the SSH command."""
        hostname = cert_dir.name
        os.environ["RENEWED_DOMAINS"] = hostname
        os.environ["RENEWED_LINEAGE"] = str(cert_dir)

        success = MagicMock()
        success.returncode = 0
        success.stdout = b""
        success.stderr = b""

        with patch.object(sys, "argv",
                          [f"{hostname}.py", "--logfile", "", "--no-verify",
                           "--reloadTimeout", "300"]), \
             patch("subprocess.run", return_value=success) as mock_run:
            mod = load_uisp()
            mod.main()

            ssh_call = mock_run.call_args_list[1]
            assert ssh_call[1]["timeout"] == 300

    def test_missing_cert_file(self, cert_dir):
        """Should exit 1 when certificate file doesn't exist."""
        hostname = cert_dir.name
        os.environ["RENEWED_DOMAINS"] = hostname
        os.environ["RENEWED_LINEAGE"] = str(cert_dir)
        (cert_dir / "fullchain.pem").unlink()
        with patch.object(sys, "argv", [f"{hostname}.py", "--logfile", ""]):
            mod = load_uisp()
            with pytest.raises(SystemExit, match="1"):
                mod.main()

    def test_scp_failure(self, cert_dir):
        """Should exit 1 when SCP fails."""
        hostname = cert_dir.name
        os.environ["RENEWED_DOMAINS"] = hostname
        os.environ["RENEWED_LINEAGE"] = str(cert_dir)

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = b""
        mock_result.stderr = b"Connection refused"

        with patch.object(sys, "argv", [f"{hostname}.py", "--logfile", ""]), \
             patch("subprocess.run", return_value=mock_result):
            mod = load_uisp()
            with pytest.raises(SystemExit, match="1"):
                mod.main()

    def test_scp_timeout(self, cert_dir):
        """Should exit 1 on SCP timeout."""
        hostname = cert_dir.name
        os.environ["RENEWED_DOMAINS"] = hostname
        os.environ["RENEWED_LINEAGE"] = str(cert_dir)

        with patch.object(sys, "argv", [f"{hostname}.py", "--logfile", ""]), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired("scp", 180)):
            mod = load_uisp()
            with pytest.raises(SystemExit, match="1"):
                mod.main()

    def test_certdir_default_from_hostname(self):
        """Should default certDir to /etc/certificates/<hostname>."""
        script_name = os.path.basename("test.example.com.py")
        hostname = script_name.removesuffix(".py")
        assert hostname == "test.example.com"
        assert f"/etc/certificates/{hostname}" == "/etc/certificates/test.example.com"


class TestVerify:
    """Tests for the post-deploy certificate verification helpers."""

    def _write_pem(self, path, der):
        import base64
        b64 = base64.b64encode(der).decode()
        path.write_text(
            f"-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n")

    def test_leaf_cert_der_roundtrip(self, tmp_path):
        """Should decode the first PEM certificate back to its DER bytes."""
        mod = load_uisp()
        der = b"\x30\x82\x01\x02 fake der bytes"
        pem = tmp_path / "c.pem"
        self._write_pem(pem, der)
        assert mod.leaf_cert_der(str(pem)) == der

    def test_verify_matches(self, tmp_path):
        """Should return quietly when the served cert matches the deployed one."""
        mod = load_uisp()
        der = b"matching der"
        pem = tmp_path / "c.pem"
        self._write_pem(pem, der)
        with patch.object(mod, "served_cert_der", return_value=der):
            mod.verify_served_certificate("h", str(pem), attempts=1, delay=0)

    def test_verify_mismatch_raises(self, tmp_path):
        """Should raise after retrying when the served cert never matches."""
        mod = load_uisp()
        pem = tmp_path / "c.pem"
        self._write_pem(pem, b"deployed der")
        with patch.object(mod, "served_cert_der", return_value=b"other der"), \
             patch.object(mod.time, "sleep") as mock_sleep:
            with pytest.raises(RuntimeError, match="Verification failed"):
                mod.verify_served_certificate("h", str(pem), attempts=3, delay=0)
            assert mock_sleep.call_count == 2

    def test_verify_deadline(self, tmp_path):
        """Should stop at the absolute deadline even if attempts remain."""
        mod = load_uisp()
        pem = tmp_path / "c.pem"
        self._write_pem(pem, b"deployed der")
        with patch.object(mod, "served_cert_der", return_value=b"other der"), \
             patch.object(mod.time, "monotonic", side_effect=[0.0, 1000.0]), \
             patch.object(mod.time, "sleep") as mock_sleep:
            with pytest.raises(RuntimeError, match="deadline"):
                mod.verify_served_certificate("h", str(pem), attempts=100,
                                              delay=10, deadline=50)
            assert mock_sleep.call_count == 0
