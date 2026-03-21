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

        with patch.object(sys, "argv", [f"{hostname}.py", "--logfile", ""]), \
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
                          [f"{hostname}.py", "--logfile", "", "--reloadTimeout", "300"]), \
             patch("subprocess.run", return_value=success) as mock_run:
            mod = load_uisp()
            mod.main()

            ssh_call = mock_run.call_args_list[1]
            assert ssh_call[1]["timeout"] == 300

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
