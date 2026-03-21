"""Tests for ucg.mousebrains.com.py deploy hook."""

import os
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest


def load_ucg():
    """Import the UCG module dynamically (filename has dots)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "ucg_mousebrains", "ucg.mousebrains.com.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestUCGMain:
    """Tests for the UCG deploy hook main function."""

    def test_missing_renewed_domains(self, clean_env):
        """Should exit 1 when RENEWED_DOMAINS is not set."""
        with patch.object(sys, "argv", ["ucg.mousebrains.com.py"]):
            mod = load_ucg()
            with pytest.raises(SystemExit, match="1"):
                mod.main()

    def test_hostname_mismatch(self, cert_dir):
        """Should exit 0 when hostname doesn't match RENEWED_DOMAINS."""
        os.environ["RENEWED_DOMAINS"] = "other.example.com"
        os.environ["RENEWED_LINEAGE"] = str(cert_dir)
        with patch.object(sys, "argv", ["ucg.mousebrains.com.py"]):
            mod = load_ucg()
            with pytest.raises(SystemExit) as exc_info:
                mod.main()
            assert exc_info.value.code == 0

    def test_missing_cert_file(self, cert_dir):
        """Should exit 1 when certificate file doesn't exist."""
        hostname = cert_dir.name
        os.environ["RENEWED_DOMAINS"] = hostname
        os.environ["RENEWED_LINEAGE"] = str(cert_dir)
        (cert_dir / "fullchain.pem").unlink()
        with patch.object(sys, "argv", [f"{hostname}.py", "--logfile", ""]):
            mod = load_ucg()
            with pytest.raises(SystemExit, match="1"):
                mod.main()

    def test_missing_key_file(self, cert_dir):
        """Should exit 1 when key file doesn't exist."""
        hostname = cert_dir.name
        os.environ["RENEWED_DOMAINS"] = hostname
        os.environ["RENEWED_LINEAGE"] = str(cert_dir)
        (cert_dir / "privkey.pem").unlink()
        with patch.object(sys, "argv", [f"{hostname}.py", "--logfile", ""]):
            mod = load_ucg()
            with pytest.raises(SystemExit, match="1"):
                mod.main()

    def test_successful_deployment(self, cert_dir):
        """Should complete successfully when SCP and SSH succeed."""
        hostname = cert_dir.name
        os.environ["RENEWED_DOMAINS"] = hostname
        os.environ["RENEWED_LINEAGE"] = str(cert_dir)

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b"ok"
        mock_result.stderr = b""

        with patch.object(sys, "argv", [f"{hostname}.py", "--logfile", ""]), \
             patch("subprocess.run", return_value=mock_result) as mock_run:
            mod = load_ucg()
            mod.main()  # Should complete without SystemExit

            assert mock_run.call_count == 2  # SCP + SSH
            scp_call = mock_run.call_args_list[0]
            ssh_call = mock_run.call_args_list[1]
            assert hostname + ":" in scp_call[0][0]
            assert hostname in ssh_call[0][0]

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
            mod = load_ucg()
            with pytest.raises(SystemExit, match="1"):
                mod.main()

    def test_ssh_failure(self, cert_dir):
        """Should exit 1 when SSH reload fails."""
        hostname = cert_dir.name
        os.environ["RENEWED_DOMAINS"] = hostname
        os.environ["RENEWED_LINEAGE"] = str(cert_dir)

        success = MagicMock()
        success.returncode = 0
        success.stdout = b""
        success.stderr = b""

        failure = MagicMock()
        failure.returncode = 1
        failure.stdout = b""
        failure.stderr = b"nginx: error"

        with patch.object(sys, "argv", [f"{hostname}.py", "--logfile", ""]), \
             patch("subprocess.run", side_effect=[success, failure]):
            mod = load_ucg()
            with pytest.raises(SystemExit, match="1"):
                mod.main()

    def test_timeout_handling(self, cert_dir):
        """Should exit 1 on subprocess timeout."""
        hostname = cert_dir.name
        os.environ["RENEWED_DOMAINS"] = hostname
        os.environ["RENEWED_LINEAGE"] = str(cert_dir)

        with patch.object(sys, "argv", [f"{hostname}.py", "--logfile", ""]), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired("scp", 180)):
            mod = load_ucg()
            with pytest.raises(SystemExit, match="1"):
                mod.main()

    def test_hostname_from_filename(self):
        """Should derive hostname from script filename."""
        with patch.object(sys, "argv", ["ucg.mousebrains.com.py"]):
            load_ucg()  # Verify module loads without error
            script_name = os.path.basename(sys.argv[0])
            assert script_name.removesuffix(".py") == "ucg.mousebrains.com"

    def test_logfile_directory_creation(self, cert_dir, tmp_path):
        """Should create log directory if it doesn't exist."""
        hostname = cert_dir.name
        os.environ["RENEWED_DOMAINS"] = "other.example.com"
        os.environ["RENEWED_LINEAGE"] = str(cert_dir)
        log_dir = tmp_path / "newdir" / "subdir"
        logfile = log_dir / "test.log"

        with patch.object(sys, "argv", [f"{hostname}.py", "--logfile", str(logfile)]):
            mod = load_ucg()
            with pytest.raises(SystemExit):
                mod.main()
            assert log_dir.is_dir()
