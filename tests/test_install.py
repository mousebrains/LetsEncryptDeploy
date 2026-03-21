"""Tests for install.py."""

import sys
from unittest.mock import patch

import pytest


def load_install():
    """Import the install module dynamically."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("install", "install.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestInstall:
    """Tests for the install script."""

    def test_not_root(self):
        """Should exit 1 when not running as root."""
        with patch("os.geteuid", return_value=1000), \
             patch.object(sys, "argv", ["install.py", "test.example.com"]):
            mod = load_install()
            with pytest.raises(SystemExit, match="1"):
                mod.main()

    def test_missing_deploy_dir(self, tmp_path):
        """Should exit 1 when deploy directory doesn't exist."""
        with patch("os.geteuid", return_value=0), \
             patch.object(sys, "argv", ["install.py", "test.example.com"]):
            mod = load_install()
            mod.DEPLOY_DIR = str(tmp_path / "nonexistent")
            with pytest.raises(SystemExit, match="1"):
                mod.main()

    def test_install_specific_script(self, tmp_path):
        """Should copy named script to deploy directory."""
        deploy_dir = tmp_path / "deploy"
        deploy_dir.mkdir()
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        script = src_dir / "test.example.com.py"
        script.write_text("#!/usr/bin/python3\n# test\n")

        with patch("os.geteuid", return_value=0), \
             patch.object(sys, "argv", [str(src_dir / "install.py"), "test.example.com"]):
            mod = load_install()
            mod.DEPLOY_DIR = str(deploy_dir)
            with pytest.raises(SystemExit) as exc_info:
                mod.main()
            assert exc_info.value.code == 0

        assert (deploy_dir / "test.example.com.py").exists()
        assert (deploy_dir / "test.example.com.py").read_text() == script.read_text()

    def test_install_with_py_suffix(self, tmp_path):
        """Should accept hostname.py and strip the suffix."""
        deploy_dir = tmp_path / "deploy"
        deploy_dir.mkdir()
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        script = src_dir / "test.example.com.py"
        script.write_text("# test\n")

        with patch("os.geteuid", return_value=0), \
             patch.object(sys, "argv", [str(src_dir / "install.py"), "test.example.com.py"]):
            mod = load_install()
            mod.DEPLOY_DIR = str(deploy_dir)
            with pytest.raises(SystemExit) as exc_info:
                mod.main()
            assert exc_info.value.code == 0

        assert (deploy_dir / "test.example.com.py").exists()

    def test_install_all_default(self, tmp_path):
        """Should install all *.mousebrains.com.py scripts when no args."""
        deploy_dir = tmp_path / "deploy"
        deploy_dir.mkdir()
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "a.mousebrains.com.py").write_text("# a\n")
        (src_dir / "b.mousebrains.com.py").write_text("# b\n")
        (src_dir / "install.py").write_text("# not a hook\n")

        with patch("os.geteuid", return_value=0), \
             patch.object(sys, "argv", [str(src_dir / "install.py")]):
            mod = load_install()
            mod.DEPLOY_DIR = str(deploy_dir)
            with pytest.raises(SystemExit) as exc_info:
                mod.main()
            assert exc_info.value.code == 0

        assert (deploy_dir / "a.mousebrains.com.py").exists()
        assert (deploy_dir / "b.mousebrains.com.py").exists()
        assert not (deploy_dir / "install.py").exists()

    def test_missing_script_error(self, tmp_path):
        """Should exit 1 when named script doesn't exist."""
        deploy_dir = tmp_path / "deploy"
        deploy_dir.mkdir()
        src_dir = tmp_path / "src"
        src_dir.mkdir()

        with patch("os.geteuid", return_value=0), \
             patch.object(sys, "argv", [str(src_dir / "install.py"), "nonexistent.example.com"]):
            mod = load_install()
            mod.DEPLOY_DIR = str(deploy_dir)
            with pytest.raises(SystemExit, match="1"):
                mod.main()

    def test_multiple_scripts(self, tmp_path):
        """Should install multiple named scripts."""
        deploy_dir = tmp_path / "deploy"
        deploy_dir.mkdir()
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "a.example.com.py").write_text("# a\n")
        (src_dir / "b.example.com.py").write_text("# b\n")

        with patch("os.geteuid", return_value=0), \
             patch.object(sys, "argv",
                          [str(src_dir / "install.py"), "a.example.com", "b.example.com"]):
            mod = load_install()
            mod.DEPLOY_DIR = str(deploy_dir)
            with pytest.raises(SystemExit) as exc_info:
                mod.main()
            assert exc_info.value.code == 0

        assert (deploy_dir / "a.example.com.py").exists()
        assert (deploy_dir / "b.example.com.py").exists()
