import subprocess
import sys
from pathlib import Path


def test_cli_help():
    result = subprocess.run(
        ["/root/AI-K8-Agent/.venv/bin/python", "-m", "k8s_agent", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "Autonomous Kubernetes Log Investigation Agent" in result.stdout


def test_cli_investigate_file_markdown():
    result = subprocess.run(
        [
            "/root/AI-K8-Agent/.venv/bin/python",
            "-m",
            "k8s_agent",
            "examples/oom_killed.log",
            "--format",
            "markdown",
        ],
        cwd="/root/AI-K8-Agent",
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "## 🎯 Root Cause Analysis" in result.stdout
    assert "Exit Code 137" in result.stdout or "OOMKilled" in result.stdout


def test_cli_investigate_stdin_json():
    log_content = "2026-10-29T10:00:00Z Warning FailedMount MountVolume.SetUp failed for volume data: pvc not found\n"
    result = subprocess.run(
        [
            "/root/AI-K8-Agent/.venv/bin/python",
            "-m",
            "k8s_agent",
            "-",
            "--format",
            "json",
        ],
        cwd="/root/AI-K8-Agent",
        input=log_content,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert '"Storage / Volume Mount Failure"' in result.stdout
