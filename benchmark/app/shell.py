"""Host utilities."""

import subprocess


def ping(host: str) -> str:
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return result.stdout


def disk_usage() -> str:
    result = subprocess.run(["df", "-h"], capture_output=True, text=True, check=True)
    return result.stdout
