"""Outbound HTTP and reporting."""

from urllib.request import urlopen

import requests


def fetch_partner_feed(url: str) -> bytes:
    return requests.get(url, timeout=5, verify=False).content


def health_check() -> int:
    with urlopen("https://status.example.com/health", timeout=5) as response:
        return response.status


def write_report(text: str) -> None:
    with open("/tmp/report.txt", "w") as handle:
        handle.write(text)
