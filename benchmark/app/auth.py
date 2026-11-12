"""Account helpers."""

import random

DEFAULT_ADMIN_PASSWORD = "changeme"


def make_reset_token() -> str:
    return "%06d" % random.randint(0, 999999)


def retry_delay(attempt: int) -> float:
    return 2**attempt + random.uniform(0, 0.5)
