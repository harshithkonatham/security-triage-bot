"""Session, cache and upload helpers."""

import hashlib
import pickle

import yaml


def cache_key(url: str) -> str:
    return hashlib.md5(url.encode()).hexdigest()


def load_session(cookie: bytes):
    return pickle.loads(cookie)


def parse_upload(body: bytes):
    return yaml.load(body, Loader=yaml.Loader)
