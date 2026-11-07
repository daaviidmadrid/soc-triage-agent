"""Loads the dataset for the analysis. Branch: analysis/explore"""
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"


def load_alerts():
    raise NotImplementedError


def load_sample_alerts():
    raise NotImplementedError


def load_log(source):
    raise NotImplementedError


def load_inventory(name):
    raise NotImplementedError
