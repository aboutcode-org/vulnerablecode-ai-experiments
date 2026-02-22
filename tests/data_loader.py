# tests/data_loader.py
import json
from pathlib import Path
from typing import List, Tuple

DATASET_PATH = Path(__file__).parent / "dataset.json"


def load_dataset() -> list[dict]:
    """
    Load the validated test dataset.

    Expected structure: a JSON array of objects, each containing at least:
      - summary
      - expected_severity
      - expected_cwe_list
    """
    with DATASET_PATH.open(encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("test_dataset.json must be a list of records")

    return data


def severity_cases() -> List[Tuple[str, str]]:
    """
    Returns:
        [(summary, expected_severity), ...]
    """
    return [
        (item["summary"], item["expected_severity"])
        for item in load_dataset()
    ]


def cwe_cases() -> List[Tuple[str, list]]:
    """
    Returns:
        [(summary, expected_cwe_list), ...]
    """
    return [
        (item["summary"], item["expected_cwe_list"])
        for item in load_dataset()
    ]
