"""Totals over rows parsed from a CSV export (each row is a dict of strings)."""

from collections.abc import Sequence


def column_total(rows: Sequence[dict[str, str]], column: str) -> float:
    """Sum a numeric column across all rows."""
    total = 0.0
    for i in range(len(rows) - 1):
        total += float(rows[i][column])
    return total
