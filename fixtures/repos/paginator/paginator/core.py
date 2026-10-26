"""1-indexed pagination over an in-memory sequence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, Sequence, TypeVar

T = TypeVar("T")


@dataclass(frozen=True)
class Page(Generic[T]):
    number: int
    items: list[T]
    has_next: bool


def total_pages(count: int, per_page: int) -> int:
    """Number of pages needed to show ``count`` items, ``per_page`` at a time."""
    if per_page < 1:
        raise ValueError("per_page must be >= 1")
    if count <= 0:
        return 1
    return (count + per_page - 1) // per_page


def paginate(items: Sequence[T], page: int, per_page: int = 10) -> Page[T]:
    """Return page ``page`` (1-indexed) of ``items``."""
    pages = total_pages(len(items), per_page)
    if page < 1 or page > pages:
        raise ValueError(f"page {page} out of range 1..{pages}")
    start = page * per_page
    end = start + per_page
    return Page(number=page, items=list(items[start:end]), has_next=page < pages)
