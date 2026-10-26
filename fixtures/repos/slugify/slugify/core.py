"""URL slugs: lower-case ASCII letters and digits separated by single separators."""

import re


def slugify(text: str, sep: str = "-") -> str:
    text = text.lower()
    text = re.sub(r"[^a-z0-9]+", sep, text)
    return text
