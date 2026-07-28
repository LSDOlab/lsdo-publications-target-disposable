from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .errors import PublicationError

ENTRY_TYPES = {
    "article",
    "inproceedings",
    "incollection",
    "book",
    "phdthesis",
    "mastersthesis",
    "techreport",
    "misc",
}
SUPPORTED_FIELDS = {
    "author", "title", "year", "journal", "booktitle", "publisher", "volume",
    "number", "pages", "month", "doi", "url", "eprint", "archiveprefix",
    "primaryclass", "edition", "series", "address", "institution", "school",
    "type", "howpublished", "note", "isbn", "issn",
}
KEY_RE = re.compile(r"^[a-z][a-z0-9]*$")
DOI_RE = re.compile(r"^10\.\d{4,9}/\S+$")


@dataclass(frozen=True, slots=True)
class Entry:
    entry_type: str
    key: str
    fields: dict[str, str]


def _balanced_value(text: str, start: int) -> tuple[str, int]:
    opener = text[start]
    if opener == "{":
        depth = 1
        i = start + 1
        while i < len(text) and depth:
            if text[i] == "{" and (i == 0 or text[i - 1] != "\\"):
                depth += 1
            elif text[i] == "}" and (i == 0 or text[i - 1] != "\\"):
                depth -= 1
            i += 1
        if depth:
            raise PublicationError("E_BIB_PARSE", "unterminated braced value")
        return text[start + 1 : i - 1].strip(), i
    if opener == '"':
        i = start + 1
        escaped = False
        while i < len(text):
            char = text[i]
            if char == '"' and not escaped:
                return text[start + 1 : i], i + 1
            escaped = char == "\\" and not escaped
            if char != "\\":
                escaped = False
            i += 1
        raise PublicationError("E_BIB_PARSE", "unterminated quoted value")
    i = start
    while i < len(text) and text[i] not in ",\n":
        i += 1
    return text[start:i].strip(), i


def parse_bibtex(text: str) -> list[Entry]:
    entries: list[Entry] = []
    i = 0
    while True:
        match = re.search(r"@([A-Za-z]+)\s*\{\s*([^,\s]+)\s*,", text[i:])
        if not match:
            break
        entry_type = match.group(1).lower()
        key = match.group(2)
        pos = i + match.end()
        fields: dict[str, str] = {}
        while pos < len(text):
            while pos < len(text) and (text[pos].isspace() or text[pos] == ","):
                pos += 1
            if pos >= len(text):
                raise PublicationError("E_BIB_PARSE", f"unterminated entry {key}")
            if text[pos] == "}":
                pos += 1
                break
            name_match = re.match(r"([A-Za-z][A-Za-z0-9_-]*)\s*=", text[pos:])
            if not name_match:
                raise PublicationError("E_BIB_PARSE", f"invalid field in {key}")
            name = name_match.group(1).lower()
            pos += name_match.end()
            while pos < len(text) and text[pos].isspace():
                pos += 1
            if pos >= len(text):
                raise PublicationError("E_BIB_PARSE", f"missing value for {key}.{name}")
            value, pos = _balanced_value(text, pos)
            if name in fields:
                raise PublicationError("E_BIB_DUPLICATE_FIELD", f"{key}.{name}")
            fields[name] = value
        entries.append(Entry(entry_type, key, fields))
        i = pos
    return entries


def load_bibtex(path: Path) -> list[Entry]:
    return parse_bibtex(path.read_text(encoding="utf-8"))


def normalize_doi(value: str) -> str:
    value = value.strip()
    value = re.sub(r"(?i)^doi:\s*", "", value)
    value = re.sub(r"(?i)^https?://(?:dx\.)?doi\.org/", "", value)
    value = value.split("?", 1)[0].split("#", 1)[0]
    return value.rstrip(".,;:)]}").lower()


def validate_entries(entries: list[Entry], expected_count: int | None = None) -> list[str]:
    errors: list[str] = []
    keys: set[str] = set()
    dois: dict[str, str] = {}
    arxiv_ids: dict[str, str] = {}
    if expected_count is not None and len(entries) != expected_count:
        errors.append(f"E_METADATA_COUNT: expected {expected_count}, got {len(entries)}")
    for entry in entries:
        if entry.entry_type not in ENTRY_TYPES:
            errors.append(f"E_BIB_TYPE: {entry.key} uses {entry.entry_type}")
        if not KEY_RE.fullmatch(entry.key):
            errors.append(f"E_KEY_FORMAT: {entry.key}")
        if entry.key in keys:
            errors.append(f"E_BIB_DUPLICATE_KEY: {entry.key}")
        keys.add(entry.key)
        unknown = sorted(set(entry.fields) - SUPPORTED_FIELDS)
        if unknown:
            errors.append(f"E_BIB_FIELD: {entry.key}: {', '.join(unknown)}")
        for required in ("author", "title", "year"):
            if not entry.fields.get(required):
                errors.append(f"E_BIB_REQUIRED: {entry.key}.{required}")
        if not re.fullmatch(r"\d{4}", entry.fields.get("year", "")):
            errors.append(f"E_BIB_YEAR: {entry.key}")
        venue = {
            "article": "journal", "inproceedings": "booktitle",
            "incollection": "booktitle", "book": "publisher",
            "phdthesis": "school", "mastersthesis": "school",
            "techreport": "institution",
        }.get(entry.entry_type)
        if venue and not entry.fields.get(venue):
            errors.append(f"E_BIB_REQUIRED: {entry.key}.{venue}")
        doi = entry.fields.get("doi")
        if doi:
            normalized = normalize_doi(doi)
            if not DOI_RE.fullmatch(normalized):
                errors.append(f"E_DOI_INVALID: {entry.key}: {doi}")
            elif normalized in dois:
                errors.append(
                    f"E_DUPLICATE_IDENTIFIER: doi {normalized}: "
                    f"{dois[normalized]}, {entry.key}"
                )
            else:
                dois[normalized] = entry.key
        arxiv = entry.fields.get("eprint")
        if arxiv and entry.fields.get("archiveprefix", "").casefold() == "arxiv":
            normalized_arxiv = re.sub(r"(?i)v\d+$", "", arxiv.strip()).lower()
            if normalized_arxiv in arxiv_ids:
                errors.append(
                    f"E_DUPLICATE_IDENTIFIER: arxiv {normalized_arxiv}: "
                    f"{arxiv_ids[normalized_arxiv]}, {entry.key}"
                )
            else:
                arxiv_ids[normalized_arxiv] = entry.key
        url = entry.fields.get("url")
        if url and not re.match(r"^https://", url, re.I):
            errors.append(f"E_URL_SCHEME: {entry.key}: {url}")
    return errors


def serialize_entry(entry: Entry, key: str | None = None) -> str:
    lines = [f"@{entry.entry_type}{{{key or entry.key},"]
    order = [
        "author", "title", "journal", "booktitle", "publisher", "year", "volume",
        "number", "pages", "month", "doi", "url", "eprint", "archiveprefix",
        "primaryclass", "edition", "series", "address", "institution", "school",
        "type", "howpublished", "note", "isbn", "issn",
    ]
    for name in order:
        if name in entry.fields:
            lines.append(f"    {name} = {{{entry.fields[name]}}},")
    lines.append("}")
    return "\n".join(lines) + "\n"
