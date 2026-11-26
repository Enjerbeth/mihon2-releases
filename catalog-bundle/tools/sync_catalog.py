"""Synchronize catalog-bundle/recipes/*.json, index.json (v2), and NOTICE.

Supports full discovery across Keiyoushi and FelipeGFA (`--sync-all`), blobless
git clones (`--filter=blob:none`, with optional `--depth` shallow fallback) for
per-source commit timestamps, cross-repo fallback, BCP-47 language filtering
(`--langs all` or e.g. `es,en,pt`), default NSFW exclusion (`--include-nsfw`),
redirect tracking with per-hop SSRF validation and live domain auto-adoption,
and R2 Spanish diagnostic reporting (`--report-out`).
"""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import copy
from datetime import datetime, timezone
import gzip
import hashlib
import hmac
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import urllib.error
import urllib.request
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlparse, urlunparse

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

sys.path.insert(0, os.path.dirname(__file__))
from catalog_diagnostics import (  # noqa: E402
    SUPPORTED_THEMES,
    build_diagnostic_report_data,
    build_diagnostic_report_markdown,
    classify_down_reason,
    classify_missing_primitives,
    detect_waf_block,
    is_cloudflare_origin_error,
    write_diagnostic_report,
)
from catalog_mappers_extra import (  # noqa: E402
    EXTRA_THEME_PRESET_MAP,
    SUPPORTED_EXTRA_THEMES,
    apply_extra_theme_to_recipe,
    detect_and_build_auth_preflight,
)
from catalog_mappers_multisrc import (  # noqa: E402
    MULTISRC_THEME_PRESET_MAP,
    SUPPORTED_MULTISRC_THEMES,
    apply_multisrc_theme_to_recipe,
)
from catalog_kt_extractor import (  # noqa: E402
    extract_pipeline_steps_from_kotlin,
    extract_query_signer_spec,
    has_unresolved_native_primitives,
    synthesize_recipe_from_kotlin,
)
from validate_catalog import (  # noqa: E402
    ALLOWED_PRESETS,
    BUNDLE_ROOT,
    MAX_HTML_BYTES,
    extract_html_items,
    parse_stdlib_dom,
    recipe_to_index_entry,
    validate_all,
    validate_bundle,
    validate_recipe,
    validate_ssrf,
)

DEFAULT_RECIPES_DIR = os.path.join(BUNDLE_ROOT, "recipes")
DEFAULT_INDEX_PATH = os.path.join(BUNDLE_ROOT, "index.json")
DEFAULT_NOTICE_PATH = os.path.join(BUNDLE_ROOT, "NOTICE")
DEFAULT_DEPRECATED_PATH = os.path.join(BUNDLE_ROOT, "deprecated_sources.json")

HTTP_UA = (
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"
)

DEFAULT_UPSTREAMS = [
    {
        "name": "keiyoushi",
        "repo_slug": "keiyoushi/extensions-source",
        "git_url": "https://github.com/keiyoushi/extensions-source.git",
        "index_pb_url": "https://raw.githubusercontent.com/keiyoushi/extensions/refs/heads/repo/index.pb",
        "priority": 2,
        "default_attribution": "The Tachiyomi / Keiyoushi Contributors",
    },
    {
        "name": "felipegfa",
        "repo_slug": "FelipeGFA/fonte-extensoes",
        "git_url": "https://github.com/FelipeGFA/fonte-extensoes.git",
        "index_pb_url": "https://raw.githubusercontent.com/FelipeGFA/extensoes/refs/heads/repo/index.pb",
        "priority": 1,
        "default_attribution": "FelipeGFA Contributors",
    },
]

NATIVE_COMPLEX_MARKERS = (
    "VrfSigner",
    "QuickJs",
    "Cipher",
    "SecretKeySpec",
    "Bitmap.createBitmap",
    "Canvas(",
    "AES",
    "MangaFire",
)

WEBVIEW_DECOY_MARKERS = (
    "runWebView",
    "__reactContainer",
    "page_list.js",
    '"ph":',
    "__next_f",
    "data-inertia",
)

THEME_PRESET_MAP = {
    "madara": "MADARA",
    "mangathemesia": "MANGA_THEMESIA",
    "mangastream": "MANGA_THEMESIA",
    "zesthub": "MANGA_THEMESIA",
    "mmrcms": "MANGA_READER_CMS",
    "fmreader": "MANGA_READER_CMS",
    "zeistmanga": "JSON_API",
    "foolslide": "CSS_GENERIC",
    "mangacatalog": "CSS_GENERIC",
    "solomanga": "CSS_GENERIC",
    "iken": "JSON_API",
    "heancms": "JSON_API",
}

THEME_DEFAULT_SELECTORS = {
    "foolslide": {
        "listSelector": "div.list div.group, div.title",
        "titleSelector": "div.title a",
        "linkSelector": "div.title a",
        "coverSelector": "div.thumb img",
        "chapterSelector": "div.element div.title a",
        "pageImgSelector": "div.inner img",
        "detailsTitleSelector": "h1.title",
        "detailsCoverSelector": "div.thumb img",
        "descriptionSelector": "div.info, div.description",
        "authorSelector": "div.author",
        "artistSelector": "div.artist",
        "chapterNameSelector": "div.title a",
        "chapterDateSelector": "div.meta_r",
        "chapterDateFormat": "yyyy.MM.dd",
    },
    "mangacatalog": {
        "listSelector": "div.content-list div.item, div.grid-item",
        "titleSelector": "h3 a, a.title",
        "linkSelector": "h3 a, a.title",
        "coverSelector": "img",
        "chapterSelector": "ul.chapter-list li a",
        "pageImgSelector": "div.page-image img",
        "detailsTitleSelector": "h1.manga-title",
        "detailsCoverSelector": "div.manga-cover img",
        "descriptionSelector": "div.manga-description, div.summary",
        "authorSelector": "div.author span",
        "artistSelector": "div.artist span",
        "genresSelector": "div.genres a",
        "statusSelector": "div.status span",
        "chapterNameSelector": "span.chapter-name, a",
        "chapterDateSelector": "span.chapter-date",
        "chapterDateFormat": "yyyy-MM-dd",
    },
    "solomanga": {
        "listSelector": "div.manga-card, div.book-item",
        "titleSelector": "h3.title a, h4.title a",
        "linkSelector": "h3.title a, h4.title a",
        "coverSelector": "div.cover img",
        "chapterSelector": "ul.chapters-list li a",
        "pageImgSelector": "div.reader-images img",
        "detailsTitleSelector": "h1.series-title",
        "detailsCoverSelector": "div.series-cover img",
        "descriptionSelector": "div.series-summary",
        "authorSelector": "span.author",
        "artistSelector": "span.artist",
        "genresSelector": "div.genres-list a",
        "statusSelector": "span.status",
        "chapterNameSelector": "span.name, a",
        "chapterDateSelector": "span.date",
        "chapterDateFormat": "yyyy-MM-dd",
    },
}

PRESET_DEFAULT_SELECTORS = {
    "MADARA": {
        "listSelector": "div.page-item-detail, div.c-tabs-item__content",
        "titleSelector": "h3.h5 a, div.post-title a",
        "linkSelector": "h3.h5 a, div.post-title a",
        "chapterSelector": "li.wp-manga-chapter a",
        "pageImgSelector": "div.reading-content img, div.page-break img",
    },
    "MANGA_THEMESIA": {
        "listSelector": "div.listupd div.bsx a, div.bsx a",
        "titleSelector": "div.tt",
        "linkSelector": "a",
        "chapterSelector": "div#chapterlist ul li a",
        "pageImgSelector": "div#readerarea img",
    },
    "MANGA_READER_CMS": {
        "listSelector": "div.media, div.col-sm-6",
        "titleSelector": "h5.media-heading a, h4.media-heading a",
        "linkSelector": "h5.media-heading a, h4.media-heading a",
        "chapterSelector": "ul.chapters li a",
        "pageImgSelector": "div#all img",
    },
    "CSS_GENERIC": {
        "listSelector": "article, div.manga-item, div.page-item-detail",
        "titleSelector": "h3 a, h4 a, a",
        "linkSelector": "a",
        "chapterSelector": "li a, div.chapter-item a",
        "pageImgSelector": "div.reading-content img, div#readerarea img",
    },
}

REPO_SLUG_NORMALIZATION = {
    "keiyoushi": "keiyoushi/extensions-source",
    "keiyoushi/extensions-source": "keiyoushi/extensions-source",
    "felipegfa": "FelipeGFA/fonte-extensoes",
    "felipegfa/fonte-extensoes": "FelipeGFA/fonte-extensoes",
}

DEFAULT_ATTRIBUTIONS = {
    "keiyoushi/extensions-source": "The Tachiyomi / Keiyoushi Contributors",
    "FelipeGFA/fonte-extensoes": "FelipeGFA Contributors",
}

REJECT_LICENSE_PATTERNS = [
    re.compile(r"\bAGPL(?:-[0-9.]+)?\b", re.I),
    re.compile(r"\bGPL(?:-[0-9.]+)?\b", re.I),
    re.compile(r"\bLGPL(?:-[0-9.]+)?\b", re.I),
    re.compile(r"\bSSPL(?:-[0-9.]+)?\b", re.I),
    re.compile(r"\bBUSL(?:-[0-9.]+)?\b", re.I),
    re.compile(r"all\s+rights\s+reserved", re.I),
    re.compile(r"\bproprietary\b", re.I),
]

OFFICIAL_CLOSURE_MARKERS = (
    "comunicado oficial",
    "cierre definitivo",
    "permanently closed",
    "shutting down",
)

CONTENT_WARNING_MAP = {
    "UNSPECIFIED": 0,
    "SAFE": 1,
    "MIXED": 2,
    "NSFW": 3,
}

MIN_SMOKE_ITEMS = 3

_SMOKE_JUNK_TITLE_RE = re.compile(
    r"^(new|nuevo|novela|novel|manga|manhwa|manhua|hot|top|\+18|18\+|leer( ahora| cap[ií]tulo| m[aá]s)?|"
    r"read( now| more| chapter)?|ver( m[aá]s)?|cap[ií]tulo|chapter|\d+([.,]\d+)?%?)$",
    re.I,
)
_CURATED_PROTECTED_KEYS = frozenset(
    {"selectors", "searchPath", "catalogPath", "headers", "chapterOrder", "singlePostAsChapter"}
)


def _is_junk_smoke_title(raw):
    text = str(raw or "").strip()
    return (not text) or bool(_SMOKE_JUNK_TITLE_RE.match(text))


def _locked_field_set(recipe):
    locked = set(recipe.get("lockedFields") or [])
    if recipe.get("curated") is True:
        locked |= _CURATED_PROTECTED_KEYS
    return locked

_DOMAIN_RATE_LOCK = threading.Lock()
_DOMAIN_NEXT_ALLOWED = {}
_DEFAULT_DOMAIN_INTERVAL_SEC = 0.25


def _respect_domain_rate_limit(url, min_interval=_DEFAULT_DOMAIN_INTERVAL_SEC):
    if min_interval <= 0:
        return
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return
    if not host:
        return
    wait_for = 0.0
    with _DOMAIN_RATE_LOCK:
        now = time.monotonic()
        allowed_at = _DOMAIN_NEXT_ALLOWED.get(host, 0.0)
        if allowed_at > now:
            wait_for = min(allowed_at - now, 3.0)
            _DOMAIN_NEXT_ALLOWED[host] = now + wait_for + min_interval
        else:
            _DOMAIN_NEXT_ALLOWED[host] = now + min_interval
    if wait_for > 0:
        time.sleep(wait_for)


def _read_varint(buf, i):
    shift = 0
    val = 0
    while i < len(buf):
        b = buf[i]
        i += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, i
        shift += 7
    raise ValueError("Truncated varint in protobuf buffer")


def _parse_pb_fields(buf):
    i = 0
    n = len(buf)
    fields = []
    while i < n:
        tag, i = _read_varint(buf, i)
        fnum = tag >> 3
        wt = tag & 7
        if wt == 0:
            v, i = _read_varint(buf, i)
            fields.append((fnum, wt, v))
        elif wt == 1:
            fields.append((fnum, wt, buf[i : i + 8]))
            i += 8
        elif wt == 2:
            length, i = _read_varint(buf, i)
            fields.append((fnum, wt, buf[i : i + length]))
            i += length
        elif wt == 5:
            fields.append((fnum, wt, buf[i : i + 4]))
            i += 4
        else:
            raise ValueError(f"Unsupported protobuf wire type: {wt}")
    return fields


def decode_index_pb(raw_bytes):
    """Decode gzipped or raw Tachiyomi/Mihon index.pb into structured extension/source dicts."""
    data = gzip.decompress(raw_bytes) if raw_bytes[:2] == b"\x1f\x8b" else raw_bytes
    top = _parse_pb_fields(data)
    repo_name = ""
    raw_extensions = []

    for fnum, wt, val in top:
        if fnum == 1 and wt == 2:
            text = val.decode("utf-8", "replace")
            if len(val) < 128 and "\n" not in text:
                repo_name = text
        elif fnum == 101 and wt == 2:
            for sf, swt, sv in _parse_pb_fields(val):
                if sf == 1 and swt == 2:
                    raw_extensions.append(sv)

    extensions = []
    for ext_bytes in raw_extensions:
        ext = {
            "name": "",
            "pkgName": "",
            "iconUrl": "",
            "versionCode": 0,
            "versionName": "",
            "contentWarning": 0,
            "isNsfw": False,
            "sources": [],
        }
        for ef, ewt, ev in _parse_pb_fields(ext_bytes):
            if ef == 1 and ewt == 2:
                ext["name"] = ev.decode("utf-8", "replace")
            elif ef == 2 and ewt == 2:
                ext["pkgName"] = ev.decode("utf-8", "replace")
            elif ef == 3 and ewt == 2:
                for af, awt, av in _parse_pb_fields(ev):
                    if af == 2 and awt == 2:
                        ext["iconUrl"] = av.decode("utf-8", "replace")
            elif ef == 5 and ewt == 0:
                ext["versionCode"] = ev
            elif ef == 6 and ewt == 2:
                ext["versionName"] = ev.decode("utf-8", "replace")
            elif ef == 7 and ewt == 0:
                ext["contentWarning"] = int(ev)
                ext["isNsfw"] = int(ev) == 3
            elif ef == 8 and ewt == 2:
                src = {
                    "sourceId": 0,
                    "name": "",
                    "lang": "",
                    "baseUrl": "",
                    "mirrors": [],
                    "contentWarning": 0,
                }
                for sf, swt, sv in _parse_pb_fields(ev):
                    if sf == 1 and swt == 0:
                        if sv >= (1 << 63):
                            sv -= 1 << 64
                        src["sourceId"] = sv
                    elif sf == 2 and swt == 2:
                        src["name"] = sv.decode("utf-8", "replace")
                    elif sf == 3 and swt == 2:
                        src["lang"] = sv.decode("utf-8", "replace")
                    elif sf == 4 and swt == 2:
                        src["baseUrl"] = sv.decode("utf-8", "replace").rstrip("/")
                    elif sf == 5 and swt == 2:
                        m_url = sv.decode("utf-8", "replace").strip().rstrip("/")
                        if m_url:
                            src["mirrors"].append(m_url)
                    elif sf == 6 and swt == 0:
                        src["contentWarning"] = int(sv)
                ext["sources"].append(src)
        extensions.append(ext)

    return {"repoName": repo_name, "extensions": extensions}


def compute_keiyoushi_source_id(name, lang, version_id=1):
    """Compute Keiyoushi/Tachiyomi deterministic 63-bit positive MD5 sourceId."""
    key = f"{str(name).lower()}/{str(lang)}/{int(version_id)}"
    digest = hashlib.md5(key.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big", signed=False) & 0x7FFFFFFFFFFFFFFF


def normalize_key(raw):
    if not raw:
        return ""
    cleaned = re.sub(r"\(personal\)", "", raw, flags=re.I)
    for tld in (".org", ".com", ".net", ".lat", ".es", ".co"):
        cleaned = cleaned.replace(tld, "")
    decomposed = unicodedata.normalize("NFD", cleaned)
    ascii_text = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")
    return re.sub(r"[^a-z0-9]", "", ascii_text.lower())


def normalize_domain(url):
    if not url or not isinstance(url, str):
        return ""
    try:
        parsed = urlparse(url.strip())
        host = (parsed.hostname or "").lower()
    except ValueError:
        return ""
    if host.startswith("www."):
        host = host[4:]
    return host


def normalize_upstream_repo(raw_repo):
    if raw_repo is None:
        return None
    cleaned = str(raw_repo).strip()
    if not cleaned:
        return None
    return REPO_SLUG_NORMALIZATION.get(cleaned.lower(), cleaned)


def infer_open_source_location(ext, default_repo="keiyoushi/extensions-source"):
    """Infer open-source repository (owner/repo, branch, src_dir, slug) from iconUrl or pkgName."""
    icon = ext.get("iconUrl", "")
    m = re.search(r"cdn\.jsdelivr\.net/gh/([^/]+/[^/@]+)@([^/]+)/src/([^/]+)/([^/]+)/", icon)
    if m:
        return normalize_upstream_repo(m.group(1)), m.group(2), f"src/{m.group(3)}/{m.group(4)}", m.group(4)

    pkg = ext.get("pkgName", "")
    parts = pkg.split(".")
    if len(parts) >= 2:
        lang_seg = parts[-2]
        slug = parts[-1]
        return normalize_upstream_repo(default_repo), "main", f"src/{lang_seg}/{slug}", slug
    return None


def _extract_balanced_blocks(text, keyword):
    """Extract balanced `{ ... }` blocks preceded by `<keyword> {`."""
    blocks = []
    pat = re.compile(rf"\b{re.escape(keyword)}\s*\{{")
    pos = 0
    while True:
        m = pat.search(text, pos)
        if not m:
            break
        brace_start = m.end() - 1
        depth = 0
        in_str = False
        escape = False
        idx = brace_start
        n = len(text)
        while idx < n:
            ch = text[idx]
            if in_str:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_str = False
            else:
                if ch == '"':
                    in_str = True
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        blocks.append(text[brace_start + 1 : idx])
                        pos = idx + 1
                        break
            idx += 1
        else:
            break
    return blocks


def _strip_kt_line_comment(expr):
    """Strip trailing `// ...` comment and `;` outside string literals."""
    in_str = False
    escape = False
    i = 0
    n = len(expr)
    while i < n:
        ch = expr[i]
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch == "/" and i + 1 < n and expr[i + 1] == "/":
                return expr[:i].strip().rstrip(";").strip()
        i += 1
    return expr.strip().rstrip(";").strip()


def _split_kt_concat_parts(expr):
    """Split a Kotlin expression by `+` outside string literals and parentheses."""
    parts = []
    cur = []
    in_str = False
    escape = False
    paren_depth = 0
    for ch in expr:
        if in_str:
            cur.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
                cur.append(ch)
            elif ch == "(":
                paren_depth += 1
                cur.append(ch)
            elif ch == ")":
                if paren_depth > 0:
                    paren_depth -= 1
                cur.append(ch)
            elif ch == "+" and paren_depth == 0:
                parts.append("".join(cur).strip())
                cur = []
            else:
                cur.append(ch)
    parts.append("".join(cur).strip())
    return parts


def _expand_kt_string_literal(raw_inner, local_vars):
    """Expand `$var` and `${var}` interpolations inside a Kotlin double-quoted string."""
    out = []
    i = 0
    n = len(raw_inner)
    while i < n:
        ch = raw_inner[i]
        if ch == "\\" and i + 1 < n:
            nxt = raw_inner[i + 1]
            if nxt in ("$", '"', "\\"):
                out.append(nxt)
                i += 2
                continue
            out.append(ch)
            out.append(nxt)
            i += 2
            continue
        if ch == "$":
            if i + 1 < n and raw_inner[i + 1] == "{":
                close_idx = raw_inner.find("}", i + 2)
                if close_idx != -1:
                    var_name = raw_inner[i + 2 : close_idx].strip()
                    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", var_name):
                        if var_name not in local_vars:
                            return None
                        out.append(local_vars[var_name])
                        i = close_idx + 1
                        continue
            m_var = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", raw_inner[i + 1 :])
            if m_var:
                var_name = m_var.group(1)
                if var_name not in local_vars:
                    return None
                out.append(local_vars[var_name])
                i += 1 + len(var_name)
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def _is_single_kt_string_literal(part):
    if len(part) < 2 or not (part.startswith('"') and part.endswith('"')):
        return False
    escape = False
    for idx in range(1, len(part) - 1):
        ch = part[idx]
        if escape:
            escape = False
        elif ch == "\\":
            escape = True
        elif ch == '"':
            return False
    return not escape


def _resolve_kt_string(expr, local_vars):
    """Resolve Kotlin string literals, `$var`/`${var}` interpolation, local variables, and `+`."""
    if not expr:
        return None
    cleaned_expr = _strip_kt_line_comment(expr)
    if not cleaned_expr:
        return None
    parts = _split_kt_concat_parts(cleaned_expr)
    resolved_parts = []
    for p in parts:
        if not p:
            return None
        if _is_single_kt_string_literal(p):
            expanded = _expand_kt_string_literal(p[1:-1], local_vars)
            if expanded is None:
                return None
            resolved_parts.append(expanded)
        elif re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", p) and p in local_vars:
            resolved_parts.append(local_vars[p])
        else:
            return None
    return "".join(resolved_parts)


def _split_kt_args(args_text):
    """Split Kotlin call arguments by commas outside quotes, comments, and nested brackets."""
    args = []
    cur = []
    in_str = False
    escape = False
    paren_depth = 0
    bracket_depth = 0
    i = 0
    n = len(args_text or "")
    while i < n:
        ch = args_text[i]
        if in_str:
            cur.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            i += 1
            continue
        if ch == "/" and i + 1 < n and args_text[i + 1] == "/":
            nl = args_text.find("\n", i)
            if nl == -1:
                break
            i = nl + 1
            continue
        if ch == '"':
            in_str = True
            cur.append(ch)
        elif ch == "(":
            paren_depth += 1
            cur.append(ch)
        elif ch == ")":
            if paren_depth > 0:
                paren_depth -= 1
            cur.append(ch)
        elif ch == "[":
            bracket_depth += 1
            cur.append(ch)
        elif ch == "]":
            if bracket_depth > 0:
                bracket_depth -= 1
            cur.append(ch)
        elif ch == "," and paren_depth == 0 and bracket_depth == 0:
            part = "".join(cur).strip()
            if part:
                args.append(part)
            cur = []
        else:
            cur.append(ch)
        i += 1
    tail = "".join(cur).strip()
    if tail:
        args.append(tail)
    return args


def _extract_call_args(text, func_name):
    """Extract argument substrings for `<func_name>(...)` respecting quotes and nested parens."""
    calls = []
    pat = re.compile(rf"\b{re.escape(func_name)}\s*\(")
    pos = 0
    n = len(text or "")
    while pos < n:
        m = pat.search(text, pos)
        if not m:
            break
        start = m.end()
        depth = 1
        in_str = False
        escape = False
        idx = start
        while idx < n:
            ch = text[idx]
            if in_str:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_str = False
            else:
                if ch == '"':
                    in_str = True
                elif ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        calls.append(text[start:idx])
                        pos = idx + 1
                        break
            idx += 1
        else:
            break
    return calls


def _extract_urls_from_kt_expr(expr_text, local_vars):
    urls = []
    for arg in _split_kt_args(expr_text or ""):
        val = _resolve_kt_string(arg, local_vars)
        if val and (val.startswith("http://") or val.startswith("https://")):
            cleaned = val.rstrip("/")
            if cleaned not in urls:
                urls.append(cleaned)
    return urls


def _collect_kt_local_vars(text, base_vars=None):
    vars_map = dict(base_vars or {})
    for m in re.finditer(
        r"(?:^|\n)\s*(?:(?:private|internal|public|const|override)\s+)*val\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*:\s*String)?\s*=\s*([^\n]+)",
        text or "",
    ):
        val = _resolve_kt_string(m.group(2), vars_map)
        if val is not None:
            vars_map[m.group(1)] = val
    return vars_map


def _parse_single_source_block(block_text, ext_name, local_vars):
    block_vars = _collect_kt_local_vars(block_text, base_vars=local_vars)
    src = {
        "name": ext_name,
        "lang": None,
        "versionId": 1,
        "id": None,
        "baseUrl": None,
        "mirrors": [],
    }
    if m := re.search(r"^\s*name\s*=\s*(.+)$", block_text, re.M):
        val = _resolve_kt_string(m.group(1), block_vars)
        if val:
            src["name"] = val
    if m := re.search(r"^\s*lang\s*=\s*(.+)$", block_text, re.M):
        val = _resolve_kt_string(m.group(1), block_vars)
        if val:
            src["lang"] = val
    if m := re.search(r"^\s*versionId\s*=\s*(\d+)", block_text, re.M):
        src["versionId"] = int(m.group(1))
    if m := re.search(r"^\s*id\s*=\s*(-?\d+)L?", block_text, re.M):
        src["id"] = int(m.group(1))

    base_blocks = _extract_balanced_blocks(block_text, "baseUrl")
    if base_blocks:
        btext = base_blocks[0]
        mirrors_calls = _extract_call_args(btext, "mirrors")
        if mirrors_calls:
            src["mirrors"].extend(_extract_urls_from_kt_expr(mirrors_calls[0], block_vars))
            if src["mirrors"]:
                src["baseUrl"] = src["mirrors"][0]
        if not src["baseUrl"]:
            custom_calls = _extract_call_args(btext, "custom")
            if custom_calls:
                c_urls = _extract_urls_from_kt_expr(custom_calls[0], block_vars)
                if c_urls:
                    src["baseUrl"] = c_urls[0]
    if not src["baseUrl"]:
        if m := re.search(r"^\s*baseUrl\s*=\s*(.+)$", block_text, re.M):
            val = _resolve_kt_string(m.group(1), block_vars)
            if val and (val.startswith("http://") or val.startswith("https://")):
                src["baseUrl"] = val.rstrip("/")

    if src["baseUrl"] and src["baseUrl"] not in src["mirrors"]:
        src["mirrors"].insert(0, src["baseUrl"])
    if src["id"] is None and src["name"] and src["lang"]:
        src["id"] = compute_keiyoushi_source_id(src["name"], src["lang"], src["versionId"])
    return src


def parse_extension_build_gradle(gradle_text):
    """Extract metadata, ContentWarning/NSFW, baseUrl, mirrors, theme, and sources from build.gradle.kts."""
    local_vars = _collect_kt_local_vars(gradle_text or "")

    info = {
        "name": None,
        "theme": None,
        "versionCode": None,
        "versionId": 1,
        "lang": None,
        "baseUrl": None,
        "mirrors": [],
        "pkgName": None,
        "contentWarning": 0,
        "isNsfw": False,
        "sources": [],
    }

    if m := re.search(r'^\s*name\s*=\s*"([^"]+)"', gradle_text, re.M):
        info["name"] = m.group(1)
    if m := re.search(r'^\s*theme\s*=\s*"([^"]+)"', gradle_text, re.M):
        info["theme"] = m.group(1).strip().lower()
    if m := re.search(r"^\s*versionCode\s*=\s*(\d+)", gradle_text, re.M):
        info["versionCode"] = int(m.group(1))
    if m := re.search(r'^\s*pkgName\s*=\s*"([^"]+)"', gradle_text, re.M):
        info["pkgName"] = m.group(1).strip()
    if m := re.search(r"\bcontentWarning\s*=\s*ContentWarning\.([A-Z_]+)", gradle_text):
        cw_name = m.group(1).upper()
        info["contentWarning"] = CONTENT_WARNING_MAP.get(cw_name, 0)
        if cw_name == "NSFW":
            info["isNsfw"] = True
    if m := re.search(r"^\s*(?:isNsfw|nsfw)\s*=\s*(true|false)", gradle_text, re.M | re.I):
        if m.group(1).lower() == "true":
            info["isNsfw"] = True
            if info["contentWarning"] == 0:
                info["contentWarning"] = 3

    source_blocks = _extract_balanced_blocks(gradle_text, "source")
    for sb in source_blocks:
        parsed_src = _parse_single_source_block(sb, info["name"], local_vars)
        info["sources"].append(parsed_src)

    if info["sources"]:
        first = info["sources"][0]
        info["lang"] = first.get("lang")
        info["versionId"] = first.get("versionId", 1)
        info["baseUrl"] = first.get("baseUrl")
        info["mirrors"] = list(first.get("mirrors") or [])
    else:
        if m := re.search(r'^\s*lang\s*=\s*"([^"]+)"', gradle_text, re.M):
            info["lang"] = m.group(1)
        if m := re.search(r"^\s*versionId\s*=\s*(\d+)", gradle_text, re.M):
            info["versionId"] = int(m.group(1))

        mirrors_calls = _extract_call_args(gradle_text, "mirrors")
        if mirrors_calls:
            urls = _extract_urls_from_kt_expr(mirrors_calls[0], local_vars)
            info["mirrors"] = urls
            if urls:
                info["baseUrl"] = urls[0]

        if not info["baseUrl"]:
            custom_calls = _extract_call_args(gradle_text, "custom")
            if custom_calls:
                c_urls = _extract_urls_from_kt_expr(custom_calls[0], local_vars)
                if c_urls:
                    info["baseUrl"] = c_urls[0]
            if not info["baseUrl"]:
                if m := re.search(r"^\s*baseUrl\s*=\s*(.+)$", gradle_text, re.M):
                    val = _resolve_kt_string(m.group(1), local_vars)
                    if val and (val.startswith("http://") or val.startswith("https://")):
                        info["baseUrl"] = val.rstrip("/")

        if info["baseUrl"] and info["baseUrl"] not in info["mirrors"]:
            info["mirrors"].insert(0, info["baseUrl"])

    return info


def classify_source_protection(kotlin_text="", html_sample="", http_status=200, headers=None):
    """Classify source protection strategy from Kotlin source, live HTML sample, and HTTP status."""
    kt = kotlin_text or ""
    html = html_sample or ""

    native_reasons = [marker for marker in NATIVE_COMPLEX_MARKERS if marker in kt]
    if re.search(r'"vrf"', kt, re.I) or re.search(r"\bvrf\b.*signer|\bsigner\b.*\bvrf\b", kt, re.I):
        native_reasons.append('"vrf" signer')
    if native_reasons:
        return {
            "strategy": "NATIVE_COMPLEX",
            "reasons": native_reasons,
            "auto_declarative_safe": False,
        }

    combined = f"{kt}\n{html}"
    webview_reasons = [marker for marker in WEBVIEW_DECOY_MARKERS if marker in combined]
    if webview_reasons:
        return {
            "strategy": "WEBVIEW_REACT_OR_JS_DECOY",
            "reasons": webview_reasons,
            "auto_declarative_safe": True,
        }

    is_waf, waf_reason = detect_waf_block(http_status, headers=headers, body=html)
    if is_waf:
        return {
            "strategy": "CLOUDFLARE_SESSION",
            "reasons": [waf_reason],
            "auto_declarative_safe": True,
        }

    return {
        "strategy": "DECLARATIVE_STANDARD",
        "reasons": [],
        "auto_declarative_safe": True,
    }


def inspect_open_source_kotlin(kotlin_text):
    """Detect catalogPath overrides, superclass theme hints, NSFW flags, and complex native primitives."""
    kt = kotlin_text or ""
    catalog_path = None
    m_sub = re.search(r'mangaSubString\s*=\s*"([^"]*)"', kt)
    if m_sub:
        val = m_sub.group(1).strip("/")
        catalog_path = f"/{val}" if val else ""
    elif m_dir := re.search(r'mangaUrlDirectory\s*=\s*"([^"]*)"', kt):
        val = m_dir.group(1).strip("/")
        catalog_path = f"/{val}" if val else ""
    elif m_mt := re.search(r'MangaThemesia\s*\([^)]*,\s*[^)]*,\s*[^)]*,\s*"(/[^"]*)"', kt):
        catalog_path = m_mt.group(1).rstrip("/")

    inferred_theme = None
    if re.search(r":\s*Madara\s*\(", kt):
        inferred_theme = "madara"
    elif re.search(r":\s*(MangaThemesia|MangaStream)\s*\(", kt):
        inferred_theme = "mangathemesia"
    elif re.search(r":\s*(MMRCMS|FMReader)\s*\(", kt):
        inferred_theme = "mmrcms"

    is_nsfw = bool(
        re.search(r"\boverride\s+val\s+nsfw\s*(?::\s*Boolean\s*)?=\s*true\b", kt)
        or re.search(r"\bval\s+nsfw\s*=\s*true\b", kt)
    )

    protection = classify_source_protection(kotlin_text=kt)
    return {
        "catalogPath": catalog_path,
        "inferredTheme": inferred_theme,
        "isNsfw": is_nsfw,
        "requiresNativeApk": not protection["auto_declarative_safe"],
        "nativeMarkers": protection["reasons"] if not protection["auto_declarative_safe"] else [],
        "protection": protection,
    }


_LICENSE_BOILERPLATE_SUBSTRINGS = (
    "notice that is included",
    "attached to the work",
    "as defined in",
    "notice and this permission notice",
    "copyright owner",
    "copyright holder",
    "copyright holders",
    "copyright law",
    "related rights",
    "you must retain",
    "source form of any",
    "derivative works",
    "permission is hereby granted",
    "without warranty of any kind",
    "the above copyright notice",
    "redistributions of source code",
    "redistributions in binary form",
    "provided that the following conditions",
    "neither the name of",
    "subject to the terms of the mozilla public",
    "incompatible with secondary licenses",
)

_LICENSE_PLACEHOLDER_SUBSTRINGS = (
    "[yyyy]",
    "[year]",
    "<year>",
    "[fullname]",
    "<owner>",
    "<copyright holders>",
    "[name of copyright owner]",
)

_COPYRIGHT_YEAR_RE = r"(?:19|20)\d{2}\b"
_COPYRIGHT_YEAR_RANGE_RE = rf"{_COPYRIGHT_YEAR_RE}(?:\s*[-–—]\s*{_COPYRIGHT_YEAR_RE})?"
_COPYRIGHT_PREFIX_RE = re.compile(
    rf"^(?:(?:copyright\b|\(c\)|©)\s*:?\s*)+"
    rf"(?:{_COPYRIGHT_YEAR_RANGE_RE}(?:\s*,\s*{_COPYRIGHT_YEAR_RANGE_RE})*"
    rf"(?:\s*[-–—]\s*present\b)?(?:\s*(?:\(c\)|©)\s*:?\s*)?\s*[,:\-–—]*\s*)?",
    re.I,
)


def _extract_copyright_attribution(texts, fallback="Upstream Open-Source Contributors"):
    for txt in texts:
        if not txt:
            continue
        for line in txt.splitlines():
            stripped = re.sub(r"\s*\*+/\s*$", "", line.strip()).lstrip("/*#").strip()
            if not stripped:
                continue
            low = stripped.lower()
            if any(placeholder in low for placeholder in _LICENSE_PLACEHOLDER_SUBSTRINGS):
                continue
            if any(phrase in low for phrase in _LICENSE_BOILERPLATE_SUBSTRINGS):
                continue
            if re.match(r"^©", stripped):
                pass
            elif re.match(r"^copyright\b", stripped, re.I):
                if not re.search(r"(?:©|\b(?:19|20)\d{2}\b)", stripped):
                    continue
            elif re.match(r"^\(c\)\s*(?:19|20)\d{2}\b", stripped, re.I):
                pass
            else:
                continue
            cleaned = _COPYRIGHT_PREFIX_RE.sub("", stripped).strip(" ,.-–—:")
            if not cleaned:
                continue
            if re.match(r"^(?:\[[^\]]+\]|<[^>]+>)(?:\s*[,;/-]?\s*(?:\[[^\]]+\]|<[^>]+>))*$", cleaned):
                continue
            return cleaned
    return fallback


def _extract_license_header_lines(txt):
    """Extract only leading file-header comments and SPDX-License-Identifier lines for license scanning."""
    if not txt:
        return ""
    header_lines = []
    in_block_comment = False
    passed_header = False
    for line in txt.splitlines()[:80]:
        stripped = line.strip()
        if "SPDX-License-Identifier:" in stripped:
            header_lines.append(stripped)
            continue
        if passed_header:
            continue
        if not stripped:
            continue
        if in_block_comment:
            header_lines.append(stripped)
            if "*/" in stripped:
                in_block_comment = False
            continue
        if stripped.startswith("/*"):
            header_lines.append(stripped)
            if "*/" not in stripped:
                in_block_comment = True
            continue
        if stripped.startswith("//") or stripped.startswith("#"):
            header_lines.append(stripped)
            continue
        passed_header = True
    return "\n".join(header_lines)


def verify_repo_license(repo_dir, gradle_text="", kotlin_texts=None, fallback_attribution="Upstream Contributors"):
    """Verify OSI-compatible license (Apache-2.0 or MIT), rejecting GPL/AGPL/SSPL/missing."""
    header_texts = [_extract_license_header_lines(gradle_text or "")] + [
        _extract_license_header_lines(kt) for kt in (kotlin_texts or [])
    ]

    for txt in header_texts:
        for pat in REJECT_LICENSE_PATTERNS:
            if pat.search(txt):
                return False, "REJECTED_NON_OSI", ""
        if m := re.search(r"SPDX-License-Identifier:\s*([A-Za-z0-9.+-]+)", txt):
            spdx = m.group(1).strip()
            if spdx in ("Apache-2.0", "MIT"):
                attr = _extract_copyright_attribution(header_texts, fallback_attribution)
                return True, spdx, attr
            return False, f"REJECTED_SPDX:{spdx}", ""

    license_texts = []
    if repo_dir and os.path.isdir(repo_dir):
        for name in ("LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING", "COPYING.txt"):
            cand = os.path.join(repo_dir, name)
            if os.path.isfile(cand):
                with open(cand, "r", encoding="utf-8", errors="ignore") as f:
                    license_texts.append(f.read())

    if not license_texts:
        return False, "MISSING_LICENSE", ""

    combined_lic = "\n".join(license_texts)
    for pat in REJECT_LICENSE_PATTERNS:
        if pat.search(combined_lic):
            return False, "REJECTED_NON_OSI", ""

    if "Apache License" in combined_lic and "Version 2.0" in combined_lic:
        attr = _extract_copyright_attribution(header_texts, "") or _extract_copyright_attribution(
            license_texts, fallback_attribution
        )
        return True, "Apache-2.0", attr

    if ("MIT License" in combined_lic or "Permission is hereby granted, free of charge" in combined_lic) and (
        'THE SOFTWARE IS PROVIDED "AS IS"' in combined_lic or "MIT" in combined_lic
    ):
        attr = _extract_copyright_attribution(header_texts, "") or _extract_copyright_attribution(
            license_texts, fallback_attribution
        )
        return True, "MIT", attr

    return False, "UNVERIFIED_LICENSE", ""


def clone_or_open_repo(git_url, target_dir, runner=subprocess.run, shallow=False):
    """Clone an upstream git repo via blobless partial clone (`--filter=blob:none`) for real history.

    Supports optional `shallow=True` (`git clone --depth 1`) and automatically unshallows
    existing shallow clones when full commit timestamps are needed, with zero GitHub REST API calls.
    """
    if os.path.isdir(os.path.join(target_dir, ".git")):
        if not shallow:
            is_shallow = runner(
                ["git", "-C", target_dir, "rev-parse", "--is-shallow-repository"],
                capture_output=True,
                text=True,
                check=False,
            )
            if getattr(is_shallow, "returncode", 1) == 0 and "true" in (getattr(is_shallow, "stdout", "") or "").lower():
                runner(
                    ["git", "-C", target_dir, "fetch", "--unshallow"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
        return target_dir

    os.makedirs(os.path.dirname(os.path.abspath(target_dir)), exist_ok=True)
    if shallow:
        cmd = ["git", "clone", "--depth", "1", "--filter=blob:none", git_url, target_dir]
        fallback_cmd = ["git", "clone", "--depth", "1", git_url, target_dir]
    else:
        cmd = ["git", "clone", "--filter=blob:none", git_url, target_dir]
        fallback_cmd = ["git", "clone", git_url, target_dir]

    res = runner(cmd, capture_output=True, text=True, check=False)
    if res.returncode != 0:
        if os.path.exists(target_dir):
            shutil.rmtree(target_dir, ignore_errors=True)
        res2 = runner(fallback_cmd, capture_output=True, text=True, check=False)
        if res2.returncode != 0:
            if os.path.exists(target_dir):
                shutil.rmtree(target_dir, ignore_errors=True)
            raise subprocess.CalledProcessError(
                res2.returncode,
                fallback_cmd,
                output=getattr(res2, "stdout", None),
                stderr=getattr(res2, "stderr", None),
            )
    return target_dir


def collect_repo_path_timestamps(repo_dir, path_prefix="src", runner=subprocess.run):
    """Collect latest commit Unix timestamp per `src/<lang>/<slug>` folder in a single git log pass."""
    if not repo_dir or not os.path.isdir(os.path.join(repo_dir, ".git")):
        return {}
    norm_prefix = path_prefix.strip("/").replace("\\", "/")
    cmd = [
        "git",
        "-C",
        repo_dir,
        "log",
        "--no-renames",
        "--format=__C__%ct",
        "--name-only",
        "--",
        f"{norm_prefix}/",
    ]
    res = runner(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    if getattr(res, "returncode", 1) != 0:
        return {}

    ts_map = {}
    current_ts = 0
    prefix_slash = f"{norm_prefix}/"
    for raw_line in (getattr(res, "stdout", "") or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("__C__"):
            try:
                current_ts = int(line[5:].strip())
            except ValueError:
                current_ts = 0
            continue
        norm_path = line.replace("\\", "/")
        if not norm_path.startswith(prefix_slash):
            continue
        parts = norm_path.split("/")
        if len(parts) >= 3:
            src_key = f"{parts[0]}/{parts[1]}/{parts[2]}"
            if current_ts > ts_map.get(src_key, 0):
                ts_map[src_key] = current_ts
    return ts_map


def _index_repo_src_dirs(repo_dir):
    """Index existing `src/<lang>/<slug>` folders inside a cloned repo."""
    idx = {}
    src_root = os.path.join(repo_dir, "src")
    if not os.path.isdir(src_root):
        return idx
    for lang_entry in os.listdir(src_root):
        lang_dir = os.path.join(src_root, lang_entry)
        if not os.path.isdir(lang_dir):
            continue
        for slug_entry in os.listdir(lang_dir):
            ext_path = os.path.join(lang_dir, slug_entry)
            if os.path.isdir(ext_path):
                rel = f"src/{lang_entry}/{slug_entry}"
                idx[(lang_entry.lower(), slug_entry.lower())] = rel
                idx.setdefault((None, slug_entry.lower()), rel)
    return idx


def _read_multisrc_theme_kotlin(repo_dir, theme, theme_cache=None):
    if not repo_dir or not theme:
        return ""
    norm_theme = theme.strip().lower()
    cache_key = (os.path.abspath(repo_dir), norm_theme)
    if theme_cache is not None and cache_key in theme_cache:
        return theme_cache[cache_key]

    chunks = []
    theme_dir = os.path.join(repo_dir, "lib-multisrc", norm_theme)
    if os.path.isdir(theme_dir):
        for root, _, files in os.walk(theme_dir):
            for fname in sorted(files):
                if fname.endswith((".kt", ".gradle.kts")):
                    with open(os.path.join(root, fname), "r", encoding="utf-8", errors="ignore") as f:
                        chunks.append(f.read())
    text = "\n".join(chunks)
    if theme_cache is not None:
        theme_cache[cache_key] = text
    return text


def read_extension_from_repo(repo_dir, src_dir, default_attribution="Upstream Contributors", theme_cache=None):
    """Read build.gradle.kts, Kotlin files, theme files, and verified OSI license from cloned repo."""
    ext_dir = os.path.join(repo_dir, src_dir.replace("/", os.sep))
    result = {
        "gradle": None,
        "gradleText": "",
        "kotlinText": "",
        "themeKotlinText": "",
        "kotlinHint": None,
        "licenseOk": False,
        "license": "MISSING_LICENSE",
        "attribution": "",
    }
    gradle_path = os.path.join(ext_dir, "build.gradle.kts")
    if not os.path.isfile(gradle_path):
        return result

    with open(gradle_path, "r", encoding="utf-8", errors="ignore") as f:
        gradle_text = f.read()
    result["gradleText"] = gradle_text
    gradle_info = parse_extension_build_gradle(gradle_text)
    result["gradle"] = gradle_info

    kt_chunks = []
    search_dirs = [os.path.join(ext_dir, "src"), ext_dir]
    seen_kt_paths = set()
    for s_dir in search_dirs:
        if os.path.isdir(s_dir):
            for root, _, files in os.walk(s_dir):
                for fname in sorted(files):
                    if fname.endswith(".kt"):
                        f_path = os.path.join(root, fname)
                        if f_path not in seen_kt_paths:
                            seen_kt_paths.add(f_path)
                            with open(f_path, "r", encoding="utf-8", errors="ignore") as kf:
                                kt_chunks.append(kf.read())

    combined_kt = "\n".join(kt_chunks)
    result["kotlinText"] = combined_kt
    if combined_kt:
        result["kotlinHint"] = inspect_open_source_kotlin(combined_kt)
        if not gradle_info.get("theme") and result["kotlinHint"].get("inferredTheme"):
            gradle_info["theme"] = result["kotlinHint"]["inferredTheme"]

    theme_name = gradle_info.get("theme")
    if theme_name:
        result["themeKotlinText"] = _read_multisrc_theme_kotlin(repo_dir, theme_name, theme_cache=theme_cache)

    lic_ok, spdx, attr = verify_repo_license(
        repo_dir,
        gradle_text=gradle_text,
        kotlin_texts=kt_chunks,
        fallback_attribution=default_attribution,
    )
    result["licenseOk"] = lic_ok
    result["license"] = spdx
    result["attribution"] = attr
    return result


def fetch_url_bytes(url, timeout=15):
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": HTTP_UA})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return resp.read()


class _RedirectSSRFError(urllib.error.URLError):
    def __init__(self, target_url, reason):
        super().__init__(reason)
        self.target_url = target_url


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, max_redirects=5):
        super().__init__()
        self.max_redirects = max_redirects
        self.redirect_chain = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        resolved = urljoin(req.full_url, newurl)
        ok_ssrf, ssrf_msg = validate_ssrf(resolved)
        if not ok_ssrf:
            raise _RedirectSSRFError(resolved, f"SSRF rejected in redirect: {ssrf_msg}")
        if len(self.redirect_chain) >= self.max_redirects:
            raise urllib.error.URLError(f"Too many redirects (> {self.max_redirects})")
        self.redirect_chain.append((req.full_url, int(code), resolved))
        return super().redirect_request(req, fp, code, msg, headers, resolved)


def _extract_html_or_js_redirect(body_text, current_url):
    """Extract destination URL from meta refresh or simple JS redirect."""
    if not body_text:
        return None
    m_meta = re.search(
        r"""<meta\s+[^>]*http-equiv=["']?refresh["']?[^>]*content=["']?[^"'>]*?url=['"]?([^"'>\s]+)['"]?""",
        body_text,
        re.I,
    )
    if not m_meta:
        m_meta = re.search(
            r"""<meta\s+[^>]*content=["']?[^"'>]*?url=['"]?([^"'>\s]+)['"]?[^>]*http-equiv=["']?refresh["']?""",
            body_text,
            re.I,
        )
    if m_meta:
        target = m_meta.group(1).strip().strip("'\"")
        if target:
            return urljoin(current_url, target)

    # Only follow JS-based redirects on small stub/interstitial pages; large HTML pages with links
    # often contain click/search handlers like `location.href = '/series?q=' + q`.
    if len(body_text) > 16384 or body_text.lower().count("<a ") >= 5:
        return None

    js_patterns = [
        r"""(?:window\.)?location(?:\.href)?\s*=\s*['"]([^'"]+)['"]\s*(?:;|\r|\n|</script>)""",
        r"""(?:window\.)?location\.replace\(\s*['"]([^'"]+)['"]\s*\)""",
        r"""(?:window\.)?location\.assign\(\s*['"]([^'"]+)['"]\s*\)""",
    ]
    for pat in js_patterns:
        m_js = re.search(pat, body_text, re.I)
        if m_js:
            target = m_js.group(1).strip()
            if target and not target.startswith("javascript:"):
                return urljoin(current_url, target)
    return None


def probe_http_sample_detailed(
    url,
    timeout=10,
    method="GET",
    headers=None,
    body=None,
    max_redirects=5,
    max_bytes=524288,
    fetcher=None,
):
    """Probe an HTTP endpoint with per-hop SSRF validation, redirect tracking, and header capture."""
    ok, msg = validate_ssrf(url)
    if not ok:
        return {
            "status_code": 0,
            "body": "",
            "message": f"SSRF rejected: {msg}",
            "final_url": url,
            "redirect_chain": [],
            "headers": {},
            "error_type": "SSRF_REJECTED",
        }

    req_headers = {"User-Agent": HTTP_UA}
    for hk, hv in (headers or {}).items():
        if isinstance(hk, str) and isinstance(hv, str):
            if hk.lower() in ("referer", "origin") and hv:
                ok_h, msg_h = validate_ssrf(hv)
                if not ok_h:
                    return {
                        "status_code": 0,
                        "body": "",
                        "message": f"SSRF rejected in header {hk}: {msg_h}",
                        "final_url": url,
                        "redirect_chain": [],
                        "headers": {},
                        "error_type": "SSRF_REJECTED",
                    }
            req_headers[hk] = hv

    redirect_chain = []
    current_url = url
    current_method = (method or "GET").upper()
    current_body = body
    hops_remaining = max_redirects

    while True:
        _respect_domain_rate_limit(current_url)
        if fetcher is not None:
            try:
                try:
                    f_status, f_body, f_msg = fetcher(current_url, method=current_method, headers=req_headers, body=current_body)
                except TypeError:
                    f_status, f_body, f_msg = fetcher(current_url)
                resp_headers = {}
                resp_body = f_body or ""
                final_url = current_url
                status = int(f_status)
                if 200 <= status < 300 and hops_remaining > 0:
                    is_waf, _ = detect_waf_block(status, headers=resp_headers, body=resp_body)
                    if not is_waf:
                        next_url = _extract_html_or_js_redirect(resp_body, final_url)
                        if next_url and next_url != final_url:
                            ok_ssrf, ssrf_msg = validate_ssrf(next_url)
                            if not ok_ssrf:
                                redirect_chain.append((final_url, status, next_url))
                                return {
                                    "status_code": 0,
                                    "body": "",
                                    "message": f"SSRF rejected in redirect: {ssrf_msg}",
                                    "final_url": final_url,
                                    "redirect_chain": list(redirect_chain),
                                    "headers": {},
                                    "error_type": "SSRF_REDIRECT_REJECTED",
                                }
                            redirect_chain.append((final_url, status, next_url))
                            current_url = next_url
                            current_method = "GET"
                            current_body = None
                            hops_remaining = max_redirects - len(redirect_chain)
                            continue
                return {
                    "status_code": status,
                    "body": resp_body,
                    "message": f_msg or f"HTTP {status}",
                    "final_url": final_url,
                    "redirect_chain": list(redirect_chain),
                    "headers": resp_headers,
                    "error_type": None if status < 400 else f"HTTPError_{status}",
                }
            except Exception as e:
                return {
                    "status_code": 0,
                    "body": "",
                    "message": str(e),
                    "final_url": current_url,
                    "redirect_chain": list(redirect_chain),
                    "headers": {},
                    "error_type": type(e).__name__,
                }
        body_bytes = current_body.encode("utf-8") if isinstance(current_body, str) else current_body
        ctx = ssl.create_default_context()
        redirect_handler = _SafeRedirectHandler(max_redirects=hops_remaining)
        opener = urllib.request.build_opener(
            redirect_handler,
            urllib.request.HTTPSHandler(context=ctx),
        )
        req = urllib.request.Request(
            current_url,
            data=body_bytes,
            headers=req_headers,
            method=current_method,
        )
        try:
            with opener.open(req, timeout=timeout) as resp:
                resp_body = resp.read(max_bytes).decode("utf-8", "ignore")
                resp_headers = {str(k): str(v) for k, v in (resp.headers.items() if resp.headers else [])}
                final_url = resp.geturl() or current_url
                for hop in redirect_handler.redirect_chain:
                    redirect_chain.append(hop)
                hops_remaining = max_redirects - len(redirect_chain)

                if 200 <= resp.status < 300 and hops_remaining > 0:
                    is_waf, _ = detect_waf_block(resp.status, headers=resp_headers, body=resp_body)
                    if not is_waf:
                        next_url = _extract_html_or_js_redirect(resp_body, final_url)
                        if next_url and next_url != final_url:
                            ok_ssrf, ssrf_msg = validate_ssrf(next_url)
                            if not ok_ssrf:
                                redirect_chain.append((final_url, int(resp.status), next_url))
                                return {
                                    "status_code": 0,
                                    "body": "",
                                    "message": f"SSRF rejected in redirect: {ssrf_msg}",
                                    "final_url": final_url,
                                    "redirect_chain": list(redirect_chain),
                                    "headers": {},
                                    "error_type": "SSRF_REDIRECT_REJECTED",
                                }
                            redirect_chain.append((final_url, int(resp.status), next_url))
                            current_url = next_url
                            current_method = "GET"
                            current_body = None
                            hops_remaining = max_redirects - len(redirect_chain)
                            continue

                return {
                    "status_code": int(resp.status),
                    "body": resp_body,
                    "message": f"HTTP {resp.status}",
                    "final_url": final_url,
                    "redirect_chain": list(redirect_chain),
                    "headers": resp_headers,
                    "error_type": None,
                }
        except urllib.error.HTTPError as e:
            for hop in redirect_handler.redirect_chain:
                redirect_chain.append(hop)
            err_body = e.read(65536).decode("utf-8", "ignore") if e.fp else ""
            err_headers = {str(k): str(v) for k, v in (e.headers.items() if e.headers else [])}
            if e.headers and e.headers.get("cf-mitigated"):
                err_body = f"cf-mitigated: {e.headers.get('cf-mitigated')}\n{err_body}"
            final_url = (e.geturl() if hasattr(e, "geturl") else None) or (
                redirect_chain[-1][2] if redirect_chain else current_url
            )
            return {
                "status_code": int(e.code),
                "body": err_body,
                "message": f"HTTP {e.code}",
                "final_url": final_url,
                "redirect_chain": list(redirect_chain),
                "headers": err_headers,
                "error_type": f"HTTPError_{e.code}",
            }
        except _RedirectSSRFError as e:
            for hop in redirect_handler.redirect_chain:
                redirect_chain.append(hop)
            return {
                "status_code": 0,
                "body": "",
                "message": str(e),
                "final_url": e.target_url,
                "redirect_chain": list(redirect_chain),
                "headers": {},
                "error_type": "SSRF_REDIRECT_REJECTED",
            }
        except Exception as e:
            for hop in redirect_handler.redirect_chain:
                redirect_chain.append(hop)
            final_url = redirect_chain[-1][2] if redirect_chain else current_url
            return {
                "status_code": 0,
                "body": "",
                "message": f"{type(e).__name__}: {e}",
                "final_url": final_url,
                "redirect_chain": list(redirect_chain),
                "headers": {},
                "error_type": type(e).__name__,
            }


def probe_http_sample(url, timeout=10, method="GET", headers=None, body=None):
    d = probe_http_sample_detailed(url, timeout=timeout, method=method, headers=headers, body=body)
    return d["status_code"], d["body"], d["message"]


_BRACKET_RE = re.compile(r"\[(\*|\d+)\]")


def _normalize_json_or_jmes_expr(expression):
    trimmed = (expression or "").strip()
    if not trimmed:
        return ""
    if trimmed.startswith("$"):
        return trimmed
    if "[" not in trimmed or "]" not in trimmed:
        return ""
    out = []
    quote = None
    i = 0
    n = len(trimmed)
    while i < n:
        ch = trimmed[i]
        if quote:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                i += 1
                out.append(trimmed[i])
            elif ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            out.append(ch)
            i += 1
        elif ch == "[" and i + 1 < n and trimmed[i + 1] == "]":
            out.append("[*]")
            i += 2
        else:
            out.append(ch)
            i += 1
    norm = "".join(out)
    return f"${norm}" if norm.startswith("[") else f"$.{norm}"


def _find_matching_json_bracket(expr, open_idx):
    depth = 0
    quote = None
    i = open_idx
    n = len(expr)
    while i < n:
        ch = expr[i]
        if quote:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == quote:
                quote = None
        else:
            if ch in ("'", '"'):
                quote = ch
            elif ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return -1


def _collect_json_descendants(nodes):
    out = []
    stack = list(reversed(nodes))
    while stack:
        node = stack.pop()
        out.append(node)
        if isinstance(node, dict):
            vals = list(node.values())
            for v in reversed(vals):
                stack.append(v)
        elif isinstance(node, list):
            for v in reversed(node):
                stack.append(v)
    return out


def _matches_json_filter(item, raw_filter):
    expr = raw_filter[1:].strip()
    while expr.startswith("(") and expr.endswith(")"):
        expr = expr[1:-1].strip()
    if not expr:
        return False

    # Find == or != outside quotes
    op_idx = -1
    op_str = None
    quote = None
    i = 0
    while i < len(expr):
        ch = expr[i]
        if quote:
            if ch == "\\" and i + 1 < len(expr):
                i += 2
                continue
            if ch == quote:
                quote = None
        else:
            if ch in ("'", '"'):
                quote = ch
            elif expr.startswith("==", i):
                op_idx, op_str = i, "=="
                break
            elif expr.startswith("!=", i):
                op_idx, op_str = i, "!="
                break
        i += 1

    lhs = expr[:op_idx].strip() if op_str else expr
    if lhs == "@":
        target = item
    else:
        field_path = lhs[2:] if lhs.startswith("@.") else (lhs[1:] if lhs.startswith("@") else lhs)
        target = item
        for part in field_path.split("."):
            if isinstance(target, dict) and part in target:
                target = target[part]
            else:
                target = None
                break

    if not op_str:
        if target is None:
            return False
        if isinstance(target, bool):
            return target
        if isinstance(target, str):
            return bool(target)
        return True

    rhs = expr[op_idx + len(op_str) :].strip()
    if (rhs.startswith("'") and rhs.endswith("'") and len(rhs) >= 2) or (
        rhs.startswith('"') and rhs.endswith('"') and len(rhs) >= 2
    ):
        expected = rhs[1:-1]
        matched = target is not None and not isinstance(target, (dict, list, bool)) and str(target) == expected
    elif rhs == "null":
        matched = target is None
    elif rhs in ("true", "false"):
        matched = isinstance(target, bool) and target == (rhs == "true")
    else:
        try:
            exp_num = float(rhs)
            matched = isinstance(target, (int, float)) and not isinstance(target, bool) and float(target) == exp_num
        except ValueError:
            matched = target is not None and str(target) == rhs
    return (not matched) if op_str == "!=" else matched


def extract_json_path(raw_json, expression):
    """Python equivalent of Kotlin LightweightJsonExtractor (recursive $.., filters, and JMESPath)."""
    norm_expr = _normalize_json_or_jmes_expr(expression)
    if not norm_expr:
        return []
    try:
        data = json.loads(raw_json) if isinstance(raw_json, str) else raw_json
    except Exception:
        return []
    if norm_expr in ("$", "$."):
        return [] if data is None else [data]

    body = norm_expr[1:]  # starts with '.' or '['
    steps = []
    pos = 0
    n = len(body)
    while pos < n:
        if body.startswith("..", pos):
            recursive = True
            pos += 2
            if pos >= n or body[pos] == ".":
                return []
        elif body[pos] == ".":
            recursive = False
            pos += 1
            if pos >= n or body[pos] == ".":
                return []
        elif body[pos] == "[":
            recursive = False
        else:
            return []

        f_start = pos
        while pos < n and body[pos] not in (".", "["):
            pos += 1
        field_name = body[f_start:pos]
        if not field_name and (pos >= n or body[pos] != "["):
            return []

        brackets = []
        while pos < n and body[pos] == "[":
            close_idx = _find_matching_json_bracket(body, pos)
            if close_idx < 0:
                return []
            brackets.append(body[pos + 1 : close_idx].strip())
            pos = close_idx + 1
        if pos < n and body[pos] != ".":
            return []
        steps.append((recursive, field_name or None, brackets))

    current = [data]
    for recursive, field_name, brackets in steps:
        if recursive:
            current = _collect_json_descendants(current)
        if field_name is not None:
            if field_name == "*":
                nxt = []
                for item in current:
                    if isinstance(item, dict):
                        nxt.extend(item.values())
                    elif isinstance(item, list):
                        nxt.extend(item)
                current = nxt
            else:
                current = [item[field_name] for item in current if isinstance(item, dict) and field_name in item]
        for tok in brackets:
            if tok == "*":
                nxt = []
                for item in current:
                    if isinstance(item, list):
                        nxt.extend(item)
                current = nxt
            elif tok.isdigit():
                idx = int(tok)
                current = [item[idx] for item in current if isinstance(item, list) and 0 <= idx < len(item)]
            elif tok.startswith("?"):
                nxt = []
                for item in current:
                    if isinstance(item, list):
                        nxt.extend(el for el in item if _matches_json_filter(el, tok))
                current = nxt
            else:
                return []
        if not current:
            break
    return [x for x in current if x is not None]


def _apply_smoke_placeholders(template_str, replacements):
    out = str(template_str or "")
    for k, v in replacements.items():
        out = out.replace(k, v)
    return out


def _compute_query_signer_parts(url, query_signer, method="GET"):
    """Compute signed query param or header additions matching Kotlin CanonicalQuerySigner."""
    if not isinstance(query_signer, dict):
        return url, {}
    parsed = urlparse(url)
    path_prefix = str(query_signer.get("pathPrefix") or "/")
    match_prefix = path_prefix if (path_prefix == "/" or path_prefix.endswith("/")) else f"{path_prefix}/"
    if not (parsed.path.startswith(match_prefix) or parsed.path == path_prefix):
        return url, {}

    strip_prefix = bool(query_signer.get("stripPathPrefix", True))
    base_path = parsed.path
    if strip_prefix and path_prefix != "/" and base_path.startswith(path_prefix):
        base_path = base_path[len(path_prefix) :]

    raw_params = parse_qsl(parsed.query, keep_blank_values=True)
    raw_params.sort(key=lambda kv: kv[0])

    canonical = base_path
    query_str = ""
    if raw_params:
        formatted = []
        last_key = ""
        arr_idx = 0
        for k, v in raw_params:
            if k.endswith("[]"):
                if last_key != k:
                    arr_idx = 0
                last_key = k
                new_k = f"{k[:-2]}[{arr_idx}]"
                arr_idx += 1
            else:
                new_k = k
            formatted.append(f"{new_k}={v}")
        query_str = "&".join(formatted)
        canonical += "?" + query_str

    now_sec = int(time.time())
    now_ms = int(time.time() * 1000)
    ts_fmt = str(query_signer.get("timestampFormat") or "EPOCH_SECONDS").strip().upper()
    if ts_fmt == "EPOCH_MILLIS":
        ts_val = str(now_ms)
    elif ts_fmt == "ISO_8601":
        ts_val = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        ts_val = str(now_sec)

    secret = str(query_signer.get("hmacSecret") or query_signer.get("salt") or "")
    sign_tpl = query_signer.get("signTemplate")
    if isinstance(sign_tpl, str) and sign_tpl.strip():
        sign_input = (
            sign_tpl.replace("{canonical}", canonical)
            .replace("{path}", base_path)
            .replace("{query}", query_str)
            .replace("{method}", str(method or "GET").upper())
            .replace("{timestamp}", ts_val)
            .replace("{secret}", secret)
        )
    else:
        sign_input = canonical

    algo = str(query_signer.get("algorithm") or "sbox_xor_cbc")
    if algo == "sbox_xor_cbc":
        stages = query_signer.get("stages") or []
        if not stages:
            return url, {}
        data = sign_input.encode("utf-8")
        for st in stages:
            table = base64.b64decode(st["tableBase64"])
            key = base64.b64decode(st["keyBase64"])
            iv = int(st["iv"]) & 0xFF
            if len(table) != 256 or not key:
                return url, {}
            out = bytearray(len(data))
            prev = iv
            key_len = len(key)
            for idx, b in enumerate(data):
                prev = table[(b ^ key[idx % key_len] ^ prev) & 0xFF] & 0xFF
                out[idx] = prev
            data = bytes(out)
        signature = base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
    elif algo == "hmac_sha256":
        if not secret:
            return url, {}
        signature = hmac.new(secret.encode("utf-8"), sign_input.encode("utf-8"), hashlib.sha256).hexdigest()
    elif algo == "hmac_sha1":
        if not secret:
            return url, {}
        signature = hmac.new(secret.encode("utf-8"), sign_input.encode("utf-8"), hashlib.sha1).hexdigest()
    elif algo == "md5_salted":
        payload = sign_input if sign_tpl else (canonical + secret)
        signature = hashlib.md5(payload.encode("utf-8")).hexdigest()
    elif algo == "sha1_salted":
        payload = sign_input if sign_tpl else (canonical + secret)
        signature = hashlib.sha1(payload.encode("utf-8")).hexdigest()
    elif algo == "sha256_timestamp":
        payload = sign_input if sign_tpl else (canonical + secret + ts_val)
        signature = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    else:
        return url, {}

    extra_headers = {}
    target = str(query_signer.get("target") or "QUERY").strip().upper()
    if target == "HEADER":
        hdr_name = str(query_signer.get("headerName") or "").strip()
        if hdr_name and hdr_name.lower() != "host":
            extra_headers[hdr_name] = signature
        ts_hdr = str(query_signer.get("timestampHeaderName") or "").strip()
        if ts_hdr and ts_hdr.lower() != "host":
            extra_headers[ts_hdr] = ts_val
        return url, extra_headers

    param_name = str(query_signer.get("paramName") or "vrf")
    sep = "&" if parsed.query else ""
    new_query = f"{parsed.query}{sep}{quote(param_name, safe='')}={quote(signature, safe='-_')}"
    if algo == "sha256_timestamp":
        ts_param = str(query_signer.get("timestampParam") or "t")
        new_query += f"&{quote(ts_param, safe='')}={quote(ts_val, safe='-_')}"
    signed_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
    return signed_url, extra_headers


def sign_url_with_query_signer(url, query_signer):
    """Python parity implementation of Kotlin CanonicalQuerySigner."""
    signed_url, _ = _compute_query_signer_parts(url, query_signer)
    return signed_url


def build_smoke_requests(recipe):
    """Build candidate (url, method, headers, body) tuples for HTTP smoke testing."""
    base_url = recipe["baseUrl"].rstrip("/")
    base_headers = dict(recipe.get("headers") or {})
    preset = recipe.get("preset", "CSS_GENERIC")
    family = recipe.get("family") or "STANDARD"
    json_api = recipe.get("jsonApi") if isinstance(recipe.get("jsonApi"), dict) else {}
    req_spec = json_api.get("popularRequest") or recipe.get("popularRequest")
    query_signer = recipe.get("querySigner") if isinstance(recipe.get("querySigner"), dict) else None

    if isinstance(req_spec, dict):
        api_base = str(json_api.get("apiBaseUrl") or base_url).rstrip("/")
        manga_list = json_api.get("mangaList") if isinstance(json_api.get("mangaList"), dict) else {}
        pagination = manga_list.get("pagination") if isinstance(manga_list.get("pagination"), dict) else {}
        start_page = str(pagination.get("startPage", 1))
        raw_lang = str(recipe.get("lang") or "es")
        lang_map = json_api.get("langMap") if isinstance(json_api.get("langMap"), dict) else {}
        lang_val = lang_map.get(raw_lang)
        if lang_val is None:
            lang_val = next((v for k, v in lang_map.items() if str(k).lower() == raw_lang.lower()), raw_lang)
        lang_val = str(lang_val)
        org_val = str(json_api.get("defaultOrg") or "")
        replacements = {
            "{baseUrl}": base_url,
            "{apiBaseUrl}": api_base,
            "{page}": start_page,
            "{offset}": "0",
            "{lang}": lang_val,
            "{org}": org_val,
            "{query}": "",
        }
        raw_path = req_spec.get("firstPagePathTemplate") or req_spec.get("pathTemplate") or recipe.get("catalogPath") or ""
        resolved_path = _apply_smoke_placeholders(raw_path, replacements)
        if resolved_path.startswith("https://") or resolved_path.startswith("http://"):
            target_url = resolved_path
        elif resolved_path:
            target_url = f"{api_base}/{resolved_path.lstrip('/')}"
        else:
            target_url = api_base

        if query_signer:
            target_url, signer_headers = _compute_query_signer_parts(target_url, query_signer, method=req_spec.get("method") or "GET")
        else:
            signer_headers = {}

        merged_headers = {}
        for hk, hv in base_headers.items():
            merged_headers[hk] = _apply_smoke_placeholders(hv, replacements)
        for hk, hv in (req_spec.get("headers") or {}).items():
            merged_headers[hk] = _apply_smoke_placeholders(hv, replacements)
        merged_headers.update(signer_headers)
        if req_spec.get("contentType"):
            merged_headers.setdefault("Content-Type", str(req_spec["contentType"]))

        if req_spec.get("graphqlQuery"):
            gql_vars_raw = _apply_smoke_placeholders(req_spec.get("graphqlVariablesTemplate") or "{}", replacements)
            try:
                gql_vars_obj = json.loads(gql_vars_raw)
            except Exception:
                gql_vars_obj = {}
            body_str = json.dumps({"query": req_spec["graphqlQuery"], "variables": gql_vars_obj})
        else:
            body_tpl = req_spec.get("bodyTemplate")
            body_str = _apply_smoke_placeholders(body_tpl, replacements) if body_tpl else None
        method = str(req_spec.get("method") or "GET").upper()
        reqs = [(target_url, method, merged_headers, body_str)]
        if preset != "JSON_API" and recipe.get("useHomeFallback") and target_url.rstrip("/") != base_url:
            reqs.append((base_url, "GET", base_headers, None))
        return reqs

    catalog_path = recipe.get("catalogPath") or ""
    if not catalog_path and family == "QWIK_SERIES" and isinstance(recipe.get("qwik"), dict):
        catalog_path = str(recipe["qwik"].get("seriesPath") or "")

    primary_url = f"{base_url}{catalog_path}"
    primary_headers = dict(base_headers)
    if query_signer:
        primary_url, signer_headers = _compute_query_signer_parts(primary_url, query_signer, method="GET")
        primary_headers.update(signer_headers)
    reqs = [(primary_url, "GET", primary_headers, None)]
    if recipe.get("useHomeFallback") and catalog_path:
        reqs.append((base_url, "GET", base_headers, None))
    return reqs


_PACKER_CHARS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _encode_packer_base(num, base):
    if num == 0:
        return "0"
    digits = []
    while num > 0:
        num, rem = divmod(num, base)
        digits.append(_PACKER_CHARS[rem] if rem < len(_PACKER_CHARS) else "")
    return "".join(reversed(digits))


def _read_js_quoted_string(text, start_idx):
    """Read a JS single- or double-quoted string starting at `start_idx`, returning (decoded_str, end_idx)."""
    if start_idx >= len(text) or text[start_idx] not in ("'", '"'):
        return None, start_idx
    quote = text[start_idx]
    out = []
    i = start_idx + 1
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\\" and i + 1 < n:
            nxt = text[i + 1]
            escapes = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\", "'": "'", '"': '"', "/": "/"}
            if nxt in escapes:
                out.append(escapes[nxt])
                i += 2
                continue
            if nxt == "x" and i + 3 < n:
                try:
                    out.append(chr(int(text[i + 2 : i + 4], 16)))
                    i += 4
                    continue
                except ValueError:
                    pass
            if nxt == "u" and i + 5 < n:
                try:
                    out.append(chr(int(text[i + 2 : i + 6], 16)))
                    i += 6
                    continue
                except ValueError:
                    pass
            out.append(nxt)
            i += 2
            continue
        if ch == quote:
            return "".join(out), i + 1
        out.append(ch)
        i += 1
    return None, start_idx


def _unpack_packer_js(text, max_blocks=4):
    """Pure-Python Dean Edwards `eval(function(p,a,c,k,e,d)...)` unpacker for smoke testing."""
    if not text or "eval(function(p,a,c,k" not in text.lower():
        return []
    unpacked_chunks = []
    search_pos = 0
    low = text.lower()
    while len(unpacked_chunks) < max_blocks:
        idx = low.find("eval(function(p,a,c,k", search_pos)
        if idx < 0:
            break
        # Find "}(" separating packer body from invocation args
        call_sep = text.find("}(", idx)
        if call_sep < 0:
            search_pos = idx + 20
            continue
        pos = call_sep + 2
        n = len(text)
        while pos < n and text[pos].isspace():
            pos += 1
        payload, pos = _read_js_quoted_string(text, pos)
        if payload is None:
            search_pos = call_sep + 2
            continue
        m_args = re.match(r"\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*", text[pos:])
        if not m_args:
            search_pos = pos
            continue
        radix = int(m_args.group(1))
        pos += m_args.end()
        kw_raw, pos = _read_js_quoted_string(text, pos)
        if kw_raw is None or not (2 <= radix <= 62):
            search_pos = pos
            continue
        keywords = kw_raw.split("|")
        kw_map = {
            _encode_packer_base(i, radix): word
            for i, word in enumerate(keywords)
            if word
        }
        unpacked = re.sub(r"\b([0-9A-Za-z]+)\b", lambda m: kw_map.get(m.group(1), m.group(1)), payload)
        unpacked_chunks.append(unpacked)
        search_pos = pos
    return unpacked_chunks


def _extract_next_rsc_payloads(html_text, max_chunks=400):
    """Extract string payloads from Next.js App Router `self.__next_f.push([..., "..."])` blocks."""
    if not html_text or "__next_f" not in html_text:
        return []
    chunks = []
    pos = 0
    marker = "__next_f.push("
    n = len(html_text)
    while len(chunks) < max_chunks:
        idx = html_text.find(marker, pos)
        if idx < 0:
            break
        cur = idx + len(marker)
        while cur < n and html_text[cur].isspace():
            cur += 1
        if cur < n and html_text[cur] == "[":
            cur += 1
            # Skip channel id up to comma
            comma_idx = html_text.find(",", cur)
            if comma_idx > 0 and comma_idx - cur < 24:
                cur = comma_idx + 1
                while cur < n and html_text[cur].isspace():
                    cur += 1
                if cur < n and html_text[cur] in ('"', "'"):
                    decoded, end_pos = _read_js_quoted_string(html_text, cur)
                    if decoded is not None:
                        chunks.append(decoded)
                        pos = end_pos
                        continue
        pos = idx + len(marker)
    return chunks


def _recipe_uses_quickjs(recipe):
    if not isinstance(recipe, dict):
        return False
    for key in ("pipelineSteps", "listPipelineSteps", "chaptersPipelineSteps"):
        if any(isinstance(s, dict) and s.get("op") == "quickjs_eval" for s in (recipe.get(key) or [])):
            return True
    ja = recipe.get("jsonApi")
    if isinstance(ja, dict):
        for sec in ("mangaList", "details", "chapters", "pages"):
            sec_obj = ja.get(sec)
            if isinstance(sec_obj, dict):
                if any(isinstance(s, dict) and s.get("op") == "quickjs_eval" for s in (sec_obj.get("pipelineSteps") or [])):
                    return True
    return False


def _collect_item_dicts_from_json_obj(obj, out, depth=0):
    """Recursively collect dict items that look like catalog entries (title/name + slug/url/id/href)."""
    if depth > 6 or len(out) >= 100:
        return
    if isinstance(obj, list):
        for el in obj:
            _collect_item_dicts_from_json_obj(el, out, depth + 1)
    elif isinstance(obj, dict):
        has_title = any(isinstance(obj.get(k), str) and obj.get(k).strip() for k in ("title", "name", "postTitle", "seriesTitle"))
        has_link = any(
            (isinstance(obj.get(k), (str, int)) and str(obj.get(k)).strip())
            for k in ("slug", "url", "href", "link", "id", "hid")
        )
        if has_title and has_link:
            out.append(obj)
            return
        for val in obj.values():
            if isinstance(val, (dict, list)):
                _collect_item_dicts_from_json_obj(val, out, depth + 1)


def _extract_items_from_rsc_or_packer(recipe, body_text):
    """Extract catalog items in pure Python from Next.js `__next_f` or Packer `eval(function(p,a,c,k)` payloads."""
    decoded_parts = []
    decoded_parts.extend(_extract_next_rsc_payloads(body_text))
    decoded_parts.extend(_unpack_packer_js(body_text))
    if not decoded_parts:
        return []

    combined = "\n".join(decoded_parts)
    selectors = recipe.get("selectors") or {}
    json_api = recipe.get("jsonApi") if isinstance(recipe.get("jsonApi"), dict) else {}
    manga_list = json_api.get("mangaList") if isinstance(json_api.get("mangaList"), dict) else {}
    items_path = manga_list.get("itemsPath", "")
    list_sel = selectors.get("listSelector", "")

    # 1. Try explicit JSONPath / JMESPath against embedded JSON blocks
    candidate_paths = []
    for expr in (list_sel, items_path):
        if isinstance(expr, str) and (expr.startswith("$.") or ("[" in expr and "]" in expr)) and expr not in candidate_paths:
            candidate_paths.append(expr)

    decoder = json.JSONDecoder()
    parsed_json_blocks = []
    pos = 0
    scans = 0
    n = len(combined)
    while pos < n and scans < 250 and len(parsed_json_blocks) < 60:
        next_obj = combined.find("{", pos)
        next_arr = combined.find("[", pos)
        candidates = [idx for idx in (next_obj, next_arr) if idx >= 0]
        if not candidates:
            break
        start_idx = min(candidates)
        scans += 1
        try:
            parsed, end_idx = decoder.raw_decode(combined, start_idx)
            if isinstance(parsed, (dict, list)):
                parsed_json_blocks.append(parsed)
            pos = end_idx
        except Exception:
            pos = start_idx + 1

    for expr in candidate_paths:
        for block in parsed_json_blocks:
            matched = extract_json_path(block, expr)
            valid = [m for m in matched if isinstance(m, dict) and any(str(v).strip() for v in m.values() if v is not None)]
            if valid:
                return valid

    # 2. Try HTML selectors on decoded content if HTML tags exist
    if "<" in combined and ">" in combined and list_sel and not list_sel.startswith("$"):
        html_items = extract_html_items(combined, selectors)
        if html_items:
            return html_items

    # 3. Collect manga-like JSON objects from parsed blocks
    item_dicts = []
    for block in parsed_json_blocks:
        _collect_item_dicts_from_json_obj(block, item_dicts)
    if item_dicts:
        return item_dicts

    return []


def _extract_inertia_json(body_text, script_sel="script[data-page]"):
    raw_json = ""
    if BeautifulSoup is not None:
        soup = BeautifulSoup(body_text or "", "html.parser")
        node = soup.select_one(script_sel)
        if node is not None:
            txt = (node.string or node.get_text() or "").strip()
            dp_val = (node.get("data-page") or "").strip()
            if txt.startswith(("{", "[")):
                raw_json = txt
            elif dp_val.startswith(("{", "[")):
                raw_json = dp_val
            else:
                raw_json = txt or dp_val
    else:
        m_script_dp = re.search(r"""<script[^>]*data-page[^>]*>(.*?)</script>""", body_text or "", re.I | re.S)
        if m_script_dp and m_script_dp.group(1).strip().startswith(("{", "[")):
            raw_json = m_script_dp.group(1).strip()
        else:
            m_dp_attr = re.search(r"""data-page=(['"])(.*?)\1""", body_text or "", re.I | re.S)
            if m_dp_attr:
                import html
                val = html.unescape(m_dp_attr.group(2).strip())
                if val.startswith(("{", "[")):
                    raw_json = val
            if not raw_json and m_script_dp and m_script_dp.group(1).strip():
                raw_json = m_script_dp.group(1).strip()
            if not raw_json:
                m_any_json = re.search(
                    r"""<script[^>]*type=["']application/json["'][^>]*>(.*?)</script>""",
                    body_text or "",
                    re.I | re.S,
                )
                if m_any_json and m_any_json.group(1).strip():
                    raw_json = m_any_json.group(1).strip()
                else:
                    m_tag = re.search(r"""<script[^>]*>(.*?)</script>""", body_text or "", re.I | re.S)
                    if m_tag:
                        raw_json = m_tag.group(1).strip()
    return raw_json


def extract_items_for_smoke(recipe, body_text):
    """Extract candidate catalog items from HTML, INERTIA_SSR, or JSON API responses."""
    selectors = recipe.get("selectors") or {}
    list_sel = selectors.get("listSelector", "")
    preset = recipe.get("preset", "CSS_GENERIC")
    family = recipe.get("family") or "STANDARD"

    if family == "INERTIA_SSR" and isinstance(recipe.get("inertia"), dict):
        inertia = recipe["inertia"]
        script_sel = inertia.get("scriptSelector") or "script[data-page]"
        series_list_path = inertia.get("seriesListPath") or ""
        if series_list_path:
            raw_json = _extract_inertia_json(body_text, script_sel=script_sel)
            if raw_json:
                raw_items = extract_json_path(raw_json, series_list_path)
                valid_inertia = [
                    it
                    for it in raw_items
                    if isinstance(it, dict) and any(isinstance(v, (str, int)) and str(v).strip() for v in it.values())
                ]
                if valid_inertia:
                    return valid_inertia

    if preset == "JSON_API":
        json_api = recipe.get("jsonApi") if isinstance(recipe.get("jsonApi"), dict) else {}
        manga_list = json_api.get("mangaList") if isinstance(json_api.get("mangaList"), dict) else {}
        items_path = manga_list.get("itemsPath", "")
        candidate_paths = []
        for expr in (list_sel, items_path, "$.feed.entry[*]"):
            if isinstance(expr, str) and (expr.startswith("$.") or ("[" in expr and "]" in expr)) and expr not in candidate_paths:
                candidate_paths.append(expr)

        def _item_has_content(obj, depth=0):
            if depth > 3:
                return False
            if isinstance(obj, (str, int)):
                return bool(str(obj).strip())
            if isinstance(obj, dict):
                return any(_item_has_content(v, depth + 1) for v in obj.values())
            if isinstance(obj, list):
                return any(_item_has_content(v, depth + 1) for v in obj)
            return False

        for expr in candidate_paths:
            raw_items = extract_json_path(body_text, expr)
            html_extract = manga_list.get("htmlExtract")
            if (
                len(raw_items) == 1
                and isinstance(raw_items[0], str)
                and isinstance(html_extract, dict)
            ):
                html_items = extract_html_items(
                    raw_items[0],
                    {
                        "listSelector": html_extract.get("itemSelector", ""),
                        "titleSelector": html_extract.get("titleSelector", ""),
                        "linkSelector": html_extract.get("urlSelector", ""),
                    },
                )
                if html_items:
                    return html_items

            valid = []
            for item in raw_items:
                if isinstance(item, dict):
                    if _item_has_content(item):
                        valid.append(item)
                elif item is not None and str(item).strip():
                    valid.append(item)
            if valid:
                return valid
        if candidate_paths:
            if _recipe_uses_quickjs(recipe) or "__next_f" in (body_text or "") or "eval(function(p,a,c,k" in (body_text or "").lower():
                rsc_items = _extract_items_from_rsc_or_packer(recipe, body_text)
                if rsc_items:
                    return rsc_items
            return []
    html_items = extract_html_items(body_text, selectors)
    if len(html_items) < MIN_SMOKE_ITEMS and (
        _recipe_uses_quickjs(recipe) or "__next_f" in (body_text or "") or "eval(function(p,a,c,k" in (body_text or "").lower()
    ):
        rsc_items = _extract_items_from_rsc_or_packer(recipe, body_text)
        if len(rsc_items) > len(html_items):
            return rsc_items
    return html_items


CANDIDATE_CHAPTER_SELECTORS = [
    "div.chapter-list-full a.chapter-link",
    "a.chapter-link",
    "ul.wp-manga-chapter li a",
    "li.wp-manga-chapter a",
    "div.eph-num a",
    "ul.clstyle li a",
    "div.listing-chapters_wrap a",
    "div.chapter-list a",
    "ul.chapters li a",
    "div.list-chapter a",
    "div#chapterlist li a",
]

_NON_CHAPTER_PATH_TOKENS = (
    "/genre/",
    "/genres/",
    "/genero/",
    "/generos/",
    "/tag/",
    "/tags/",
    "/category/",
    "/categories/",
    "/categoria/",
    "/author/",
    "/artist/",
    "/login",
    "/register",
    "/signup",
    "/logout",
    "/account",
    "/profile",
    "/search",
    "/wp-login",
    "/wp-admin",
    "/dmca",
    "/privacy",
    "/terms",
    "/contact",
)
_NON_CHAPTER_TAIL_RE = re.compile(
    r"/(?:genre|genres|genero|generos|tag|tags|category|categories|categoria|login|register|search|manga|series|comics|latest|home)/?$",
    re.I,
)
_SINGLE_BUTTON_CH_RE = re.compile(
    r"^\s*(?:ultimo|último|primer|primero|empezar|comenzar|leer\s+(?:primero|último|ultimo)|first\s+chapter|latest\s+chapter|read\s+now)\b",
    re.I,
)


def _first_json_scalar(obj, expr):
    if not expr or obj is None:
        return ""
    vals = extract_json_path(obj, expr)
    for v in vals:
        if isinstance(v, (str, int, float)) and not isinstance(v, bool):
            s = str(v).strip()
            if s:
                return s
    return ""


def _extract_hid_for_smoke(raw_url):
    clean = str(raw_url or "").split("?")[0].split("#")[0].rstrip("/")
    last_part = clean.rsplit("/", 1)[-1]
    if "." in last_part:
        return last_part.rsplit(".", 1)[-1]
    if "-" in last_part:
        return last_part.split("-", 1)[0]
    return last_part


def _extract_manga_vars_for_smoke(raw_url, default_org, lang, base_url):
    clean = str(raw_url or "").split("?")[0].split("#")[0].rstrip("/")
    clean_base = str(base_url or "").rstrip("/")
    if clean.lower().startswith(clean_base.lower()):
        path_only = clean[len(clean_base) :]
    elif "://" in clean:
        after_scheme = clean.split("://", 1)[1]
        path_only = "/" + after_scheme.split("/", 1)[1] if "/" in after_scheme else ""
    else:
        path_only = clean
    parts = [p for p in path_only.strip("/").split("/") if p]
    fallback_org = str(default_org or "").strip()
    if "manhwa" in parts and parts.index("manhwa") + 1 < len(parts):
        slug, org = parts[-1], fallback_org
    elif len(parts) >= 3 and parts[1] == "manga":
        slug, org = parts[2], parts[0]
    elif len(parts) >= 2 and parts[0] == "series":
        last = parts[-1]
        slug, org = (last[6:] if last.startswith("comic-") else last), fallback_org
    elif len(parts) >= 2 and parts[0] == "title":
        slug, org = parts[-1], fallback_org
    elif len(parts) == 2:
        slug, org = parts[0], parts[1]
    elif len(parts) == 1:
        slug, org = parts[0], fallback_org
    else:
        slug, org = "", fallback_org
    hid = _extract_hid_for_smoke(clean)
    return {
        "{url}": clean,
        "{mangaUrl}": clean,
        "{slug}": slug,
        "{org}": org,
        "{id}": hid,
        "{hid}": hid,
        "{lang}": str(lang or "es"),
        "{baseUrl}": clean_base,
    }


def extract_sample_manga_urls(recipe, body_text, limit=2):
    """Extract up to `limit` SSRF-safe absolute manga URLs from a catalog listing payload."""
    if not isinstance(recipe, dict) or not body_text or limit <= 0:
        return []
    base_url = str(recipe.get("baseUrl") or "").rstrip("/")
    if not base_url:
        return []

    raw_candidates = []
    preset = recipe.get("preset", "CSS_GENERIC")
    family = recipe.get("family") or "STANDARD"
    selectors = recipe.get("selectors") or {}
    list_sel = selectors.get("listSelector", "")
    link_sel = selectors.get("linkSelector", "")

    if family == "INERTIA_SSR" and isinstance(recipe.get("inertia"), dict):
        inertia = recipe["inertia"]
        raw_json = _extract_inertia_json(body_text, inertia.get("scriptSelector") or "script[data-page]")
        series_path = inertia.get("seriesListPath") or ""
        if raw_json and series_path:
            for it in extract_json_path(raw_json, series_path):
                if isinstance(it, dict):
                    cand = it.get("url") or it.get("href") or it.get("link") or it.get("slug")
                    if cand:
                        raw_candidates.append(str(cand).strip())
    elif preset == "JSON_API":
        json_api = recipe.get("jsonApi") if isinstance(recipe.get("jsonApi"), dict) else {}
        manga_list = json_api.get("mangaList") if isinstance(json_api.get("mangaList"), dict) else {}
        raw_lang = str(recipe.get("lang") or "es")
        lang_map = json_api.get("langMap") if isinstance(json_api.get("langMap"), dict) else {}
        mapped_lang = lang_map.get(raw_lang)
        if mapped_lang is None:
            mapped_lang = next((v for k, v in lang_map.items() if str(k).lower() == raw_lang.lower()), raw_lang)
        default_org = str(json_api.get("defaultOrg") or "")
        url_tpl = manga_list.get("urlTemplate") or ""
        for item in extract_items_for_smoke(recipe, body_text):
            if not isinstance(item, dict):
                continue
            if item.get("link"):
                raw_candidates.append(str(item["link"]).strip())
                continue
            slug_val = _first_json_scalar(item, manga_list.get("slugPath")) or str(item.get("slug") or "").strip()
            id_val = _first_json_scalar(item, manga_list.get("idPath")) or str(item.get("id") or item.get("hid") or "").strip()
            org_val = _first_json_scalar(item, manga_list.get("orgPath")) or default_org
            direct_url = (
                _first_json_scalar(item, manga_list.get("urlPath"))
                or _first_json_scalar(item, "$.url")
                or _first_json_scalar(item, "$.href")
                or _first_json_scalar(item, "$.link")
            )
            resolved = ""
            if url_tpl:
                if "{slug}" in url_tpl and "{id}" in url_tpl and not slug_val and not id_val:
                    continue
                if "{slug}" in url_tpl and "{id}" not in url_tpl and not slug_val:
                    continue
                built = _apply_smoke_placeholders(
                    url_tpl,
                    {
                        "{slug}": slug_val,
                        "{org}": org_val,
                        "{id}": id_val,
                        "{hid}": id_val,
                        "{url}": direct_url,
                        "{lang}": str(mapped_lang),
                        "{baseUrl}": base_url,
                    },
                )
                resolved = built.rstrip("-") if not slug_val else built
            elif direct_url:
                resolved = direct_url
            elif slug_val:
                resolved = slug_val
            if resolved:
                raw_candidates.append(resolved)
    else:
        if BeautifulSoup is not None and list_sel:
            soup = BeautifulSoup(body_text, "html.parser")
            for node in soup.select(list_sel):
                if node.find_parent(["header", "nav", "footer", "aside"]) is not None:
                    continue
                link_node = node.select_one(link_sel) if link_sel else (node if node.name == "a" else node.find("a"))
                if link_node is None and node.name == "a":
                    link_node = node
                if link_node is not None and link_node.has_attr("href"):
                    href = str(link_node["href"]).strip()
                    if href:
                        raw_candidates.append(href)
        elif list_sel:
            dom = parse_stdlib_dom(body_text)
            for node in dom.select(list_sel):
                if node.find_parent(["header", "nav", "footer", "aside"]) is not None:
                    continue
                link_node = node.select_one(link_sel) if link_sel else (node if node.tag == "a" else node.select_one("a"))
                if link_node is None and node.tag == "a":
                    link_node = node
                if link_node is not None and link_node.has_attr("href"):
                    href = str(link_node.get("href") or "").strip()
                    if href:
                        raw_candidates.append(href)
        if not raw_candidates:
            for item in extract_items_for_smoke(recipe, body_text):
                if isinstance(item, dict):
                    cand = item.get("link") or item.get("url") or item.get("href") or item.get("slug")
                    if cand:
                        raw_candidates.append(str(cand).strip())

    clean_urls = []
    seen = set()
    base_norm = base_url.rstrip("/")
    for href in raw_candidates:
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        abs_url = urljoin(base_norm + "/", href)
        if abs_url.rstrip("/") == base_norm:
            continue
        if not validate_ssrf(abs_url)[0]:
            continue
        if abs_url not in seen:
            seen.add(abs_url)
            clean_urls.append(abs_url)
            if len(clean_urls) >= limit:
                break
    return clean_urls


def _is_clean_chapter_href(href, manga_url, anchor_node=None):
    if anchor_node is not None and anchor_node.find_parent(["header", "nav", "footer", "aside"]) is not None:
        return None
    raw = str(href or "").strip()
    if not raw or raw.startswith(("#", "javascript:", "mailto:", "tel:")):
        return None
    abs_url = urljoin(manga_url, raw)
    if not validate_ssrf(abs_url)[0]:
        return None

    manga_parsed = urlparse(manga_url)
    cand_parsed = urlparse(abs_url)
    if manga_parsed.netloc and normalize_domain(abs_url) != normalize_domain(manga_url):
        return None

    path_low = cand_parsed.path.lower()
    if any(tok in path_low for tok in _NON_CHAPTER_PATH_TOKENS):
        return None
    if _NON_CHAPTER_TAIL_RE.search(path_low):
        return None

    manga_path = manga_parsed.path.rstrip("/").lower()
    cand_path = path_low.rstrip("/")
    if cand_path == manga_path or not cand_path:
        q_keys = {k.lower() for k, _ in parse_qsl(cand_parsed.query)}
        if not (q_keys & {"ch", "chapter", "cap", "c", "ep", "episode"}):
            return None
    return abs_url


def _extract_clean_chapter_links(html_text, css_selector, manga_url):
    if not html_text or not css_selector:
        return []
    chapters = []
    seen = set()
    if BeautifulSoup is not None:
        soup = BeautifulSoup(html_text, "html.parser")
        for node in soup.select(css_selector):
            if node.find_parent(["header", "nav", "footer", "aside"]) is not None:
                continue
            link_node = node if node.name == "a" else node.select_one("a[href]")
            if link_node is None or not link_node.has_attr("href"):
                continue
            clean_url = _is_clean_chapter_href(link_node["href"], manga_url, anchor_node=link_node)
            if not clean_url or clean_url in seen:
                continue
            name = (link_node.get_text(" ", strip=True) or node.get_text(" ", strip=True) or str(link_node.get("title") or "")).strip()
            seen.add(clean_url)
            chapters.append({"name": name or clean_url.rsplit("/", 1)[-1], "url": clean_url})
    else:
        dom = parse_stdlib_dom(html_text)
        for node in dom.select(css_selector):
            if node.find_parent(["header", "nav", "footer", "aside"]) is not None:
                continue
            link_node = node if node.tag == "a" else node.select_one("a[href]")
            if link_node is None or not link_node.has_attr("href"):
                continue
            clean_url = _is_clean_chapter_href(link_node["href"], manga_url, anchor_node=link_node)
            if not clean_url or clean_url in seen:
                continue
            name = (link_node.get_text(" ", strip=True) or node.get_text(" ", strip=True) or str(link_node.get("title") or "")).strip()
            seen.add(clean_url)
            chapters.append({"name": name or clean_url.rsplit("/", 1)[-1], "url": clean_url})
    return chapters


def extract_chapters_for_smoke(recipe, manga_body_text, manga_url):
    """Extract clean chapter items from HTML or JSON_API chapter/detail payloads."""
    if not isinstance(recipe, dict) or not manga_body_text:
        return []
    preset = recipe.get("preset", "CSS_GENERIC")
    selectors = recipe.get("selectors") or {}

    if preset == "JSON_API":
        json_api = recipe.get("jsonApi") if isinstance(recipe.get("jsonApi"), dict) else {}
        ch_spec = json_api.get("chapters") if isinstance(json_api.get("chapters"), dict) else {}
        items_path = ch_spec.get("itemsPath") or ""
        if isinstance(ch_spec.get("htmlExtract"), dict) and items_path:
            html_sel = ch_spec["htmlExtract"].get("urlSelector") or "a[href]"
            out = []
            for chunk in extract_json_path(manga_body_text, items_path):
                if isinstance(chunk, str) and "<" in chunk:
                    out.extend(_extract_clean_chapter_links(chunk, html_sel, manga_url))
            if out:
                return out
        if items_path:
            out = []
            for item in extract_json_path(manga_body_text, items_path):
                if isinstance(item, dict):
                    has_ch = any(
                        _first_json_scalar(item, p)
                        for p in (ch_spec.get("idPath"), ch_spec.get("urlPath"), ch_spec.get("numberPath"), ch_spec.get("namePath"))
                        if p
                    ) or any(v is not None and str(v).strip() for v in item.values())
                    if has_ch:
                        label = _first_json_scalar(item, ch_spec.get("namePath")) or _first_json_scalar(item, ch_spec.get("numberPath")) or "Chapter"
                        ch_u = _first_json_scalar(item, ch_spec.get("urlPath")) or _first_json_scalar(item, ch_spec.get("idPath")) or ""
                        out.append({"name": label, "url": ch_u})
                elif item is not None and str(item).strip():
                    out.append({"name": str(item).strip(), "url": str(item).strip()})
            if out:
                return out
        if not manga_body_text.lstrip().startswith("<"):
            return []

    ch_sel = (selectors.get("chapterSelector") or PRESET_DEFAULT_SELECTORS.get(preset, {}).get("chapterSelector") or "li a, div.chapter-item a").strip()
    return _extract_clean_chapter_links(manga_body_text, ch_sel, manga_url)


def detect_chapter_selector_in_html(manga_html, manga_url):
    """Find the most specific clean chapter CSS selector on a 200 HTML manga page."""
    if not manga_html or not manga_url:
        return None
    single_candidates = []
    for sel in CANDIDATE_CHAPTER_SELECTORS:
        matches = _extract_clean_chapter_links(manga_html, sel, manga_url)
        if len(matches) >= 2:
            return sel
        if len(matches) == 1:
            single_candidates.append((sel, matches[0]))
    for sel, single_item in single_candidates:
        if not _SINGLE_BUTTON_CH_RE.match(single_item.get("name") or ""):
            return sel
    return single_candidates[0][0] if single_candidates else None


def probe_chapters_for_recipe(recipe, list_body_text, fetcher=None, timeout=10, auto_fix_selector=False):
    """Probe up to 2 sample manga pages for >=1 chapter; detect Cloudflare and optionally auto-fix CSS_GENERIC chapterSelector."""
    sample_urls = extract_sample_manga_urls(recipe, list_body_text, limit=2)
    if not sample_urls:
        return {
            "ok": False,
            "category": "NEEDS_PRIMITIVE",
            "subReason": "CHAPTERS_EMPTY",
            "chaptersFound": 0,
            "sampleMangaUrl": None,
            "detectedSelector": None,
            "detail": "Listado OK pero no se pudieron resolver URLs de manga para sondear capítulos",
        }

    base_url = str(recipe.get("baseUrl") or "").rstrip("/")
    base_headers = dict(recipe.get("headers") or {})
    preset = recipe.get("preset", "CSS_GENERIC")
    query_signer = recipe.get("querySigner") if isinstance(recipe.get("querySigner"), dict) else None
    smoke_max_bytes = min(MAX_HTML_BYTES, max(524288, int(recipe.get("maxHtmlBytes") or 524288)))

    waf_hit = None
    empty_200_url = None
    suggested_selector = None
    last_err = None

    for manga_url in sample_urls:
        req_url = manga_url
        req_method = "GET"
        req_headers = dict(base_headers)
        req_headers.setdefault("Referer", f"{base_url}/")
        req_body = None

        if preset == "JSON_API":
            json_api = recipe.get("jsonApi") if isinstance(recipe.get("jsonApi"), dict) else {}
            api_base = str(json_api.get("apiBaseUrl") or base_url).rstrip("/")
            raw_lang = str(recipe.get("lang") or "es")
            lang_map = json_api.get("langMap") if isinstance(json_api.get("langMap"), dict) else {}
            mapped_lang = lang_map.get(raw_lang)
            if mapped_lang is None:
                mapped_lang = next((v for k, v in lang_map.items() if str(k).lower() == raw_lang.lower()), raw_lang)
            m_vars = _extract_manga_vars_for_smoke(manga_url, json_api.get("defaultOrg"), mapped_lang, base_url)
            m_vars.update({"{apiBaseUrl}": api_base, "{page}": "1", "{offset}": "0"})

            ch_req = json_api.get("chaptersRequest")
            det_req = json_api.get("detailsRequest")
            if isinstance(ch_req, dict) and ("{id}" in str(ch_req.get("pathTemplate") or "") or "{hid}" in str(ch_req.get("pathTemplate") or "")):
                if not m_vars["{id}"] and isinstance(det_req, dict):
                    det_path = _apply_smoke_placeholders(det_req.get("pathTemplate") or "", m_vars)
                    det_url = det_path if det_path.startswith(("http://", "https://")) else f"{api_base}/{det_path.lstrip('/')}"
                    if query_signer:
                        det_url, ds_hdrs = _compute_query_signer_parts(det_url, query_signer, method=det_req.get("method") or "GET")
                    else:
                        ds_hdrs = {}
                    det_probe = _invoke_fetcher(fetcher, det_url, str(det_req.get("method") or "GET").upper(), {**req_headers, **ds_hdrs}, None, timeout, max_bytes=smoke_max_bytes)
                    if 200 <= int(det_probe.get("status_code") or 0) < 400:
                        det_spec = json_api.get("details") if isinstance(json_api.get("details"), dict) else {}
                        id_expr = det_spec.get("idPath") or "$..id"
                        found_id = _first_json_scalar(det_probe.get("body") or "", id_expr)
                        if found_id:
                            m_vars["{id}"] = found_id
                            m_vars["{hid}"] = found_id

            target_req = ch_req if isinstance(ch_req, dict) else (det_req if isinstance(det_req, dict) else None)
            if isinstance(target_req, dict):
                raw_p = target_req.get("pathTemplate") or ""
                resolved_p = _apply_smoke_placeholders(raw_p, m_vars)
                req_url = resolved_p if resolved_p.startswith(("http://", "https://")) else f"{api_base}/{resolved_p.lstrip('/')}"
                req_method = str(target_req.get("method") or "GET").upper()
                for hk, hv in (target_req.get("headers") or {}).items():
                    req_headers[hk] = _apply_smoke_placeholders(hv, m_vars)
                if target_req.get("contentType"):
                    req_headers.setdefault("Content-Type", str(target_req["contentType"]))
                if target_req.get("graphqlQuery"):
                    gql_v_raw = _apply_smoke_placeholders(target_req.get("graphqlVariablesTemplate") or "{}", m_vars)
                    try:
                        gql_v = json.loads(gql_v_raw)
                    except Exception:
                        gql_v = {}
                    req_body = json.dumps({"query": target_req["graphqlQuery"], "variables": gql_v})
                elif target_req.get("bodyTemplate"):
                    req_body = _apply_smoke_placeholders(target_req["bodyTemplate"], m_vars)

        if query_signer:
            req_url, signer_hdrs = _compute_query_signer_parts(req_url, query_signer, method=req_method)
            req_headers.update(signer_hdrs)

        if not validate_ssrf(req_url)[0]:
            continue

        probe = _invoke_fetcher(fetcher, req_url, req_method, req_headers, req_body, timeout, max_bytes=smoke_max_bytes)
        status = int(probe.get("status_code") or 0)
        body = probe.get("body") or ""
        headers = probe.get("headers") or {}

        is_waf, waf_reason = detect_waf_block(status, headers=headers, body=body)
        cf_mitigated = str(headers.get("cf-mitigated") or "").strip().lower() == "challenge"
        # Passive Cloudflare JS detection (`jsd/main.js`) can appear inside real HTTP 200 manga pages;
        # still check for real chapters on 200..399 non-mitigated HTML, falling back to CLOUDFLARE_ANTIBOT if none exist.
        if is_waf and (status >= 400 or status < 200 or cf_mitigated):
            if waf_hit is None:
                waf_hit = (waf_reason, status, manga_url)
            continue

        if 200 <= status < 400:
            chapters = extract_chapters_for_smoke(recipe, body, manga_url)
            if not chapters and preset == "MADARA" and not is_waf:
                ajax_url = f"{manga_url.rstrip('/')}/ajax/chapters/"
                if validate_ssrf(ajax_url)[0]:
                    ajax_hdrs = {**req_headers, "Referer": manga_url, "X-Requested-With": "XMLHttpRequest"}
                    ajax_probe = _invoke_fetcher(fetcher, ajax_url, "POST", ajax_hdrs, None, timeout, max_bytes=smoke_max_bytes)
                    ajax_st = int(ajax_probe.get("status_code") or 0)
                    ajax_body = ajax_probe.get("body") or ""
                    ajax_waf, ajax_waf_reason = detect_waf_block(ajax_st, headers=ajax_probe.get("headers") or {}, body=ajax_body)
                    if ajax_waf:
                        if waf_hit is None:
                            waf_hit = (ajax_waf_reason, ajax_st, manga_url)
                        continue
                    if 200 <= ajax_st < 400:
                        chapters = extract_chapters_for_smoke(recipe, ajax_body, manga_url)

            if len(chapters) >= 1:
                return {
                    "ok": True,
                    "status": "OK_CHAPTERS",
                    "chaptersFound": len(chapters),
                    "sampleMangaUrl": manga_url,
                    "detectedSelector": None,
                    "detail": f"OK_CHAPTERS ({len(chapters)} capítulos)",
                }

            detected_candidate = detect_chapter_selector_in_html(body, manga_url) if preset == "CSS_GENERIC" else None
            if is_waf and not detected_candidate:
                if waf_hit is None:
                    waf_hit = (waf_reason, status, manga_url)
                continue

            if empty_200_url is None:
                empty_200_url = manga_url
                if not auto_fix_selector and preset == "CSS_GENERIC":
                    suggested_selector = detected_candidate

            if auto_fix_selector and preset == "CSS_GENERIC" and detected_candidate:
                recipe.setdefault("selectors", {})["chapterSelector"] = detected_candidate
                fixed_chapters = extract_chapters_for_smoke(recipe, body, manga_url)
                if len(fixed_chapters) >= 1:
                    return {
                        "ok": True,
                        "status": "OK_CHAPTERS_AUTODETECTED",
                        "chaptersFound": len(fixed_chapters),
                        "sampleMangaUrl": manga_url,
                        "detectedSelector": detected_candidate,
                        "detail": f"OK_CHAPTERS_AUTODETECTED ({len(fixed_chapters)} capítulos con '{detected_candidate}')",
                    }
        else:
            last_err = (status, probe.get("message") or f"HTTP {status}", manga_url)

    if empty_200_url is not None:
        detail_msg = "Listado OK pero 0 capítulos detectados (selector/endpoint de capítulos roto)"
        if suggested_selector:
            detail_msg += f" [auto-fix disponible: {suggested_selector}]"
        return {
            "ok": False,
            "category": "NEEDS_PRIMITIVE",
            "subReason": "CHAPTERS_EMPTY",
            "chaptersFound": 0,
            "sampleMangaUrl": empty_200_url,
            "detectedSelector": None,
            "suggestedSelector": suggested_selector,
            "detail": detail_msg,
        }

    if waf_hit is not None:
        waf_reason, status, manga_url = waf_hit
        return {
            "ok": False,
            "category": "CLOUDFLARE_ANTIBOT",
            "subReason": waf_reason,
            "httpStatus": status,
            "chaptersFound": 0,
            "sampleMangaUrl": manga_url,
            "detectedSelector": None,
            "detail": f"Cloudflare/WAF en página de capítulos ({waf_reason})",
        }

    err_st, err_msg, err_url = last_err or (0, "NETWORK_ERROR", sample_urls[0])
    return {
        "ok": False,
        "category": "DOWN_OR_NONEXISTENT",
        "subReason": classify_down_reason(err_st, err_msg, ""),
        "httpStatus": err_st,
        "chaptersFound": 0,
        "sampleMangaUrl": err_url,
        "detectedSelector": None,
        "detail": f"Error obteniendo capítulos ({err_msg})",
    }


def _invoke_fetcher(fetcher, url, method, req_headers, req_body, timeout, max_bytes=524288):
    if fetcher is None:
        return probe_http_sample_detailed(
            url,
            timeout=timeout,
            method=method,
            headers=req_headers,
            body=req_body,
            max_bytes=max_bytes,
        )
    try:
        try:
            res = fetcher(url, method=method, headers=req_headers, body=req_body)
        except TypeError:
            res = fetcher(url)
    except urllib.error.URLError as exc:
        return {
            "status_code": 0,
            "body": "",
            "message": str(exc),
            "final_url": url,
            "redirect_chain": [],
            "headers": {},
            "error_type": "NETWORK_ERROR",
        }

    if isinstance(res, dict):
        res.setdefault("final_url", url)
        res.setdefault("headers", {})
        res.setdefault("redirect_chain", [])
        res.setdefault("error_type", None)
        return res
    if isinstance(res, tuple) and len(res) >= 4:
        return {
            "status_code": res[0],
            "body": res[1],
            "message": res[2],
            "final_url": res[3] or url,
            "redirect_chain": [(url, 302, res[3])] if res[3] and res[3] != url else [],
            "headers": res[4] if len(res) >= 5 and isinstance(res[4], dict) else {},
            "error_type": None,
        }
    return {
        "status_code": res[0],
        "body": res[1],
        "message": res[2],
        "final_url": url,
        "redirect_chain": [],
        "headers": {},
        "error_type": None,
    }


def _adopt_domain_updates(recipe, old_base, new_base):
    cloned = copy.deepcopy(recipe)
    cloned["baseUrl"] = new_base
    update_referer_in_recipe(cloned, old_base, new_base)
    mirrors = [new_base]
    for m in [old_base] + list(cloned.get("mirrors") or []):
        m_clean = str(m).rstrip("/")
        if m_clean and m_clean not in mirrors and validate_ssrf(m_clean)[0]:
            mirrors.append(m_clean)
    updates = {
        "baseUrl": new_base,
        "headers": cloned.get("headers") or {"Referer": f"{new_base}/"},
        "pipelineSteps": cloned.get("pipelineSteps") or [{"op": "referer_bind", "refererUrl": f"{new_base}/"}],
        "mirrors": mirrors,
        "status": "ACTIVE",
    }
    return cloned, updates


def run_http_smoke_test(
    recipe,
    fetcher=None,
    timeout=10,
    is_existing_active=False,
    allow_redirect_adopt=True,
    return_details=False,
    include_cloudflare=False,
    probe_chapters=False,
    auto_fix_chapters=False,
):
    """Verify source responds cleanly and yields >= 3 valid items, with redirect auto-adoption."""
    if recipe.get("curated") is True:
        auto_fix_chapters = False
    smoke_requests = build_smoke_requests(recipe)
    orig_base = recipe["baseUrl"].rstrip("/")
    orig_domain = normalize_domain(orig_base)

    last_probe = {
        "status_code": 0,
        "body": "",
        "message": "",
        "final_url": orig_base,
        "headers": {},
        "redirect_chain": [],
        "error_type": None,
    }
    redirected_candidate = None

    smoke_max_bytes = min(MAX_HTML_BYTES, max(524288, int(recipe.get("maxHtmlBytes") or 524288)))
    for url, method, req_headers, req_body in smoke_requests:
        probe = _invoke_fetcher(fetcher, url, method, req_headers, req_body, timeout, max_bytes=smoke_max_bytes)
        last_probe = probe
        status_code = int(probe.get("status_code") or 0)
        body_text = probe.get("body") or ""
        final_url = probe.get("final_url") or url
        req_domain = normalize_domain(url)
        final_domain = normalize_domain(final_url)

        if allow_redirect_adopt and final_domain and req_domain and final_domain != req_domain and req_domain == orig_domain:
            parsed_final = urlparse(final_url)
            final_base = f"{parsed_final.scheme.lower()}://{parsed_final.netloc.lower()}".rstrip("/")
            if redirected_candidate is None:
                redirected_candidate = (final_base, probe)
            continue

        if 200 <= status_code < 400:
            body_lower = body_text.lower()
            if any(marker in body_lower for marker in OFFICIAL_CLOSURE_MARKERS):
                details = {
                    "category": "DOWN_OR_NONEXISTENT",
                    "subReason": "OFFICIAL_CLOSURE",
                    "httpStatus": status_code,
                    "headers": probe.get("headers") or {},
                    "bodySample": body_text[:4096],
                    "finalUrl": final_url,
                    "domainChanged": False,
                    "domainAdopted": False,
                }
                res = (False, 0, "OFFICIAL_CLOSURE_NOTICE", {"status": "DISABLED"})
                return (*res, details) if return_details else res

            items = extract_items_for_smoke(recipe, body_text)
            if len(items) >= MIN_SMOKE_ITEMS:
                if not is_existing_active and not recipe.get("curated"):
                    non_empty_titles = [
                        str(it.get("title", "")).strip()
                        for it in items
                        if isinstance(it, dict) and str(it.get("title", "")).strip()
                    ]
                    junk_count = sum(1 for t in non_empty_titles if _is_junk_smoke_title(t))
                    distinct_titles = {t.lower() for t in non_empty_titles}
                    if non_empty_titles and (
                        (junk_count / len(non_empty_titles) > 0.5)
                        or (len(non_empty_titles) >= 4 and len(distinct_titles) < 2)
                    ):
                        details = {
                            "category": "NEEDS_PRIMITIVE",
                            "subReason": "JUNK_OR_DUP_TITLES",
                            "httpStatus": status_code,
                            "headers": probe.get("headers") or {},
                            "bodySample": body_text[:4096],
                            "finalUrl": final_url,
                            "domainChanged": False,
                            "domainAdopted": False,
                            "itemsFound": len(items),
                        }
                        res = (False, len(items), "JUNK_OR_DUP_TITLES", {"status": "DRAFT"})
                        return (*res, details) if return_details else res
                if probe_chapters:
                    ch_res = probe_chapters_for_recipe(
                        recipe,
                        body_text,
                        fetcher=fetcher,
                        timeout=timeout,
                        auto_fix_selector=auto_fix_chapters,
                    )
                    if ch_res.get("ok"):
                        updates = {"status": "ACTIVE"}
                        if ch_res.get("detectedSelector") and isinstance(recipe.get("selectors"), dict):
                            updates["selectors"] = copy.deepcopy(recipe["selectors"])
                        details = {
                            "category": "VIABLE",
                            "subReason": ch_res.get("status") or "OK",
                            "httpStatus": status_code,
                            "headers": probe.get("headers") or {},
                            "bodySample": body_text[:4096],
                            "finalUrl": final_url,
                            "domainChanged": False,
                            "domainAdopted": False,
                            "itemsFound": len(items),
                            "chaptersFound": ch_res.get("chaptersFound", 0),
                            "sampleMangaUrl": ch_res.get("sampleMangaUrl"),
                            "detectedChapterSelector": ch_res.get("detectedSelector"),
                        }
                        ok_msg = f"OK ({len(items)} items, {ch_res.get('chaptersFound', 0)} chapters)"
                        if ch_res.get("detectedSelector"):
                            ok_msg += f" [chapterSelector={ch_res['detectedSelector']}]"
                        res = (True, len(items), ok_msg, updates)
                        return (*res, details) if return_details else res
                    if ch_res.get("category") == "CLOUDFLARE_ANTIBOT":
                        if include_cloudflare and recipe.get("preset") in ALLOWED_PRESETS:
                            cf_upd = {
                                "status": "ACTIVE",
                                "requiresCloudflareBypass": True,
                                "requiresWebViewCapture": False,
                            }
                            details = {
                                "category": "CLOUDFLARE_ANTIBOT",
                                "subReason": ch_res.get("subReason"),
                                "httpStatus": ch_res.get("httpStatus", status_code),
                                "headers": probe.get("headers") or {},
                                "bodySample": body_text[:4096],
                                "finalUrl": ch_res.get("sampleMangaUrl") or final_url,
                                "domainChanged": False,
                                "domainAdopted": False,
                                "itemsFound": len(items),
                                "requiresCloudflareBypass": True,
                            }
                            res = (True, len(items), f"CLOUDFLARE_CHAPTERS_ACCEPTED ({ch_res.get('subReason')})", cf_upd)
                            return (*res, details) if return_details else res
                        details = {
                            "category": "CLOUDFLARE_ANTIBOT",
                            "subReason": ch_res.get("subReason"),
                            "httpStatus": ch_res.get("httpStatus", status_code),
                            "headers": probe.get("headers") or {},
                            "bodySample": body_text[:4096],
                            "finalUrl": ch_res.get("sampleMangaUrl") or final_url,
                            "domainChanged": False,
                            "domainAdopted": False,
                            "itemsFound": len(items),
                        }
                        res = (False, len(items), ch_res.get("detail") or "CLOUDFLARE_CHAPTERS", {"status": "QUARANTINED" if is_existing_active else "DRAFT"})
                        return (*res, details) if return_details else res
                    new_status = "DISABLED" if is_existing_active else "DRAFT"
                    ch_cat = ch_res.get("category") or "NEEDS_PRIMITIVE"
                    ch_sub = ch_res.get("subReason") or "CHAPTERS_EMPTY"
                    details = {
                        "category": ch_cat,
                        "subReason": ch_sub,
                        "primaryCapability": "CHAPTERS_EMPTY" if ch_sub == "CHAPTERS_EMPTY" else None,
                        "allCapabilities": ["CHAPTERS_EMPTY"] if ch_sub == "CHAPTERS_EMPTY" else None,
                        "httpStatus": ch_res.get("httpStatus", status_code),
                        "headers": probe.get("headers") or {},
                        "bodySample": body_text[:4096],
                        "finalUrl": ch_res.get("sampleMangaUrl") or final_url,
                        "domainChanged": False,
                        "domainAdopted": False,
                        "itemsFound": len(items),
                        "chaptersFound": 0,
                        "sampleMangaUrl": ch_res.get("sampleMangaUrl"),
                        "detail": ch_res.get("detail"),
                    }
                    res = (False, len(items), ch_res.get("detail") or ch_sub, {"status": new_status})
                    return (*res, details) if return_details else res
                details = {
                    "category": "VIABLE",
                    "subReason": "OK",
                    "httpStatus": status_code,
                    "headers": probe.get("headers") or {},
                    "bodySample": body_text[:4096],
                    "finalUrl": final_url,
                    "domainChanged": False,
                    "domainAdopted": False,
                    "itemsFound": len(items),
                }
                res = (True, len(items), f"OK ({len(items)} items)", {"status": "ACTIVE"})
                return (*res, details) if return_details else res

    # If a cross-domain redirect occurred, validate SSRF and run live smoke test against destination
    if allow_redirect_adopt and redirected_candidate is not None:
        final_base, redir_probe = redirected_candidate
        ok_ssrf, err_ssrf = validate_ssrf(final_base)
        if not ok_ssrf:
            new_status = "DISABLED" if is_existing_active else "DRAFT"
            details = {
                "category": "DOMAIN_CHANGE_FAILED",
                "subReason": f"SSRF_REJECTED ({err_ssrf})",
                "httpStatus": int(redir_probe.get("status_code") or 0),
                "headers": redir_probe.get("headers") or {},
                "bodySample": (redir_probe.get("body") or "")[:4096],
                "finalUrl": final_base,
                "domainChanged": True,
                "domainAdopted": False,
                "domainChangeFailed": True,
                "redirectedFrom": orig_base,
                "redirectedTo": final_base,
            }
            res = (False, 0, f"DOMAIN_CHANGE_FAILED ({orig_base} -> {final_base}: SSRF {err_ssrf})", {"status": new_status})
            return (*res, details) if return_details else res

        cloned_recipe, adopted_updates = _adopt_domain_updates(recipe, orig_base, final_base)
        dest_ok, dest_count, dest_msg, dest_upd, dest_details = run_http_smoke_test(
            cloned_recipe,
            fetcher=fetcher,
            timeout=timeout,
            is_existing_active=is_existing_active,
            allow_redirect_adopt=False,
            return_details=True,
            include_cloudflare=include_cloudflare,
            probe_chapters=probe_chapters,
            auto_fix_chapters=auto_fix_chapters,
        )
        is_cf_dest = bool(dest_details.get("category") == "CLOUDFLARE_ANTIBOT")
        is_compatible = bool(recipe.get("preset") in ALLOWED_PRESETS)
        if dest_ok or (include_cloudflare and is_cf_dest and is_compatible):
            if is_existing_active or recipe.get("version"):
                adopted_updates["version"] = int(recipe.get("version", 1)) + 1
            if include_cloudflare and is_cf_dest:
                adopted_updates["status"] = "ACTIVE"
                adopted_updates["requiresCloudflareBypass"] = True
                adopted_updates["requiresWebViewCapture"] = False
                details = {
                    "category": "VIABLE",
                    "subReason": "DOMAIN_AUTO_ADOPTED_CLOUDFLARE",
                    "httpStatus": dest_details.get("httpStatus", 200),
                    "headers": dest_details.get("headers") or {},
                    "bodySample": dest_details.get("bodySample", ""),
                    "finalUrl": final_base,
                    "domainChanged": True,
                    "domainAdopted": True,
                    "redirectedFrom": orig_base,
                    "redirectedTo": final_base,
                    "itemsFound": dest_count,
                    "requiresCloudflareBypass": True,
                }
                res = (
                    True,
                    dest_count,
                    f"OK_REDIRECTED_CLOUDFLARE ({orig_base} -> {final_base})",
                    adopted_updates,
                )
                return (*res, details) if return_details else res
            adopted_updates.update(dest_upd)
            if dest_upd.get("requiresCloudflareBypass"):
                adopted_updates["requiresCloudflareBypass"] = True
                adopted_updates["requiresWebViewCapture"] = False
            details = {
                "category": "VIABLE",
                "subReason": "DOMAIN_AUTO_ADOPTED",
                "httpStatus": dest_details.get("httpStatus", 200),
                "headers": dest_details.get("headers") or {},
                "bodySample": dest_details.get("bodySample", ""),
                "finalUrl": final_base,
                "domainChanged": True,
                "domainAdopted": True,
                "redirectedFrom": orig_base,
                "redirectedTo": final_base,
                "itemsFound": dest_count,
            }
            if dest_upd.get("requiresCloudflareBypass"):
                details["requiresCloudflareBypass"] = True
            res = (
                True,
                dest_count,
                f"OK_REDIRECTED ({orig_base} -> {final_base}, {dest_count} items)",
                adopted_updates,
            )
            return (*res, details) if return_details else res

        new_status = "DISABLED" if is_existing_active else "DRAFT"
        details = dict(dest_details)
        details.update(
            {
                "category": "DOMAIN_CHANGE_FAILED",
                "domainChanged": True,
                "domainAdopted": False,
                "domainChangeFailed": True,
                "redirectedFrom": orig_base,
                "redirectedTo": final_base,
                "destFailureCategory": dest_details.get("category"),
                "destFailureMsg": dest_msg,
            }
        )
        res = (False, 0, f"DOMAIN_CHANGE_FAILED ({orig_base} -> {final_base}: {dest_msg})", {"status": new_status})
        return (*res, details) if return_details else res

    # Fallback to SSRF-valid mirrors if baseUrl failed
    if allow_redirect_adopt:
        mirrors = list(recipe.get("mirrors") or [])
        for mirror in mirrors:
            m_clean = str(mirror).rstrip("/")
            if not m_clean or normalize_domain(m_clean) == orig_domain:
                continue
            ok_m, _ = validate_ssrf(m_clean)
            if not ok_m:
                continue
            cloned_mirror, adopted_mirror_updates = _adopt_domain_updates(recipe, orig_base, m_clean)
            m_ok, m_cnt, m_msg, m_upd, m_details = run_http_smoke_test(
                cloned_mirror,
                fetcher=fetcher,
                timeout=timeout,
                is_existing_active=is_existing_active,
                allow_redirect_adopt=False,
                return_details=True,
                include_cloudflare=include_cloudflare,
                probe_chapters=probe_chapters,
                auto_fix_chapters=auto_fix_chapters,
            )
            is_cf_mirror = bool(m_details.get("category") == "CLOUDFLARE_ANTIBOT")
            is_compatible = bool(recipe.get("preset") in ALLOWED_PRESETS)
            if m_ok or (include_cloudflare and is_cf_mirror and is_compatible):
                if is_existing_active or recipe.get("version"):
                    adopted_mirror_updates["version"] = int(recipe.get("version", 1)) + 1
                adopted_mirror_updates.update(m_upd)
                if include_cloudflare and is_cf_mirror:
                    adopted_mirror_updates["status"] = "ACTIVE"
                    adopted_mirror_updates["requiresCloudflareBypass"] = True
                    adopted_mirror_updates["requiresWebViewCapture"] = False
                    m_details["category"] = "VIABLE"
                    m_details["subReason"] = "MIRROR_AUTO_ADOPTED_CLOUDFLARE"
                    m_details["requiresCloudflareBypass"] = True
                m_details["domainChanged"] = True
                m_details["domainAdopted"] = True
                m_details["redirectedFrom"] = orig_base
                m_details["redirectedTo"] = m_clean
                res = (
                    True,
                    m_cnt,
                    f"OK_MIRROR ({orig_base} -> {m_clean}: {m_msg})",
                    adopted_mirror_updates,
                )
                return (*res, m_details) if return_details else res

    last_status = int(last_probe.get("status_code") or 0)
    last_body = last_probe.get("body") or ""
    last_msg = last_probe.get("message") or ""
    last_headers = last_probe.get("headers") or {}
    last_final_url = last_probe.get("final_url") or orig_base

    # If redirected to an unsafe SSRF target during redirect handler
    if last_probe.get("error_type") == "SSRF_REDIRECT_REJECTED":
        new_status = "DISABLED" if is_existing_active else "DRAFT"
        details = {
            "category": "DOMAIN_CHANGE_FAILED",
            "subReason": last_msg,
            "httpStatus": 0,
            "headers": last_headers,
            "bodySample": "",
            "finalUrl": last_final_url,
            "domainChanged": True,
            "domainAdopted": False,
            "domainChangeFailed": True,
            "redirectedFrom": orig_base,
            "redirectedTo": last_final_url,
        }
        res = (False, 0, f"DOMAIN_CHANGE_FAILED ({last_msg})", {"status": new_status})
        return (*res, details) if return_details else res

    is_waf, waf_reason = detect_waf_block(last_status, headers=last_headers, body=last_body)
    if is_waf:
        if include_cloudflare and recipe.get("preset") in ALLOWED_PRESETS:
            adopted_updates = {
                "status": "ACTIVE",
                "requiresCloudflareBypass": True,
                "requiresWebViewCapture": False,
            }
            details = {
                "category": "CLOUDFLARE_ANTIBOT",
                "subReason": waf_reason,
                "httpStatus": last_status,
                "headers": last_headers,
                "bodySample": last_body[:4096],
                "finalUrl": last_final_url,
                "domainChanged": False,
                "domainAdopted": False,
                "requiresCloudflareBypass": True,
            }
            res = (True, 0, f"CLOUDFLARE_CHALLENGE_ACCEPTED ({waf_reason})", adopted_updates)
            return (*res, details) if return_details else res

        new_status = "QUARANTINED" if is_existing_active else "DRAFT"
        details = {
            "category": "CLOUDFLARE_ANTIBOT",
            "subReason": waf_reason,
            "httpStatus": last_status,
            "headers": last_headers,
            "bodySample": last_body[:4096],
            "finalUrl": last_final_url,
            "domainChanged": False,
            "domainAdopted": False,
        }
        res = (False, 0, f"CLOUDFLARE_CHALLENGE ({waf_reason})", {"status": new_status})
        return (*res, details) if return_details else res

    if last_status == 429:
        new_status = "DISABLED" if is_existing_active else "DRAFT"
        details = {
            "category": "NEEDS_PRIMITIVE",
            "subReason": "HTTP_429_RATE_LIMIT",
            "httpStatus": 429,
            "headers": last_headers,
            "bodySample": last_body[:4096],
            "finalUrl": last_final_url,
            "domainChanged": False,
            "domainAdopted": False,
        }
        res = (False, 0, "RATE_LIMIT_429 (HTTP 429)", {"status": new_status})
        return (*res, details) if return_details else res

    # Only check JS decoy when HTTP succeeded cleanly (not on 404/52x error pages)
    if 200 <= last_status < 400:
        protection = classify_source_protection(html_sample=last_body, http_status=last_status, headers=last_headers)
        non_rsc_decoys = [r for r in protection.get("reasons", []) if r != "__next_f"]
        if protection["strategy"] == "WEBVIEW_REACT_OR_JS_DECOY" and (non_rsc_decoys or not _recipe_uses_quickjs(recipe)):
            details = {
                "category": "NEEDS_PRIMITIVE",
                "subReason": "JS_DECOY_NEEDS_WEBVIEW",
                "httpStatus": last_status,
                "headers": last_headers,
                "bodySample": last_body[:4096],
                "finalUrl": last_final_url,
                "domainChanged": False,
                "domainAdopted": False,
            }
            res = (False, 0, "JS_DECOY_NEEDS_WEBVIEW", {"status": "DRAFT", "requiresWebViewCapture": True})
            return (*res, details) if return_details else res

        items_found = len(extract_items_for_smoke(recipe, last_body))
        new_status = "DISABLED" if is_existing_active else "DRAFT"
        details = {
            "category": "NEEDS_PRIMITIVE",
            "subReason": f"INSUFFICIENT_ITEMS ({items_found} < {MIN_SMOKE_ITEMS})",
            "httpStatus": last_status,
            "headers": last_headers,
            "bodySample": last_body[:4096],
            "finalUrl": last_final_url,
            "domainChanged": False,
            "domainAdopted": False,
            "itemsFound": items_found,
        }
        res = (
            False,
            items_found,
            f"INSUFFICIENT_ITEMS ({items_found} < {MIN_SMOKE_ITEMS})",
            {"status": new_status},
        )
        return (*res, details) if return_details else res

    down_sub = classify_down_reason(status_code=last_status, message=last_msg, body=last_body)
    new_status = "DISABLED" if is_existing_active else "DRAFT"
    details = {
        "category": "DOWN_OR_NONEXISTENT",
        "subReason": down_sub,
        "httpStatus": last_status,
        "headers": last_headers,
        "bodySample": last_body[:4096],
        "finalUrl": last_final_url,
        "domainChanged": False,
        "domainAdopted": False,
    }
    res = (False, 0, f"DEAD_OR_HTTP_ERROR ({last_msg or down_sub})", {"status": new_status})
    return (*res, details) if return_details else res


def parse_langs_arg(langs="es"):
    raw = (langs or "es").strip().lower()
    if raw == "all":
        return None
    parsed = {part.strip().lower() for part in raw.split(",") if part.strip()}
    return parsed or {"es"}


def lang_matches_filter(source_lang, target_langs):
    """Match source language against `--langs` supporting `--langs all` and BCP-47 prefixes."""
    sl = (source_lang or "").strip().lower()
    if not sl:
        return False
    if target_langs is None:
        return True
    if sl in target_langs:
        return True
    if sl == "all":
        return False
    base = sl.split("-", 1)[0]
    return base in target_langs


def load_deprecated_sources(path=DEFAULT_DEPRECATED_PATH):
    if not path or not os.path.isfile(path):
        return set(), set()
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    deprecated_ids = set()
    deprecated_names = set()
    for item in data.get("removeImmediately", []):
        sid = str(item.get("sourceId", "")).strip()
        if sid:
            deprecated_ids.add(sid)
        name = normalize_key(item.get("name", ""))
        if name:
            deprecated_names.add(name)
    return deprecated_ids, deprecated_names


class _UnionFind:
    def __init__(self, n):
        self.parent = list(range(n))

    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def merge_candidates(candidates):
    """Deduplicate multi-repo source candidates by (lang, normalized_domain), sourceId, and pkgName.

    Prioritizes highest (lastCommitTs, versionCode, versionId, repoPriority), merges upstreamSourceIds,
    and retains sorted `alternatives` for automatic cross-repo fallback.
    """
    if not candidates:
        return []

    n = len(candidates)
    uf = _UnionFind(n)
    by_domain = {}
    by_source_id = {}
    by_pkg = {}

    for idx, c in enumerate(candidates):
        dom = normalize_domain(c.get("baseUrl", ""))
        lang = (c.get("lang") or "en").strip().lower()
        if dom:
            d_key = (lang, dom)
            if d_key in by_domain:
                uf.union(idx, by_domain[d_key])
            else:
                by_domain[d_key] = idx

        sids = set()
        if c.get("sourceId") is not None:
            sids.add(int(c["sourceId"]))
        for extra_sid in c.get("upstreamSourceIds") or []:
            sids.add(int(extra_sid))
        for sid in sids:
            if sid in by_source_id:
                uf.union(idx, by_source_id[sid])
            else:
                by_source_id[sid] = idx

        pkg = (c.get("pkgName") or "").strip().lower()
        if pkg:
            p_key = (lang, pkg)
            if p_key in by_pkg:
                uf.union(idx, by_pkg[p_key])
            else:
                by_pkg[p_key] = idx

    groups = {}
    for idx, c in enumerate(candidates):
        root = uf.find(idx)
        groups.setdefault(root, []).append(c)

    merged = []
    for group in groups.values():
        group_sorted = sorted(
            group,
            key=lambda item: (
                int(item.get("lastCommitTs") or 0),
                int(item.get("versionCode") or item.get("extVersionCode") or 0),
                int(item.get("versionId") or 1),
                int(item.get("repoPriority") or 0),
            ),
            reverse=True,
        )
        winner = dict(group_sorted[0])
        all_sids = set()
        for item in group_sorted:
            if item.get("sourceId") is not None:
                all_sids.add(int(item["sourceId"]))
            for extra in item.get("upstreamSourceIds") or []:
                all_sids.add(int(extra))
        winner["upstreamSourceIds"] = sorted(all_sids)
        winner["upstreamSourceId"] = int(winner["sourceId"]) if winner.get("sourceId") is not None else None
        winner["alternatives"] = [dict(x) for x in group_sorted[1:]]
        merged.append(winner)

    merged.sort(key=lambda x: (str(x.get("lang", "")).lower(), normalize_domain(x.get("baseUrl", "")), str(x.get("name", ""))))
    return merged


def _resolve_repo_src_dir(loc, repo_dir, src_index, src_lang):
    if loc and os.path.isdir(os.path.join(repo_dir, loc[2].replace("/", os.sep))):
        return loc[2]
    if loc:
        slug_lower = loc[3].lower()
        for key in ((src_lang.lower(), slug_lower), ("all", slug_lower), (None, slug_lower)):
            if key in src_index:
                return src_index[key]
    return loc[2] if loc else ""


def build_upstream_catalog(index_payloads, langs="es", repo_dirs=None, repo_timestamps=None):
    """Build full deduplicated upstream catalog + lookup indexes with real git commit timestamps."""
    target_langs = parse_langs_arg(langs)
    repo_dirs = repo_dirs or {}
    repo_timestamps = dict(repo_timestamps) if repo_timestamps is not None else {}
    priority_map = {u["repo_slug"]: u["priority"] for u in DEFAULT_UPSTREAMS}
    attr_map = {u["repo_slug"]: u["default_attribution"] for u in DEFAULT_UPSTREAMS}

    theme_cache = {}
    ext_meta_cache = {}
    src_dir_indexes = {}

    for repo_slug, repo_dir in repo_dirs.items():
        norm_slug = normalize_upstream_repo(repo_slug) or repo_slug
        if norm_slug not in repo_timestamps and repo_dir:
            repo_timestamps[norm_slug] = collect_repo_path_timestamps(repo_dir)
        if repo_dir and os.path.isdir(repo_dir):
            src_dir_indexes[norm_slug] = _index_repo_src_dirs(repo_dir)

    raw_candidates = []
    for repo_label, payload in index_payloads:
        norm_label = normalize_upstream_repo(repo_label) or "keiyoushi/extensions-source"
        for ext in payload.get("extensions", []):
            loc = infer_open_source_location(ext, default_repo=norm_label)
            repo_slug = loc[0] if loc else norm_label
            prio = priority_map.get(repo_slug, 0)
            ext_cw = int(ext.get("contentWarning") or 0)
            ext_nsfw = bool(ext.get("isNsfw")) or ext_cw == 3

            for src in ext.get("sources", []):
                lang = src.get("lang", "")
                if not lang_matches_filter(lang, target_langs):
                    continue

                src_cw = int(src.get("contentWarning") or 0)
                eff_cw = max(ext_cw, src_cw)
                cand = {
                    "repoLabel": repo_label,
                    "upstreamRepo": repo_slug,
                    "repoPriority": prio,
                    "sourceId": int(src["sourceId"]),
                    "name": src["name"],
                    "lang": lang,
                    "baseUrl": src["baseUrl"],
                    "mirrors": list(src.get("mirrors") or []),
                    "versionCode": int(ext.get("versionCode", 0)),
                    "extVersionCode": int(ext.get("versionCode", 0)),
                    "versionId": 1,
                    "pkgName": ext.get("pkgName", ""),
                    "iconUrl": ext.get("iconUrl") or None,
                    "openSource": loc,
                    "defaultAttribution": attr_map.get(repo_slug, "Upstream Contributors"),
                    "lastCommitTs": 0,
                    "contentWarning": eff_cw,
                    "isNsfw": ext_nsfw or eff_cw == 3,
                }

                if repo_slug in repo_dirs:
                    repo_dir = repo_dirs[repo_slug]
                    resolved_src_dir = _resolve_repo_src_dir(
                        loc,
                        repo_dir,
                        src_dir_indexes.get(repo_slug, {}),
                        lang,
                    )
                    if loc and resolved_src_dir and resolved_src_dir != loc[2]:
                        cand["openSource"] = (loc[0], loc[1], resolved_src_dir, loc[3])
                    ts_map = repo_timestamps.get(repo_slug, {})
                    if resolved_src_dir:
                        cand["lastCommitTs"] = int(ts_map.get(resolved_src_dir, 0))
                        cache_key = (repo_slug, resolved_src_dir)
                        if cache_key not in ext_meta_cache:
                            ext_meta_cache[cache_key] = read_extension_from_repo(
                                repo_dir,
                                resolved_src_dir,
                                default_attribution=cand["defaultAttribution"],
                                theme_cache=theme_cache,
                            )
                        ext_info = ext_meta_cache[cache_key]
                        cand["repoMeta"] = ext_info
                        gradle = ext_info.get("gradle")
                        if gradle:
                            # Match specific source entry inside multi-source build.gradle.kts if available
                            matched_g_src = None
                            for g_src in gradle.get("sources") or []:
                                if g_src.get("id") == cand["sourceId"] or (
                                    (g_src.get("lang") or "").lower() == lang.lower()
                                    and normalize_key(g_src.get("name")) == normalize_key(cand["name"])
                                ):
                                    matched_g_src = g_src
                                    break
                            if matched_g_src:
                                cand["versionId"] = int(matched_g_src.get("versionId") or 1)
                                for gm in matched_g_src.get("mirrors") or []:
                                    if gm not in cand["mirrors"]:
                                        cand["mirrors"].append(gm)
                            else:
                                cand["versionId"] = int(gradle.get("versionId") or 1)
                                for gm in gradle.get("mirrors") or []:
                                    if gm not in cand["mirrors"]:
                                        cand["mirrors"].append(gm)

                            if gradle.get("contentWarning"):
                                cand["contentWarning"] = int(gradle["contentWarning"])
                            if gradle.get("isNsfw"):
                                cand["isNsfw"] = True
                        if ext_info.get("kotlinHint") and ext_info["kotlinHint"].get("isNsfw"):
                            cand["isNsfw"] = True

                raw_candidates.append(cand)

    deduped = merge_candidates(raw_candidates)
    by_source_id = {}
    by_name_key = {}
    by_domain = {}

    for entry in deduped:
        for sid in entry.get("upstreamSourceIds") or [entry["sourceId"]]:
            by_source_id[int(sid)] = entry
        nkey = normalize_key(entry["name"])
        prev = by_name_key.get(nkey)
        entry_prio = 2 if entry["lang"].lower() == "es" else (1 if entry["lang"].lower() != "all" else 0)
        prev_prio = (
            (2 if prev["lang"].lower() == "es" else (1 if prev["lang"].lower() != "all" else 0))
            if prev is not None
            else -1
        )
        if prev is None or entry_prio > prev_prio or (
            entry_prio == prev_prio
            and (entry.get("lastCommitTs", 0), entry["versionCode"]) > (prev.get("lastCommitTs", 0), prev["versionCode"])
        ):
            by_name_key[nkey] = entry
        dom = normalize_domain(entry["baseUrl"])
        if dom:
            by_domain[(entry["lang"].lower(), dom)] = entry

    return {
        "candidates": deduped,
        "by_source_id": by_source_id,
        "by_name_key": by_name_key,
        "by_domain": by_domain,
    }


def build_upstream_lookup(index_payloads, langs="es", repo_dirs=None, repo_timestamps=None):
    """Build deduplicated candidate indexes by sourceId, normalized name, and (lang, domain)."""
    catalog = build_upstream_catalog(
        index_payloads,
        langs=langs,
        repo_dirs=repo_dirs,
        repo_timestamps=repo_timestamps,
    )
    return catalog["by_source_id"], catalog["by_name_key"], catalog["by_domain"]


def update_referer_in_recipe(recipe, old_base, new_base):
    headers = recipe.get("headers")
    if isinstance(headers, dict):
        for k in list(headers.keys()):
            if k.lower() == "referer" and (headers[k].startswith(old_base) or "{baseUrl}" not in headers[k]):
                if headers[k].startswith(old_base):
                    headers[k] = new_base.rstrip("/") + "/"
            elif k.lower() == "origin" and headers[k].startswith(old_base):
                headers[k] = new_base.rstrip("/")
    for step in recipe.get("pipelineSteps", []):
        if step.get("op") == "referer_bind":
            ref = step.get("refererUrl", "")
            if ref.startswith(old_base) or not ref:
                step["refererUrl"] = new_base.rstrip("/") + "/"


def preset_from_theme(theme):
    if not theme:
        return "CSS_GENERIC"
    norm = theme.lower()
    if norm in EXTRA_THEME_PRESET_MAP:
        return EXTRA_THEME_PRESET_MAP[norm]
    if norm in MULTISRC_THEME_PRESET_MAP:
        return MULTISRC_THEME_PRESET_MAP[norm]
    return THEME_PRESET_MAP.get(norm, "CSS_GENERIC")


def _build_zeistmanga_json_api(base_url):
    clean_base = base_url.rstrip("/")
    return {
        "apiBaseUrl": clean_base,
        "popularRequest": {
            "method": "GET",
            "pathTemplate": "/feeds/posts/default?alt=json&start-index={page}&max-results=24",
            "headers": {"Accept": "application/json", "Referer": f"{clean_base}/"},
        },
        "latestRequest": {
            "method": "GET",
            "pathTemplate": "/feeds/posts/default?alt=json&start-index={page}&max-results=24",
            "headers": {"Accept": "application/json", "Referer": f"{clean_base}/"},
        },
        "searchRequest": {
            "method": "GET",
            "pathTemplate": "/feeds/posts/default?alt=json&q={query}&start-index={page}&max-results=24",
            "headers": {"Accept": "application/json", "Referer": f"{clean_base}/"},
        },
        "mangaList": {
            "itemsPath": "$.feed.entry[*]",
            "titlePaths": ["$.title.$t"],
            "urlPath": "$.link[?(@.rel=='alternate')].href",
            "coverPaths": ["$.media$thumbnail.url"],
            "htmlExtract": {
                "titleSelector": "h1.entry-title, h1.post-title",
                "coverSelector": "div.post-body img, div.entry-content img",
                "baseUrl": clean_base,
            },
            "pagination": {
                "mode": "PAGE_NUMBER",
                "startPage": 1,
                "pageSize": 24,
            },
        },
        "details": {
            "rootPath": "$",
            "titlePaths": ["$.feed.entry[0].title.$t", "$.title.$t"],
        },
        "chapters": {
            "itemsPath": "$.feed.entry[*]",
            "namePath": "$.title.$t",
            "urlPath": "$.link[?(@.rel=='alternate')].href",
            "datePath": "$.published.$t",
            "dateFormat": "iso",
            "htmlExtract": {
                "titleSelector": "h1.entry-title",
                "dateSelector": "time",
                "baseUrl": clean_base,
            },
        },
        "pages": {
            "itemsPath": "$.feed.entry[*]",
            "readerHtmlPageSelector": "div.post-body img, div.entry-content img",
            "requiresReaderHtmlFallback": True,
        },
    }


def _build_iken_json_api(base_url, kotlin_text=""):
    clean_base = base_url.rstrip("/")
    api_base = clean_base
    kt = kotlin_text or ""
    m_api = re.search(r'override\s+val\s+apiUrl\s*=\s*"(https://[^"\s]+)"', kt)
    if m_api:
        cand_api = m_api.group(1).rstrip("/")
        if validate_ssrf(cand_api)[0]:
            api_base = cand_api
    per_page = 18
    m_pp = re.search(r'override\s+val\s+perPage\s*=\s*(\d+)', kt)
    if m_pp and 1 <= int(m_pp.group(1)) <= 100:
        per_page = int(m_pp.group(1))
    req_headers = {"Accept": "application/json", "Referer": f"{clean_base}/"}
    return {
        "apiBaseUrl": api_base,
        "popularRequest": {
            "method": "GET",
            "pathTemplate": f"/api/query?perPage={per_page}&orderBy=totalViews&orderDirection=desc&page={{page}}",
            "headers": dict(req_headers),
        },
        "latestRequest": {
            "method": "GET",
            "pathTemplate": f"/api/query?perPage={per_page}&orderBy=lastChapterAddedAt&orderDirection=desc&page={{page}}",
            "headers": dict(req_headers),
        },
        "searchRequest": {
            "method": "GET",
            "pathTemplate": f"/api/query?perPage={per_page}&searchTerm={{query}}&page={{page}}",
            "headers": dict(req_headers),
        },
        "detailsRequest": {
            "method": "GET",
            "pathTemplate": "/api/post?postSlug={slug}",
            "headers": dict(req_headers),
        },
        "chaptersRequest": {
            "method": "GET",
            "pathTemplate": "/api/chapters?postId={id}",
            "headers": dict(req_headers),
        },
        "pagesRequest": {
            "method": "GET",
            "pathTemplate": "/api/chapter?chapterId={chapterId}",
            "headers": dict(req_headers),
        },
        "mangaList": {
            "itemsPath": "$.posts[*]",
            "titlePaths": ["$.postTitle", "$.title", "$.name"],
            "urlTemplate": "{slug}/{id}",
            "slugPath": "$.slug",
            "idPath": "$.id",
            "coverPaths": ["$.featuredImage", "$.cover", "$.thumbnail"],
            "pagination": {
                "mode": "PAGE_NUMBER",
                "startPage": 1,
                "pageSize": per_page,
            },
        },
        "details": {
            "rootPath": "$.post",
            "titlePaths": ["$.postTitle", "$.title", "$.name"],
            "descriptionPaths": ["$.postContent", "$.description", "$.synopsis"],
            "stripHtmlInDescription": True,
            "coverPaths": ["$.featuredImage", "$.cover", "$.thumbnail"],
            "genresPath": "$.genres[*].name",
            "statusPath": "$.seriesStatus",
            "statusMap": {
                "ONGOING": 1,
                "COMING_SOON": 1,
                "MASS_RELEASED": 1,
                "COMPLETED": 2,
                "CANCELLED": 5,
                "DROPPED": 5,
            },
        },
        "chapters": {
            "itemsPath": "$.post.chapters[*]",
            "namePath": "$.title",
            "urlTemplate": "{id}",
            "idPath": "$.id",
            "numberPath": "$.number",
            "lockedPath": "$.isLocked",
            "datePath": "$.createdAt",
            "dateFormat": "iso",
        },
        "pages": {
            "itemsPath": "$.chapter.images[*]",
            "imageUrlPath": "$.url",
        },
    }


def _build_heancms_json_api(base_url):
    clean_base = base_url.rstrip("/")
    return {
        "apiBaseUrl": clean_base,
        "popularRequest": {
            "method": "GET",
            "pathTemplate": "/api/series?page={page}&order=views",
            "headers": {"Accept": "application/json", "Referer": f"{clean_base}/"},
        },
        "latestRequest": {
            "method": "GET",
            "pathTemplate": "/api/series?page={page}&order=latest",
            "headers": {"Accept": "application/json", "Referer": f"{clean_base}/"},
        },
        "searchRequest": {
            "method": "GET",
            "pathTemplate": "/api/series?page={page}&query={query}",
            "headers": {"Accept": "application/json", "Referer": f"{clean_base}/"},
        },
        "detailsRequest": {
            "method": "GET",
            "pathTemplate": "/api/series/{slug}",
            "headers": {"Accept": "application/json", "Referer": f"{clean_base}/"},
        },
        "chaptersRequest": {
            "method": "GET",
            "pathTemplate": "/api/series/{slug}",
            "headers": {"Accept": "application/json", "Referer": f"{clean_base}/"},
        },
        "pagesRequest": {
            "method": "GET",
            "pathTemplate": "/api/chapters/{chapterId}",
            "headers": {"Accept": "application/json", "Referer": f"{clean_base}/"},
        },
        "mangaList": {
            "itemsPath": "$.data[*]",
            "titlePaths": ["$.title"],
            "urlTemplate": "{slug}",
            "slugPath": "$.slug",
            "coverPaths": ["$.thumbnail", "$.cover"],
            "pagination": {
                "mode": "PAGE_NUMBER",
                "startPage": 1,
                "pageSize": 24,
            },
        },
        "details": {
            "rootPath": "$.data",
            "titlePaths": ["$.title"],
            "descriptionPaths": ["$.description"],
            "coverPaths": ["$.thumbnail", "$.cover"],
        },
        "chapters": {
            "itemsPath": "$.data.chapters[*]",
            "namePath": "$.title",
            "urlTemplate": "{id}",
            "idPath": "$.id",
            "numberPath": "$.chapter_number",
            "datePath": "$.created_at",
            "dateFormat": "iso",
        },
        "pages": {
            "itemsPath": "$.data.pages[*]",
            "imageUrlPath": "$.url",
        },
    }


def build_recipe_dict(
    source_id,
    name,
    base_url,
    preset,
    lang="es",
    catalog_path="/manga",
    version_id=1,
    use_home_fallback=False,
    requires_webview_capture=None,
    requires_cloudflare_bypass=None,
    mirrors=None,
    icon_url=None,
    pkg_name=None,
    upstream_source_id=None,
    upstream_source_ids=None,
    upstream_version_code=None,
    upstream_repo=None,
    license_id="Apache-2.0",
    attribution="Mihon Declarative Catalog Contributors",
    status="DRAFT",
    theme=None,
    kotlin_text="",
):
    norm_theme = (theme or "").strip().lower()
    if norm_theme in THEME_DEFAULT_SELECTORS:
        selectors = dict(THEME_DEFAULT_SELECTORS[norm_theme])
    else:
        selectors = dict(PRESET_DEFAULT_SELECTORS.get(preset, PRESET_DEFAULT_SELECTORS["CSS_GENERIC"]))
    clean_base = base_url.rstrip("/")
    all_sids = sorted(
        {
            int(s)
            for s in ([upstream_source_id] if upstream_source_id is not None else []) + list(upstream_source_ids or [])
            if s is not None
        }
    )
    recipe = {
        "schemaVersion": 2,
        "sourceId": source_id,
        "name": name,
        "baseUrl": clean_base,
        "lang": lang,
        "version": 1,
        "versionId": version_id,
        "preset": preset,
        "status": status,
        "maxHtmlBytes": 2097152,
        "catalogPath": catalog_path,
        "useHomeFallback": use_home_fallback,
        "headers": {"Referer": f"{clean_base}/"},
        "selectors": selectors,
        "pipelineSteps": [
            {"op": "referer_bind", "refererUrl": f"{clean_base}/"},
        ],
        "recipePath": f"recipes/{source_id}.json",
        "mode": "declarative",
        "upstreamSourceIds": all_sids,
        "license": license_id,
        "attribution": attribution,
    }
    if preset == "JSON_API":
        if norm_theme == "zeistmanga":
            recipe["jsonApi"] = _build_zeistmanga_json_api(clean_base)
            recipe["selectors"] = {"listSelector": "$.feed.entry[*]"}
        elif norm_theme == "iken":
            recipe["jsonApi"] = _build_iken_json_api(clean_base, kotlin_text=kotlin_text)
            recipe["selectors"] = {"listSelector": "$.posts[*]"}
        elif norm_theme == "heancms":
            recipe["jsonApi"] = _build_heancms_json_api(clean_base)
            recipe["selectors"] = {"listSelector": "$.data[*]"}
    if requires_webview_capture is not None:
        recipe["requiresWebViewCapture"] = bool(requires_webview_capture)
    if requires_cloudflare_bypass is not None:
        recipe["requiresCloudflareBypass"] = bool(requires_cloudflare_bypass)
    if mirrors:
        recipe["mirrors"] = mirrors
    if icon_url and validate_ssrf(icon_url)[0]:
        recipe["iconUrl"] = icon_url
    if pkg_name:
        recipe["pkgName"] = pkg_name
    if upstream_source_id is not None:
        recipe["upstreamSourceId"] = int(upstream_source_id)
    if upstream_version_code is not None:
        recipe["upstreamExtVersionCode"] = int(upstream_version_code)
        recipe["versionCode"] = int(upstream_version_code)
    if upstream_repo:
        recipe["upstreamRepo"] = normalize_upstream_repo(upstream_repo)
    return recipe


def _iter_recipes_for_dedicated_lookup(recipes_dir, dedicated_recipes=None):
    seen_ids = set()
    for r in dedicated_recipes or []:
        if isinstance(r, dict) and r.get("sourceId"):
            seen_ids.add(r["sourceId"])
            yield r
    if recipes_dir and os.path.isdir(recipes_dir):
        for fname in sorted(os.listdir(recipes_dir)):
            if not fname.endswith(".json"):
                continue
            try:
                with open(os.path.join(recipes_dir, fname), "r", encoding="utf-8") as f:
                    r = json.load(f)
            except Exception:
                continue
            if isinstance(r, dict) and r.get("sourceId") not in seen_ids:
                yield r


def _is_multilang_compatible_dedicated(dedicated, cand, base_url=""):
    if not isinstance(dedicated, dict):
        return False
    if dedicated.get("status") in ("DISABLED", "QUARANTINED"):
        return False
    if dedicated.get("preset") != "JSON_API" and not _is_specialized_recipe(dedicated):
        return False
    cand_name = normalize_key(cand.get("name", ""))
    ded_name = normalize_key(dedicated.get("name", ""))
    if not cand_name or cand_name != ded_name:
        return False
    cand_pkg = (cand.get("pkgName") or "").strip().lower()
    ded_pkg = (dedicated.get("pkgName") or "").strip().lower()
    same_pkg = bool(cand_pkg and ded_pkg and cand_pkg == ded_pkg)
    same_domain = bool(base_url and normalize_domain(dedicated.get("baseUrl", "")) == normalize_domain(base_url))
    if not (same_pkg or same_domain):
        return False
    if same_pkg and ".all." in cand_pkg:
        return True
    json_api = dedicated.get("jsonApi") if isinstance(dedicated.get("jsonApi"), dict) else {}
    if isinstance(json_api.get("langMap"), dict) or "{lang}" in json.dumps(json_api):
        return True
    return False


def _inherit_dedicated_native_recipe(
    dedicated,
    cand,
    source_id,
    base_url,
    mirrors=None,
    license_id="Apache-2.0",
    attribution="Upstream Contributors",
    upstream_repo=None,
    version_id=1,
):
    cloned = copy.deepcopy(dedicated)
    clean_base = (base_url or cloned.get("baseUrl") or "").rstrip("/")
    cloned["schemaVersion"] = 2
    cloned["sourceId"] = source_id
    cloned["recipePath"] = f"recipes/{source_id}.json"
    cloned["name"] = cand.get("name") or cloned.get("name")
    cloned["lang"] = cand.get("lang") or cloned.get("lang") or "en"
    cloned["baseUrl"] = clean_base
    cloned["version"] = 1
    cloned["versionId"] = int(version_id or 1)
    cloned["status"] = "DRAFT"
    cloned["license"] = license_id or cloned.get("license") or "Apache-2.0"
    cloned["attribution"] = attribution or cloned.get("attribution") or "Upstream Contributors"
    cand_sids = [int(s) for s in (cand.get("upstreamSourceIds") or []) if s is not None]
    if cand.get("sourceId") is not None:
        cid = int(cand["sourceId"])
        if cid not in cand_sids:
            cand_sids.insert(0, cid)
        cloned["upstreamSourceId"] = cid
    else:
        cloned.pop("upstreamSourceId", None)
    if cand_sids:
        cloned["upstreamSourceIds"] = sorted(set(cand_sids))
    else:
        cloned.pop("upstreamSourceIds", None)
    if cand.get("pkgName"):
        cloned["pkgName"] = cand["pkgName"]
    if upstream_repo:
        cloned["upstreamRepo"] = normalize_upstream_repo(upstream_repo)
    if cand.get("iconUrl") and validate_ssrf(cand["iconUrl"])[0]:
        cloned["iconUrl"] = cand["iconUrl"]
    vc = cand.get("versionCode") or cand.get("extVersionCode")
    if vc:
        cloned["upstreamExtVersionCode"] = int(vc)
        cloned["versionCode"] = int(vc)
    valid_mirrors = [m for m in (mirrors or [clean_base]) if validate_ssrf(m)[0]]
    if valid_mirrors:
        cloned["mirrors"] = valid_mirrors
    return cloned


def _find_dedicated_native_recipe(
    recipes_dir,
    upstream_source_id,
    name,
    base_url=None,
    pkg_name=None,
    dedicated_recipes=None,
):
    target_key = normalize_key(name)
    norm_pkg = (pkg_name or "").strip().lower()
    norm_dom = normalize_domain(base_url or "")
    best = None
    best_score = -1
    for r in _iter_recipes_for_dedicated_lookup(recipes_dir, dedicated_recipes=dedicated_recipes):
        if r.get("status") in ("DISABLED", "QUARANTINED"):
            continue
        is_json_or_spec = r.get("preset") == "JSON_API" or _is_specialized_recipe(r)
        if not is_json_or_spec:
            continue
        all_ids = set(r.get("upstreamSourceIds") or [])
        if r.get("upstreamSourceId") is not None:
            all_ids.add(r["upstreamSourceId"])
        id_match = upstream_source_id is not None and upstream_source_id in all_ids
        name_match = bool(target_key and normalize_key(r.get("name", "")) == target_key)
        if not (id_match or name_match):
            continue
        r_pkg = (r.get("pkgName") or "").strip().lower()
        r_dom = normalize_domain(r.get("baseUrl", ""))
        pkg_match = bool(norm_pkg and r_pkg and norm_pkg == r_pkg)
        dom_match = bool(norm_dom and r_dom and norm_dom == r_dom)
        score = (
            (8 if id_match else 0)
            + (4 if pkg_match else 0)
            + (2 if dom_match else 0)
            + (2 if r.get("querySigner") else 0)
            + (1 if r.get("status") == "ACTIVE" else 0)
        )
        if score > best_score:
            best_score = score
            best = r
    return best


def _default_catalog_path_for_preset(preset, kotlin_hint=None, theme=None):
    if kotlin_hint and kotlin_hint.get("catalogPath") is not None:
        return kotlin_hint["catalogPath"], False
    norm_theme = (theme or "").strip().lower()
    if norm_theme == "zeistmanga":
        return "/feeds/posts/default?alt=json", False
    if norm_theme == "iken":
        return "/api/query?perPage=18&orderBy=totalViews&orderDirection=desc&page=1", False
    if norm_theme == "heancms":
        return "/api/series", False
    if norm_theme == "foolslide":
        return "/directory/", False
    if norm_theme == "mangacatalog":
        return "/manga", False
    if norm_theme == "solomanga":
        return "/series", False
    if preset == "MANGA_READER_CMS":
        return "/manga-list", True
    if preset in ("MADARA", "MANGA_THEMESIA"):
        return "/manga", True
    return "/manga", True


def generate_recipe_from_slug(
    slug,
    recipes_dir,
    upstream_lookup,
    repo_dirs=None,
    apply=False,
    kotlin_text="",
    html_sample="",
    http_status=200,
    probe_live=False,
    fetcher=None,
    deprecated_path=DEFAULT_DEPRECATED_PATH,
    include_nsfw=False,
):
    _, by_name, _ = upstream_lookup
    repo_dirs = repo_dirs or {}
    key = normalize_key(slug)
    match = by_name.get(key)
    if not match:
        for item in by_name.values():
            if item.get("openSource") and normalize_key(item["openSource"][3]) == key:
                match = item
                break
    if not match:
        return None, f"Slug '{slug}' not found in index.pb"

    deprecated_ids, deprecated_names = load_deprecated_sources(deprecated_path)
    all_cands = {str(s) for s in (match.get("upstreamSourceIds") or [match["sourceId"]])}
    if all_cands & deprecated_ids or normalize_key(match.get("name", "")) in deprecated_names:
        return None, f"SKIP_DEPRECATED: '{match['name']}' is listed in deprecated_sources.json"

    if match.get("isNsfw") and not include_nsfw:
        return None, f"SKIP_NSFW: '{match['name']}' is marked 18+ (NSFW)"

    base_url = match["baseUrl"]
    ok_ssrf, err_ssrf = validate_ssrf(base_url)
    if not ok_ssrf:
        return None, f"Unsafe upstream baseUrl '{base_url}': {err_ssrf}"

    preset = "CSS_GENERIC"
    version_id = int(match.get("versionId") or 1)
    mirrors = []
    up_repo = normalize_upstream_repo(match.get("upstreamRepo"))
    fetched_kotlin = ""
    catalog_path = "/manga"
    use_home_fallback = False
    license_id = "Apache-2.0"
    attribution = match.get("defaultAttribution") or DEFAULT_ATTRIBUTIONS.get(
        up_repo or "", "Mihon Declarative Catalog Contributors"
    )

    repo_meta = match.get("repoMeta")
    if repo_meta is None and match.get("openSource") and match["openSource"][0] in repo_dirs:
        repo_slug, _, src_dir, _ = match["openSource"]
        repo_meta = read_extension_from_repo(repo_dirs[repo_slug], src_dir, default_attribution=attribution)

    if repo_meta is None or not repo_meta.get("licenseOk"):
        reason = repo_meta["license"] if repo_meta and repo_meta.get("license") else "UNVERIFIED_LICENSE"
        return None, f"SKIP_UNVERIFIED_LICENSE ({reason})"

    license_id = repo_meta["license"]
    if repo_meta["attribution"]:
        attribution = repo_meta["attribution"]
    fetched_kotlin = repo_meta.get("kotlinText", "")
    if repo_meta.get("gradle"):
        if (repo_meta["gradle"].get("isNsfw") or repo_meta["gradle"].get("contentWarning") == 3) and not include_nsfw:
            return None, f"SKIP_NSFW: '{match['name']}' is marked NSFW in build.gradle.kts"
        preset = preset_from_theme(repo_meta["gradle"].get("theme"))
        version_id = repo_meta["gradle"].get("versionId") or version_id
        mirrors = [m for m in repo_meta["gradle"].get("mirrors", []) if validate_ssrf(m)[0]]

    effective_kotlin = kotlin_text or fetched_kotlin
    kt_hint = inspect_open_source_kotlin(effective_kotlin) if effective_kotlin else {"requiresNativeApk": False}
    if kt_hint.get("isNsfw") and not include_nsfw:
        return None, f"SKIP_NSFW: '{match['name']}' is marked NSFW in Kotlin"

    theme_name = (repo_meta.get("gradle") or {}).get("theme")
    gradle_text = repo_meta.get("gradleText") or ""
    catalog_path, use_home_fallback = _default_catalog_path_for_preset(preset, kt_hint, theme=theme_name)

    recipe_lang = match["lang"] or "es"
    safe_id = re.sub(r"[^a-z0-9_]", "_", slug.lower()).strip("_") or f"src_{match['sourceId']}"
    source_id = f"{recipe_lang.lower()}.{safe_id}"

    recipe = build_recipe_dict(
        source_id=source_id,
        name=match["name"],
        base_url=base_url,
        preset=preset,
        lang=recipe_lang,
        catalog_path=catalog_path,
        version_id=version_id,
        use_home_fallback=use_home_fallback,
        mirrors=mirrors,
        icon_url=match.get("iconUrl"),
        pkg_name=match.get("pkgName"),
        upstream_source_id=match["sourceId"],
        upstream_source_ids=match.get("upstreamSourceIds"),
        upstream_version_code=match.get("versionCode"),
        upstream_repo=up_repo,
        license_id=license_id,
        attribution=attribution,
        status="DRAFT",
        theme=theme_name,
    )

    if effective_kotlin or gradle_text:
        kt_synth = synthesize_recipe_from_kotlin(
            kotlin_text=effective_kotlin,
            source_id=source_id,
            name=match["name"],
            base_url=base_url,
            lang=recipe_lang,
            pkg_name=match.get("pkgName") or "",
            version_code=int(match.get("versionCode") or 1),
            upstream_source_id=match["sourceId"],
            upstream_repo=up_repo or "keiyoushi/extensions-source",
            attribution=attribution,
            license_id=license_id,
            gradle_text=gradle_text,
        )
        if kt_synth:
            for k in ("preset", "jsonApi", "selectors", "catalogPath", "pipelineSteps", "listPipelineSteps", "querySigner", "authPreFlight"):
                if kt_synth.get(k) is not None:
                    recipe[k] = kt_synth[k]
        else:
            steps = extract_pipeline_steps_from_kotlin(effective_kotlin, gradle_text=gradle_text)
            if steps:
                recipe["pipelineSteps"] = list(recipe.get("pipelineSteps") or []) + steps
            qs = extract_query_signer_spec(effective_kotlin)
            if qs:
                recipe["querySigner"] = qs
            pf = detect_and_build_auth_preflight(effective_kotlin, base_url)
            if pf:
                recipe["authPreFlight"] = pf

    unresolved, _ = has_unresolved_native_primitives(effective_kotlin, gradle_text=gradle_text, recipe=recipe)
    if unresolved or ("MangaFire" in effective_kotlin and not recipe.get("querySigner")):
        dedicated = _find_dedicated_native_recipe(
            recipes_dir,
            match.get("sourceId"),
            match.get("name", ""),
            base_url=base_url,
            pkg_name=match.get("pkgName"),
        )
        if dedicated is not None:
            if dedicated.get("sourceId") == source_id:
                return dedicated, "EXISTING_DEDICATED"
            if _is_multilang_compatible_dedicated(dedicated, match, base_url):
                recipe = _inherit_dedicated_native_recipe(
                    dedicated,
                    match,
                    source_id=source_id,
                    base_url=base_url,
                    mirrors=mirrors,
                    license_id=license_id,
                    attribution=attribution,
                    upstream_repo=up_repo,
                    version_id=version_id,
                )
            else:
                return dedicated, "EXISTING_DEDICATED"
        else:
            return None, "SKIP_NATIVE_COMPLEX: requires native adapter"

    if probe_live or fetcher is not None:
        smoke_ok, _, smoke_msg, updates = run_http_smoke_test(recipe, fetcher=fetcher, is_existing_active=False)
        recipe.update(updates)
        if not smoke_ok:
            status_tag = f"CREATED_DRAFT:{smoke_msg}"
        else:
            status_tag = f"CREATED_ACTIVE:{smoke_msg}"
    elif html_sample:
        if 200 <= http_status < 400 and len(extract_items_for_smoke(recipe, html_sample)) >= MIN_SMOKE_ITEMS:
            recipe["status"] = "ACTIVE"
        else:
            prot = classify_source_protection(html_sample=html_sample, http_status=http_status)
            non_rsc_decoys = [r for r in prot.get("reasons", []) if r != "__next_f"]
            if prot["strategy"] == "WEBVIEW_REACT_OR_JS_DECOY" and (non_rsc_decoys or not _recipe_uses_quickjs(recipe)):
                recipe["requiresWebViewCapture"] = True
                recipe["status"] = "DRAFT"
        status_tag = f"CREATED_{recipe['status']}"
    else:
        status_tag = "CREATED_DRAFT"

    ok, errs = validate_recipe(recipe, base_dir=os.path.dirname(recipes_dir) or BUNDLE_ROOT)
    if not ok:
        return None, f"Validation failed: {errs}"
    if apply:
        os.makedirs(recipes_dir, exist_ok=True)
        out_path = os.path.join(recipes_dir, f"{recipe['sourceId']}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(recipe, f, indent=2, ensure_ascii=False)
            f.write("\n")
    return recipe, status_tag


def sync_existing_recipes(
    recipes_dir,
    upstream_lookup,
    repo_dirs=None,
    apply=False,
    probe_live=False,
    fetcher=None,
    force_upstream_url=False,
    langs="es",
    deprecated_path=DEFAULT_DEPRECATED_PATH,
    probe_chapters=False,
):
    by_id, by_name, by_domain = upstream_lookup
    repo_dirs = repo_dirs or {}
    target_langs = parse_langs_arg(langs)
    deprecated_ids, deprecated_names = load_deprecated_sources(deprecated_path)
    reports = []

    for fname in sorted(os.listdir(recipes_dir)):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(recipes_dir, fname)
        with open(fpath, "r", encoding="utf-8") as f:
            recipe = json.load(f)

        if not lang_matches_filter(recipe.get("lang", "es"), target_langs):
            continue

        sid_str = str(recipe.get("sourceId", ""))
        uid_strs = {str(x) for x in (recipe.get("upstreamSourceIds") or [])}
        if recipe.get("upstreamSourceId") is not None:
            uid_strs.add(str(recipe["upstreamSourceId"]))
        if sid_str in deprecated_ids or (uid_strs & deprecated_ids) or normalize_key(recipe.get("name", "")) in deprecated_names:
            if recipe.get("status") != "DISABLED":
                recipe["status"] = "DISABLED"
                if apply:
                    with open(fpath, "w", encoding="utf-8") as f:
                        json.dump(recipe, f, indent=2, ensure_ascii=False)
                        f.write("\n")
                reports.append((fname, "DEPRECATED_DISABLED", recipe.get("baseUrl")))
            else:
                reports.append((fname, "DEPRECATED", recipe.get("baseUrl")))
            continue

        uid = recipe.get("upstreamSourceId")
        match = by_id.get(uid) if uid is not None else None
        if match is None:
            for extra_uid in recipe.get("upstreamSourceIds") or []:
                if extra_uid in by_id:
                    match = by_id[extra_uid]
                    break
        if match is None:
            dom = normalize_domain(recipe.get("baseUrl", ""))
            match = by_domain.get((recipe.get("lang", "es").lower(), dom))
        if match is None:
            match = by_name.get(normalize_key(recipe.get("name", "")))

        changes = []
        old_url = recipe["baseUrl"].rstrip("/")

        if match:
            new_url = match["baseUrl"].rstrip("/")
            old_vc = recipe.get("versionCode") or recipe.get("upstreamExtVersionCode")
            new_vc = match.get("versionCode") or match.get("extVersionCode")

            merged_sids = sorted(
                {
                    int(s)
                    for s in ([recipe.get("upstreamSourceId")] + list(recipe.get("upstreamSourceIds") or []) + list(match.get("upstreamSourceIds") or []))
                    if s is not None
                }
            )
            if merged_sids != (recipe.get("upstreamSourceIds") or []):
                recipe["upstreamSourceIds"] = merged_sids
                changes.append("MERGED_UPSTREAM_IDS")

            if recipe.get("upstreamSourceId") != match["sourceId"]:
                recipe["upstreamSourceId"] = match["sourceId"]
                changes.append("LINK_ID")

            norm_repo = normalize_upstream_repo(match.get("upstreamRepo"))
            if norm_repo and recipe.get("upstreamRepo") != norm_repo:
                recipe["upstreamRepo"] = norm_repo
                changes.append("LINK_REPO")

            if match.get("pkgName") and recipe.get("pkgName") != match["pkgName"]:
                recipe["pkgName"] = match["pkgName"]
                changes.append("PKG_NAME")

            if match.get("iconUrl") and validate_ssrf(match["iconUrl"])[0] and recipe.get("iconUrl") != match["iconUrl"]:
                recipe["iconUrl"] = match["iconUrl"]
                changes.append("ICON_URL")

            repo_meta = match.get("repoMeta")
            if repo_meta is None and match.get("openSource") and match["openSource"][0] in repo_dirs:
                repo_slug, _, src_dir, _ = match["openSource"]
                default_attr = match.get("defaultAttribution") or DEFAULT_ATTRIBUTIONS.get(
                    repo_slug, "Upstream Contributors"
                )
                repo_meta = read_extension_from_repo(
                    repo_dirs[repo_slug],
                    src_dir,
                    default_attribution=default_attr,
                )

            if repo_meta is not None:
                if not repo_meta["licenseOk"]:
                    reports.append((fname, f"SKIP_UNVERIFIED_LICENSE({repo_meta['license']})", old_url))
                    continue
                if recipe.get("license") != repo_meta["license"]:
                    recipe["license"] = repo_meta["license"]
                    changes.append("LICENSE")
                if repo_meta["attribution"] and recipe.get("attribution") != repo_meta["attribution"]:
                    recipe["attribution"] = repo_meta["attribution"]
                    changes.append("ATTRIBUTION")
                gradle = repo_meta.get("gradle")
                if gradle:
                    valid_mirrors = [m for m in gradle.get("mirrors", []) if validate_ssrf(m)[0]]
                    if valid_mirrors and valid_mirrors != recipe.get("mirrors", []):
                        recipe["mirrors"] = valid_mirrors
                        changes.append("NEW_MIRRORS")
                    if gradle.get("versionId", 1) != recipe.get("versionId", 1):
                        recipe["versionId"] = gradle["versionId"]
                        changes.append("VERSION_ID")

            if new_vc and old_vc != new_vc:
                recipe["upstreamExtVersionCode"] = new_vc
                recipe["versionCode"] = new_vc
                changes.append(f"VERSION_BUMPED({old_vc}->{new_vc})")

            domain_status = "OK"
            if new_url and new_url != old_url:
                ok_ssrf, err_ssrf = validate_ssrf(new_url)
                if not ok_ssrf:
                    domain_status = f"UNSAFE_DOMAIN_SKIPPED({err_ssrf})"
                else:
                    should_switch = force_upstream_url
                    if not should_switch:
                        mirrors = list(recipe.get("mirrors", []))
                        if new_url not in mirrors:
                            mirrors.append(new_url)
                            recipe["mirrors"] = mirrors
                            changes.append("RECORDED_UPSTREAM_MIRROR")
                        domain_status = f"DOMAIN_DRIFT({old_url} vs {new_url})"
                    if should_switch:
                        recipe["baseUrl"] = new_url
                        update_referer_in_recipe(recipe, old_url, new_url)
                        recipe["version"] = int(recipe.get("version", 1)) + 1
                        domain_status = f"DOMAIN_CHANGED({old_url}->{new_url})"
                        changes.append(domain_status)
        else:
            domain_status = "MISSING_UPSTREAM"

        if probe_live or fetcher is not None:
            is_active = recipe.get("status") == "ACTIVE"
            is_curated = recipe.get("curated") is True
            locked = _locked_field_set(recipe)
            smoke_ok, _, smoke_msg, updates = run_http_smoke_test(
                recipe,
                fetcher=fetcher,
                is_existing_active=is_active,
                probe_chapters=probe_chapters,
                auto_fix_chapters=False if is_curated else probe_chapters,
            )
            for k, v in updates.items():
                if k in locked:
                    continue
                if is_curated and is_active and k == "status" and v in ("DISABLED", "QUARANTINED"):
                    continue
                if recipe.get(k) != v:
                    recipe[k] = v
                    changes.append(f"SMOKE_{k.upper()}={v}")
            if not smoke_ok:
                if is_curated and is_active:
                    changes.append(f"CURATED_SMOKE_WARN:{smoke_msg}")
                elif f"SMOKE_{updates.get('status', '')}" not in changes:
                    changes.append(f"SMOKE:{smoke_msg}")

        if apply and changes:
            base_dir = os.path.dirname(os.path.abspath(recipes_dir))
            ok, errs = validate_recipe(recipe, base_dir=base_dir, expected_filename=fname)
            if not ok:
                reports.append((fname, f"INVALID_AFTER_PATCH:{errs}", old_url))
                continue
            with open(fpath, "w", encoding="utf-8") as f:
                json.dump(recipe, f, indent=2, ensure_ascii=False)
                f.write("\n")

        status = ", ".join(changes) if changes else domain_status
        reports.append((fname, status, recipe["baseUrl"]))

    return reports


def _is_specialized_recipe(recipe):
    if not isinstance(recipe, dict):
        return False
    if recipe.get("curated") is True or recipe.get("lockedFields"):
        return True
    if recipe.get("searchPath") or recipe.get("singlePostAsChapter") is True:
        return True
    if (recipe.get("chapterOrder") or "AS_IS") != "AS_IS":
        return True
    if recipe.get("preset") == "JSON_API":
        return True
    if recipe.get("family") and recipe.get("family") != "STANDARD":
        return True
    if recipe.get("popularRequest") or recipe.get("querySigner") or recipe.get("qwik") or recipe.get("inertia") or recipe.get("multiViewReader"):
        return True
    preset = recipe.get("preset", "CSS_GENERIC")
    default_sel = PRESET_DEFAULT_SELECTORS.get(preset, {})
    if recipe.get("selectors") and recipe.get("selectors") != default_sel:
        return True
    return False


def _merge_upstream_metadata_into_recipe(recipe, cand, repo_meta=None):
    updated = copy.deepcopy(recipe)
    locked = _locked_field_set(updated)
    merged_sids = sorted(
        {
            int(s)
            for s in ([updated.get("upstreamSourceId")] + list(updated.get("upstreamSourceIds") or []) + list(cand.get("upstreamSourceIds") or [cand.get("sourceId")]))
            if s is not None
        }
    )
    if "upstreamSourceIds" not in locked:
        updated["upstreamSourceIds"] = merged_sids
    if cand.get("sourceId") is not None and "upstreamSourceId" not in locked:
        updated["upstreamSourceId"] = int(cand["sourceId"])
    norm_repo = normalize_upstream_repo(cand.get("upstreamRepo"))
    if norm_repo and "upstreamRepo" not in locked:
        updated["upstreamRepo"] = norm_repo
    if cand.get("pkgName") and "pkgName" not in locked:
        updated["pkgName"] = cand["pkgName"]
    if cand.get("iconUrl") and validate_ssrf(cand["iconUrl"])[0] and "iconUrl" not in locked:
        updated["iconUrl"] = cand["iconUrl"]
    vc = cand.get("versionCode") or cand.get("extVersionCode")
    if vc:
        if "upstreamExtVersionCode" not in locked:
            updated["upstreamExtVersionCode"] = int(vc)
        if "versionCode" not in locked:
            updated["versionCode"] = int(vc)
    if repo_meta and repo_meta.get("licenseOk"):
        if "license" not in locked:
            updated["license"] = repo_meta["license"]
        if repo_meta.get("attribution") and "attribution" not in locked:
            updated["attribution"] = repo_meta["attribution"]
        if repo_meta.get("gradle") and "versionId" not in locked:
            updated["versionId"] = int(cand.get("versionId") or repo_meta["gradle"].get("versionId") or updated.get("versionId") or 1)
    else:
        if "license" not in locked:
            updated["license"] = updated.get("license") or "Apache-2.0"
        if "attribution" not in locked:
            updated["attribution"] = updated.get("attribution") or cand.get("defaultAttribution") or "Upstream Contributors"
    return updated


def _build_candidate_recipe_for_attempt(
    cand,
    source_id,
    existing_recipe=None,
    repo_dirs=None,
    gradle_theme=None,
    recipes_dir=DEFAULT_RECIPES_DIR,
    dedicated_recipes=None,
):
    repo_dirs = repo_dirs or {}
    up_repo = normalize_upstream_repo(cand.get("upstreamRepo"))
    attribution = cand.get("defaultAttribution") or DEFAULT_ATTRIBUTIONS.get(
        up_repo or "", "Mihon Declarative Catalog Contributors"
    )
    repo_meta = cand.get("repoMeta")
    if repo_meta is None and cand.get("openSource") and cand["openSource"][0] in repo_dirs:
        repo_slug, _, src_dir, _ = cand["openSource"]
        repo_meta = read_extension_from_repo(repo_dirs[repo_slug], src_dir, default_attribution=attribution)
    if repo_meta is None and gradle_theme is not None:
        repo_meta = {
            "licenseOk": True,
            "license": "Apache-2.0",
            "attribution": attribution,
            "gradle": {"theme": gradle_theme, "versionId": cand.get("versionId", 1)},
            "kotlinText": "",
            "themeKotlinText": "",
        }

    if existing_recipe is not None and _is_specialized_recipe(existing_recipe):
        if repo_meta is not None and not repo_meta.get("licenseOk"):
            return None, None, "REJECTED_LICENSE", repo_meta["license"]
        rec = _merge_upstream_metadata_into_recipe(existing_recipe, cand, repo_meta=repo_meta)
        return rec, repo_meta, "SPECIALIZED", ""

    if repo_meta is None or not repo_meta.get("licenseOk"):
        reason = repo_meta["license"] if repo_meta and repo_meta.get("license") else "UNVERIFIED_LICENSE"
        return None, repo_meta, "REJECTED_LICENSE", reason

    license_id = repo_meta["license"]
    if repo_meta.get("attribution"):
        attribution = repo_meta["attribution"]

    gradle = repo_meta.get("gradle") or {}
    theme = gradle.get("theme")
    norm_theme = (theme or "").strip().lower()
    preset = preset_from_theme(theme)
    version_id = int(cand.get("versionId") or gradle.get("versionId") or 1)
    kotlin_text = repo_meta.get("kotlinText", "")
    theme_kotlin_text = repo_meta.get("themeKotlinText", "")
    gradle_text = (repo_meta or {}).get("gradleText") or ""
    kotlin_hint = repo_meta.get("kotlinHint") or (inspect_open_source_kotlin(kotlin_text) if kotlin_text else {})

    mirrors = [m for m in (list(cand.get("mirrors") or []) + list(gradle.get("mirrors") or [])) if validate_ssrf(m)[0]]
    dedup_mirrors = []
    for m in mirrors:
        if m not in dedup_mirrors:
            dedup_mirrors.append(m)

    base_url = (cand.get("baseUrl") or gradle.get("baseUrl") or "").rstrip("/")
    ok_ssrf, err_ssrf = validate_ssrf(base_url)
    if not ok_ssrf:
        return None, repo_meta, "SSRF_REJECTED", err_ssrf

    catalog_path, use_home_fallback = _default_catalog_path_for_preset(preset, kotlin_hint, theme=theme)
    recipe = build_recipe_dict(
        source_id=source_id,
        name=cand["name"],
        base_url=base_url,
        preset=preset,
        lang=cand["lang"],
        catalog_path=catalog_path,
        version_id=version_id,
        use_home_fallback=use_home_fallback,
        mirrors=dedup_mirrors,
        icon_url=cand.get("iconUrl"),
        pkg_name=cand.get("pkgName"),
        upstream_source_id=cand["sourceId"],
        upstream_source_ids=cand.get("upstreamSourceIds"),
        upstream_version_code=cand.get("versionCode"),
        upstream_repo=up_repo,
        license_id=license_id,
        attribution=attribution,
        status="DRAFT",
        theme=theme,
        kotlin_text=kotlin_text,
    )
    if norm_theme in SUPPORTED_EXTRA_THEMES:
        recipe = apply_extra_theme_to_recipe(recipe, theme, base_url, kotlin_text=kotlin_text)
    elif norm_theme in SUPPORTED_MULTISRC_THEMES:
        apply_multisrc_theme_to_recipe(recipe, norm_theme, base_url, kotlin_text=kotlin_text)

    is_supported = (
        (not theme)
        or (norm_theme in SUPPORTED_THEMES)
        or (norm_theme in SUPPORTED_EXTRA_THEMES)
        or (norm_theme in SUPPORTED_MULTISRC_THEMES)
    )

    if (not is_supported or not theme) and (kotlin_text or theme_kotlin_text):
        kt_synth = synthesize_recipe_from_kotlin(
            kotlin_text=kotlin_text or theme_kotlin_text,
            source_id=source_id,
            name=cand["name"],
            base_url=base_url,
            lang=cand["lang"],
            pkg_name=cand.get("pkgName"),
            version_code=int(cand.get("versionCode") or 1),
            upstream_source_id=cand.get("sourceId"),
            upstream_repo=up_repo,
            attribution=attribution,
            license_id=license_id,
            gradle_text=gradle_text,
        )
        if kt_synth:
            if kt_synth.get("preset") == "JSON_API" and kt_synth.get("jsonApi"):
                recipe["preset"] = "JSON_API"
                recipe["jsonApi"] = kt_synth["jsonApi"]
                recipe["selectors"] = None
                is_supported = True
            elif kt_synth.get("selectors") and kt_synth["selectors"].get("listSelector"):
                recipe["selectors"] = kt_synth["selectors"]
                if kt_synth.get("catalogPath"):
                    recipe["catalogPath"] = kt_synth["catalogPath"]
                is_supported = True
            for opt_key in ("pipelineSteps", "listPipelineSteps", "chaptersPipelineSteps", "querySigner", "authPreFlight"):
                if kt_synth.get(opt_key) is not None and not recipe.get(opt_key):
                    recipe[opt_key] = kt_synth[opt_key]

    # Select Kotlin scope for primitive mapping and residual blocker checks:
    # - Known themes (except iken/heancms) isolate to extension's own kotlin_text.
    # - iken/heancms and unmapped themes also inspect theme_kotlin_text.
    if norm_theme in ("iken", "heancms") or not is_supported:
        inspect_kt = f"{kotlin_text}\n{theme_kotlin_text}".strip()
    else:
        inspect_kt = kotlin_text

    if inspect_kt or gradle_text:
        extracted_steps = extract_pipeline_steps_from_kotlin(inspect_kt, gradle_text=gradle_text)
        if extracted_steps:
            existing_steps = list(recipe.get("pipelineSteps") or [])
            seen_ops = {s.get("op") for s in existing_steps if isinstance(s, dict)}
            for st in extracted_steps:
                if st.get("op") not in seen_ops or st.get("op") == "quickjs_eval":
                    if len(existing_steps) < 12:
                        existing_steps.append(st)
                        seen_ops.add(st.get("op"))
            recipe["pipelineSteps"] = existing_steps
            rsc_steps = [s for s in extracted_steps if s.get("op") == "quickjs_eval" and s.get("preset") == "NEXT_RSC"]
            if rsc_steps:
                if recipe.get("preset") == "JSON_API" and isinstance(recipe.get("jsonApi"), dict):
                    ml = recipe["jsonApi"].setdefault("mangaList", {"itemsPath": "$.data[*]"})
                    ml.setdefault("pipelineSteps", [])
                    if not any(s.get("op") == "quickjs_eval" for s in ml["pipelineSteps"]):
                        ml["pipelineSteps"].extend(rsc_steps)
                elif not recipe.get("listPipelineSteps"):
                    recipe["listPipelineSteps"] = list(rsc_steps)
            if recipe.get("preset") == "JSON_API" and isinstance(recipe.get("jsonApi"), dict):
                page_steps = [
                    s
                    for s in extracted_steps
                    if s.get("op") in ("dynamic_crypto", "aes_ecb_decrypt", "openssl_salted_decrypt", "lz_string", "gzip_decompress", "deflate_decompress")
                    or (s.get("op") == "quickjs_eval" and s.get("preset") != "NEXT_RSC")
                ]
                if page_steps:
                    pg = recipe["jsonApi"].setdefault("pages", {"itemsPath": "$.data[*]"})
                    pg.setdefault("pipelineSteps", [])
                    for ps in page_steps:
                        if len(pg["pipelineSteps"]) < 12:
                            pg["pipelineSteps"].append(ps)

        if not recipe.get("querySigner"):
            qs_spec = extract_query_signer_spec(inspect_kt)
            if qs_spec:
                recipe["querySigner"] = qs_spec

        if not recipe.get("authPreFlight"):
            preflight = detect_and_build_auth_preflight(inspect_kt, base_url)
            if preflight:
                recipe["authPreFlight"] = preflight

    if existing_recipe:
        for keep_key in (
            "accountSync",
            "authPreFlight",
            "listPipelineSteps",
            "chaptersPipelineSteps",
            "querySigner",
            "searchPath",
            "catalogPath",
            "headers",
            "useHomeFallback",
            "chapterOrder",
            "singlePostAsChapter",
            "curated",
            "lockedFields",
        ):
            if existing_recipe.get(keep_key) is not None and (recipe.get(keep_key) is None or keep_key in ("searchPath", "catalogPath", "headers", "useHomeFallback", "chapterOrder", "singlePostAsChapter", "curated", "lockedFields")):
                recipe[keep_key] = copy.deepcopy(existing_recipe[keep_key])

    has_unresolved, unresolved_reasons = has_unresolved_native_primitives(
        inspect_kt,
        gradle_text=gradle_text,
        recipe=recipe,
    )
    if "MangaFire" in inspect_kt and not recipe.get("querySigner"):
        has_unresolved = True
        if "VRF_SIGNING" not in unresolved_reasons:
            unresolved_reasons.append("MangaFire VRF")
    if has_unresolved:
        dedicated = _find_dedicated_native_recipe(
            recipes_dir,
            cand.get("sourceId"),
            cand.get("name", ""),
            base_url=base_url,
            pkg_name=cand.get("pkgName"),
            dedicated_recipes=dedicated_recipes,
        )
        if dedicated is not None and _is_multilang_compatible_dedicated(dedicated, cand, base_url):
            inherited = _inherit_dedicated_native_recipe(
                dedicated,
                cand,
                source_id=source_id,
                base_url=base_url,
                mirrors=dedup_mirrors,
                license_id=license_id,
                attribution=attribution,
                upstream_repo=up_repo,
                version_id=version_id,
            )
            ok_inh, _ = validate_recipe(inherited, base_dir=BUNDLE_ROOT)
            if ok_inh:
                return inherited, repo_meta, "DECLARATIVE", ""
        return (
            None,
            repo_meta,
            "STATIC_NEEDS_PRIMITIVE",
            f"Kotlin native complexity (unresolvable): {', '.join(unresolved_reasons)}",
        )

    ok_rec, errs_rec = validate_recipe(recipe, base_dir=BUNDLE_ROOT)
    if not ok_rec:
        return None, repo_meta, "STATIC_NEEDS_PRIMITIVE", f"Synthesized recipe validation failed: {errs_rec}"

    kind = "DECLARATIVE" if is_supported else "UNMAPPED_THEME"
    return recipe, repo_meta, kind, ""


def _evaluate_candidate_group_live(job, fetcher=None, timeout=10, include_nsfw=False, include_cloudflare=False, probe_chapters=False):
    """Evaluate a deduplicated candidate group with cross-repo fallback and redirect adoption."""
    cand = job["cand"]
    existing_recipe = job["existingRecipe"]
    source_id = job["sourceId"]
    repo_dirs = job["repoDirs"]
    attempt_chain = [cand] + list(cand.get("alternatives") or [])

    # Deduplicate attempts that have identical (upstreamRepo, sourceId, baseUrl)
    filtered_chain = []
    seen_attempts = set()
    for item in attempt_chain:
        key = (item.get("upstreamRepo"), item.get("sourceId"), item.get("baseUrl"))
        if key not in seen_attempts:
            seen_attempts.add(key)
            filtered_chain.append(item)

    primary_repo = cand.get("upstreamRepo")
    primary_failure_reason = None
    primary_record = None
    fallback_failures = []
    last_record = None
    last_license_err = None

    def _record_attempt_failure(attempt_idx, attempt_obj, rec_obj):
        nonlocal primary_record, last_record
        last_record = rec_obj
        if attempt_idx == 0 and primary_record is None:
            primary_record = rec_obj
        elif attempt_idx > 0:
            fb_repo = attempt_obj.get("upstreamRepo") or "?"
            fb_cat = rec_obj.get("category") or "?"
            fb_sub = rec_obj.get("subReason") or rec_obj.get("primaryCapability") or ""
            fallback_failures.append(f"{fb_repo}: {fb_cat}" + (f" ({fb_sub})" if fb_sub else ""))

    for attempt_idx, attempt in enumerate(filtered_chain):
        is_fallback = attempt_idx > 0 and attempt.get("upstreamRepo") != primary_repo
        # Check NSFW per attempt too
        if attempt.get("isNsfw") and not include_nsfw:
            if attempt_idx == 0:
                return None, {
                    "sourceId": source_id,
                    "name": cand["name"],
                    "lang": cand["lang"],
                    "upstreamRepo": attempt.get("upstreamRepo"),
                    "baseUrl": attempt.get("baseUrl"),
                    "category": "EXCLUDED_NSFW",
                    "detail": "ContentWarning.NSFW / isNsfw=true",
                }
            continue

        recipe, repo_meta, kind, err_msg = _build_candidate_recipe_for_attempt(
            attempt,
            source_id=source_id,
            existing_recipe=existing_recipe if attempt_idx == 0 or _is_specialized_recipe(existing_recipe) else None,
            repo_dirs=repo_dirs,
            recipes_dir=job.get("recipesDir", DEFAULT_RECIPES_DIR),
            dedicated_recipes=job.get("dedicatedRecipes"),
        )

        gradle = (repo_meta or {}).get("gradle") or {}
        theme = gradle.get("theme")
        gradle_text = (repo_meta or {}).get("gradleText") or ""
        kotlin_text = (repo_meta or {}).get("kotlinText") or ""
        theme_kotlin_text = (repo_meta or {}).get("themeKotlinText") or ""

        if kind == "REJECTED_LICENSE":
            last_license_err = err_msg
            rec_obj = {
                "sourceId": source_id,
                "name": attempt["name"],
                "lang": attempt["lang"],
                "upstreamRepo": attempt.get("upstreamRepo"),
                "baseUrl": attempt.get("baseUrl"),
                "category": "REJECTED_LICENSE",
                "subReason": err_msg or "UNVERIFIED_LICENSE",
                "detail": err_msg or "UNVERIFIED_LICENSE",
            }
            _record_attempt_failure(attempt_idx, attempt, rec_obj)
            if attempt_idx == 0:
                primary_failure_reason = f"Licencia ({err_msg})"
            continue

        if kind == "SSRF_REJECTED":
            rec_obj = {
                "sourceId": source_id,
                "name": attempt["name"],
                "lang": attempt["lang"],
                "upstreamRepo": attempt.get("upstreamRepo"),
                "baseUrl": attempt.get("baseUrl"),
                "category": "DOWN_OR_NONEXISTENT",
                "subReason": "SSRF_REJECTED",
                "detail": f"SSRF rechazado: {err_msg}",
            }
            _record_attempt_failure(attempt_idx, attempt, rec_obj)
            if attempt_idx == 0:
                primary_failure_reason = f"SSRF ({err_msg})"
            continue

        if kind == "STATIC_NEEDS_PRIMITIVE":
            primary_cap, all_caps, cap_reasons = classify_missing_primitives(
                theme=theme,
                gradle_text=gradle_text,
                kotlin_text=kotlin_text,
                theme_kotlin_text=theme_kotlin_text,
            )
            rec_obj = {
                "sourceId": source_id,
                "name": attempt["name"],
                "lang": attempt["lang"],
                "upstreamRepo": attempt.get("upstreamRepo"),
                "baseUrl": attempt.get("baseUrl"),
                "category": "NEEDS_PRIMITIVE",
                "primaryCapability": primary_cap,
                "allCapabilities": all_caps,
                "detail": "; ".join(cap_reasons) or primary_cap,
            }
            _record_attempt_failure(attempt_idx, attempt, rec_obj)
            if attempt_idx == 0:
                primary_failure_reason = primary_cap
            continue

        # Run live probe for SPECIALIZED, DECLARATIVE, or UNMAPPED_THEME (for accurate WAF/Down vs Theme classification)
        is_existing_active = bool(existing_recipe and existing_recipe.get("status") == "ACTIVE")
        is_curated = recipe.get("curated") is True
        smoke_ok, items_cnt, smoke_msg, updates, details = run_http_smoke_test(
            recipe,
            fetcher=fetcher,
            timeout=timeout,
            is_existing_active=is_existing_active,
            allow_redirect_adopt=True,
            return_details=True,
            include_cloudflare=include_cloudflare,
            probe_chapters=probe_chapters,
            auto_fix_chapters=False if is_curated else probe_chapters,
        )

        # If an existing specialized recipe failed on its saved baseUrl AND upstream has a different URL, try upstream URL too
        if (
            not smoke_ok
            and existing_recipe is not None
            and _is_specialized_recipe(existing_recipe)
            and normalize_domain(attempt.get("baseUrl", "")) != normalize_domain(recipe.get("baseUrl", ""))
            and validate_ssrf(attempt.get("baseUrl", ""))[0]
        ):
            alt_recipe, alt_updates = _adopt_domain_updates(
                recipe,
                recipe["baseUrl"].rstrip("/"),
                attempt["baseUrl"].rstrip("/"),
            )
            smoke_ok2, items_cnt2, smoke_msg2, updates2, details2 = run_http_smoke_test(
                alt_recipe,
                fetcher=fetcher,
                timeout=timeout,
                is_existing_active=is_existing_active,
                allow_redirect_adopt=True,
                return_details=True,
                include_cloudflare=include_cloudflare,
            )
            if smoke_ok2:
                recipe = alt_recipe
                updates = {**alt_updates, **updates2}
                smoke_ok, items_cnt, smoke_msg, details = smoke_ok2, items_cnt2, smoke_msg2, details2

        if kind == "UNMAPPED_THEME":
            cat = details.get("category")
            if cat in ("CLOUDFLARE_ANTIBOT", "DOWN_OR_NONEXISTENT", "DOMAIN_CHANGE_FAILED"):
                rec_obj = {
                    "sourceId": source_id,
                    "name": attempt["name"],
                    "lang": attempt["lang"],
                    "upstreamRepo": attempt.get("upstreamRepo"),
                    "baseUrl": attempt.get("baseUrl"),
                    "finalUrl": details.get("finalUrl"),
                    "category": cat,
                    "subReason": details.get("subReason"),
                    "domainChangeFailed": details.get("domainChangeFailed", False),
                    "redirectedFrom": details.get("redirectedFrom"),
                    "redirectedTo": details.get("redirectedTo"),
                    "detail": smoke_msg,
                }
                _record_attempt_failure(attempt_idx, attempt, rec_obj)
                if attempt_idx == 0:
                    primary_failure_reason = smoke_msg
                continue
            # Live site responded (200 or redirect to live 200), classify by missing theme primitive
            primary_cap, all_caps, cap_reasons = classify_missing_primitives(
                theme=theme,
                gradle_text=gradle_text,
                kotlin_text=kotlin_text,
                theme_kotlin_text=theme_kotlin_text,
                http_status=details.get("httpStatus", 200),
                html_sample=details.get("bodySample", ""),
                headers=details.get("headers"),
            )
            rec_obj = {
                "sourceId": source_id,
                "name": attempt["name"],
                "lang": attempt["lang"],
                "upstreamRepo": attempt.get("upstreamRepo"),
                "baseUrl": attempt.get("baseUrl"),
                "finalUrl": details.get("finalUrl"),
                "category": "NEEDS_PRIMITIVE",
                "primaryCapability": primary_cap,
                "allCapabilities": all_caps,
                "detail": "; ".join(cap_reasons) or f"Tema no soportado: {theme}",
            }
            if details.get("domainAdopted"):
                rec_obj["redirectedFrom"] = details.get("redirectedFrom")
                rec_obj["redirectedTo"] = details.get("redirectedTo")
            _record_attempt_failure(attempt_idx, attempt, rec_obj)
            if attempt_idx == 0:
                primary_failure_reason = primary_cap
            continue

        if smoke_ok:
            locked = _locked_field_set(recipe)
            for k, v in updates.items():
                if k not in locked:
                    recipe[k] = v
            recipe["status"] = "ACTIVE"
            if updates.get("requiresCloudflareBypass") or details.get("requiresCloudflareBypass"):
                recipe["requiresCloudflareBypass"] = True
                recipe["requiresWebViewCapture"] = False
            if existing_recipe is None:
                recipe["version"] = 1
            rec_diag = {
                "sourceId": source_id,
                "name": recipe["name"],
                "lang": recipe["lang"],
                "upstreamRepo": attempt.get("upstreamRepo"),
                "baseUrl": recipe["baseUrl"],
                "finalUrl": details.get("finalUrl") or recipe["baseUrl"],
                "category": "VIABLE",
                "domainAdopted": bool(details.get("domainAdopted")),
                "redirectedFrom": details.get("redirectedFrom"),
                "redirectedTo": details.get("redirectedTo"),
                "fallbackUsed": is_fallback,
                "fallbackFromRepo": primary_repo if is_fallback else None,
                "fallbackPrimaryFailure": primary_failure_reason if is_fallback else None,
                "itemsFound": items_cnt,
                "detail": smoke_msg,
            }
            if recipe.get("requiresCloudflareBypass"):
                rec_diag["requiresCloudflareBypass"] = True
            return recipe, rec_diag

        cat = details.get("category") or "DOWN_OR_NONEXISTENT"
        if cat == "NEEDS_PRIMITIVE":
            if details.get("subReason") == "CHAPTERS_EMPTY":
                rec_obj = {
                    "sourceId": source_id,
                    "name": attempt["name"],
                    "lang": attempt["lang"],
                    "upstreamRepo": attempt.get("upstreamRepo"),
                    "baseUrl": attempt.get("baseUrl"),
                    "finalUrl": details.get("finalUrl"),
                    "category": "NEEDS_PRIMITIVE",
                    "subReason": "CHAPTERS_EMPTY",
                    "primaryCapability": "CHAPTERS_EMPTY",
                    "allCapabilities": ["CHAPTERS_EMPTY"],
                    "detail": details.get("detail") or smoke_msg,
                }
            else:
                primary_cap, all_caps, cap_reasons = classify_missing_primitives(
                    theme=theme,
                    gradle_text=gradle_text,
                    kotlin_text=kotlin_text,
                    theme_kotlin_text=theme_kotlin_text,
                    http_status=details.get("httpStatus", 0),
                    html_sample=details.get("bodySample", ""),
                    headers=details.get("headers"),
                    family=recipe.get("family"),
                )
                rec_obj = {
                    "sourceId": source_id,
                    "name": attempt["name"],
                    "lang": attempt["lang"],
                    "upstreamRepo": attempt.get("upstreamRepo"),
                    "baseUrl": attempt.get("baseUrl"),
                    "finalUrl": details.get("finalUrl"),
                    "category": "NEEDS_PRIMITIVE",
                    "primaryCapability": primary_cap,
                    "allCapabilities": all_caps,
                    "detail": f"{smoke_msg} ({'; '.join(cap_reasons)})" if cap_reasons else smoke_msg,
                }
        else:
            rec_obj = {
                "sourceId": source_id,
                "name": attempt["name"],
                "lang": attempt["lang"],
                "upstreamRepo": attempt.get("upstreamRepo"),
                "baseUrl": attempt.get("baseUrl"),
                "finalUrl": details.get("finalUrl"),
                "category": cat,
                "subReason": details.get("subReason"),
                "domainChangeFailed": details.get("domainChangeFailed", False),
                "redirectedFrom": details.get("redirectedFrom"),
                "redirectedTo": details.get("redirectedTo"),
                "detail": smoke_msg,
            }
        _record_attempt_failure(attempt_idx, attempt, rec_obj)
        if attempt_idx == 0:
            primary_failure_reason = smoke_msg

    chosen = primary_record if primary_record is not None else last_record
    if chosen is not None:
        if fallback_failures:
            chosen = dict(chosen)
            chosen["fallbackAttempted"] = True
            chosen["fallbackFailures"] = fallback_failures
            fb_note = "; ".join(fallback_failures)
            chosen["detail"] = f"{chosen.get('detail') or ''} [fallback también falló: {fb_note}]".strip()
        return None, chosen

    return None, {
        "sourceId": source_id,
        "name": cand["name"],
        "lang": cand["lang"],
        "upstreamRepo": cand.get("upstreamRepo"),
        "baseUrl": cand.get("baseUrl"),
        "category": "REJECTED_LICENSE",
        "detail": last_license_err or "UNVERIFIED_LICENSE",
    }


def _allocate_source_id(cand, used_ids):
    lang_prefix = (cand.get("lang") or "en").strip().lower()
    slug_raw = ""
    if cand.get("openSource") and cand["openSource"][3]:
        slug_raw = cand["openSource"][3]
    else:
        slug_raw = cand.get("name") or str(cand.get("sourceId"))
    safe_slug = re.sub(r"[^a-z0-9_]", "_", slug_raw.lower()).strip("_") or f"src_{cand['sourceId']}"
    base_id = f"{lang_prefix}.{safe_slug}"
    if base_id not in used_ids:
        used_ids.add(base_id)
        return base_id

    name_slug = re.sub(r"[^a-z0-9_]", "_", normalize_key(cand.get("name", "")) or safe_slug).strip("_")
    cand_id = f"{lang_prefix}.{safe_slug}_{name_slug}"
    if cand_id not in used_ids:
        used_ids.add(cand_id)
        return cand_id

    vid = int(cand.get("versionId") or 1)
    cand_id2 = f"{lang_prefix}.{safe_slug}_v{vid}"
    if cand_id2 not in used_ids:
        used_ids.add(cand_id2)
        return cand_id2

    cand_id3 = f"{lang_prefix}.{safe_slug}_{abs(int(cand['sourceId'])) % 100000}"
    if cand_id3 not in used_ids:
        used_ids.add(cand_id3)
        return cand_id3

    suffix_idx = 2
    while True:
        cand_id_n = f"{cand_id3}_{suffix_idx}"
        if cand_id_n not in used_ids:
            used_ids.add(cand_id_n)
            return cand_id_n
        suffix_idx += 1


def sync_all_catalog(
    recipes_dir,
    upstream_catalog,
    repo_dirs=None,
    apply=False,
    probe_live=True,
    only_working=True,
    include_nsfw=False,
    include_cloudflare=False,
    langs="es,en,pt",
    deprecated_path=DEFAULT_DEPRECATED_PATH,
    workers=16,
    fetcher=None,
    timeout=10,
    report_out=None,
    probe_chapters=False,
):
    """Process all candidates from Keiyoushi and FelipeGFA, test live, write working recipes & R2 report."""
    repo_dirs = repo_dirs or {}
    target_langs = parse_langs_arg(langs)
    deprecated_ids, deprecated_names = load_deprecated_sources(deprecated_path)

    existing_recipes = {}
    existing_by_uid = {}
    existing_by_domain = {}
    existing_by_name = {}
    if recipes_dir and os.path.isdir(recipes_dir):
        for fname in sorted(os.listdir(recipes_dir)):
            if not fname.endswith(".json"):
                continue
            fpath = os.path.join(recipes_dir, fname)
            with open(fpath, "r", encoding="utf-8") as f:
                rec = json.load(f)
            existing_recipes[fname] = rec
            for uid in [rec.get("upstreamSourceId")] + list(rec.get("upstreamSourceIds") or []):
                if uid is not None:
                    existing_by_uid.setdefault(int(uid), []).append((fname, rec))
            dom = normalize_domain(rec.get("baseUrl", ""))
            if dom:
                existing_by_domain.setdefault((rec.get("lang", "").lower(), dom), []).append((fname, rec))
            nk = normalize_key(rec.get("name", ""))
            if nk:
                existing_by_name.setdefault((rec.get("lang", "").lower(), nk), []).append((fname, rec))

    def _pick_existing_match(cand):
        lang_l = (cand.get("lang") or "").lower()
        hits = []
        for uid in cand.get("upstreamSourceIds") or [cand.get("sourceId")]:
            if uid is not None and int(uid) in existing_by_uid:
                hits.extend(existing_by_uid[int(uid)])
        dom = normalize_domain(cand.get("baseUrl", ""))
        if dom and (lang_l, dom) in existing_by_domain:
            hits.extend(existing_by_domain[(lang_l, dom)])
        nk = normalize_key(cand.get("name", ""))
        if nk and (lang_l, nk) in existing_by_name:
            hits.extend(existing_by_name[(lang_l, nk)])
        if not hits:
            return None, None
        # Prefer specialized recipes & exact lang match
        hits_sorted = sorted(
            hits,
            key=lambda pair: (
                1 if pair[1].get("lang", "").lower() == lang_l else 0,
                1 if _is_specialized_recipe(pair[1]) else 0,
                1 if pair[1].get("status") == "ACTIVE" else 0,
            ),
            reverse=True,
        )
        return hits_sorted[0]

    records = []
    jobs = []
    used_source_ids = {
        rec["sourceId"]
        for rec in existing_recipes.values()
        if rec.get("sourceId")
    }
    matched_existing_fnames = set()
    dedicated_pool = list(existing_recipes.values())

    for cand in upstream_catalog.get("candidates", []):
        matched_fname, matched_recipe = _pick_existing_match(cand)
        if matched_fname and matched_fname not in matched_existing_fnames:
            matched_existing_fnames.add(matched_fname)
            sid = matched_recipe["sourceId"]
            used_source_ids.add(sid)
        else:
            matched_recipe = None
            sid = _allocate_source_id(cand, used_source_ids)

        all_cand_sids = {str(s) for s in (cand.get("upstreamSourceIds") or [cand["sourceId"]])}
        if (
            sid in deprecated_ids
            or (all_cand_sids & deprecated_ids)
            or normalize_key(cand.get("name", "")) in deprecated_names
        ):
            records.append(
                {
                    "sourceId": sid,
                    "name": cand["name"],
                    "lang": cand["lang"],
                    "upstreamRepo": cand.get("upstreamRepo"),
                    "baseUrl": cand.get("baseUrl"),
                    "category": "DOWN_OR_NONEXISTENT",
                    "subReason": "DEPRECATED",
                    "detail": "Listado en deprecated_sources.json",
                }
            )
            continue

        if cand.get("isNsfw") and not include_nsfw:
            records.append(
                {
                    "sourceId": sid,
                    "name": cand["name"],
                    "lang": cand["lang"],
                    "upstreamRepo": cand.get("upstreamRepo"),
                    "baseUrl": cand.get("baseUrl"),
                    "category": "EXCLUDED_NSFW",
                    "detail": "Excluida por filtro NSFW (ContentWarning.NSFW / isNsfw=true)",
                }
            )
            continue

        jobs.append(
            {
                "cand": cand,
                "existingRecipe": matched_recipe,
                "sourceId": sid,
                "repoDirs": repo_dirs,
                "recipesDir": recipes_dir,
                "dedicatedRecipes": dedicated_pool,
            }
        )

    # Also handle unmatched existing recipes in target languages (orphaned / custom recipes)
    orphan_jobs = []
    for fname, rec in existing_recipes.items():
        if fname in matched_existing_fnames:
            continue
        if not lang_matches_filter(rec.get("lang", "es"), target_langs):
            continue
        sid = rec.get("sourceId", "")
        uid_strs = {str(x) for x in (rec.get("upstreamSourceIds") or [])}
        if rec.get("upstreamSourceId") is not None:
            uid_strs.add(str(rec["upstreamSourceId"]))
        if sid in deprecated_ids or (uid_strs & deprecated_ids) or normalize_key(rec.get("name", "")) in deprecated_names:
            records.append(
                {
                    "sourceId": sid,
                    "name": rec.get("name"),
                    "lang": rec.get("lang"),
                    "upstreamRepo": rec.get("upstreamRepo"),
                    "baseUrl": rec.get("baseUrl"),
                    "category": "DOWN_OR_NONEXISTENT",
                    "subReason": "DEPRECATED",
                    "detail": "Receta existente marcada en deprecated_sources.json",
                }
            )
            continue
        orphan_jobs.append(rec)

    active_recipes = []
    max_workers = max(1, int(workers or 1))

    if probe_live or fetcher is not None:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            future_map = {
                pool.submit(
                    _evaluate_candidate_group_live,
                    job,
                    fetcher=fetcher,
                    timeout=timeout,
                    include_nsfw=include_nsfw,
                    include_cloudflare=include_cloudflare,
                    probe_chapters=probe_chapters,
                ): job
                for job in jobs
            }
            for fut in as_completed(future_map):
                job = future_map[fut]
                try:
                    rec_out, diag_rec = fut.result()
                except Exception as exc:
                    cand = job["cand"]
                    records.append(
                        {
                            "sourceId": job["sourceId"],
                            "name": cand.get("name") or job["sourceId"],
                            "lang": cand.get("lang") or "?",
                            "upstreamRepo": cand.get("upstreamRepo"),
                            "baseUrl": cand.get("baseUrl"),
                            "category": "DOWN_OR_NONEXISTENT",
                            "subReason": classify_down_reason(0, str(exc), ""),
                            "detail": f"Error inesperado en evaluación: {exc}",
                        }
                    )
                    continue
                records.append(diag_rec)
                if rec_out is not None:
                    active_recipes.append(rec_out)

            if orphan_jobs:
                orphan_futs = {
                    pool.submit(
                        run_http_smoke_test,
                        rec,
                        fetcher=fetcher,
                        timeout=timeout,
                        is_existing_active=(rec.get("status") == "ACTIVE"),
                        allow_redirect_adopt=True,
                        return_details=True,
                        include_cloudflare=include_cloudflare,
                        probe_chapters=probe_chapters,
                        auto_fix_chapters=probe_chapters,
                    ): rec
                    for rec in orphan_jobs
                }
                for fut in as_completed(orphan_futs):
                    orig_rec = orphan_futs[fut]
                    try:
                        ok_o, cnt_o, msg_o, upd_o, det_o = fut.result()
                    except Exception as exc:
                        records.append(
                            {
                                "sourceId": orig_rec["sourceId"],
                                "name": orig_rec.get("name"),
                                "lang": orig_rec.get("lang"),
                                "upstreamRepo": orig_rec.get("upstreamRepo"),
                                "baseUrl": orig_rec.get("baseUrl"),
                                "category": "DOWN_OR_NONEXISTENT",
                                "subReason": classify_down_reason(0, str(exc), ""),
                                "detail": f"Error inesperado en verificación local: {exc}",
                            }
                        )
                        continue
                    if ok_o:
                        kept = copy.deepcopy(orig_rec)
                        kept.update(upd_o)
                        kept["status"] = "ACTIVE"
                        if det_o.get("requiresCloudflareBypass"):
                            kept["requiresCloudflareBypass"] = True
                        elif "requiresCloudflareBypass" in kept and not kept.get("requiresCloudflareBypass"):
                            kept.pop("requiresCloudflareBypass", None)
                        active_recipes.append(kept)
                        records.append(
                            {
                                "sourceId": kept["sourceId"],
                                "name": kept["name"],
                                "lang": kept["lang"],
                                "upstreamRepo": kept.get("upstreamRepo"),
                                "baseUrl": kept["baseUrl"],
                                "finalUrl": det_o.get("finalUrl") or kept["baseUrl"],
                                "category": "VIABLE",
                                "domainAdopted": bool(det_o.get("domainAdopted")),
                                "redirectedFrom": det_o.get("redirectedFrom"),
                                "redirectedTo": det_o.get("redirectedTo"),
                                "itemsFound": cnt_o,
                                "requiresCloudflareBypass": bool(det_o.get("requiresCloudflareBypass")),
                                "detail": f"Receta local preservada: {msg_o}",
                            }
                        )
                    else:
                        records.append(
                            {
                                "sourceId": orig_rec["sourceId"],
                                "name": orig_rec["name"],
                                "lang": orig_rec["lang"],
                                "upstreamRepo": orig_rec.get("upstreamRepo"),
                                "baseUrl": orig_rec["baseUrl"],
                                "finalUrl": det_o.get("finalUrl"),
                                "category": det_o.get("category") or "DOWN_OR_NONEXISTENT",
                                "subReason": det_o.get("subReason"),
                                "domainChangeFailed": det_o.get("domainChangeFailed", False),
                                "redirectedFrom": det_o.get("redirectedFrom"),
                                "redirectedTo": det_o.get("redirectedTo"),
                                "detail": msg_o,
                            }
                        )
    else:
        for job in jobs:
            cand = job["cand"]
            recipe, repo_meta, kind, err_msg = _build_candidate_recipe_for_attempt(
                cand,
                source_id=job["sourceId"],
                existing_recipe=job["existingRecipe"],
                repo_dirs=repo_dirs,
            )
            if recipe is not None and kind in ("DECLARATIVE", "SPECIALIZED"):
                recipe["status"] = "ACTIVE" if not only_working else (job["existingRecipe"] or {}).get("status", "DRAFT")
                if not only_working or recipe["status"] == "ACTIVE":
                    active_recipes.append(recipe)
                    records.append(
                        {
                            "sourceId": recipe["sourceId"],
                            "name": recipe["name"],
                            "lang": recipe["lang"],
                            "upstreamRepo": recipe.get("upstreamRepo"),
                            "baseUrl": recipe["baseUrl"],
                            "category": "VIABLE",
                            "detail": "Validación estática (sin --probe-live)",
                        }
                    )
            else:
                records.append(
                    {
                        "sourceId": job["sourceId"],
                        "name": cand["name"],
                        "lang": cand["lang"],
                        "upstreamRepo": cand.get("upstreamRepo"),
                        "baseUrl": cand.get("baseUrl"),
                        "category": "REJECTED_LICENSE" if kind == "REJECTED_LICENSE" else "NEEDS_PRIMITIVE",
                        "detail": err_msg or kind,
                    }
                )

    records.sort(key=lambda r: (str(r.get("category", "")), str(r.get("lang", "")), str(r.get("name", ""))))

    base_dir = os.path.dirname(os.path.abspath(recipes_dir)) or BUNDLE_ROOT
    validated_active = []
    for rec in sorted(active_recipes, key=lambda r: r["sourceId"]):
        ok_v, errs_v = validate_recipe(rec, base_dir=base_dir, expected_filename=f"{rec['sourceId']}.json")
        if ok_v:
            validated_active.append(rec)
        else:
            records = [r for r in records if r.get("sourceId") != rec["sourceId"]]
            records.append(
                {
                    "sourceId": rec["sourceId"],
                    "name": rec["name"],
                    "lang": rec["lang"],
                    "upstreamRepo": rec.get("upstreamRepo"),
                    "baseUrl": rec.get("baseUrl"),
                    "category": "NEEDS_PRIMITIVE",
                    "primaryCapability": "CUSTOM_HTML_SELECTOR_OR_PARSER",
                    "allCapabilities": ["CUSTOM_HTML_SELECTOR_OR_PARSER"],
                    "detail": f"Validación de receta fallida: {errs_v}",
                }
            )

    if apply:
        os.makedirs(recipes_dir, exist_ok=True)
        keep_filenames = {f"{rec['sourceId']}.json" for rec in validated_active}
        if only_working:
            for existing_fname in list(os.listdir(recipes_dir)):
                if existing_fname.endswith(".json") and existing_fname not in keep_filenames:
                    os.remove(os.path.join(recipes_dir, existing_fname))
        for rec in validated_active:
            out_path = os.path.join(recipes_dir, f"{rec['sourceId']}.json")
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(rec, f, indent=2, ensure_ascii=False)
                f.write("\n")

    metadata = {
        "langs": langs,
        "includeNsfw": include_nsfw,
        "includeCloudflare": include_cloudflare,
        "onlyWorking": only_working,
        "nsfwPolicy": (
            "Todas las fuentes incluidas (--include-nsfw)"
            if include_nsfw
            else "ContentWarning.NSFW (3) e isNsfw/nsfw=true excluidas por defecto; ContentWarning.MIXED (2) conservado"
        ),
        "upstreams": sorted({u["repo_slug"] for u in DEFAULT_UPSTREAMS}),
    }

    report_files = None
    if report_out:
        os.makedirs(os.path.dirname(os.path.abspath(report_out)), exist_ok=True)
        report_files = write_diagnostic_report(report_out, records, metadata)

    return {
        "activeRecipes": validated_active,
        "records": records,
        "reportData": build_diagnostic_report_data(records, metadata),
        "reportMarkdown": build_diagnostic_report_markdown(records, metadata),
        "reportFiles": report_files,
    }


def write_notice(notice_path, recipes):
    """Generate deterministic NOTICE file listing all verified upstream repositories and attributions."""
    grouped = {}
    for recipe in recipes:
        repo = recipe.get("upstreamRepo") or "Declarative Catalog Original Recipes"
        lic = recipe.get("license") or "Apache-2.0"
        attr = recipe.get("attribution") or DEFAULT_ATTRIBUTIONS.get(repo, "Mihon Declarative Catalog Contributors")
        key = (repo, lic, attr)
        grouped.setdefault(key, []).append(recipe["sourceId"])

    lines = [
        "Mihon Declarative Catalog Bundle — Third-Party Attribution & License Notice",
        "========================================================================",
        "",
        "This catalog bundle is distributed under the Apache License, Version 2.0.",
        "Recipes derived from external open-source extension repositories retain their",
        "verified OSI-compliant licenses and upstream contributor attributions below:",
        "",
    ]

    for (repo, lic, attr) in sorted(grouped.keys()):
        sids = sorted(grouped[(repo, lic, attr)])
        lines.append(f"- Source: {repo}")
        lines.append(f"  License: {lic}")
        lines.append(f"  Attribution: {attr}")
        lines.append(f"  Recipes ({len(sids)}): {', '.join(sids)}")
        lines.append("")

    os.makedirs(os.path.dirname(os.path.abspath(notice_path)), exist_ok=True)
    with open(notice_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return notice_path


def write_v2_bundle(recipes_dir, index_path, notice_path=None, revision=None):
    """Build lightweight v2 index.json (`entries` only, no inline `recipes`) and write NOTICE."""
    recipes = []
    recipes_sha = {}
    for fname in sorted(os.listdir(recipes_dir)):
        if fname.endswith(".json"):
            fpath = os.path.join(recipes_dir, fname)
            with open(fpath, "rb") as f:
                content = f.read().replace(b"\r\n", b"\n")
                sha = hashlib.sha256(content).hexdigest()
            rec = json.loads(content.decode("utf-8"))
            recipes.append(rec)
            sid = rec.get("sourceId") or fname[:-5]
            recipes_sha[sid] = sha

    recipes.sort(key=lambda r: r.get("sourceId", ""))
    entries = []
    for r in recipes:
        ent = recipe_to_index_entry(r)
        sid = ent["sourceId"]
        if sid in recipes_sha:
            ent["sha256"] = recipes_sha[sid]
        entries.append(ent)

    next_rev = revision
    if next_rev is None:
        prev_rev = 1
        prev_entries = None
        if os.path.exists(index_path):
            with open(index_path, "r", encoding="utf-8") as f:
                prev = json.load(f)
            prev_rev = int(prev.get("catalogRevision", 1))
            prev_entries = prev.get("entries")
        next_rev = prev_rev if prev_entries == entries else (prev_rev + 1 if prev_entries is not None else 1)

    bundle = {
        "schemaVersion": 2,
        "generatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "catalogRevision": next_rev,
        "entries": entries,
    }

    base_dir = os.path.dirname(os.path.abspath(index_path))
    if notice_path:
        write_notice(notice_path, recipes)

    ok, errs = validate_bundle(bundle, base_dir=base_dir)
    if not ok:
        raise ValueError(f"Generated v2 bundle failed validation: {errs}")

    os.makedirs(base_dir, exist_ok=True)
    with open(index_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(bundle, f, indent=2, ensure_ascii=False)
        f.write("\n")

    return bundle


def migrate_v1_recipes(src_dir, dst_recipes_dir, index_path, notice_path, revision=7):
    """Migrate v1 recipes into v2 catalog-bundle/recipes/<sourceId>.json + index.json + NOTICE."""
    os.makedirs(dst_recipes_dir, exist_ok=True)
    for fname in sorted(os.listdir(src_dir)):
        if not fname.endswith(".json"):
            continue
        with open(os.path.join(src_dir, fname), "r", encoding="utf-8") as f:
            raw = json.load(f)

        sid = raw["sourceId"]
        recipe = dict(raw)
        recipe["schemaVersion"] = 2
        recipe["versionId"] = int(recipe.get("versionId") or 1)
        recipe["recipePath"] = f"recipes/{sid}.json"
        recipe["mode"] = "declarative"

        norm_repo = normalize_upstream_repo(recipe.get("upstreamRepo"))
        recipe["upstreamRepo"] = norm_repo

        sids = []
        if recipe.get("upstreamSourceId") is not None:
            sids.append(int(recipe["upstreamSourceId"]))
        for extra in recipe.get("upstreamSourceIds") or []:
            if int(extra) not in sids:
                sids.append(int(extra))
        recipe["upstreamSourceIds"] = sorted(sids)

        if recipe.get("upstreamExtVersionCode") is not None:
            recipe["versionCode"] = int(recipe["upstreamExtVersionCode"])

        recipe["license"] = recipe.get("license") or "Apache-2.0"
        if norm_repo:
            recipe["attribution"] = recipe.get("attribution") or DEFAULT_ATTRIBUTIONS.get(
                norm_repo, "Upstream Open-Source Contributors"
            )
        else:
            recipe["attribution"] = recipe.get("attribution") or "Mihon Declarative Catalog Contributors"

        # Sanitize template placeholder mirrors such as https://$sub.novelcool.com
        if "mirrors" in recipe and isinstance(recipe["mirrors"], list):
            cleaned_mirrors = []
            for m in recipe["mirrors"]:
                if "$" in str(m):
                    cleaned_mirrors.append(recipe["baseUrl"])
                elif validate_ssrf(str(m))[0]:
                    cleaned_mirrors.append(str(m).rstrip("/"))
            dedup_mirrors = []
            for m in cleaned_mirrors:
                if m not in dedup_mirrors:
                    dedup_mirrors.append(m)
            recipe["mirrors"] = dedup_mirrors

        out_path = os.path.join(dst_recipes_dir, f"{sid}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(recipe, f, indent=2, ensure_ascii=False)
            f.write("\n")

    bundle = write_v2_bundle(dst_recipes_dir, index_path, notice_path=notice_path, revision=revision)
    ok, errs = validate_all(os.path.dirname(os.path.abspath(index_path)))
    if not ok:
        raise ValueError(f"Migrated bundle validation failed: {errs}")
    return bundle


def _audit_single_recipe_chapters(fname, orig_rec, fetcher=None, timeout=10, apply=False):
    rec = copy.deepcopy(orig_rec)
    smoke_max_bytes = min(MAX_HTML_BYTES, max(524288, int(rec.get("maxHtmlBytes") or 524288)))
    last_probe = None
    matched_body = None
    matched_items = []
    final_url = rec.get("baseUrl") or ""

    for url, method, req_headers, req_body in build_smoke_requests(rec):
        probe = _invoke_fetcher(fetcher, url, method, req_headers, req_body, timeout, max_bytes=smoke_max_bytes)
        last_probe = probe
        st = int(probe.get("status_code") or 0)
        body = probe.get("body") or ""
        final_url = probe.get("final_url") or url
        hdrs = probe.get("headers") or {}
        is_waf, _ = detect_waf_block(st, headers=hdrs, body=body)
        cf_mitigated = str(hdrs.get("cf-mitigated") or "").strip().lower() == "challenge"
        if is_waf and (st >= 400 or st < 200 or cf_mitigated):
            continue
        if 200 <= st < 400:
            items = extract_items_for_smoke(rec, body)
            if len(items) >= 1 and extract_sample_manga_urls(rec, body, limit=1):
                matched_body = body
                matched_items = items
                break

    sid = rec.get("sourceId") or fname
    base_diag = {
        "sourceId": sid,
        "name": rec.get("name") or sid,
        "lang": rec.get("lang") or "?",
        "upstreamRepo": rec.get("upstreamRepo"),
        "baseUrl": rec.get("baseUrl"),
        "finalUrl": final_url,
    }

    if matched_body is not None:
        ch_res = probe_chapters_for_recipe(
            rec,
            matched_body,
            fetcher=fetcher,
            timeout=timeout,
            auto_fix_selector=apply,
        )
        if ch_res.get("ok"):
            fixed = ch_res.get("status") == "OK_CHAPTERS_AUTODETECTED"
            updated_recipe = rec if fixed else None
            diag = {
                **base_diag,
                "category": "VIABLE",
                "itemsFound": len(matched_items),
                "chaptersFound": ch_res.get("chaptersFound", 0),
                "sampleMangaUrl": ch_res.get("sampleMangaUrl"),
                "autoFixedSelector": ch_res.get("detectedSelector"),
                "detail": (
                    f"Auto-reparado selector '{ch_res['detectedSelector']}' ({ch_res['chaptersFound']} capítulos en {ch_res.get('sampleMangaUrl')})"
                    if fixed
                    else f"OK ({len(matched_items)} items listado, {ch_res.get('chaptersFound', 0)} capítulos)"
                ),
            }
            return updated_recipe, diag
        if ch_res.get("category") == "CLOUDFLARE_ANTIBOT":
            return None, {
                **base_diag,
                "finalUrl": ch_res.get("sampleMangaUrl") or final_url,
                "category": "CLOUDFLARE_ANTIBOT",
                "subReason": ch_res.get("subReason"),
                "detail": ch_res.get("detail") or "Cloudflare en página de capítulos",
            }
        if ch_res.get("subReason") == "CHAPTERS_EMPTY":
            return None, {
                **base_diag,
                "finalUrl": ch_res.get("sampleMangaUrl") or final_url,
                "category": "NEEDS_PRIMITIVE",
                "subReason": "CHAPTERS_EMPTY",
                "primaryCapability": "CHAPTERS_EMPTY",
                "allCapabilities": ["CHAPTERS_EMPTY"],
                "suggestedSelector": ch_res.get("suggestedSelector"),
                "detail": ch_res.get("detail") or "Listado OK pero 0 capítulos detectados",
            }
        return None, {
            **base_diag,
            "finalUrl": ch_res.get("sampleMangaUrl") or final_url,
            "category": ch_res.get("category") or "DOWN_OR_NONEXISTENT",
            "subReason": ch_res.get("subReason"),
            "detail": ch_res.get("detail") or "Error obteniendo capítulos",
        }

    lp = last_probe or {"status_code": 0, "body": "", "headers": {}, "message": "NO_REQUEST", "final_url": final_url}
    lp_st = int(lp.get("status_code") or 0)
    lp_body = lp.get("body") or ""
    lp_headers = lp.get("headers") or {}
    is_waf, waf_reason = detect_waf_block(lp_st, headers=lp_headers, body=lp_body)
    if is_waf:
        return None, {
            **base_diag,
            "finalUrl": lp.get("final_url") or final_url,
            "category": "CLOUDFLARE_ANTIBOT",
            "subReason": waf_reason,
            "detail": f"Cloudflare en listado ({waf_reason})",
        }
    if 200 <= lp_st < 400:
        return None, {
            **base_diag,
            "finalUrl": lp.get("final_url") or final_url,
            "category": "NEEDS_PRIMITIVE",
            "primaryCapability": "CUSTOM_HTML_SELECTOR_OR_PARSER",
            "allCapabilities": ["CUSTOM_HTML_SELECTOR_OR_PARSER"],
            "detail": "Listado HTML 200 pero sin URLs de manga extraíbles",
        }
    return None, {
        **base_diag,
        "finalUrl": lp.get("final_url") or final_url,
        "category": "DOWN_OR_NONEXISTENT",
        "subReason": classify_down_reason(lp_st, lp.get("message") or "", lp_body),
        "detail": lp.get("message") or f"HTTP {lp_st}",
    }


def audit_chapters_catalog(
    recipes_dir,
    index_path=DEFAULT_INDEX_PATH,
    notice_path=DEFAULT_NOTICE_PATH,
    apply=False,
    workers=16,
    fetcher=None,
    timeout=10,
    report_out=None,
    langs="all",
):
    """Audit all ACTIVE recipes in `recipes_dir` in parallel for 2nd-level chapter loading."""
    target_langs = parse_langs_arg(langs)
    targets = []
    if recipes_dir and os.path.isdir(recipes_dir):
        for fname in sorted(os.listdir(recipes_dir)):
            if not fname.endswith(".json"):
                continue
            fpath = os.path.join(recipes_dir, fname)
            with open(fpath, "r", encoding="utf-8") as f:
                rec = json.load(f)
            if rec.get("status") != "ACTIVE":
                continue
            if not lang_matches_filter(rec.get("lang", "es"), target_langs):
                continue
            targets.append((fname, fpath, rec))

    records = []
    fixed_files = []
    base_dir = os.path.dirname(os.path.abspath(recipes_dir)) if recipes_dir else BUNDLE_ROOT
    max_workers = max(1, int(workers or 1))

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        fmap = {
            pool.submit(_audit_single_recipe_chapters, fname, rec, fetcher=fetcher, timeout=timeout, apply=apply): (fname, fpath)
            for fname, fpath, rec in targets
        }
        for fut in as_completed(fmap):
            fname, fpath = fmap[fut]
            try:
                updated_rec, diag = fut.result()
            except Exception as exc:
                records.append(
                    {
                        "sourceId": fname[:-5],
                        "name": fname[:-5],
                        "lang": "?",
                        "baseUrl": "",
                        "category": "DOWN_OR_NONEXISTENT",
                        "subReason": classify_down_reason(0, str(exc), ""),
                        "detail": f"Error en auditoría de capítulos: {exc}",
                    }
                )
                continue
            if apply and updated_rec is not None:
                ok_v, errs_v = validate_recipe(updated_rec, base_dir=base_dir, expected_filename=fname)
                if ok_v:
                    with open(fpath, "w", encoding="utf-8") as wf:
                        json.dump(updated_rec, wf, indent=2, ensure_ascii=False)
                        wf.write("\n")
                    fixed_files.append(fname)
                else:
                    diag = {
                        "sourceId": updated_rec.get("sourceId"),
                        "name": updated_rec.get("name"),
                        "lang": updated_rec.get("lang"),
                        "baseUrl": updated_rec.get("baseUrl"),
                        "category": "NEEDS_PRIMITIVE",
                        "subReason": "CHAPTERS_EMPTY",
                        "primaryCapability": "CHAPTERS_EMPTY",
                        "allCapabilities": ["CHAPTERS_EMPTY"],
                        "detail": f"Auto-selector inválido tras validación: {errs_v}",
                    }
            records.append(diag)

    records.sort(key=lambda r: (str(r.get("lang") or ""), str(r.get("name") or ""), str(r.get("sourceId") or "")))
    bundle = None
    if apply:
        bundle = write_v2_bundle(recipes_dir, index_path, notice_path=notice_path)

    metadata = {
        "langs": langs,
        "onlyWorking": True,
        "includeCloudflare": True,
        "upstreams": ["chapter-audit"],
    }
    report_data = build_diagnostic_report_data(records, metadata)
    report_files = None
    if report_out:
        out_dir = os.path.dirname(os.path.abspath(report_out))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        report_files = write_diagnostic_report(report_out, records, metadata)

    return {
        "audited": len(targets),
        "fixedFiles": sorted(fixed_files),
        "records": records,
        "reportData": report_data,
        "reportFiles": report_files,
        "bundle": bundle,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Sync v2 catalog-bundle/recipes/*.json, index.json, and NOTICE from upstream repos.",
    )
    parser.add_argument("--recipes-dir", default=DEFAULT_RECIPES_DIR)
    parser.add_argument("--index-out", default=DEFAULT_INDEX_PATH)
    parser.add_argument("--notice-out", default=DEFAULT_NOTICE_PATH)
    parser.add_argument("--deprecated-path", default=DEFAULT_DEPRECATED_PATH)
    parser.add_argument("--index-pb", action="append", default=[], help="Local path to index.pb (offline/testing)")
    parser.add_argument("--repos-cache-dir", default=None, help="Directory for upstream git clones")
    parser.add_argument(
        "--local-repo",
        action="append",
        default=[],
        help="Map repo_slug=local_path for offline testing",
    )
    parser.add_argument("--clone-upstreams", action="store_true", help="Clone upstream repos via blobless git clone")
    parser.add_argument("--shallow", action="store_true", help="Use shallow --depth 1 git clone (disables commit timestamps)")
    parser.add_argument("--apply", action="store_true", help="Write updated recipes, index.json, and NOTICE")
    parser.add_argument("--probe-live", action="store_true", help="Run HTTP smoke test (>= 3 items) on sources")
    parser.add_argument(
        "--probe-chapters",
        action="store_true",
        help="Run 2nd-level chapter probe inside smoke test (flags/fixes CHAPTERS_EMPTY)",
    )
    parser.add_argument(
        "--audit-chapters",
        action="store_true",
        help="Fast dedicated parallel audit of chapters across ACTIVE recipes in --recipes-dir",
    )
    parser.add_argument("--force-upstream-url", action="store_true", help="Adopt upstream baseUrl on drift")
    parser.add_argument("--langs", default=None, help="Comma-separated BCP-47 languages or 'all'")
    parser.add_argument("--add-slug", action="append", default=[], help="Generate a new recipe from slug")
    parser.add_argument("--sync-all", action="store_true", help="Discover and recreate all matching upstream sources")
    parser.add_argument("--include-nsfw", action="store_true", help="Include 18+ (NSFW) sources (excluded by default)")
    parser.add_argument(
        "--include-cloudflare",
        action="store_true",
        help="Include sources protected by Cloudflare anti-bot as active with requiresCloudflareBypass=true",
    )
    parser.add_argument(
        "--only-working",
        dest="only_working",
        action="store_true",
        default=None,
        help="Keep only live-verified ACTIVE recipes in recipes/ (default true with --sync-all)",
    )
    parser.add_argument("--no-only-working", dest="only_working", action="store_false")
    parser.add_argument("--workers", type=int, default=16, help="Max concurrent HTTP workers (default: 16)")
    parser.add_argument("--report-out", default=None, help="Write Spanish R2 diagnostic report (.md or .json)")
    parser.add_argument("--migrate-from", default=None, help="Migrate v1 recipes dir into catalog-bundle v2")
    args = parser.parse_args(argv)

    if args.migrate_from:
        bundle = migrate_v1_recipes(args.migrate_from, args.recipes_dir, args.index_out, args.notice_out)
        print(f"Migrated {len(bundle['entries'])} v2 recipes -> {args.index_out}")
        return 0

    if args.audit_chapters:
        audit_langs = args.langs or "all"
        summary = audit_chapters_catalog(
            recipes_dir=args.recipes_dir,
            index_path=args.index_out,
            notice_path=args.notice_out,
            apply=args.apply,
            workers=args.workers,
            report_out=args.report_out,
            langs=audit_langs,
        )
        c = summary["reportData"]["counts"]
        print(
            f"Audit-chapters ({audit_langs}): audited={summary['audited']} "
            f"viable={c['viable']} chapters_empty={c.get('chaptersEmpty', 0)} "
            f"cloudflare={c['cloudflareAntibot']} down={c['downOrNonexistent']} "
            f"auto_fixed={len(summary['fixedFiles'])}"
        )
        if summary.get("reportFiles"):
            print(f"Diagnostic report written -> {summary['reportFiles'][0]}")
        if summary.get("bundle"):
            b = summary["bundle"]
            print(f"Wrote v2 index revision {b['catalogRevision']} ({len(b['entries'])} entries)")
        return 0

    effective_langs = args.langs or "es,en"

    repo_dirs = {}
    for mapping in args.local_repo:
        if "=" in mapping:
            slug, path = mapping.split("=", 1)
            repo_dirs[normalize_upstream_repo(slug)] = path

    temp_clone_dir = None
    try:
        if args.clone_upstreams:
            base_cache = args.repos_cache_dir
            if not base_cache:
                temp_clone_dir = tempfile.mkdtemp(prefix="catalog_repos_")
                base_cache = temp_clone_dir
            clone_attempted = 0
            for up in DEFAULT_UPSTREAMS:
                slug = up["repo_slug"]
                if slug in repo_dirs:
                    continue
                clone_attempted += 1
                target = os.path.join(base_cache, up["name"])
                try:
                    repo_dirs[slug] = clone_or_open_repo(up["git_url"], target, shallow=args.shallow)
                except Exception as e:
                    print(f"WARN: git clone failed for {slug}: {e}")
            if clone_attempted > 0 and not repo_dirs:
                print("ERROR: all upstream git clones failed; aborting sync.")
                return 1

        index_payloads = []
        if args.index_pb:
            for p in args.index_pb:
                with open(p, "rb") as f:
                    payload = decode_index_pb(f.read())
                index_payloads.append((payload.get("repoName") or os.path.basename(p), payload))
        else:
            fetch_attempted = 0
            for up in DEFAULT_UPSTREAMS:
                fetch_attempted += 1
                try:
                    raw = fetch_url_bytes(up["index_pb_url"], timeout=15)
                    index_payloads.append((up["repo_slug"], decode_index_pb(raw)))
                except Exception as e:
                    print(f"WARN: could not fetch {up['repo_slug']} index.pb: {e}")
            if fetch_attempted > 0 and not index_payloads:
                print("ERROR: all upstream index.pb fetches failed; aborting sync.")
                return 1

        upstream_catalog = build_upstream_catalog(index_payloads, langs=effective_langs, repo_dirs=repo_dirs)
        upstream_lookup = (
            upstream_catalog["by_source_id"],
            upstream_catalog["by_name_key"],
            upstream_catalog["by_domain"],
        )

        if args.sync_all:
            only_working = True if args.only_working is None else bool(args.only_working)
            summary = sync_all_catalog(
                recipes_dir=args.recipes_dir,
                upstream_catalog=upstream_catalog,
                repo_dirs=repo_dirs,
                apply=args.apply,
                probe_live=args.probe_live or only_working,
                only_working=only_working,
                include_nsfw=args.include_nsfw,
                include_cloudflare=args.include_cloudflare,
                langs=effective_langs,
                deprecated_path=args.deprecated_path,
                workers=args.workers,
                report_out=args.report_out,
                probe_chapters=args.probe_chapters,
            )
            c = summary["reportData"]["counts"]
            print(
                f"Sync-all ({effective_langs}): evaluated={c['totalEvaluated']} "
                f"viable={c['viable']} (cf_bypass={c.get('viableCloudflareBypass', 0)}, redirect_adopted={c['viableDomainAdopted']}, fallback={c['viableFallbackRepo']}) "
                f"cloudflare={c['cloudflareAntibot']} down={c['downOrNonexistent']} "
                f"domain_failed={c['domainChangeFailed']} needs_primitive={c['needsPrimitive']} "
                f"chapters_empty={c.get('chaptersEmpty', 0)} "
                f"license={c['rejectedLicense']} nsfw_excluded={c['excludedNsfw']}"
            )
            if summary.get("reportFiles"):
                print(f"Diagnostic report written -> {summary['reportFiles'][0]}")
        else:
            for slug in args.add_slug:
                rec, msg = generate_recipe_from_slug(
                    slug,
                    args.recipes_dir,
                    upstream_lookup,
                    repo_dirs=repo_dirs,
                    apply=args.apply,
                    probe_live=args.probe_live,
                    deprecated_path=args.deprecated_path,
                    include_nsfw=args.include_nsfw,
                )
                print(f"Slug '{slug}': {msg} ({rec['sourceId'] if rec else '-'})")

            reports = sync_existing_recipes(
                recipes_dir=args.recipes_dir,
                upstream_lookup=upstream_lookup,
                repo_dirs=repo_dirs,
                apply=args.apply,
                probe_live=args.probe_live,
                force_upstream_url=args.force_upstream_url,
                langs=effective_langs,
                deprecated_path=args.deprecated_path,
                probe_chapters=args.probe_chapters,
            )
            for fname, status, url in reports:
                print(f"  {fname:32s} | {status:40s} | {url}")

        if args.apply:
            bundle = write_v2_bundle(args.recipes_dir, args.index_out, notice_path=args.notice_out)
            print(f"Wrote v2 index revision {bundle['catalogRevision']} ({len(bundle['entries'])} entries)")
    finally:
        if temp_clone_dir and os.path.exists(temp_clone_dir):
            shutil.rmtree(temp_clone_dir, ignore_errors=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
