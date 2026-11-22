"""catalog_kt_extractor.py — Static analysis and declarative spec extractor for extension Kotlin files.

Extracts declarative recipes directly from `ParsedHttpSource`, `HttpSource`, and individual
JSON/HTML/GraphQL extension Kotlin source files in upstream repositories (`keiyoushi/extensions-source`,
`FelipeGFA/fonte-extensoes`).

Features:
- Extracts popularMangaRequest / latestUpdatesRequest / searchMangaRequest / details / chapters / pages specs.
- Emits official SourceRecipe.kt `jsonApi` structures (`mangaList`, `details`, `chapters`, `pages`) and GraphQL POST payloads.
- Automatically maps statically extractable QuickJS (`PACKER`, `NEXT_RSC`, `CUSTOM`), dynamic crypto
  (`dynamic_crypto`, `openssl_salted_decrypt`, `lz_string`), image descrambling (`grid_unscramble` incl.
  `PUBLUS`/`SPEEDBINB`), and custom request signing (`querySigner`).
- Synthesizes valid SourceRecipe v2 dicts ready for live diagnostic probing.

Strictly stdlib: no external dependencies.
"""

from __future__ import annotations

import base64
import re
from typing import Any


_FORBIDDEN_JS_TOKENS = (
    "XMLHttpRequest",
    "fetch(",
    "WebSocket",
    "Packages.",
    "java.",
    "android.",
    "System.exit",
    "Runtime.getRuntime",
)

_ALLOWED_ROTATIONS = {0, 90, 180, 270}


def _clean_str(val: str | None) -> str | None:
    if val is None:
        return None
    val = val.strip().strip('"\'')
    return val if val else None


def _unescape_kt_str(raw: str) -> str:
    return raw.encode("utf-8").decode("unicode_escape", errors="ignore")


def _check_redos_safe(pattern: str) -> bool:
    """Return True if pattern has no nested quantifiers (safe from catastrophic backtracking)."""
    if not isinstance(pattern, str) or not pattern.strip() or len(pattern) > 256:
        return False
    group_has_quantifier: list[bool] = []
    escaped = False
    in_char_class = False
    for index, ch in enumerate(pattern):
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == "[" and not in_char_class:
            in_char_class = True
            continue
        if ch == "]" and in_char_class:
            in_char_class = False
            continue
        if in_char_class:
            continue
        if ch == "(":
            group_has_quantifier.append(False)
        elif ch == ")" and group_has_quantifier:
            inner_q = group_has_quantifier.pop()
            next_ch = pattern[index + 1] if index + 1 < len(pattern) else ""
            grp_q = next_ch in ("*", "+", "{")
            if inner_q and grp_q:
                return False
            if grp_q and group_has_quantifier:
                group_has_quantifier[-1] = True
        elif ch in ("*", "+", "{") and group_has_quantifier:
            group_has_quantifier[-1] = True
    try:
        re.compile(pattern)
    except re.error:
        return False
    return True


def _extract_kt_string_constants(kt_text: str) -> dict[str, str]:
    """Extract string constants (val/var/const val) from Kotlin source."""
    consts: dict[str, str] = {}
    if not kt_text:
        return consts
    triple_pat = re.compile(
        r'(?:(?:private|internal|protected|public|const|override)\s+)*\b(?:val|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*String)?\s*=\s*"""([\s\S]*?)"""'
    )
    for m in triple_pat.finditer(kt_text):
        consts[m.group(1)] = m.group(2)

    single_pat = re.compile(
        r'(?:(?:private|internal|protected|public|const|override)\s+)*\b(?:val|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*String)?\s*=\s*"([^"\\]*(?:\\.[^"\\]*)*)"'
    )
    for m in single_pat.finditer(kt_text):
        consts.setdefault(m.group(1), _unescape_kt_str(m.group(2)))
    return consts


def _extract_kt_int_constants(kt_text: str) -> dict[str, int]:
    """Extract integer constants from Kotlin source."""
    consts: dict[str, int] = {}
    if not kt_text:
        return consts
    pat = re.compile(
        r'(?:(?:private|internal|protected|public|const|override)\s+)*\b(?:val|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*Int)?\s*=\s*(\d+)\b'
    )
    for m in pat.finditer(kt_text):
        consts[m.group(1)] = int(m.group(2))
    return consts


def _extract_kt_function_body(kt_text: str, func_name: str) -> str | None:
    """Extract body of `fun <func_name>(...) { ... }` or `fun <func_name>(...) = ...`."""
    if not kt_text:
        return None
    sig_pat = re.compile(rf'\bfun\s+{re.escape(func_name)}\s*\([^)]*\)(?:\s*:\s*[^\s{{=]+)?\s*([{{=])')
    m = sig_pat.search(kt_text)
    if not m:
        return None
    delim = m.group(1)
    start = m.end()
    if delim == "=":
        # Single-expression function: capture until next blank line / override / fun / closing brace at class level
        end_m = re.search(r'\n\s*(?:override\b|private\b|internal\b|fun\b|val\b|\})', kt_text[start:])
        chunk = kt_text[start : start + end_m.start()] if end_m else kt_text[start:]
        return chunk.strip()

    depth = 1
    in_str = False
    escape = False
    i = start
    n = len(kt_text)
    while i < n:
        ch = kt_text[i]
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
                    return kt_text[start:i]
        i += 1
    return kt_text[start:]


def _resolve_kt_string_expr(expr: str, string_consts: dict[str, str]) -> str | None:
    """Resolve a literal string `"..."` or constant name from Kotlin expression."""
    if not expr:
        return None
    cleaned = expr.strip()
    m_lit = re.fullmatch(r'"([^"\\]*(?:\\.[^"\\]*)*)"', cleaned)
    if m_lit:
        return _unescape_kt_str(m_lit.group(1))
    m_tri = re.fullmatch(r'"""([\s\S]*?)"""', cleaned)
    if m_tri:
        return m_tri.group(1)
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", cleaned):
        return string_consts.get(cleaned)
    m_bytes = re.match(r'^"([^"\\]*(?:\\.[^"\\]*)*)"\s*\.toByteArray\(', cleaned)
    if m_bytes:
        return _unescape_kt_str(m_bytes.group(1))
    m_var_bytes = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\s*\.toByteArray\(', cleaned)
    if m_var_bytes:
        return string_consts.get(m_var_bytes.group(1))
    return None


def extract_string_literal(kt_text: str, var_name: str) -> str | None:
    """Extract simple string property or override val foo = "bar"."""
    pattern = rf'(?:override\s+)?(?:val|var)\s+{re.escape(var_name)}\s*(?::\s*String)?\s*=\s*"([^"\\]*(?:\\.[^"\\]*)*)"'
    match = re.search(pattern, kt_text)
    if match:
        return _unescape_kt_str(match.group(1))
    return None


def extract_selector(kt_text: str, func_or_prop: str) -> str | None:
    """Extract CSS selector from either override val xxx = "sel" or override fun xxx() = "sel" / select("sel")."""
    prop_val = extract_string_literal(kt_text, func_or_prop)
    if prop_val:
        return prop_val

    func_pattern = rf'(?:override\s+)?fun\s+{re.escape(func_or_prop)}\s*\([^)]*\)\s*(?::\s*String)?\s*=\s*"([^"\\]*(?:\\.[^"\\]*)*)"'
    match = re.search(func_pattern, kt_text)
    if match:
        return _unescape_kt_str(match.group(1))

    body = _extract_kt_function_body(kt_text, func_or_prop)
    if body:
        sel_match = re.search(r'\bselect(?:First)?\(\s*"([^"\\]*(?:\\.[^"\\]*)*)"', body)
        if sel_match:
            return _unescape_kt_str(sel_match.group(1))

    return None


def _normalize_kt_path(raw_path: str) -> str:
    path = raw_path.strip()
    path = re.sub(r'^\$\{?(?:baseUrl|apiUrl|apiBaseUrl)\}?\/?', '/', path)
    path = re.sub(r'^https?://[^/]+', '', path)
    path = re.sub(r'\$\{page\}|\$page', '{page}', path)
    path = re.sub(r'\$\{offset\}|\$offset', '{offset}', path)
    path = re.sub(r'\$\{query\}|\$query', '{query}', path)
    path = re.sub(r'\$\{manga\.url\}|\$\{?slug\}?', '{slug}', path)
    path = re.sub(r'\$\{chapter\.url\}|\$\{?chapterId\}?', '{chapterId}', path)
    if path and not path.startswith("/"):
        path = "/" + path
    return path


def _extract_graphql_from_chunk(chunk: str, kt_text: str, func_name: str, consts: dict[str, str]) -> tuple[str | None, str | None]:
    """Extract GraphQL query string and variables template from a request function chunk."""
    gql_query: str | None = None

    # 1. Direct query string inside chunk (triple or regular quotes, must contain '{')
    m_tri = re.search(r'"""([\s\S]*?\b(?:query|mutation)\b[\s\S]*?\{[\s\S]*?)"""', chunk)
    if m_tri:
        gql_query = m_tri.group(1)
    else:
        m_str = re.search(
            r'"([^"\\]*(?:\\.[^"\\]*)*\b(?:query|mutation)\b[^"\\]*\{[^"\\]*(?:\\.[^"\\]*)*)"',
            chunk,
        )
        if m_str:
            gql_query = _unescape_kt_str(m_str.group(1))

    # 2. Constant referenced in chunk (e.g., POPULAR_QUERY, SEARCH_QUERY, DETAILS_QUERY, query)
    if not gql_query:
        for var_name, val in consts.items():
            if re.search(rf'\b{re.escape(var_name)}\b', chunk) and re.search(r'\b(?:query|mutation)\b\s*[A-Za-z0-9_]*\s*[\({]', val):
                gql_query = val
                break

    # 3. Fallback: search matching phase constant in file
    if not gql_query:
        phase_hints = {
            "popularMangaRequest": ("POPULAR", "LIST", "SERIES", "MANGA"),
            "latestUpdatesRequest": ("LATEST", "RECENT", "UPDATE", "POPULAR"),
            "searchMangaRequest": ("SEARCH", "POPULAR"),
            "mangaDetailsRequest": ("DETAIL", "MANGA", "SERIES"),
            "chapterListRequest": ("CHAPTER",),
            "pageListRequest": ("PAGE", "CHAPTER"),
        }.get(func_name, ())
        for var_name, val in consts.items():
            if re.search(r'\b(?:query|mutation)\b\s*[A-Za-z0-9_]*\s*[\({]', val):
                if any(h in var_name.upper() for h in phase_hints):
                    gql_query = val
                    break
        if not gql_query:
            for val in consts.values():
                if re.search(r'\b(?:query|mutation)\b\s*[A-Za-z0-9_]*\s*[\({]', val):
                    gql_query = val
                    break

    if not gql_query:
        return None, None

    clean_query = re.sub(r'\s+', ' ', gql_query).strip()

    # Extract variables template from leaf buildJsonObject / JSONObject put calls or default by phase
    vars_pairs: list[str] = []
    for m_put in re.finditer(r'\bput\(\s*"([^"]+)"\s*,\s*([^(){}]+?)\)', chunk):
        k = m_put.group(1)
        v_expr = m_put.group(2).strip()
        if k in ("query", "variables"):
            continue
        if "offset" in v_expr.lower() or k == "offset":
            vars_pairs.append(f'"{k}":{{offset}}')
        elif "page" in v_expr.lower() or k == "page":
            vars_pairs.append(f'"{k}":{{page}}')
        elif "query" in v_expr.lower() or k in ("q", "search", "keyword"):
            vars_pairs.append(f'"{k}":"{{query}}"')
        elif "chapter" in v_expr.lower() or k in ("chapterId",):
            vars_pairs.append(f'"{k}":"{{chapterId}}"')
        elif "slug" in v_expr.lower() or "manga" in v_expr.lower() or k in ("slug", "id", "mangaId"):
            vars_pairs.append(f'"{k}":"{{slug}}"')
        elif re.fullmatch(r"\d+", v_expr):
            vars_pairs.append(f'"{k}":{v_expr}')

    if vars_pairs:
        vars_tpl = "{" + ",".join(vars_pairs) + "}"
    else:
        if "search" in func_name.lower():
            vars_tpl = '{"query":"{query}","page":{page}}'
        elif "details" in func_name.lower():
            vars_tpl = '{"slug":"{slug}"}'
        elif "chapter" in func_name.lower():
            vars_tpl = '{"slug":"{slug}","page":{page}}'
        elif "page" in func_name.lower():
            vars_tpl = '{"chapterId":"{chapterId}"}'
        elif "$offset" in clean_query:
            vars_tpl = '{"offset":{offset},"limit":24}'
        else:
            vars_tpl = '{"page":{page}}'

    return clean_query, vars_tpl


def extract_request_path(kt_text: str, request_fun: str) -> dict[str, Any] | None:
    """Extract endpoint path, HTTP method, GraphQL body, and pagination style from request builders."""
    chunk = _extract_kt_function_body(kt_text, request_fun)
    if not chunk:
        return None

    consts = _extract_kt_string_constants(kt_text)
    has_graphql_cue = bool(
        re.search(r'\bgraphql\b|\bGraphQL\b|graphqlQuery|GraphQLRequest', chunk + "\n" + kt_text, re.I)
        or "/graphql" in chunk
        or re.search(r'\b(?:query|mutation)\b\s+[A-Za-z0-9_]*\s*\(', chunk)
    )
    method = (
        "POST"
        if ("POST(" in chunk or "FormBody" in chunk or "toRequestBody" in chunk or has_graphql_cue)
        else "GET"
    )

    url_m = re.search(r'(?:GET|POST)\(\s*["\']([^"\']+)["\']', chunk)
    path = ""
    if url_m:
        path = _normalize_kt_path(url_m.group(1))
    else:
        interp = re.search(r'["\'](?:\$baseUrl|\$\{baseUrl\}|\$apiUrl|\$\{apiUrl\})([^"\']*)["\']', chunk)
        if interp:
            path = _normalize_kt_path(interp.group(1))
        else:
            url_call = re.search(r'\.url\(\s*["\']([^"\']+)["\']', chunk)
            if url_call:
                path = _normalize_kt_path(url_call.group(1))

    # Extract addQueryParameter("k", v)
    qp_list: list[str] = []
    for qp_m in re.finditer(r'\.addQueryParameter\(\s*"([^"]+)"\s*,\s*([^)]+)\)', chunk):
        qk = qp_m.group(1)
        qv = qp_m.group(2).strip()
        if "page" in qv.lower() or qk == "page":
            qp_list.append(f"{qk}={{page}}")
        elif "query" in qv.lower() or qk in ("q", "search"):
            qp_list.append(f"{qk}={{query}}")
        elif "offset" in qv.lower():
            qp_list.append(f"{qk}={{offset}}")
    if qp_list and "?" not in path:
        path = (path or "/") + "?" + "&".join(qp_list)

    page_m = re.search(r'["\']\s*\+\s*page\b|page=\$(\{page\}|page)|\bpage\b', chunk)
    has_page = bool(page_m or "{page}" in path or "$page" in path)

    spec: dict[str, Any] = {
        "method": method,
        "pathTemplate": path or ("/graphql" if has_graphql_cue else "/page/{page}"),
        "hasPage": has_page,
    }

    if method == "POST" and has_graphql_cue:
        gql_query, gql_vars = _extract_graphql_from_chunk(chunk, kt_text, request_fun, consts)
        if gql_query:
            spec["contentType"] = "application/json"
            spec["graphqlQuery"] = gql_query
            spec["graphqlVariablesTemplate"] = gql_vars or "{}"
            if not path:
                spec["pathTemplate"] = "/graphql"

    return spec


def _to_request_spec(extracted: dict[str, Any] | None, fallback_path: str, is_graphql: bool = False, gql_query: str | None = None, gql_vars: str | None = None) -> dict[str, Any]:
    if extracted:
        req: dict[str, Any] = {
            "method": extracted.get("method", "GET"),
            "pathTemplate": extracted.get("pathTemplate") or fallback_path,
        }
        if extracted.get("contentType"):
            req["contentType"] = extracted["contentType"]
        if extracted.get("graphqlQuery"):
            req["method"] = "POST"
            req["graphqlQuery"] = extracted["graphqlQuery"]
            req["graphqlVariablesTemplate"] = extracted.get("graphqlVariablesTemplate") or "{}"
        return req
    if is_graphql and gql_query:
        return {
            "method": "POST",
            "pathTemplate": "/graphql",
            "contentType": "application/json",
            "graphqlQuery": gql_query,
            "graphqlVariablesTemplate": gql_vars or "{}",
        }
    return {
        "method": "GET",
        "pathTemplate": fallback_path,
    }


def extract_html_selectors(kt_text: str) -> dict[str, str]:
    """Extract standard ParsedHttpSource CSS selectors."""
    selectors: dict[str, str] = {}

    list_sel = extract_selector(kt_text, "popularMangaSelector")
    if not list_sel:
        list_sel = extract_selector(kt_text, "latestUpdatesSelector")
    if list_sel:
        selectors["listSelector"] = list_sel

    next_page = extract_selector(kt_text, "popularMangaNextPageSelector")
    if not next_page:
        next_page = extract_selector(kt_text, "latestUpdatesNextPageSelector")
    if next_page:
        selectors["nextPageSelector"] = next_page

    title_sel = extract_selector(kt_text, "mangaDetailsTitleSelector")
    if not title_sel:
        m = re.search(r'mangaDetailsParse\b[^{]*\{[\s\S]*?(?:title\s*=\s*|select(?:First)?\(\s*)"([^"]+)"', kt_text)
        if m:
            title_sel = m.group(1)
    if title_sel:
        selectors["titleSelector"] = title_sel

    chapter_sel = extract_selector(kt_text, "chapterListSelector")
    if chapter_sel:
        selectors["chapterSelector"] = chapter_sel

    img_sel = None
    page_body = _extract_kt_function_body(kt_text, "pageListParse")
    if page_body:
        m_img = re.search(r'\bselect(?:First)?\(\s*"([^"]+)"\s*\)', page_body)
        if m_img:
            img_sel = m_img.group(1)
    if not img_sel:
        img_sel = extract_selector(kt_text, "pageListSelector")
    if img_sel:
        selectors["pageImgSelector"] = img_sel

    return selectors


def _infer_items_path(kt_text: str, section_body: str | None = None, default_path: str = "$.data[*]") -> str:
    text = section_body or kt_text
    m_path = re.search(r'(?:getJSONArray|optJSONArray)\(\s*["\']([^"\']+)["\']\s*\)', text)
    if m_path:
        return f"$.{m_path.group(1)}[*]"
    if "items" in text and "data" not in text:
        return "$.items[*]"
    if "results" in text and "data" not in text:
        return "$.results[*]"
    if "rows" in text and "data" in text:
        return "$.data.rows[*]"
    if "data" in text and "items" not in text:
        return "$.data[*]"
    if "items" in text:
        return "$.items[*]"
    if "results" in text:
        return "$.results[*]"
    return default_path


def extract_json_api_spec(kt_text: str, base_url: str = "") -> dict[str, Any] | None:
    """Detect JSON or GraphQL source and emit official SourceRecipe.kt `jsonApi` spec."""
    if not kt_text:
        return None
    is_json = bool(
        re.search(r'\bjson\.decodeFromString\b|\bJson\.parseToJsonElement\b|\bJSONObject\(|\bJSONArray\(', kt_text)
        or re.search(r'response\.parseAs<|\bJSON_API\b|\bapplication/json\b|\bMoshi\b|\bGson\(', kt_text)
    )
    is_graphql = bool(
        re.search(r'\bgraphql\b|\bGraphQL\b|graphqlQuery|GraphQLRequest|/graphql', kt_text, re.I)
        or re.search(r'"""[\s\S]*?\b(?:query|mutation)\b[\s\S]*?"""', kt_text)
    )
    if not is_json and not is_graphql:
        return None

    pop_ext = extract_request_path(kt_text, "popularMangaRequest")
    lat_ext = extract_request_path(kt_text, "latestUpdatesRequest")
    search_ext = extract_request_path(kt_text, "searchMangaRequest")
    det_ext = extract_request_path(kt_text, "mangaDetailsRequest")
    ch_ext = extract_request_path(kt_text, "chapterListRequest")
    pg_ext = extract_request_path(kt_text, "pageListRequest")

    pop_fallback = "/graphql" if is_graphql else "/api/manga?page={page}"
    pop_req = _to_request_spec(pop_ext, pop_fallback, is_graphql=is_graphql)
    lat_req = _to_request_spec(lat_ext, pop_req["pathTemplate"], is_graphql=is_graphql, gql_query=pop_req.get("graphqlQuery"), gql_vars=pop_req.get("graphqlVariablesTemplate"))
    search_fallback = "/graphql" if is_graphql else (
        f"{pop_req['pathTemplate']}&q={{query}}" if "?" in pop_req["pathTemplate"] else f"{pop_req['pathTemplate']}?q={{query}}"
    )
    search_req = _to_request_spec(
        search_ext,
        search_fallback,
        is_graphql=is_graphql,
        gql_query=pop_req.get("graphqlQuery"),
        gql_vars='{"query":"{query}","page":{page}}' if is_graphql else None,
    )
    det_req = _to_request_spec(det_ext, "/graphql" if is_graphql else "/api/manga/{slug}", is_graphql=is_graphql, gql_query=pop_req.get("graphqlQuery"), gql_vars='{"slug":"{slug}"}' if is_graphql else None)
    ch_req = _to_request_spec(ch_ext, "/graphql" if is_graphql else "/api/manga/{slug}/chapters", is_graphql=is_graphql, gql_query=pop_req.get("graphqlQuery"), gql_vars='{"slug":"{slug}","page":{page}}' if is_graphql else None)
    pg_req = _to_request_spec(pg_ext, "/graphql" if is_graphql else "/api/chapters/{chapterId}/pages", is_graphql=is_graphql, gql_query=pop_req.get("graphqlQuery"), gql_vars='{"chapterId":"{chapterId}"}' if is_graphql else None)

    pop_body = _extract_kt_function_body(kt_text, "popularMangaParse")
    ch_body = _extract_kt_function_body(kt_text, "chapterListParse")
    pg_body = _extract_kt_function_body(kt_text, "pageListParse")

    items_path = _infer_items_path(kt_text, pop_body, "$.data[*]")
    if is_graphql and pop_req.get("graphqlQuery"):
        m_gql_op = re.search(r'\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\([^)]*\))?\s*\{', pop_req["graphqlQuery"])
        if m_gql_op:
            op_field = m_gql_op.group(1)
            if "rows" in pop_req["graphqlQuery"]:
                items_path = f"$.data.{op_field}.rows[*]"
            elif "items" in pop_req["graphqlQuery"]:
                items_path = f"$.data.{op_field}.items[*]"
            elif items_path == "$.data[*]":
                items_path = f"$.data.{op_field}[*]"

    ch_items_path = _infer_items_path(kt_text, ch_body, "$.chapters[*]" if "chapters" in kt_text else "$.data[*]")
    pg_items_path = _infer_items_path(
        kt_text,
        pg_body,
        "$.pages[*]" if "pages" in kt_text else ("$.images[*]" if "images" in kt_text else "$.data[*]"),
    )

    spec: dict[str, Any] = {
        "apiBaseUrl": base_url.rstrip("/") if base_url else None,
        "popularRequest": pop_req,
        "latestRequest": lat_req,
        "searchRequest": search_req,
        "detailsRequest": det_req,
        "chaptersRequest": ch_req,
        "pagesRequest": pg_req,
        "mangaList": {
            "itemsPath": items_path,
            "titlePaths": ["$.title", "$.name"],
            "urlPath": "$.url",
            "slugPath": "$.slug",
            "idPath": "$.id",
            "coverPaths": ["$.cover", "$.thumbnail", "$.image"],
            "pagination": {
                "mode": "PAGE_NUMBER",
                "startPage": 1,
                "pageSize": 24,
            },
        },
        "details": {
            "rootPath": "$.data" if "data" in kt_text else "$",
            "titlePaths": ["$.title", "$.name"],
            "descriptionPaths": ["$.description", "$.synopsis"],
            "coverPaths": ["$.cover", "$.thumbnail", "$.image"],
            "authorsPath": "$.author",
            "artistsPath": "$.artist",
            "genresPath": "$.genres[*]",
            "statusPath": "$.status",
        },
        "chapters": {
            "itemsPath": ch_items_path,
            "namePath": "$.title",
            "urlPath": "$.url",
            "idPath": "$.id",
            "numberPath": "$.number",
            "datePath": "$.createdAt",
        },
        "pages": {
            "itemsPath": pg_items_path,
            "imageUrlPath": "$.url",
        },
    }

    # Attach extracted pipeline steps to appropriate phases if present
    qjs_steps = extract_quickjs_steps(kt_text)
    crypto_steps = extract_crypto_steps(kt_text)
    if crypto_steps:
        spec["pages"]["pipelineSteps"] = list(crypto_steps)
    if qjs_steps:
        # Next.js RSC is usually list/details; Packer is usually pages
        if any(s.get("preset") == "NEXT_RSC" for s in qjs_steps):
            spec["mangaList"]["pipelineSteps"] = [s for s in qjs_steps if s.get("preset") == "NEXT_RSC"]
        if any(s.get("preset") != "NEXT_RSC" for s in qjs_steps):
            spec["pages"].setdefault("pipelineSteps", [])
            spec["pages"]["pipelineSteps"].extend(s for s in qjs_steps if s.get("preset") != "NEXT_RSC")
            if not spec["pages"]["pipelineSteps"]:
                del spec["pages"]["pipelineSteps"]

    return spec


def extract_quickjs_steps(kt_text: str, gradle_text: str = "") -> list[dict[str, Any]]:
    """Detect Unpacker/Synchrony/QuickJs/Next.js RSC cues and synthesize `quickjs_eval` steps."""
    kt = kt_text or ""
    combined = f"{kt}\n{gradle_text or ''}"
    combined_low = combined.lower()
    steps: list[dict[str, Any]] = []

    if (
        any(tok in kt for tok in ("Unpacker", "Synchrony"))
        or "lib:unpacker" in combined_low
        or "lib:synchrony" in combined_low
        or "eval(function(p,a,c,k" in combined_low
    ):
        steps.append(
            {
                "op": "quickjs_eval",
                "preset": "PACKER",
                "script": "var out = unpackPacker(input); out;",
                "outputVar": "out",
                "timeoutMs": 2000,
            }
        )

    if "__next_f" in combined:
        steps.append(
            {
                "op": "quickjs_eval",
                "preset": "NEXT_RSC",
                "script": "var out = extractNextRsc(input); out;",
                "outputVar": "out",
                "timeoutMs": 2000,
            }
        )

    if not steps and any(tok in kt for tok in ("QuickJs", "quickjs", "evaluateJs", "Duktape")):
        # Try extracting a literal JS snippet from evaluate("...") / evaluate("""...""")
        m_js = re.search(
            r'\b(?:evaluate|evaluateJs)\s*\(\s*(?:"""([\s\S]*?)"""|"([^"\\]*(?:\\.[^"\\]*)*)")',
            kt,
        )
        if m_js:
            raw_js = m_js.group(1) if m_js.group(1) is not None else _unescape_kt_str(m_js.group(2))
            raw_js = (raw_js or "").strip()
            if (
                raw_js
                and len(raw_js) <= 16384
                and "$" not in raw_js
                and not any(tok in raw_js for tok in _FORBIDDEN_JS_TOKENS)
            ):
                steps.append(
                    {
                        "op": "quickjs_eval",
                        "preset": "CUSTOM",
                        "script": raw_js,
                        "timeoutMs": 2500,
                    }
                )

    return steps


def _parse_key_or_iv_from_expr(expr: str, consts: dict[str, str]) -> dict[str, str] | None:
    """Resolve a Kotlin key/IV expression into hex, utf8, or base64 dict fields."""
    if not expr:
        return None
    cleaned = expr.strip()

    # hexStringToByteArray("...") / decodeHex("...")
    m_hex = re.search(r'(?:hexStringToByteArray|decodeHex)\(\s*"([0-9a-fA-F]+)"\s*\)', cleaned)
    if m_hex:
        return {"hex": m_hex.group(1)}
    m_hex_var = re.search(r'(?:hexStringToByteArray|decodeHex)\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)', cleaned)
    if m_hex_var and m_hex_var.group(1) in consts:
        val = consts[m_hex_var.group(1)]
        if re.fullmatch(r"[0-9a-fA-F]+", val):
            return {"hex": val}

    # Base64.decode("...", ...)
    m_b64 = re.search(r'Base64\.decode\(\s*"([^"]+)"', cleaned)
    if m_b64:
        try:
            decoded = base64.b64decode(m_b64.group(1), validate=True)
            if decoded:
                return {"base64": m_b64.group(1), "hex": decoded.hex()}
        except Exception:
            pass

    # UTF-8 string literal or constant
    resolved = _resolve_kt_string_expr(cleaned, consts)
    if resolved:
        raw_bytes = resolved.encode("utf-8")
        return {"utf8": resolved, "hex": raw_bytes.hex()}

    return None


def extract_crypto_steps(kt_text: str, gradle_text: str = "") -> list[dict[str, Any]]:
    """Detect static crypto/decompression in Kotlin and synthesize dynamic_crypto / openssl_salted_decrypt / lz_string."""
    kt = kt_text or ""
    combined_low = f"{kt}\n{gradle_text or ''}".lower()
    consts = _extract_kt_string_constants(kt)
    steps: list[dict[str, Any]] = []

    # 1. CryptoAES.decrypt(cipher, password) or Salted__ with static password
    m_caes = re.search(r'CryptoAES\.decrypt\([^,]+,\s*([^)]+)\)', kt)
    if m_caes:
        pw = _resolve_kt_string_expr(m_caes.group(1), consts)
        if pw:
            if any(tok in kt for tok in ('"ct"', '"iv"', '"s"', "CryptoJS")):
                steps.append(
                    {
                        "op": "dynamic_crypto",
                        "algorithm": "CRYPTOJS_JSON",
                        "keyUtf8": pw,
                        "inputFormat": "AUTO",
                        "outputFormat": "UTF8",
                    }
                )
            else:
                steps.append({"op": "openssl_salted_decrypt", "password": pw})

    # 2. Cipher.getInstance("AES/...") + SecretKeySpec(..., "AES") / keyRegex
    m_cipher = re.search(r'Cipher\.getInstance\(\s*"(AES(?:/(ECB|CBC|GCM)(?:/[^"]+)?)?)"\s*\)', kt)
    has_aes_secret_spec = bool(re.search(r'SecretKeySpec\([^)]*,\s*"AES"\s*\)', kt))
    if m_cipher or has_aes_secret_spec:
        mode = (m_cipher.group(2) if m_cipher and m_cipher.group(2) else "").upper()
        if not mode:
            mode = "CBC" if ("IvParameterSpec(" in kt or "ivPrepend" in kt) else "ECB"
        algo = {"ECB": "AES_ECB", "CBC": "AES_CBC", "GCM": "AES_GCM"}.get(mode)
        if algo:
            key_info: dict[str, str] | None = None
            m_sks = re.search(r'SecretKeySpec\(\s*([^,]+?)\s*,\s*"AES"\s*\)', kt)
            if m_sks:
                key_info = _parse_key_or_iv_from_expr(m_sks.group(1), consts)

            if key_info is None:
                for k_name in ("AES_KEY", "KEY", "SECRET_KEY", "DECRYPT_KEY", "keyHex", "aesKey", "secretKey"):
                    if k_name in consts:
                        val = consts[k_name]
                        if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{48}|[0-9a-fA-F]{64}", val):
                            key_info = {"hex": val}
                            break
                        if len(val.encode("utf-8")) in (16, 24, 32):
                            key_info = {"utf8": val, "hex": val.encode("utf-8").hex()}
                            break

            # Support dynamic keyRegex if specified in Kotlin
            key_regex: str | None = None
            if key_info is None:
                m_krx = re.search(r'(?:key|aesKey|secret)\s*=\s*Regex\(\s*"([^"]+)"\s*\)', kt, re.I)
                if m_krx and _check_redos_safe(m_krx.group(1)):
                    key_regex = m_krx.group(1)

            iv_info: dict[str, str] | None = None
            m_iv = re.search(r'IvParameterSpec\(\s*([^)]+)\)', kt)
            if m_iv:
                iv_info = _parse_key_or_iv_from_expr(m_iv.group(1), consts)
            else:
                for iv_name in ("AES_IV", "IV", "ivHex", "aesIv"):
                    if iv_name in consts:
                        val = consts[iv_name]
                        if re.fullmatch(r"[0-9a-fA-F]{24}|[0-9a-fA-F]{32}", val):
                            iv_info = {"hex": val}
                            break
                        if len(val.encode("utf-8")) in (12, 16):
                            iv_info = {"utf8": val, "hex": val.encode("utf-8").hex()}
                            break

            iv_prepend = bool(
                re.search(r'(?:copyOfRange|sliceArray)\(\s*0\s*(?:,|\.\.)\s*(?:15|16|11|12)\s*\)', kt)
            )

            valid_key = False
            step: dict[str, Any] = {
                "op": "dynamic_crypto",
                "algorithm": algo,
                "inputFormat": "AUTO",
                "outputFormat": "UTF8",
            }
            if key_info:
                k_hex = key_info.get("hex", "")
                if len(k_hex) in (32, 48, 64):
                    step["keyHex"] = k_hex
                    valid_key = True
                elif "utf8" in key_info and len(key_info["utf8"].encode("utf-8")) in (16, 24, 32):
                    step["keyUtf8"] = key_info["utf8"]
                    valid_key = True
                elif "base64" in key_info:
                    step["keyBase64"] = key_info["base64"]
                    valid_key = True
            elif key_regex:
                step["keyRegex"] = key_regex
                valid_key = True

            if algo in ("AES_CBC", "AES_GCM"):
                req_iv_hex_len = 24 if algo == "AES_GCM" else 32
                if iv_info and len(iv_info.get("hex", "")) == req_iv_hex_len:
                    step["ivHex"] = iv_info["hex"]
                elif iv_info and "base64" in iv_info:
                    step["ivBase64"] = iv_info["base64"]
                elif iv_info and "utf8" in iv_info:
                    step["ivUtf8"] = iv_info["utf8"]
                elif iv_prepend:
                    step["ivPrepend"] = True
                else:
                    valid_key = False

            if valid_key:
                steps.append(step)

    # 3. Salted__ literal without CryptoAES wrapper
    if not any(s["op"] in ("openssl_salted_decrypt", "dynamic_crypto") for s in steps) and "Salted__" in kt:
        for cand_name in ("password", "PASSWORD", "secret", "SECRET", "passphrase", "KEY", "key"):
            if cand_name in consts and consts[cand_name]:
                steps.append({"op": "openssl_salted_decrypt", "password": consts[cand_name]})
                break

    # 4. LZString decompression
    if "LZString.decompressFromEncodedURIComponent" in kt:
        steps.append({"op": "lz_string", "mode": "URI_COMPONENT"})
    elif "LZString" in kt or "lib:lzstring" in combined_low:
        steps.append({"op": "lz_string", "mode": "BASE64"})

    # 5. GZIP / Deflate
    if "GZIPInputStream" in kt:
        steps.append({"op": "gzip_decompress"})
    elif "InflaterInputStream" in kt:
        steps.append({"op": "deflate_decompress"})

    return steps


def extract_image_unscramble_steps(kt_text: str, gradle_text: str = "") -> list[dict[str, Any]]:
    """Detect image descrambling (Publus, SpeedBinb, Grid/Strip Canvas) with extractable parameters."""
    kt = kt_text or ""
    combined_low = f"{kt}\n{gradle_text or ''}".lower()
    ints = _extract_kt_int_constants(kt)
    consts = _extract_kt_string_constants(kt)

    mode: str | None = None
    if "publus" in combined_low or "lib:publus" in combined_low:
        mode = "PUBLUS"
    elif "speedbinb" in combined_low or "lib:speedbinb" in combined_low:
        mode = "SPEEDBINB"

    cols: int | None = None
    rows: int | None = None
    block_w: int | None = None
    block_h: int | None = None

    for k in ("columns", "cols", "colCount", "COLUMNS", "COLS", "DIVIDE_X", "sliceX"):
        if k in ints and ints[k] > 0:
            cols = ints[k]
            break
    for k in ("rows", "rowCount", "ROWS", "DIVIDE_Y", "sliceY", "pieces", "slices", "stripCount"):
        if k in ints and ints[k] > 0:
            rows = ints[k]
            break
    if cols is None and rows is None:
        m_div = re.search(r'\bdivideNum\s*=\s*(\d+)', kt, re.I)
        if m_div and int(m_div.group(1)) > 0:
            cols = int(m_div.group(1))
            rows = int(m_div.group(1))
        else:
            m_wh = re.search(r'width\s*/\s*(\d+)[\s\S]{0,120}height\s*/\s*(\d+)', kt)
            if m_wh and int(m_wh.group(1)) > 0 and int(m_wh.group(2)) > 0:
                cols = int(m_wh.group(1))
                rows = int(m_wh.group(2))

    for k in ("blockWidth", "tileWidth", "pieceWidth", "BLOCK_WIDTH", "TILE_WIDTH"):
        if k in ints and ints[k] > 0:
            block_w = ints[k]
            break
    for k in ("blockHeight", "tileHeight", "pieceHeight", "BLOCK_HEIGHT", "TILE_HEIGHT"):
        if k in ints and ints[k] > 0:
            block_h = ints[k]
            break
    if block_w is None and block_h is None:
        for k in ("blockSize", "tileSize", "BLOCK_SIZE", "TILE_SIZE"):
            if k in ints and ints[k] > 0:
                block_w = ints[k]
                block_h = ints[k]
                break

    if mode is None:
        has_bitmap_cue = any(tok in kt for tok in ("Bitmap.createBitmap", "Canvas(", "ImageInterceptor"))
        if not has_bitmap_cue:
            return []
        if cols is not None and rows is None and cols > 1:
            rows = 1
            mode = "GRID"
        elif rows is not None and cols is None and rows > 1:
            cols = 1
            mode = "STRIP_VERTICAL"
        elif (cols and cols > 1) or (rows and rows > 1) or (block_w and block_h):
            mode = "GRID"
        else:
            return []

    step: dict[str, Any] = {
        "op": "grid_unscramble",
        "mode": mode,
        "columns": cols or 1,
        "rows": rows or 1,
    }
    if block_w is not None:
        step["blockWidth"] = block_w
    if block_h is not None:
        step["blockHeight"] = block_h

    m_filter = re.search(r'(?:url|imageUrl)\.(?:contains|endsWith)\(\s*"([^"]+)"', kt)
    if m_filter:
        step["imageUrlContains"] = m_filter.group(1)

    m_seed_int = re.search(r'\bseed\s*=\s*(-?\d+)L?\b', kt)
    if m_seed_int:
        step["seed"] = int(m_seed_int.group(1))

    m_seed_rx = re.search(r'(?:seedRegex|seedPattern)\s*=\s*"([^"]+)"', kt)
    if m_seed_rx and _check_redos_safe(m_seed_rx.group(1)):
        step["seedFromUrlRegex"] = m_seed_rx.group(1)
    elif "seedRegex" in consts and _check_redos_safe(consts["seedRegex"]):
        step["seedFromUrlRegex"] = consts["seedRegex"]

    if "SPLIT_FIRST" in kt:
        step["remainderPolicy"] = "SPLIT_FIRST"

    m_rots = re.search(r'(?:rotations|ROTATIONS)\s*=\s*(?:listOf|intArrayOf)\(\s*([0-9,\s]+)\)', kt)
    if m_rots:
        raw_rots = [int(x.strip()) for x in m_rots.group(1).split(",") if x.strip().isdigit()]
        if raw_rots and all(r in _ALLOWED_ROTATIONS for r in raw_rots):
            step["rotations"] = raw_rots

    return [step]


def extract_query_signer_spec(kt_text: str) -> dict[str, Any] | None:
    """Detect HMAC/MD5/SHA1/SHA256 signing with an extractable literal secret and emit `querySigner`."""
    kt = kt_text or ""
    if not kt:
        return None
    consts = _extract_kt_string_constants(kt)

    algo: str | None = None
    if re.search(r'\bHmacSHA256\b|\bhmacSha256\b', kt):
        algo = "hmac_sha256"
    elif re.search(r'\bHmacSHA1\b|\bhmacSha1\b', kt):
        algo = "hmac_sha1"
    elif re.search(r'MessageDigest\.getInstance\(\s*"SHA-1"\s*\)|\bsha1(?:Hex)?\b', kt):
        algo = "sha1_salted"
    elif re.search(r'MessageDigest\.getInstance\(\s*"MD5"\s*\)|\bmd5(?:Hex)?\b', kt):
        algo = "md5_salted"
    elif re.search(r'MessageDigest\.getInstance\(\s*"SHA-256"\s*\)|\bsha256(?:Hex)?\b', kt):
        if any(tok in kt for tok in ("currentTimeMillis", "epochSecond", "timestamp", "Instant")):
            algo = "sha256_timestamp"
        else:
            algo = "sha256_timestamp"

    if algo is None:
        return None

    secret: str | None = None
    m_sks = re.search(r'SecretKeySpec\(\s*([^,]+?)\s*,\s*"Hmac', kt)
    if m_sks:
        secret = _resolve_kt_string_expr(m_sks.group(1), consts)

    if not secret:
        for var_name in (
            "hmacSecret",
            "HMAC_SECRET",
            "signSecret",
            "SIGN_SECRET",
            "vrfSecret",
            "VRF_SECRET",
            "apiSecret",
            "API_SECRET",
            "salt",
            "SALT",
            "secret",
            "SECRET",
            "signKey",
            "SIGN_KEY",
        ):
            if var_name in consts and consts[var_name]:
                secret = consts[var_name]
                break

    if not secret:
        return None

    target = "QUERY"
    header_name: str | None = None
    param_name = "vrf"

    m_hdr = re.search(
        r'\.(?:addHeader|header)\(\s*"([^"]+)"\s*,\s*(?:sign|signature|sig|hmac|digest|token|vrf)[^)]*\)',
        kt,
        re.I,
    )
    if m_hdr and m_hdr.group(1).strip().lower() not in ("host", "referer", "origin", "user-agent", "accept", "content-type"):
        target = "HEADER"
        header_name = m_hdr.group(1).strip()
    else:
        m_qp = re.search(
            r'\.addQueryParameter\(\s*"([^"]+)"\s*,\s*(?:sign|signature|sig|hmac|digest|token|vrf)[^)]*\)',
            kt,
            re.I,
        )
        if m_qp and m_qp.group(1).strip():
            param_name = m_qp.group(1).strip()
        elif "vrf" not in kt.lower() and re.search(r'\b(signature|sig)\b', kt, re.I):
            param_name = "sig"

    ts_header: str | None = None
    m_tsh = re.search(r'\.(?:addHeader|header)\(\s*"([^"]*(?:time|ts|date)[^"]*)"\s*,', kt, re.I)
    if m_tsh and m_tsh.group(1).strip().lower() != "host":
        ts_header = m_tsh.group(1).strip()

    ts_format = "EPOCH_SECONDS"
    if "currentTimeMillis" in kt:
        ts_format = "EPOCH_MILLIS"
    elif "ISO_INSTANT" in kt or "ISO_8601" in kt:
        ts_format = "ISO_8601"

    m_prefix = re.search(r'encodedPath\.startsWith\(\s*"(/[^"]*)"\s*\)', kt)
    path_prefix = m_prefix.group(1) if m_prefix else ("/api" if "/api" in kt else "/")

    signer: dict[str, Any] = {
        "algorithm": algo,
        "pathPrefix": path_prefix,
        "stripPathPrefix": True,
        "paramName": param_name,
        "hmacSecret": secret,
        "target": target,
        "timestampFormat": ts_format,
    }
    if header_name:
        signer["headerName"] = header_name
    if ts_header:
        signer["timestampHeaderName"] = ts_header

    return signer


def extract_pipeline_steps_from_kotlin(kt_text: str, gradle_text: str = "") -> list[dict[str, Any]]:
    """Collect all statically extractable pipeline steps (QuickJS, crypto, image unscramble)."""
    steps: list[dict[str, Any]] = []
    steps.extend(extract_quickjs_steps(kt_text, gradle_text=gradle_text))
    steps.extend(extract_crypto_steps(kt_text, gradle_text=gradle_text))
    steps.extend(extract_image_unscramble_steps(kt_text, gradle_text=gradle_text))
    return steps[:12]


def _collect_all_recipe_ops(recipe: dict[str, Any] | None) -> set[str]:
    ops: set[str] = set()
    if not isinstance(recipe, dict):
        return ops
    for key in ("pipelineSteps", "listPipelineSteps", "chaptersPipelineSteps"):
        for step in recipe.get(key) or []:
            if isinstance(step, dict) and step.get("op"):
                ops.add(str(step["op"]))
    ja = recipe.get("jsonApi")
    if isinstance(ja, dict):
        for sec in ("mangaList", "details", "chapters", "pages"):
            sec_obj = ja.get(sec)
            if isinstance(sec_obj, dict):
                for step in sec_obj.get("pipelineSteps") or []:
                    if isinstance(step, dict) and step.get("op"):
                        ops.add(str(step["op"]))
    return ops


def _strip_optional_filter_methods(kt_text: str) -> str:
    """Remove optional filter-only methods (parseGenres/fetchFilterData) when checking core runtime blockers."""
    text = kt_text or ""
    if not text:
        return ""
    out = []
    pos = 0
    n = len(text)
    removed_any = False
    sig_re = re.compile(r"\b(?:override\s+|protected\s+|private\s+|open\s+|suspend\s+)*fun\s+(?:parseGenres|fetchFilterData)\b")
    while pos < n:
        m = sig_re.search(text, pos)
        if not m:
            out.append(text[pos:])
            break
        removed_any = True
        out.append(text[pos : m.start()])
        # Scan header to '=' (expression body) or '{' (block body)
        i = m.end()
        brace_idx = -1
        eq_idx = -1
        paren_depth = 0
        while i < n:
            ch = text[i]
            if ch == "(":
                paren_depth += 1
            elif ch == ")":
                paren_depth = max(0, paren_depth - 1)
            elif paren_depth == 0:
                if ch == "{":
                    brace_idx = i
                    break
                if ch == "=" and eq_idx < 0:
                    eq_idx = i
                elif ch == "\n" and eq_idx >= 0 and not text[eq_idx:i].strip().endswith(("=", ".", "(")):
                    pos = i + 1
                    break
            i += 1
        else:
            pos = n
            break

        if brace_idx >= 0:
            depth = 0
            in_str = None
            j = brace_idx
            while j < n:
                c = text[j]
                if in_str:
                    if c == "\\":
                        j += 2
                        continue
                    if c == in_str:
                        in_str = None
                else:
                    if c in ('"', "'"):
                        in_str = c
                    elif c == "{":
                        depth += 1
                    elif c == "}":
                        depth -= 1
                        if depth == 0:
                            j += 1
                            break
                j += 1
            pos = j
        elif eq_idx >= 0 and i < n:
            pos = i + 1
    result = "".join(out)
    if removed_any:
        result = re.sub(r"^\s*import\s+[^\n]+\n?", "", result, flags=re.M)
    return result


def has_unresolved_native_primitives(
    kt_text: str,
    gradle_text: str = "",
    recipe: dict[str, Any] | None = None,
) -> tuple[bool, list[str]]:
    """Return (has_unresolved, reasons) comparing Kotlin native cues against synthesized recipe capabilities."""
    kt = kt_text or ""
    core_kt = _strip_optional_filter_methods(kt)
    combined = f"{kt}\n{gradle_text or ''}"
    combined_low = combined.lower()
    ops = _collect_all_recipe_ops(recipe)
    rec = recipe or {}
    unresolved: list[str] = []

    has_qjs_cue = (
        any(tok in core_kt for tok in ("QuickJs", "quickjs", "evaluateJs", "Duktape", "Synchrony", "Unpacker"))
        or "lib:synchrony" in combined_low
        or "lib:unpacker" in combined_low
        or "__next_f" in combined
        or "eval(function(p,a,c,k" in combined_low
    )
    if has_qjs_cue and "quickjs_eval" not in ops:
        unresolved.append("QUICKJS")

    has_aes_sks = bool(re.search(r'SecretKeySpec\([^)]*,\s*"(?!Hmac)[^"]*"\s*\)', kt))
    has_cipher_cue = (
        any(tok in kt for tok in ("CryptoAES", "Cipher", "CryptoJS", "Salted__", "PBKDF2", "AES/GCM", "AES/ECB", "AES/CBC", "AES"))
        or has_aes_sks
        or "lib:cryptoaes" in combined_low
    )
    has_cipher_op = bool(
        {"dynamic_crypto", "aes_ecb_decrypt", "aes_cbc_decrypt", "aes_gcm_decrypt", "openssl_salted_decrypt"} & ops
    )
    if has_cipher_cue and not has_cipher_op:
        unresolved.append("CRYPTO (Cipher/AES sin clave extraible)")

    has_lz_cue = "LZString" in kt or "lib:lzstring" in combined_low
    if has_lz_cue and "lz_string" not in ops:
        unresolved.append("CRYPTO (LZString)")

    has_img_cue = (
        any(tok in kt for tok in ("Bitmap.createBitmap", "Canvas(", "ImageInterceptor", "publus", "speedbinb"))
        or "lib:publus" in combined_low
        or "lib:speedbinb" in combined_low
        or "lib:dataimage" in combined_low
    )
    if has_img_cue and "grid_unscramble" not in ops:
        unresolved.append("IMAGE_SCRAMBLE")

    has_vrf_cue = bool(
        "VrfSigner" in kt
        or re.search(r'"vrf"', kt, re.I)
        or re.search(r"\b(signRequest|generateVrf|vrfToken)\b", kt, re.I)
    )
    if has_vrf_cue and not isinstance(rec.get("querySigner"), dict):
        unresolved.append("VRF_SIGNING")

    has_auth_cue = any(tok in kt for tok in ("authToken", "Bearer", "login("))
    if has_auth_cue and not isinstance(rec.get("authPreFlight"), dict):
        unresolved.append("AUTH")

    return bool(unresolved), unresolved


def synthesize_recipe_from_kotlin(
    kotlin_text: str,
    source_id: str,
    name: str,
    base_url: str,
    lang: str = "es",
    pkg_name: str = "",
    version_code: int = 1,
    upstream_source_id: int | None = None,
    upstream_repo: str = "keiyoushi/extensions-source",
    attribution: str = "The Tachiyomi / Keiyoushi Contributors",
    license_id: str = "Apache-2.0",
    gradle_text: str = "",
) -> dict[str, Any] | None:
    """Analyze Kotlin source text and construct a SourceRecipe v2 dict if declarative patterns exist.

    Synthesizes selectors, JSON/GraphQL API specs, QuickJS unpackers, dynamic crypto,
    grid unscrambling, and query/header signers. Returns None if required native logic
    cannot be statically extracted into declarative primitives.
    """
    if not kotlin_text or not base_url:
        return None

    selectors = extract_html_selectors(kotlin_text)
    json_api = extract_json_api_spec(kotlin_text, base_url)
    extracted_steps = extract_pipeline_steps_from_kotlin(kotlin_text, gradle_text=gradle_text)
    query_signer = extract_query_signer_spec(kotlin_text)

    preset = "CSS_GENERIC"
    if json_api:
        preset = "JSON_API"
    elif not selectors.get("listSelector"):
        # Allow RSC / Packer sources with QuickJS steps even when listSelector isn't explicit in Kotlin
        if any(s.get("op") == "quickjs_eval" for s in extracted_steps):
            selectors["listSelector"] = "a[href*='/manga/'], a[href*='/series/'], div.manga-item"
        else:
            return None

    pop_req = extract_request_path(kotlin_text, "popularMangaRequest")
    cat_path = "/manga"
    if pop_req and pop_req.get("pathTemplate"):
        raw_p = pop_req["pathTemplate"].split("?")[0].replace("/page/{page}", "")
        cat_path = raw_p if raw_p else "/manga"

    clean_base = base_url.rstrip("/")
    recipe: dict[str, Any] = {
        "schemaVersion": 2,
        "sourceId": source_id,
        "name": name,
        "baseUrl": clean_base,
        "lang": lang,
        "version": 1,
        "versionId": 1,
        "preset": preset,
        "status": "ACTIVE",
        "maxHtmlBytes": 2097152,
        "catalogPath": cat_path,
        "headers": {
            "Referer": f"{clean_base}/",
        },
        "mode": "declarative",
        "license": license_id,
        "attribution": attribution,
        "upstreamRepo": upstream_repo,
        "pkgName": pkg_name,
        "versionCode": version_code,
        "upstreamExtVersionCode": version_code,
    }

    if upstream_source_id is not None:
        recipe["upstreamSourceId"] = upstream_source_id
        recipe["upstreamSourceIds"] = [upstream_source_id]

    if query_signer is not None:
        recipe["querySigner"] = query_signer

    if extracted_steps:
        recipe["pipelineSteps"] = extracted_steps
        if any(s.get("op") == "quickjs_eval" and s.get("preset") == "NEXT_RSC" for s in extracted_steps):
            recipe["listPipelineSteps"] = [
                s for s in extracted_steps if s.get("op") == "quickjs_eval" and s.get("preset") == "NEXT_RSC"
            ]

    if preset == "JSON_API":
        recipe["jsonApi"] = json_api
    else:
        final_selectors = {
            "listSelector": selectors.get("listSelector", "div.manga, div.item"),
            "titleSelector": selectors.get("titleSelector", "h3 a, h2 a, a.title"),
            "linkSelector": selectors.get("titleSelector", "a"),
            "chapterSelector": selectors.get("chapterSelector", "li a, div.chapter a"),
            "pageImgSelector": selectors.get("pageImgSelector", "div.page img, img.chapter-img"),
        }
        if selectors.get("nextPageSelector"):
            final_selectors["nextPageSelector"] = selectors["nextPageSelector"]
        recipe["selectors"] = final_selectors

    has_unresolved, _ = has_unresolved_native_primitives(kotlin_text, gradle_text=gradle_text, recipe=recipe)
    if has_unresolved:
        return None

    return recipe
