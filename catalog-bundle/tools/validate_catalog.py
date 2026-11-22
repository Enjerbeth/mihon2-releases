"""Validate v2 catalog index, source recipes, fixtures, NOTICE, and bundle isolation."""

import argparse
import base64
import hashlib
from html.parser import HTMLParser
import ipaddress
import json
import os
import re
from urllib.parse import urlparse

try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover
    BeautifulSoup = None

try:
    import jsonschema
except ImportError:  # pragma: no cover
    jsonschema = None


BUNDLE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MAX_HEADERS = 16
MAX_STEPS = 12
MAX_LANG_LENGTH = 12
MIN_HTML_BYTES = 65_536
MAX_HTML_BYTES = 3_145_728
MAX_REGEX_PATTERN_LENGTH = 256
SUPPORTED_SCHEMA_VERSIONS = (1, 2)
ALLOWED_PRESETS = {"MADARA", "MANGA_THEMESIA", "MANGA_READER_CMS", "CSS_GENERIC", "JSON_API"}
ALLOWED_STATUSES = {"DRAFT", "ACTIVE", "QUARANTINED", "DISABLED"}
ALLOWED_FAMILIES = {"STANDARD", "QWIK_SERIES", "INERTIA_SSR", "DATATABLES_AJAX", "MULTI_VIEW_HTML"}
ALLOWED_HTTP_METHODS = {"GET", "POST"}
ALLOWED_PAGINATION_MODES = {
    "PAGE_NUMBER",
    "NEXT_SELECTOR",
    "JSON_HAS_NEXT",
    "JSON_PAGE_COMPARE",
    "JSON_CURSOR",
    "OFFSET_LIMIT",
}
ALLOWED_GRID_FORMATS = {"PNG", "WEBP", "JPEG", "JPG"}
ALLOWED_GRID_MODES = {"GRID", "STRIP_VERTICAL", "PUBLUS", "SPEEDBINB"}
ALLOWED_GRID_ROTATIONS = {0, 90, 180, 270}
ALLOWED_QUICKJS_PRESETS = {"PACKER", "NEXT_RSC", "CUSTOM"}
QUICKJS_OUTPUT_VAR_RE = re.compile(r"^[a-zA-Z_$][a-zA-Z0-9_$]*$")
ALLOWED_DYNAMIC_CRYPTO_ALGORITHMS = {
    "AES_CBC",
    "AES_ECB",
    "AES_GCM",
    "OPENSSL_SALTED",
    "CRYPTOJS_JSON",
    "XOR",
}
ALLOWED_CRYPTO_INPUT_FORMATS = {"AUTO", "UTF8", "BASE64", "HEX", "CRYPTOJS_JSON", "RAW", "BYTES"}
ALLOWED_CRYPTO_OUTPUT_FORMATS = {"UTF8", "BASE64", "HEX"}
ALLOWED_DECOMPRESS_ALGORITHMS = {"GZIP", "DEFLATE", "LZ_STRING_BASE64", "LZ_STRING_URI"}
ALLOWED_LZ_STRING_MODES = {"BASE64", "URI", "URI_COMPONENT", "ENCODED_URI_COMPONENT"}
ALLOWED_QUERY_SIGNER_ALGORITHMS = {
    "sbox_xor_cbc",
    "hmac_sha256",
    "hmac_sha1",
    "md5_salted",
    "sha1_salted",
    "sha256_timestamp",
}
ALLOWED_QUERY_SIGNER_TARGETS = {"QUERY", "HEADER"}
ALLOWED_OPS = {
    "css_select",
    "regex_extract",
    "base64_decode",
    "url_resolve",
    "trim_normalize",
    "grid_unscramble",
    "json_path",
    "hex_decode",
    "xor_decrypt",
    "aes_cbc_decrypt",
    "aes_ecb_decrypt",
    "dynamic_crypto",
    "referer_bind",
    "lz_string",
    "gzip_decompress",
    "deflate_decompress",
    "decompress",
    "aes_gcm_decrypt",
    "openssl_salted_decrypt",
    "quickjs_eval",
}

LANG_TAG_RE = re.compile(r"^[a-zA-Z]{2,5}(-[a-zA-Z0-9]{2,8})*$")
SOURCE_ID_RE = re.compile(r"^[a-z0-9._-]+$")
HOST_VALID_RE = re.compile(r"^[a-zA-Z0-9.-]+$|^[0-9a-fA-F:]+$")
BARE_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9.-]+$")
TEMPLATE_PLACEHOLDER_RE = re.compile(r"\{[a-zA-Z0-9_]+\}")

# Built strictly with generic patterns; callers can pass extra patterns via CLI/env.
FORBIDDEN_PRIVACY_PATTERNS = [
    ("personal_email", re.compile(r"@gmail\.com", re.I)),
    ("token_classic", re.compile(r"ghp_[A-Za-z0-9_]+")),
    ("token_fine", re.compile(r"github_pat_[A-Za-z0-9_]+")),
    ("local_windows_users_path", re.compile(r"[a-zA-Z]:[/\\]+users[/\\]+", re.I)),
    ("local_macos_users_path", re.compile(r"(?<![A-Za-z0-9._-])/Users/[A-Za-z0-9._-]+")),
    ("local_linux_home_path", re.compile(r"(?<![A-Za-z0-9._-])/home/[A-Za-z0-9._-]+")),
]


def _compile_extra_forbidden_patterns(extra_patterns=None):
    raw_items = []
    env_val = os.environ.get("CATALOG_FORBIDDEN_PATTERNS", "")
    if env_val.strip():
        for part in re.split(r"[,;]", env_val):
            cleaned = part.strip()
            if cleaned:
                raw_items.append(cleaned)
    for item in extra_patterns or []:
        if isinstance(item, tuple) and len(item) == 2 and hasattr(item[1], "search"):
            raw_items.append(item)
        elif isinstance(item, str) and item.strip():
            raw_items.append(item.strip())

    compiled = []
    for idx, item in enumerate(raw_items):
        if isinstance(item, tuple):
            compiled.append(item)
            continue
        try:
            pat = re.compile(item, re.I)
        except re.error:
            pat = re.compile(re.escape(item), re.I)
        compiled.append((f"custom_{idx}:{item}", pat))
    return compiled


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def check_redos(pattern_str):
    """Return True if pattern has nested quantifiers that risk catastrophic backtracking."""
    if not isinstance(pattern_str, str):
        return True
    group_has_quantifier = []
    escaped = False
    in_char_class = False

    for index, ch in enumerate(pattern_str):
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
            inner_quantified = group_has_quantifier.pop()
            next_ch = pattern_str[index + 1] if index + 1 < len(pattern_str) else ""
            group_quantified = next_ch in ("*", "+", "{")
            if inner_quantified and group_quantified:
                return True
            if group_quantified and group_has_quantifier:
                group_has_quantifier[-1] = True
        elif ch in ("*", "+", "{") and group_has_quantifier:
            group_has_quantifier[-1] = True
    return False


def is_public_ip(ip_obj):
    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    ):
        return False
    if isinstance(ip_obj, ipaddress.IPv4Address):
        b0 = ip_obj.packed[0]
        b1 = ip_obj.packed[1]
        if b0 == 0 or b0 == 10 or b0 == 127:
            return False
        if b0 == 100 and (b1 & 0xC0) == 64:  # 100.64.0.0/10 CGNAT
            return False
        if b0 == 169 and b1 == 254:
            return False
        if b0 == 172 and 16 <= b1 <= 31:
            return False
        if b0 == 192 and b1 == 168:
            return False
        if b0 >= 224:
            return False
        return True
    if isinstance(ip_obj, ipaddress.IPv6Address):
        if ip_obj.ipv4_mapped is not None:
            return False
        first_byte = ip_obj.packed[0]
        second_byte = ip_obj.packed[1]
        if (first_byte & 0xFE) == 0xFC:  # fc00::/7 ULA
            return False
        if first_byte == 0xFE and (second_byte & 0xC0) == 0x80:  # fe80::/10 link-local
            return False
        return True
    return False


def validate_ssrf(url_str):
    """Validate strict HTTPS port-443 public URL policy matching Kotlin SafeUrlPolicy."""
    if not isinstance(url_str, str) or not url_str.strip():
        return False, "URL must be a non-empty string"
    if any(ch.isspace() for ch in url_str):
        return False, "URL must not contain whitespace"
    try:
        parsed = urlparse(url_str)
        if parsed.scheme.lower() != "https":
            return False, "Scheme must be https"
        if parsed.username is not None or parsed.password is not None:
            return False, "Userinfo is not allowed in URL"
        try:
            port = parsed.port
        except ValueError as e:
            return False, f"Invalid port: {e}"
        if port is not None and port != 443:
            return False, f"Only port 443 is allowed, got: {port}"

        hostname = parsed.hostname
        if not hostname:
            return False, "Missing hostname"
        if not HOST_VALID_RE.match(hostname):
            return False, f"Invalid characters in hostname: {hostname}"

        lower_host = hostname.lower()
        if (
            lower_host == "localhost"
            or lower_host.endswith(".localhost")
            or lower_host.endswith(".local")
            or lower_host.endswith(".internal")
            or lower_host.endswith(".arpa")
        ):
            return False, "Forbidden hostname (localhost/local/internal/arpa)"

        try:
            ip = ipaddress.ip_address(hostname)
            if not is_public_ip(ip):
                return False, "IP address is not globally routable"
        except ValueError:
            pass

        return True, ""
    except Exception as e:
        return False, str(e)


def validate_lang_tag(lang):
    if not isinstance(lang, str):
        return False, "lang must be a string"
    trimmed = lang.strip()
    if not (2 <= len(trimmed) <= MAX_LANG_LENGTH) or not LANG_TAG_RE.match(trimmed):
        return False, f"Invalid BCP-47 lang tag: {lang}"
    return True, ""


def validate_relative_recipe_path(raw_path):
    if not isinstance(raw_path, str) or not raw_path.strip():
        return False, "recipePath must not be blank"
    clean_path = raw_path.strip()
    if (
        clean_path.startswith("/")
        or clean_path.startswith("\\")
        or "\\" in clean_path
        or "://" in clean_path
        or clean_path.startswith("//")
        or ":" in clean_path
    ):
        return False, f"Unsafe recipePath must be relative: {raw_path}"
    segments = clean_path.split("/")
    if any(seg in ("", ".", "..") for seg in segments):
        return False, f"Unsafe recipePath contains invalid segment: {raw_path}"
    return True, ""


class _StdlibElement:
    def __init__(self, tag, attrs, parent=None):
        self.tag = tag.lower()
        self.attrs = {k.lower(): (v or "") for k, v in attrs}
        self.classes = set(self.attrs.get("class", "").split())
        self.id = self.attrs.get("id", "")
        self.parent = parent
        self.children = []
        self.text_parts = []

    @property
    def name(self):
        return self.tag

    def get_text(self, separator=" ", strip=True):
        texts = []

        def _collect(el):
            for part in el.text_parts:
                if part:
                    texts.append(part)
            for ch in el.children:
                _collect(ch)

        _collect(self)
        res = separator.join(texts)
        return res.strip() if strip else res

    def find_parent(self, tag_names):
        cur = self.parent
        tag_set = {t.lower() for t in tag_names}
        while cur is not None:
            if cur.tag in tag_set:
                return cur
            cur = cur.parent
        return None

    def has_attr(self, name):
        return name.lower() in self.attrs

    def get(self, name, default=None):
        return self.attrs.get(name.lower(), default)

    def __getitem__(self, name):
        return self.attrs[name.lower()]

    def find(self, name):
        target = name.lower()
        for ch in self.children:
            if ch.tag == target:
                return ch
        for ch in self.children:
            res = ch.find(target)
            if res is not None:
                return res
        return None

    def _matches_simple_step(self, step):
        s = step.strip()
        if not s or s == "*":
            return True
        attr_matches = re.findall(r"\[([a-zA-Z0-9_-]+)(?:([*^$]?=)([\"']?)(.*?)\3)?\]", s)
        s_without_attrs = re.sub(r"\[.*?\]", "", s)

        id_match = re.search(r"#([a-zA-Z0-9_-]+)", s_without_attrs)
        if id_match and self.id != id_match.group(1):
            return False

        class_matches = re.findall(r"\.([a-zA-Z0-9_-]+)", s_without_attrs)
        for cls in class_matches:
            if cls not in self.classes:
                return False

        tag_match = re.match(r"^([a-zA-Z0-9_-]+)", s_without_attrs)
        if tag_match and self.tag != tag_match.group(1).lower():
            return False

        for attr_name, op, _, val in attr_matches:
            attr_name = attr_name.lower()
            if attr_name not in self.attrs:
                return False
            attr_val = self.attrs[attr_name]
            if not op:
                continue
            elif op == "=" and attr_val != val:
                return False
            elif op == "*=" and val not in attr_val:
                return False
            elif op == "^=" and not attr_val.startswith(val):
                return False
            elif op == "$=" and not attr_val.endswith(val):
                return False

        return True

    def select(self, selector):
        results = []
        groups = [g.strip() for g in selector.split(",") if g.strip()]
        for grp in groups:
            raw_tokens = re.split(r"(\s*>\s*|\s+)", grp)
            ops = []
            tokens = []
            for t in raw_tokens:
                if not t:
                    continue
                if t.strip() == ">":
                    ops.append(">")
                elif t.isspace():
                    ops.append(" ")
                else:
                    tokens.append(t.strip())

            def _find_matches(current_elements, step_idx):
                if step_idx >= len(tokens):
                    return current_elements
                step = tokens[step_idx]
                op = ops[step_idx - 1] if step_idx > 0 else " "
                matched = []
                for el in current_elements:
                    if op == ">":
                        candidates = el.children
                    else:
                        candidates = []

                        def _collect_desc(node):
                            for child in node.children:
                                candidates.append(child)
                                _collect_desc(child)

                        _collect_desc(el)

                    for cand in candidates:
                        if cand._matches_simple_step(step):
                            if cand not in matched:
                                matched.append(cand)

                return _find_matches(matched, step_idx + 1)

            res = _find_matches([self], 0)
            for r in res:
                if r not in results:
                    results.append(r)
        return results

    def select_one(self, selector):
        res = self.select(selector)
        return res[0] if res else None


class _StdlibDomParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.root = _StdlibElement("root", [])
        self.stack = [self.root]

    def handle_starttag(self, tag, attrs):
        parent = self.stack[-1]
        elem = _StdlibElement(tag, attrs, parent=parent)
        parent.children.append(elem)
        if tag.lower() not in {"img", "input", "br", "hr", "meta", "link", "base", "area", "col", "source", "wbr"}:
            self.stack.append(elem)

    def handle_endtag(self, tag):
        t = tag.lower()
        for idx in range(len(self.stack) - 1, 0, -1):
            if self.stack[idx].tag == t:
                self.stack = self.stack[:idx]
                break

    def handle_data(self, data):
        if self.stack and data:
            self.stack[-1].text_parts.append(data)


def parse_stdlib_dom(html_content):
    parser = _StdlibDomParser()
    parser.feed(html_content)
    return parser.root


class SimpleHTMLItemParser(HTMLParser):
    def __init__(self, list_sel="", title_sel="", link_sel=""):
        super().__init__()
        self.list_sel = list_sel
        self.title_sel = title_sel
        self.link_sel = link_sel
        self.items = []
        self.in_item = False
        self.current_title = ""
        self.current_link = ""

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)
        classes = attr_dict.get("class", "").split()
        if any(cls in classes for cls in ("manga-item", "page-item-detail", "media", "book-item", "bsx")):
            self.in_item = True
            self.current_title = ""
            self.current_link = ""
        if self.in_item and tag == "a":
            href = attr_dict.get("href", "")
            if href and not self.current_link:
                self.current_link = href

    def handle_endtag(self, tag):
        if tag in ("div", "article", "li") and self.in_item:
            self.in_item = False
            if self.current_title and self.current_link:
                self.items.append({"title": self.current_title.strip(), "link": self.current_link})

    def handle_data(self, data):
        if self.in_item and data.strip() and not self.current_title:
            self.current_title = data


def extract_html_items(html_content, selectors):
    """Extract catalog items using BeautifulSoup/soupsieve when available, else stdlib fallback."""
    list_sel = (selectors or {}).get("listSelector", "")
    title_sel = (selectors or {}).get("titleSelector", "")
    link_sel = (selectors or {}).get("linkSelector", "")
    if BeautifulSoup is not None and list_sel:
        soup = BeautifulSoup(html_content, "html.parser")
        nodes = soup.select(list_sel)
        items = []
        for node in nodes:
            title_node = node.select_one(title_sel) if title_sel else node
            link_node = node.select_one(link_sel) if link_sel else (node if node.name == "a" else node.find("a"))
            title = title_node.get_text(" ", strip=True) if title_node else ""
            if not title and link_node is not None and link_node.has_attr("title"):
                title = str(link_node["title"]).strip()
            if not title:
                title = node.get_text(" ", strip=True)
            href = ""
            if link_node is not None and link_node.has_attr("href"):
                href = str(link_node["href"]).strip()
            elif node.name == "a" and node.has_attr("href"):
                href = str(node["href"]).strip()
            if title and href:
                items.append({"title": title, "link": href})
        return items

    if list_sel:
        dom = parse_stdlib_dom(html_content)
        nodes = dom.select(list_sel)
        items = []
        for node in nodes:
            title_node = node.select_one(title_sel) if title_sel else node
            link_node = node.select_one(link_sel) if link_sel else (node if node.tag == "a" else node.select_one("a"))
            title = title_node.get_text(" ", strip=True) if title_node else ""
            if not title and link_node is not None and link_node.has_attr("title"):
                title = str(link_node.get("title") or "").strip()
            if not title:
                title = node.get_text(" ", strip=True)
            href = ""
            if link_node is not None and link_node.has_attr("href"):
                href = str(link_node.get("href") or "").strip()
            elif node.tag == "a" and node.has_attr("href"):
                href = str(node.get("href") or "").strip()
            if title and href:
                items.append({"title": title, "link": href})
        if items:
            return items

    parser = SimpleHTMLItemParser(list_sel, title_sel, link_sel)
    parser.feed(html_content)
    return parser.items


def validate_headers_map(headers, recipe=None):
    errors = []
    if not isinstance(headers, dict):
        return ["headers must be an object"]
    if len(headers) > MAX_HEADERS:
        errors.append(f"headers cannot exceed {MAX_HEADERS} entries")
    base_url = (recipe or {}).get("baseUrl", "").rstrip("/")
    api_base_url = ((recipe or {}).get("jsonApi") or {}).get("apiBaseUrl") or base_url
    api_base_url = str(api_base_url).rstrip("/") if api_base_url else base_url
    for k, v in headers.items():
        if not isinstance(k, str) or not isinstance(v, str):
            errors.append("header key and value must be strings")
            continue
        if not k.strip():
            errors.append("header key must not be blank")
        if "\r" in k or "\n" in k or "\r" in v or "\n" in v:
            errors.append(f"header '{k}' contains forbidden CR/LF characters")
        lower_k = k.strip().lower()
        if lower_k == "host":
            errors.append("header 'Host' override is forbidden")
        if lower_k in ("referer", "origin"):
            resolved_v = v.strip()
            if base_url:
                resolved_v = resolved_v.replace("{baseUrl}", base_url).replace("{mangaUrl}", f"{base_url}/manga")
            if api_base_url:
                resolved_v = resolved_v.replace("{apiBaseUrl}", api_base_url)
            ok_url, err_url = validate_ssrf(resolved_v)
            if not ok_url:
                errors.append(f"header '{k}' SSRF violation: {err_url}")
    return errors


def _validate_regex_field(pattern, field_name):
    if not isinstance(pattern, str) or not pattern.strip():
        return [f"{field_name} must not be blank"]
    if len(pattern) > MAX_REGEX_PATTERN_LENGTH:
        return [f"{field_name} exceeds {MAX_REGEX_PATTERN_LENGTH} chars"]
    if check_redos(pattern):
        return [f"Potential ReDoS pattern detected in {field_name}"]
    try:
        re.compile(pattern)
    except Exception as e:
        return [f"Invalid regex in {field_name}: {e}"]
    return []


def _validate_path_template(template, field_name, recipe):
    if not isinstance(template, str) or not template.strip():
        return [f"{field_name} must not be blank"]
    if "\r" in template or "\n" in template:
        return [f"{field_name} must not contain CR/LF"]
    trimmed = template.strip()
    if trimmed.lower().startswith("http://"):
        return [f"{field_name} must use https://, not http://"]
    if (
        trimmed.lower().startswith("https://")
        or trimmed.startswith("{baseUrl}")
        or trimmed.startswith("{apiBaseUrl}")
        or trimmed.startswith("{mangaUrl}")
    ):
        base_url = str((recipe or {}).get("baseUrl", "")).rstrip("/")
        api_base = str(((recipe or {}).get("jsonApi") or {}).get("apiBaseUrl") or base_url).rstrip("/")
        substituted = (
            trimmed.replace("{baseUrl}", base_url)
            .replace("{apiBaseUrl}", api_base)
            .replace("{mangaUrl}", f"{base_url}/manga")
        )
        substituted = TEMPLATE_PLACEHOLDER_RE.sub("placeholder", substituted)
        ok_url, err_url = validate_ssrf(substituted)
        if not ok_url:
            return [f"{field_name} SSRF violation: {err_url}"]
    return []


def validate_request_spec(spec, field_name, recipe):
    errors = []
    if not isinstance(spec, dict):
        return [f"{field_name} must be an object"]
    method = spec.get("method", "GET")
    if method not in ALLOWED_HTTP_METHODS:
        errors.append(f"{field_name}.method must be one of {sorted(ALLOWED_HTTP_METHODS)}")
    errors.extend(_validate_path_template(spec.get("pathTemplate", ""), f"{field_name}.pathTemplate", recipe))
    if spec.get("firstPagePathTemplate") is not None:
        errors.extend(
            _validate_path_template(spec["firstPagePathTemplate"], f"{field_name}.firstPagePathTemplate", recipe)
        )
    if spec.get("headers") is not None:
        errors.extend(validate_headers_map(spec["headers"], recipe))
    if spec.get("graphqlQuery") is not None:
        gq = spec["graphqlQuery"]
        if not isinstance(gq, str) or not gq.strip():
            errors.append(f"{field_name}.graphqlQuery must be a non-blank string")
        if method != "POST":
            errors.append(f"{field_name}.method must be POST when graphqlQuery is set")
    if spec.get("graphqlVariablesTemplate") is not None:
        gvt = spec["graphqlVariablesTemplate"]
        if not isinstance(gvt, str):
            errors.append(f"{field_name}.graphqlVariablesTemplate must be a string")
    return errors


def validate_pagination_spec(spec, field_name):
    errors = []
    if not isinstance(spec, dict):
        return [f"{field_name} must be an object"]
    mode = spec.get("mode", "PAGE_NUMBER")
    if mode not in ALLOWED_PAGINATION_MODES:
        errors.append(f"{field_name}.mode invalid: {mode}")
    start_page = spec.get("startPage", 1)
    if not _is_int(start_page) or start_page < 0:
        errors.append(f"{field_name}.startPage must be >= 0")
    page_size = spec.get("pageSize", 24)
    if not _is_int(page_size) or not (1 <= page_size <= 200):
        errors.append(f"{field_name}.pageSize must be in 1..200")
    max_pages = spec.get("maxPages", 20)
    if not _is_int(max_pages) or not (1 <= max_pages <= 250):
        errors.append(f"{field_name}.maxPages must be in 1..250")
    return errors


_JMES_SEGMENT_RE = re.compile(r"^(?:[A-Za-z_*$][A-Za-z0-9_$-]*)?(?:\[[^\]]*\])*$")


def validate_json_expression(expr, context_name="json_path", allow_root=False):
    """Validate JSONPath (including $.. recursive descent and [?(...)] filters) or JMESPath syntax."""
    if not isinstance(expr, str) or not expr.strip():
        return [f"{context_name} must be a non-blank expression"]
    if "\r" in expr or "\n" in expr:
        return [f"{context_name} must not contain CR/LF"]

    trimmed = expr.strip()
    if trimmed in ("$", "$."):
        if allow_root:
            return []
        return [f"{context_name} expression must specify a path beyond root '$', got: {expr}"]

    # Structural scan: balanced quotes, brackets, parens, no triple-dots outside strings
    in_quote = None
    escaped = False
    bracket_depth = 0
    paren_depth = 0
    brackets = []
    cur_bracket_start = -1
    i = 0
    n = len(trimmed)
    while i < n:
        ch = trimmed[i]
        if in_quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == in_quote:
                in_quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            in_quote = ch
        elif ch == "[":
            if bracket_depth == 0:
                cur_bracket_start = i + 1
            bracket_depth += 1
        elif ch == "]":
            if bracket_depth == 0:
                return [f"{context_name} has unmatched ']' in: {expr}"]
            bracket_depth -= 1
            if bracket_depth == 0:
                brackets.append(trimmed[cur_bracket_start:i])
        elif ch == "(":
            paren_depth += 1
        elif ch == ")":
            if paren_depth == 0:
                return [f"{context_name} has unmatched ')' in: {expr}"]
            paren_depth -= 1
        elif ch in (";", "{", "}"):
            return [f"{context_name} contains invalid character '{ch}' in: {expr}"]
        elif ch.isspace() and bracket_depth == 0:
            return [f"{context_name} contains unexpected whitespace in: {expr}"]
        elif ch == "." and bracket_depth == 0 and trimmed[i : i + 3] == "...":
            return [f"{context_name} contains invalid '...' operator in: {expr}"]
        i += 1

    if in_quote is not None or bracket_depth != 0 or paren_depth != 0:
        return [f"{context_name} has unclosed quote or bracket in: {expr}"]

    for b_inner in brackets:
        b_strip = b_inner.strip()
        if b_strip in ("", "*"):
            continue
        if re.fullmatch(r"\d+(?:\s*,\s*\d+)*|\d*:\d*(?::\d*)?", b_strip):
            continue
        if (b_strip.startswith("'") and b_strip.endswith("'") and len(b_strip) >= 2) or (
            b_strip.startswith('"') and b_strip.endswith('"') and len(b_strip) >= 2
        ):
            continue
        if b_strip.startswith("?"):
            cond = b_strip[1:].strip()
            if cond.startswith("(") and cond.endswith(")"):
                cond = cond[1:-1].strip()
            if not cond or (trimmed.startswith("$") and "@" not in cond):
                return [f"{context_name} has invalid filter predicate '[{b_inner}]' in: {expr}"]
            continue
        return [f"{context_name} has invalid bracket selector '[{b_inner}]' in: {expr}"]

    if trimmed.startswith("$"):
        if not (trimmed.startswith("$.") or trimmed.startswith("$[")):
            return [f"{context_name} JSONPath must start with '$.' or '$[', got: {expr}"]
        if trimmed.endswith("."):
            return [f"{context_name} JSONPath must not end with '.': {expr}"]
        body = trimmed[2:] if trimmed.startswith("$.") else trimmed[1:]
        if body.startswith("."):
            # Recursive descent at root: $..field or $..[...]
            body = body[1:]
        if not body:
            return [f"{context_name} JSONPath has empty path after '$': {expr}"]
        # Split outside brackets/quotes by '..' then '.'
        return []

    # JMESPath-style expression (e.g. data[].title, items[0].url)
    if trimmed.startswith(".") or trimmed.startswith("/") or trimmed.endswith(".") or ".." in trimmed:
        return [f"{context_name} JMESPath expression syntax invalid: {expr}"]
    if "[" not in trimmed or "]" not in trimmed:
        return [f"{context_name} must be JSONPath ('$.'/'$[') or JMESPath with '[]'/'[idx]': {expr}"]

    # Split outside brackets/quotes by '.'
    segments = []
    cur = []
    b_depth = 0
    q_ch = None
    esc = False
    for ch in trimmed:
        if q_ch:
            cur.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == q_ch:
                q_ch = None
        elif ch in ("'", '"'):
            q_ch = ch
            cur.append(ch)
        elif ch == "[":
            b_depth += 1
            cur.append(ch)
        elif ch == "]":
            b_depth -= 1
            cur.append(ch)
        elif ch == "." and b_depth == 0:
            segments.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    segments.append("".join(cur))
    if any(not seg or not _JMES_SEGMENT_RE.match(seg) for seg in segments):
        return [f"{context_name} JMESPath expression contains invalid segment: {expr}"]
    return []


def validate_pipeline_steps(steps, context_name="pipelineSteps"):
    errors = []
    if steps is None:
        return errors
    if not isinstance(steps, list):
        return [f"{context_name} must be an array"]
    if len(steps) > MAX_STEPS:
        errors.append(f"{context_name} cannot exceed {MAX_STEPS} items")

    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            errors.append(f"{context_name}[{i}] must be an object")
            continue
        op = step.get("op")
        if not isinstance(op, str) or not op.strip():
            errors.append(f"Missing operation at {context_name}[{i}]")
            continue
        if "webview" in op.lower() or op == "webview_capture" or op not in ALLOWED_OPS:
            errors.append(f"Unauthorized operation '{op}' at {context_name}[{i}]")
            continue

        if op == "css_select":
            sel = step.get("selector", "")
            if not isinstance(sel, str) or not sel.strip():
                errors.append(f"css_select selector must not be blank at {context_name}[{i}]")

        elif op == "regex_extract":
            pattern = step.get("pattern", "")
            if not isinstance(pattern, str) or not pattern.strip():
                errors.append(f"regex_extract pattern must not be blank at {context_name}[{i}]")
            elif len(pattern) > MAX_REGEX_PATTERN_LENGTH:
                errors.append(f"regex_extract pattern exceeds {MAX_REGEX_PATTERN_LENGTH} chars at {context_name}[{i}]")
            elif check_redos(pattern):
                errors.append(f"Potential ReDoS pattern detected in regex_extract at {context_name}[{i}]")
            else:
                try:
                    re.compile(pattern)
                except Exception as e:
                    errors.append(f"Invalid regex at {context_name}[{i}]: {e}")
            grp = step.get("group", 1)
            if not _is_int(grp) or grp < 0:
                errors.append(f"regex_extract group must be >= 0 at {context_name}[{i}]")

        elif op == "url_resolve":
            b_url = step.get("baseUrl")
            if b_url is not None:
                ok_b, err_b = validate_ssrf(b_url)
                if not ok_b:
                    errors.append(f"url_resolve baseUrl SSRF violation at {context_name}[{i}]: {err_b}")

        elif op == "grid_unscramble":
            mode = step.get("mode", "GRID")
            if mode is not None and mode not in ALLOWED_GRID_MODES:
                errors.append(
                    f"grid_unscramble mode must be one of {sorted(ALLOWED_GRID_MODES)} at {context_name}[{i}]"
                )
            cols = step.get("columns", 1)
            rows = step.get("rows", 1)
            if not _is_int(cols) or cols <= 0 or not _is_int(rows) or rows <= 0:
                errors.append(f"grid_unscramble columns and rows must be > 0 at {context_name}[{i}]")
            bw = step.get("blockWidth")
            if bw is not None and (not _is_int(bw) or bw <= 0):
                errors.append(f"grid_unscramble blockWidth must be > 0 at {context_name}[{i}]")
            bh = step.get("blockHeight")
            if bh is not None and (not _is_int(bh) or bh <= 0):
                errors.append(f"grid_unscramble blockHeight must be > 0 at {context_name}[{i}]")
            rots = step.get("rotations")
            if rots is not None:
                if not isinstance(rots, list) or any(not _is_int(r) or r not in ALLOWED_GRID_ROTATIONS for r in rots):
                    errors.append(
                        f"grid_unscramble rotations must be an array of values in {{0, 90, 180, 270}} at {context_name}[{i}]"
                    )
                elif rots and (bw is None and bh is None) and _is_int(cols) and cols > 0 and _is_int(rows) and rows > 0:
                    eff_c = 1 if mode == "STRIP_VERTICAL" else cols
                    if len(rots) not in (1, eff_c * rows):
                        errors.append(
                            f"grid_unscramble rotations length must be 1 or {eff_c * rows} at {context_name}[{i}]"
                        )
            perm = step.get("permutation", [])
            if not isinstance(perm, list):
                errors.append(f"grid_unscramble permutation must be an array at {context_name}[{i}]")
            elif perm and _is_int(cols) and cols > 0 and _is_int(rows) and rows > 0:
                effective_cols = 1 if mode == "STRIP_VERTICAL" else cols
                if (bw is not None or bh is not None) and effective_cols == 1 and rows == 1:
                    expected = list(range(len(perm)))
                else:
                    expected = list(range(effective_cols * rows))
                if any(not _is_int(x) for x in perm) or sorted(perm) != expected:
                    errors.append(f"grid_unscramble permutation invalid at {context_name}[{i}]")
            seed = step.get("seed")
            if seed is not None and not _is_int(seed):
                errors.append(f"grid_unscramble seed must be an integer at {context_name}[{i}]")
            for rx_field in ("seedFromUrlRegex", "seedUrlRegex"):
                if step.get(rx_field) is not None:
                    errors.extend(_validate_regex_field(step[rx_field], f"grid_unscramble.{rx_field} at {context_name}[{i}]"))
            shn = step.get("seedHeaderName")
            if shn is not None and (not isinstance(shn, str) or not shn.strip()):
                errors.append(f"grid_unscramble seedHeaderName must not be blank at {context_name}[{i}]")
            fmt = step.get("format", "PNG")
            if not isinstance(fmt, str) or fmt.upper() not in ALLOWED_GRID_FORMATS:
                errors.append(f"grid_unscramble format must be in {sorted(ALLOWED_GRID_FORMATS)} at {context_name}[{i}]")
            rp = step.get("remainderPolicy")
            if rp is not None and rp not in ("KEEP_EDGE", "SPLIT_FIRST"):
                errors.append(f"grid_unscramble remainderPolicy must be KEEP_EDGE or SPLIT_FIRST at {context_name}[{i}]")
            ha = step.get("hashAlgorithm")
            if ha is not None and ha not in ("MD5", "SHA-256"):
                errors.append(f"grid_unscramble hashAlgorithm must be MD5 or SHA-256 at {context_name}[{i}]")

        elif op == "quickjs_eval":
            preset = step.get("preset")
            if preset is not None and preset not in ALLOWED_QUICKJS_PRESETS:
                errors.append(
                    f"quickjs_eval preset must be one of {sorted(ALLOWED_QUICKJS_PRESETS)} at {context_name}[{i}]"
                )
            script = step.get("script")
            allow_empty_preset = preset in ("PACKER", "NEXT_RSC")
            if script is None:
                if not allow_empty_preset:
                    errors.append(f"quickjs_eval script must be a non-blank string at {context_name}[{i}]")
            elif not isinstance(script, str) or (not script.strip() and not allow_empty_preset):
                errors.append(f"quickjs_eval script must be a non-blank string at {context_name}[{i}]")
            elif len(script) > 16384:
                errors.append(f"quickjs_eval script exceeds 16384 chars at {context_name}[{i}]")
            elif script:
                forbid_tokens = (
                    "XMLHttpRequest",
                    "fetch(",
                    "WebSocket",
                    "Packages.",
                    "java.",
                    "android.",
                    "System.exit",
                    "Runtime.getRuntime",
                )
                if any(tok in script for tok in forbid_tokens):
                    errors.append(f"quickjs_eval script contains forbidden security token at {context_name}[{i}]")
            out_var = step.get("outputVar")
            if out_var is not None and (not isinstance(out_var, str) or not QUICKJS_OUTPUT_VAR_RE.match(out_var)):
                errors.append(
                    f"quickjs_eval outputVar must match ^[a-zA-Z_$][a-zA-Z0-9_$]*$ at {context_name}[{i}]"
                )
            t_ms = step.get("timeoutMs", 1000)
            if not _is_int(t_ms) or not (1 <= t_ms <= 3000):
                errors.append(f"quickjs_eval timeoutMs must be between 1 and 3000 at {context_name}[{i}]")

        elif op == "json_path":
            errors.extend(validate_json_expression(step.get("expression", ""), f"{context_name}[{i}].expression", allow_root=False))

        elif op == "xor_decrypt":
            key_hex = step.get("keyHex", "")
            if not isinstance(key_hex, str) or not re.match(r"^[0-9a-fA-F]+$", key_hex) or len(key_hex) % 2 != 0:
                errors.append(f"xor_decrypt keyHex must be non-empty even-length hex at {context_name}[{i}]")

        elif op == "aes_cbc_decrypt":
            key_hex = step.get("keyHex", "")
            if not isinstance(key_hex, str) or not re.match(r"^[0-9a-fA-F]+$", key_hex) or len(key_hex) not in (32, 48, 64):
                errors.append(f"aes_cbc_decrypt keyHex length must be 32, 48, or 64 hex chars at {context_name}[{i}]")
            iv_hex = step.get("ivHex")
            if iv_hex is not None and (not isinstance(iv_hex, str) or not re.match(r"^[0-9a-fA-F]{32}$", iv_hex)):
                errors.append(f"aes_cbc_decrypt ivHex length must be exactly 32 hex chars at {context_name}[{i}]")

        elif op == "aes_ecb_decrypt":
            key_hex = step.get("keyHex", "")
            if not isinstance(key_hex, str) or not re.match(r"^[0-9a-fA-F]+$", key_hex) or len(key_hex) not in (32, 48, 64):
                errors.append(f"aes_ecb_decrypt keyHex length must be 32, 48, or 64 hex chars at {context_name}[{i}]")

        elif op == "aes_gcm_decrypt":
            key_hex = step.get("keyHex", "")
            if not isinstance(key_hex, str) or not re.match(r"^[0-9a-fA-F]+$", key_hex) or len(key_hex) not in (32, 48, 64):
                errors.append(f"aes_gcm_decrypt keyHex length must be 32, 48, or 64 hex chars at {context_name}[{i}]")
            iv_hex = step.get("ivHex")
            if iv_hex is not None and (not isinstance(iv_hex, str) or not re.match(r"^[0-9a-fA-F]{24}$", iv_hex)):
                errors.append(f"aes_gcm_decrypt ivHex length must be exactly 24 hex chars at {context_name}[{i}]")

        elif op == "openssl_salted_decrypt":
            pwd = step.get("password")
            if not isinstance(pwd, str) or not pwd:
                errors.append(f"openssl_salted_decrypt password must be a non-empty string at {context_name}[{i}]")

        elif op == "dynamic_crypto":
            algo = step.get("algorithm", "AES_CBC")
            if algo is not None and algo not in ALLOWED_DYNAMIC_CRYPTO_ALGORITHMS:
                errors.append(
                    f"dynamic_crypto algorithm must be one of {sorted(ALLOWED_DYNAMIC_CRYPTO_ALGORITHMS)} at {context_name}[{i}]"
                )
            k_hex = step.get("keyHex")
            if k_hex is not None:
                is_aes = algo in ("AES_CBC", "AES_ECB", "AES_GCM", None)
                valid_hex = isinstance(k_hex, str) and bool(re.match(r"^[0-9a-fA-F]+$", k_hex)) and (
                    len(k_hex) in (32, 48, 64) if is_aes else (len(k_hex) > 0 and len(k_hex) % 2 == 0)
                )
                if not valid_hex:
                    errors.append(f"dynamic_crypto keyHex invalid format or length at {context_name}[{i}]")
            iv_hex = step.get("ivHex")
            if iv_hex is not None:
                valid_iv_lens = (24,) if algo == "AES_GCM" else ((32,) if algo == "AES_CBC" else (24, 32))
                if not isinstance(iv_hex, str) or not re.match(r"^[0-9a-fA-F]+$", iv_hex) or len(iv_hex) not in valid_iv_lens:
                    errors.append(f"dynamic_crypto ivHex has invalid hex format or length at {context_name}[{i}]")
            for b64_f in ("keyBase64", "ivBase64"):
                b64_v = step.get(b64_f)
                if b64_v is not None:
                    if not isinstance(b64_v, str) or not b64_v.strip():
                        errors.append(f"dynamic_crypto {b64_f} must not be blank at {context_name}[{i}]")
                    else:
                        try:
                            raw_b = base64.b64decode(b64_v.strip(), validate=True)
                            if not raw_b:
                                errors.append(f"dynamic_crypto {b64_f} decoded to empty bytes at {context_name}[{i}]")
                        except Exception:
                            errors.append(f"dynamic_crypto {b64_f} is not valid base64 at {context_name}[{i}]")
            for utf_f in ("keyUtf8", "ivUtf8"):
                utf_v = step.get(utf_f)
                if utf_v is not None and (not isinstance(utf_v, str) or not utf_v):
                    errors.append(f"dynamic_crypto {utf_f} must be a non-empty string at {context_name}[{i}]")
            for rx_f in ("keyRegex", "ivRegex"):
                if step.get(rx_f) is not None:
                    errors.extend(_validate_regex_field(step[rx_f], f"dynamic_crypto.{rx_f} at {context_name}[{i}]"))
            for sel_f in ("keySelector", "ivSelector"):
                sel_v = step.get(sel_f)
                if sel_v is not None and (not isinstance(sel_v, str) or not sel_v.strip()):
                    errors.append(f"dynamic_crypto {sel_f} must not be blank at {context_name}[{i}]")
            if "ivPrepend" in step and not isinstance(step["ivPrepend"], bool):
                errors.append(f"dynamic_crypto ivPrepend must be a boolean at {context_name}[{i}]")
            in_fmt = step.get("inputFormat")
            if in_fmt is not None and in_fmt not in ALLOWED_CRYPTO_INPUT_FORMATS:
                errors.append(
                    f"dynamic_crypto inputFormat must be one of {sorted(ALLOWED_CRYPTO_INPUT_FORMATS)} at {context_name}[{i}]"
                )
            out_fmt = step.get("outputFormat")
            if out_fmt is not None and out_fmt not in ALLOWED_CRYPTO_OUTPUT_FORMATS:
                errors.append(
                    f"dynamic_crypto outputFormat must be one of {sorted(ALLOWED_CRYPTO_OUTPUT_FORMATS)} at {context_name}[{i}]"
                )
            has_key = any(
                isinstance(step.get(kf), str) and bool(step.get(kf).strip())
                for kf in ("keyHex", "keyUtf8", "keyBase64", "keyRegex", "keySelector")
            )
            if not has_key:
                errors.append(
                    f"dynamic_crypto requires at least one key source (keyHex/keyUtf8/keyBase64/keyRegex/keySelector) at {context_name}[{i}]"
                )

        elif op == "lz_string":
            lzm = step.get("mode", "BASE64")
            if lzm is not None and lzm not in ALLOWED_LZ_STRING_MODES:
                errors.append(
                    f"lz_string mode must be one of {sorted(ALLOWED_LZ_STRING_MODES)} at {context_name}[{i}]"
                )

        elif op == "decompress":
            dalgo = step.get("algorithm")
            if dalgo not in ALLOWED_DECOMPRESS_ALGORITHMS:
                errors.append(
                    f"decompress algorithm must be one of {sorted(ALLOWED_DECOMPRESS_ALGORITHMS)} at {context_name}[{i}]"
                )

        elif op == "referer_bind":
            ref_url = step.get("refererUrl", "")
            ok_ref, err_ref = validate_ssrf(ref_url)
            if not ok_ref:
                errors.append(f"referer_bind refererUrl SSRF violation at {context_name}[{i}]: {err_ref}")
    return errors


def _validate_html_extract(he_spec, context_name):
    errors = []
    if he_spec is not None:
        if not isinstance(he_spec, dict):
            errors.append(f"{context_name} must be an object")
        else:
            for s_field in ("titleSelector", "urlSelector", "coverSelector", "dateSelector", "itemSelector"):
                if s_field in he_spec and he_spec[s_field] is not None and not isinstance(he_spec[s_field], str):
                    errors.append(f"{context_name}.{s_field} must be a string or null")
            b_url = he_spec.get("baseUrl")
            if b_url is not None and str(b_url).strip() != "":
                ok_b, err_b = validate_ssrf(str(b_url))
                if not ok_b:
                    errors.append(f"{context_name}.baseUrl SSRF violation: {err_b}")
    return errors


def validate_auth_preflight_spec(spec, recipe):
    errors = []
    if not isinstance(spec, dict):
        return ["authPreFlight must be an object"]
    raw_url = spec.get("url")
    if not isinstance(raw_url, str) or not raw_url.strip():
        errors.append("authPreFlight.url must be a non-blank string")
    else:
        ok_u, err_u = validate_ssrf(raw_url)
        if not ok_u:
            errors.append(f"authPreFlight.url SSRF violation: {err_u}")
    meth = spec.get("method", "GET")
    if meth not in ALLOWED_HTTP_METHODS:
        errors.append(f"authPreFlight.method must be one of {sorted(ALLOWED_HTTP_METHODS)}")
    if spec.get("headers") is not None:
        errors.extend(validate_headers_map(spec["headers"], recipe))
    em = spec.get("extractMode")
    if em not in ("JSON_PATH", "REGEX", "CSS", "HEADER"):
        errors.append("authPreFlight.extractMode must be one of JSON_PATH, REGEX, CSS, HEADER")
    pat = spec.get("extractPattern")
    if not isinstance(pat, str) or not pat.strip():
        errors.append("authPreFlight.extractPattern must not be blank")
    elif em == "REGEX":
        errors.extend(_validate_regex_field(pat, "authPreFlight.extractPattern"))
    ttl = spec.get("cacheTtlSeconds", 900)
    if not _is_int(ttl) or not (1 <= ttl <= 86400):
        errors.append("authPreFlight.cacheTtlSeconds must be between 1 and 86400")
    return errors


def validate_account_sync_spec(spec, recipe):
    errors = []
    if not isinstance(spec, dict):
        return ["accountSync must be an object"]
    login_url = spec.get("loginUrl")
    if login_url is not None and str(login_url).strip() != "":
        ok_u, err_u = validate_ssrf(str(login_url))
        if not ok_u:
            errors.append(f"accountSync.loginUrl SSRF violation: {err_u}")
    if spec.get("loggedOutStatusCodes") is not None:
        codes = spec["loggedOutStatusCodes"]
        if not isinstance(codes, list) or not all(_is_int(c) and 100 <= c <= 599 for c in codes):
            errors.append("accountSync.loggedOutStatusCodes must be a list of HTTP status codes (100..599)")
    if spec.get("loggedOutBodyMarkers") is not None:
        markers = spec["loggedOutBodyMarkers"]
        if not isinstance(markers, list) or not all(isinstance(m, str) and m.strip() for m in markers):
            errors.append("accountSync.loggedOutBodyMarkers must be a list of non-blank strings")
    if spec.get("loggedOutRedirectContains") is not None:
        redirs = spec["loggedOutRedirectContains"]
        if not isinstance(redirs, list) or not all(isinstance(r, str) and r.strip() for r in redirs):
            errors.append("accountSync.loggedOutRedirectContains must be a list of non-blank strings")
    max_pages = spec.get("maxPagesPerSection", 5)
    if not _is_int(max_pages) or not (1 <= max_pages <= 50):
        errors.append("accountSync.maxPagesPerSection must be between 1 and 50")
    sections = spec.get("sections")
    if not isinstance(sections, list) or not (1 <= len(sections) <= 6):
        errors.append("accountSync.sections must be an array of 1..6 section objects")
    else:
        for idx, sec in enumerate(sections):
            if not isinstance(sec, dict):
                errors.append(f"accountSync.sections[{idx}] must be an object")
                continue
            fmt = sec.get("format", "HTML")
            if fmt not in ("HTML", "JSON"):
                errors.append(f"accountSync.sections[{idx}].format must be HTML or JSON")
            items_sel = sec.get("itemsSelector")
            if not isinstance(items_sel, str) or not items_sel.strip():
                errors.append(f"accountSync.sections[{idx}].itemsSelector must be a non-blank string")
            url_sel = sec.get("urlSelector")
            if not isinstance(url_sel, str) or not url_sel.strip():
                errors.append(f"accountSync.sections[{idx}].urlSelector must be a non-blank string")
            req = sec.get("request")
            if req is not None:
                errors.extend(validate_request_spec(req, f"accountSync.sections[{idx}].request", recipe))
                headers = req.get("headers") if isinstance(req, dict) else None
                if isinstance(headers, dict):
                    for hk in headers.keys():
                        if str(hk).lower() in ("cookie", "authorization"):
                            errors.append(
                                f"accountSync.sections[{idx}].request.headers must not contain credential header '{hk}'"
                            )
            if sec.get("pagination") is not None:
                errors.extend(validate_pagination_spec(sec["pagination"], f"accountSync.sections[{idx}].pagination"))
    return errors


def validate_json_api_spec(spec, recipe):
    errors = []
    if not isinstance(spec, dict):
        return ["jsonApi must be an object"]
    api_base = spec.get("apiBaseUrl")
    if api_base is not None and str(api_base).strip() != "":
        ok_u, err_u = validate_ssrf(str(api_base))
        if not ok_u:
            errors.append(f"jsonApi.apiBaseUrl SSRF violation: {err_u}")
    fallback_pages = spec.get("searchFallbackPages", 1)
    if not _is_int(fallback_pages) or not (1 <= fallback_pages <= 20):
        errors.append("jsonApi.searchFallbackPages must be in 1..20")
    for req_key in ("popularRequest", "latestRequest", "searchRequest", "detailsRequest", "chaptersRequest", "pagesRequest"):
        if spec.get(req_key) is not None:
            errors.extend(validate_request_spec(spec[req_key], f"jsonApi.{req_key}", recipe))
    if spec.get("imageHeaders") is not None:
        errors.extend(validate_headers_map(spec["imageHeaders"], recipe))
    ml = spec.get("mangaList")
    if ml is not None:
        if not isinstance(ml, dict):
            errors.append("jsonApi.mangaList must be an object")
        else:
            if ml.get("itemsPath") is not None:
                errors.extend(validate_json_expression(ml["itemsPath"], "jsonApi.mangaList.itemsPath", allow_root=True))
            for pk in ("urlPath", "slugPath", "orgPath", "idPath"):
                if ml.get(pk) is not None:
                    errors.extend(validate_json_expression(ml[pk], f"jsonApi.mangaList.{pk}", allow_root=True))
            for apk in ("titlePaths", "coverPaths"):
                if isinstance(ml.get(apk), list):
                    for idx, pv in enumerate(ml[apk]):
                        errors.extend(validate_json_expression(pv, f"jsonApi.mangaList.{apk}[{idx}]", allow_root=True))
            cover_base = ml.get("coverBaseUrl")
            if cover_base is not None and str(cover_base).strip() != "":
                ok_c, err_c = validate_ssrf(str(cover_base))
                if not ok_c:
                    errors.append(f"jsonApi.mangaList.coverBaseUrl SSRF violation: {err_c}")
            if ml.get("htmlExtract") is not None:
                errors.extend(_validate_html_extract(ml["htmlExtract"], "jsonApi.mangaList.htmlExtract"))
            if ml.get("pipelineSteps") is not None:
                errors.extend(validate_pipeline_steps(ml["pipelineSteps"], context_name="jsonApi.mangaList.pipelineSteps"))
            if ml.get("pagination") is not None:
                errors.extend(validate_pagination_spec(ml["pagination"], "jsonApi.mangaList.pagination"))
    dt = spec.get("details")
    if dt is not None:
        if not isinstance(dt, dict):
            errors.append("jsonApi.details must be an object")
        else:
            for pk in ("rootPath", "genresPath", "authorsPath", "artistsPath", "statusPath", "idPath", "slugPath"):
                if dt.get(pk) is not None:
                    errors.extend(validate_json_expression(dt[pk], f"jsonApi.details.{pk}", allow_root=True))
            for apk in ("titlePaths", "descriptionPaths", "coverPaths", "extraGenrePaths"):
                if isinstance(dt.get(apk), list):
                    for idx, pv in enumerate(dt[apk]):
                        errors.extend(validate_json_expression(pv, f"jsonApi.details.{apk}[{idx}]", allow_root=True))
            if dt.get("pipelineSteps") is not None:
                errors.extend(validate_pipeline_steps(dt["pipelineSteps"], context_name="jsonApi.details.pipelineSteps"))
    ch = spec.get("chapters")
    if ch is not None:
        if not isinstance(ch, dict):
            errors.append("jsonApi.chapters must be an object")
        else:
            for pk in (
                "itemsPath",
                "urlPath",
                "idPath",
                "namePath",
                "numberPath",
                "datePath",
                "scanlatorPath",
                "skipIfTruePath",
                "skipIfNonBlankPath",
                "lockedPath",
            ):
                if ch.get(pk) is not None:
                    errors.extend(validate_json_expression(ch[pk], f"jsonApi.chapters.{pk}", allow_root=True))
            if ch.get("htmlExtract") is not None:
                errors.extend(_validate_html_extract(ch["htmlExtract"], "jsonApi.chapters.htmlExtract"))
            if ch.get("pipelineSteps") is not None:
                errors.extend(validate_pipeline_steps(ch["pipelineSteps"], context_name="jsonApi.chapters.pipelineSteps"))
            if ch.get("pagination") is not None:
                errors.extend(validate_pagination_spec(ch["pagination"], "jsonApi.chapters.pagination"))
    pg = spec.get("pages")
    if pg is not None:
        if not isinstance(pg, dict):
            errors.append("jsonApi.pages must be an object")
        else:
            for pk in ("itemsPath", "imageUrlPath", "orderPath", "decoyTriggerPath"):
                if pg.get(pk) is not None:
                    errors.extend(validate_json_expression(pg[pk], f"jsonApi.pages.{pk}", allow_root=True))
            if pg.get("imageHeaders") is not None:
                errors.extend(validate_headers_map(pg["imageHeaders"], recipe))
            if pg.get("readerHtmlRegex") is not None and str(pg["readerHtmlRegex"]).strip() != "":
                errors.extend(_validate_regex_field(pg["readerHtmlRegex"], "jsonApi.pages.readerHtmlRegex"))
            if pg.get("pipelineSteps") is not None:
                errors.extend(validate_pipeline_steps(pg["pipelineSteps"], context_name="jsonApi.pages.pipelineSteps"))
    return errors


def validate_qwik_spec(spec):
    errors = []
    if not isinstance(spec, dict):
        return ["qwik must be an object"]
    if not isinstance(spec.get("searchQrlHash"), str) or not spec["searchQrlHash"].strip():
        errors.append("qwik.searchQrlHash must not be blank")
    if not isinstance(spec.get("defaultSearchChunk"), str) or not spec["defaultSearchChunk"].strip():
        errors.append("qwik.defaultSearchChunk must not be blank")
    page_size = spec.get("searchPageSize", 26)
    if not _is_int(page_size) or not (1 <= page_size <= 200):
        errors.append("qwik.searchPageSize must be in 1..200")
    dco = spec.get("defaultCoverOrigin")
    if dco is not None and str(dco).strip() != "":
        ok_u, err_u = validate_ssrf(str(dco))
        if not ok_u:
            errors.append(f"qwik.defaultCoverOrigin SSRF violation: {err_u}")
    for rx_key in ("coverOriginRegex", "pageUrlRegex", "requiredChapterSegmentRegex"):
        if spec.get(rx_key) is not None and str(spec[rx_key]).strip() != "":
            errors.extend(_validate_regex_field(spec[rx_key], f"qwik.{rx_key}"))
    return errors


def validate_inertia_spec(spec):
    errors = []
    if not isinstance(spec, dict):
        return ["inertia must be an object"]
    sel = spec.get("scriptSelector", "script[data-page]")
    if not isinstance(sel, str) or not sel.strip():
        errors.append("inertia.scriptSelector must not be blank")
    hosts = spec.get("urlRewriteHosts", [])
    if not isinstance(hosts, list):
        errors.append("inertia.urlRewriteHosts must be an array")
    else:
        for idx, raw_host in enumerate(hosts):
            if not isinstance(raw_host, str):
                errors.append(f"inertia.urlRewriteHosts[{idx}] must be a string")
                continue
            host = raw_host.strip()
            if not host or "://" in host or "/" in host or "@" in host or any(c.isspace() for c in host):
                errors.append(f"inertia.urlRewriteHosts[{idx}] must be a bare hostname: {raw_host}")
                continue
            if not BARE_HOSTNAME_RE.match(host):
                errors.append(f"inertia.urlRewriteHosts[{idx}] contains invalid characters: {raw_host}")
                continue
            ok_h, err_h = validate_ssrf(f"https://{host}")
            if not ok_h:
                errors.append(f"inertia.urlRewriteHosts[{idx}] SSRF violation: {err_h}")
    return errors


def validate_multi_view_spec(spec):
    errors = []
    if not isinstance(spec, dict):
        return ["multiViewReader must be an object"]
    if not isinstance(spec.get("urlTemplate"), str) or not spec["urlTemplate"].strip():
        errors.append("multiViewReader.urlTemplate must not be blank")
    max_views = spec.get("maxViews", 25)
    if not _is_int(max_views) or not (1 <= max_views <= 100):
        errors.append("multiViewReader.maxViews must be in 1..100")
    min_items = spec.get("minItemsPerView", 10)
    if not _is_int(min_items) or not (1 <= min_items <= 200):
        errors.append("multiViewReader.minItemsPerView must be in 1..200")
    return errors


def validate_query_signer(qs):
    errors = []
    if not isinstance(qs, dict):
        return ["querySigner must be an object"]
    algo = qs.get("algorithm")
    param_name = qs.get("paramName", "vrf")
    path_prefix = qs.get("pathPrefix", "/api")
    if not isinstance(param_name, str) or not param_name.strip():
        errors.append("querySigner paramName must be a non-empty string")
    if not isinstance(path_prefix, str) or not path_prefix.startswith("/"):
        errors.append("querySigner pathPrefix must start with '/'")

    target = qs.get("target", "QUERY")
    if target not in ALLOWED_QUERY_SIGNER_TARGETS:
        errors.append(f"querySigner target must be one of {sorted(ALLOWED_QUERY_SIGNER_TARGETS)}")

    header_name = qs.get("headerName")
    if target == "HEADER":
        if not isinstance(header_name, str) or not header_name.strip():
            errors.append("querySigner headerName is required when target is HEADER")
        elif "\r" in header_name or "\n" in header_name or header_name.strip().lower() == "host":
            errors.append(f"querySigner headerName invalid: {header_name!r}")
    elif header_name is not None:
        if not isinstance(header_name, str) or not header_name.strip() or "\r" in header_name or "\n" in header_name or header_name.strip().lower() == "host":
            errors.append(f"querySigner headerName invalid: {header_name!r}")

    ts_header = qs.get("timestampHeaderName")
    if ts_header is not None:
        if not isinstance(ts_header, str) or not ts_header.strip() or "\r" in ts_header or "\n" in ts_header or ts_header.strip().lower() == "host":
            errors.append(f"querySigner timestampHeaderName invalid: {ts_header!r}")

    ts_fmt = qs.get("timestampFormat")
    if ts_fmt is not None:
        if not isinstance(ts_fmt, str) or not ts_fmt.strip() or "\r" in ts_fmt or "\n" in ts_fmt or len(ts_fmt) > 64:
            errors.append(f"querySigner timestampFormat invalid: {ts_fmt!r}")

    sign_tpl = qs.get("signTemplate")
    if sign_tpl is not None:
        if not isinstance(sign_tpl, str) or not sign_tpl.strip() or "\r" in sign_tpl or "\n" in sign_tpl:
            errors.append("querySigner signTemplate must be a non-blank single-line string")

    if algo == "sbox_xor_cbc":
        stages = qs.get("stages")
        if not isinstance(stages, list) or not (1 <= len(stages) <= 8):
            errors.append("querySigner sbox_xor_cbc stages must contain 1..8 entries")
        else:
            for idx, st in enumerate(stages):
                if not isinstance(st, dict):
                    errors.append(f"querySigner stages[{idx}] must be an object")
                    continue
                try:
                    table_bytes = base64.b64decode(st.get("tableBase64", ""), validate=True)
                except Exception:
                    table_bytes = b""
                if len(table_bytes) != 256:
                    errors.append(f"querySigner stages[{idx}] tableBase64 must decode to 256 bytes (got {len(table_bytes)})")
                try:
                    key_bytes = base64.b64decode(st.get("keyBase64", ""), validate=True)
                except Exception:
                    key_bytes = b""
                if not key_bytes:
                    errors.append(f"querySigner stages[{idx}] keyBase64 must decode to non-empty bytes")
                iv = st.get("iv")
                if not _is_int(iv) or not (0 <= iv <= 255):
                    errors.append(f"querySigner stages[{idx}] iv must be an integer in 0..255")
    elif algo in ("hmac_sha256", "hmac_sha1"):
        secret = qs.get("hmacSecret")
        if not isinstance(secret, str) or not secret.strip():
            errors.append(f"querySigner {algo} requires a non-empty hmacSecret")
    elif algo in ("md5_salted", "sha1_salted", "sha256_timestamp"):
        secret = qs.get("hmacSecret") or qs.get("salt")
        if secret is not None and not isinstance(secret, str):
            errors.append(f"querySigner {algo} hmacSecret/salt must be a string if provided")
    else:
        errors.append(f"Invalid querySigner algorithm: {algo}")
    return errors


_SCHEMA_VALIDATOR_CACHE = {}


def _load_schema(base_dir, filename):
    if jsonschema is None:
        return None
    schema_path = os.path.join(base_dir, "schema", filename)
    if os.path.exists(schema_path):
        with open(schema_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return None


def _validate_with_cached_schema(instance, base_dir, filename):
    if jsonschema is None:
        return
    schema_path = os.path.join(base_dir, "schema", filename)
    if not os.path.exists(schema_path):
        return
    mtime_ns = os.stat(schema_path).st_mtime_ns
    cache_key = (os.path.abspath(schema_path), mtime_ns)
    validator = _SCHEMA_VALIDATOR_CACHE.get(cache_key)
    if validator is None:
        schema = _load_schema(base_dir, filename)
        if schema is None:
            return
        validator_cls = getattr(jsonschema, "Draft202012Validator", None)
        if validator_cls is not None:
            validator_cls.check_schema(schema)
            validator = validator_cls(schema)
            _SCHEMA_VALIDATOR_CACHE[cache_key] = validator
        else:
            jsonschema.validate(instance=instance, schema=schema)
            return
    validator.validate(instance)


LICENSE_BOILERPLATE_ATTRIBUTION_PHRASES = (
    "you must retain",
    "source form of any",
    "derivative works",
    "notice that is included",
    "attached to the work",
    "as defined in",
    "notice and this permission notice",
    "permission is hereby granted",
    "without warranty of any kind",
    "the above copyright notice",
    "redistributions of source code",
    "redistributions in binary form",
    "provided that the following conditions",
    "neither the name of",
    "subject to the terms of the mozilla public",
    "incompatible with secondary licenses",
    "copyright holder",
    "copyright holders",
    "copyright owner",
    "copyright law",
    "related rights",
    "[yyyy]",
    "[year]",
    "[fullname]",
    "[name of copyright owner]",
    "<year>",
    "<owner>",
    "<copyright holders>",
)


def is_license_boilerplate_attribution(attribution):
    if not isinstance(attribution, str):
        return False
    cleaned = attribution.strip()
    if not cleaned:
        return False
    low = cleaned.lower()
    if any(phrase in low for phrase in LICENSE_BOILERPLATE_ATTRIBUTION_PHRASES):
        return True
    if re.match(r"^(?:\[[^\]]+\]|<[^>]+>)(?:\s*[,;/-]?\s*(?:\[[^\]]+\]|<[^>]+>))*$", cleaned):
        return True
    return False


def validate_recipe(recipe, base_dir=BUNDLE_ROOT, expected_filename=None):
    errors = []
    if not isinstance(recipe, dict):
        return False, ["Recipe must be a JSON object"]

    if recipe.get("schemaVersion") not in SUPPORTED_SCHEMA_VERSIONS:
        errors.append(f"schemaVersion must be in {SUPPORTED_SCHEMA_VERSIONS}")

    source_id = recipe.get("sourceId", "")
    if not isinstance(source_id, str) or not SOURCE_ID_RE.match(source_id):
        errors.append("sourceId must match ^[a-z0-9._-]+$")
    elif expected_filename is not None and expected_filename != f"{source_id}.json":
        errors.append(f"Filename mismatch: '{expected_filename}' must be '{source_id}.json'")

    name = recipe.get("name", "")
    if not isinstance(name, str) or not name.strip():
        errors.append("name must be a non-blank string")

    ok_lang, err_lang = validate_lang_tag(recipe.get("lang", ""))
    if not ok_lang:
        errors.append(err_lang)

    ok_url, err_url = validate_ssrf(recipe.get("baseUrl", ""))
    if not ok_url:
        errors.append(f"SSRF violation in baseUrl: {err_url}")

    icon_url = recipe.get("iconUrl")
    if icon_url is not None and str(icon_url).strip() != "":
        ok_icon, err_icon = validate_ssrf(str(icon_url))
        if not ok_icon:
            errors.append(f"SSRF violation in iconUrl: {err_icon}")

    version = recipe.get("version", 1)
    if not _is_int(version) or version < 1:
        errors.append("version must be an integer >= 1")

    version_id = recipe.get("versionId", 1)
    if not _is_int(version_id) or version_id < 1:
        errors.append("versionId must be an integer >= 1")

    max_html = recipe.get("maxHtmlBytes", 0)
    if not _is_int(max_html) or max_html < MIN_HTML_BYTES or max_html > MAX_HTML_BYTES:
        errors.append(f"maxHtmlBytes must be between {MIN_HTML_BYTES} and {MAX_HTML_BYTES}")

    preset = recipe.get("preset")
    if preset not in ALLOWED_PRESETS:
        errors.append(f"Invalid preset: {preset}")

    status = recipe.get("status")
    if status not in ALLOWED_STATUSES:
        errors.append(f"Invalid status: {status}")

    if "requiresWebViewCapture" in recipe and not isinstance(recipe["requiresWebViewCapture"], bool):
        errors.append("requiresWebViewCapture must be a boolean")

    if "requiresCloudflareBypass" in recipe and not isinstance(recipe["requiresCloudflareBypass"], bool):
        errors.append("requiresCloudflareBypass must be a boolean")

    if "useHomeFallback" in recipe and not isinstance(recipe["useHomeFallback"], bool):
        errors.append("useHomeFallback must be a boolean")

    if "catalogPath" in recipe and recipe["catalogPath"] is not None and not isinstance(recipe["catalogPath"], str):
        errors.append("catalogPath must be a string")

    if "searchPath" in recipe and recipe["searchPath"] is not None and not isinstance(recipe["searchPath"], str):
        errors.append("searchPath must be a string")

    if "recipePath" in recipe and recipe["recipePath"] is not None:
        ok_rp, err_rp = validate_relative_recipe_path(recipe["recipePath"])
        if not ok_rp:
            errors.append(err_rp)
        elif source_id and recipe["recipePath"] != f"recipes/{source_id}.json":
            errors.append(f"recipePath '{recipe['recipePath']}' must match 'recipes/{source_id}.json'")

    if "upstreamSourceId" in recipe and recipe["upstreamSourceId"] is not None:
        if not _is_int(recipe["upstreamSourceId"]):
            errors.append("upstreamSourceId must be an integer")

    if "upstreamSourceIds" in recipe and recipe["upstreamSourceIds"] is not None:
        uids = recipe["upstreamSourceIds"]
        if not isinstance(uids, list) or any(not _is_int(x) for x in uids):
            errors.append("upstreamSourceIds must be an array of integers")

    for vc_field in ("upstreamExtVersionCode", "versionCode"):
        if vc_field in recipe and recipe[vc_field] is not None:
            vc = recipe[vc_field]
            if not _is_int(vc) or vc < 0:
                errors.append(f"{vc_field} must be a non-negative integer")

    up_repo = recipe.get("upstreamRepo")
    if up_repo is not None:
        if not isinstance(up_repo, str) or not up_repo.strip():
            errors.append("upstreamRepo must be null or a non-blank string")
        else:
            lic = recipe.get("license")
            attr = recipe.get("attribution")
            if not isinstance(lic, str) or not lic.strip():
                errors.append("license is required when upstreamRepo is set")
            if not isinstance(attr, str) or not attr.strip():
                errors.append("attribution is required when upstreamRepo is set")

    attr_val = recipe.get("attribution")
    if isinstance(attr_val, str) and attr_val.strip() and is_license_boilerplate_attribution(attr_val):
        errors.append("attribution must not contain license boilerplate or placeholder text")

    if "headers" in recipe and recipe["headers"] is not None:
        errors.extend(validate_headers_map(recipe["headers"], recipe))

    if "family" in recipe and recipe["family"] is not None:
        if recipe["family"] not in ALLOWED_FAMILIES:
            errors.append(f"Invalid family: {recipe['family']}")

    for req_key in ("popularRequest", "latestRequest", "searchRequest", "detailsRequest", "chaptersRequest", "pagesRequest"):
        if recipe.get(req_key) is not None:
            errors.extend(validate_request_spec(recipe[req_key], req_key, recipe))

    if recipe.get("jsonApi") is not None:
        errors.extend(validate_json_api_spec(recipe["jsonApi"], recipe))

    if recipe.get("qwik") is not None:
        errors.extend(validate_qwik_spec(recipe["qwik"]))

    if recipe.get("inertia") is not None:
        errors.extend(validate_inertia_spec(recipe["inertia"]))

    if recipe.get("multiViewReader") is not None:
        errors.extend(validate_multi_view_spec(recipe["multiViewReader"]))

    if "mirrors" in recipe and recipe["mirrors"] is not None:
        mirrors = recipe["mirrors"]
        if not isinstance(mirrors, list):
            errors.append("mirrors must be an array")
        else:
            for idx, m_url in enumerate(mirrors):
                ok_m, err_m = validate_ssrf(m_url)
                if not ok_m:
                    errors.append(f"SSRF violation in mirrors[{idx}]: {err_m}")

    if "querySigner" in recipe and recipe["querySigner"] is not None:
        errors.extend(validate_query_signer(recipe["querySigner"]))

    selectors = recipe.get("selectors")
    if selectors is not None:
        if not isinstance(selectors, dict):
            errors.append("selectors must be an object or null")
        else:
            ls = selectors.get("listSelector", "")
            if not isinstance(ls, str) or not ls.strip():
                errors.append("selectors.listSelector must be a non-blank string")
            for s_field in (
                "titleSelector",
                "linkSelector",
                "coverSelector",
                "chapterSelector",
                "pageImgSelector",
                "nextPageSelector",
                "detailsTitleSelector",
                "detailsCoverSelector",
                "descriptionSelector",
                "authorSelector",
                "artistSelector",
                "genresSelector",
                "statusSelector",
                "chapterNameSelector",
                "chapterDateSelector",
                "chapterDateFormat",
            ):
                if s_field in selectors and selectors[s_field] is not None and not isinstance(selectors[s_field], str):
                    errors.append(f"selectors.{s_field} must be a string or null")

    steps = recipe.get("pipelineSteps", [])
    errors.extend(validate_pipeline_steps(steps, "pipelineSteps"))
    if isinstance(selectors, dict):
        clean_list_sel = str(selectors.get("listSelector") or "").strip()
        if clean_list_sel and isinstance(steps, list):
            for i, step in enumerate(steps):
                if isinstance(step, dict) and step.get("op") == "css_select" and str(step.get("selector") or "").strip() == clean_list_sel:
                    errors.append(
                        f"pipelineSteps[{i}] repeats selectors.listSelector ('{clean_list_sel}'), "
                        "which breaks chapter page extraction",
                    )
    json_api = recipe.get("jsonApi")
    if isinstance(json_api, dict) and recipe.get("status") not in ("QUARANTINED", "DISABLED"):
        for req_key in ("popularRequest", "latestRequest", "searchRequest", "detailsRequest", "chaptersRequest", "pagesRequest"):
            req_spec = json_api.get(req_key)
            if isinstance(req_spec, dict):
                path_tmpl = str(req_spec.get("pathTemplate") or "")
                if "/graphql" in path_tmpl and not req_spec.get("bodyTemplate") and not req_spec.get("graphqlQuery") and "query=" not in path_tmpl:
                    errors.append(
                        f"jsonApi.{req_key} targets '/graphql' without bodyTemplate, graphqlQuery, or query= parameter",
                    )
    if recipe.get("listPipelineSteps") is not None:
        errors.extend(validate_pipeline_steps(recipe["listPipelineSteps"], "listPipelineSteps"))
    if recipe.get("chaptersPipelineSteps") is not None:
        errors.extend(validate_pipeline_steps(recipe["chaptersPipelineSteps"], "chaptersPipelineSteps"))
    if recipe.get("authPreFlight") is not None:
        errors.extend(validate_auth_preflight_spec(recipe["authPreFlight"], recipe))
    if recipe.get("accountSync") is not None:
        errors.extend(validate_account_sync_spec(recipe["accountSync"], recipe))

    if not errors:
        try:
            _validate_with_cached_schema(recipe, base_dir, "source-recipe.v2.schema.json")
        except Exception as e:
            errors.append(f"JSON Schema validation failed: {getattr(e, 'message', e)}")

    if errors:
        return False, errors

    if preset != "JSON_API":
        fixture_candidates = [
            os.path.join(base_dir, "fixtures", f"{source_id}_list.html"),
            os.path.join(base_dir, "catalog", "fixtures", f"{source_id}_list.html"),
        ]
        for fixture_path in fixture_candidates:
            if os.path.exists(fixture_path):
                with open(fixture_path, "r", encoding="utf-8") as f:
                    html_content = f.read()
                items = extract_html_items(html_content, selectors or {})
                if not items:
                    return False, [f"Fixture '{fixture_path}' parsed 0 items using selectors"]
                break

    return True, []


def validate_index_entry(entry):
    errors = []
    if not isinstance(entry, dict):
        return ["Index entry must be an object"]
    sid = entry.get("sourceId", "")
    if not isinstance(sid, str) or not SOURCE_ID_RE.match(sid):
        errors.append("Index entry sourceId must match ^[a-z0-9._-]+$")
    name = entry.get("name", "")
    if not isinstance(name, str) or not name.strip():
        errors.append(f"Index entry '{sid}' name must not be blank")
    ok_lang, err_lang = validate_lang_tag(entry.get("lang", ""))
    if not ok_lang:
        errors.append(f"Index entry '{sid}' {err_lang}")
    ok_url, err_url = validate_ssrf(entry.get("baseUrl", ""))
    if not ok_url:
        errors.append(f"Index entry '{sid}' baseUrl SSRF violation: {err_url}")
    icon_url = entry.get("iconUrl")
    if icon_url is not None and str(icon_url).strip() != "":
        ok_icon, err_icon = validate_ssrf(str(icon_url))
        if not ok_icon:
            errors.append(f"Index entry '{sid}' iconUrl SSRF violation: {err_icon}")
    if not _is_int(entry.get("version", 1)) or entry.get("version", 1) < 1:
        errors.append(f"Index entry '{sid}' version must be >= 1")
    if not _is_int(entry.get("versionId", 1)) or entry.get("versionId", 1) < 1:
        errors.append(f"Index entry '{sid}' versionId must be >= 1")
    if entry.get("preset") not in ALLOWED_PRESETS:
        errors.append(f"Index entry '{sid}' invalid preset: {entry.get('preset')}")
    if entry.get("status") not in ALLOWED_STATUSES:
        errors.append(f"Index entry '{sid}' invalid status: {entry.get('status')}")
    ok_rp, err_rp = validate_relative_recipe_path(entry.get("recipePath", ""))
    if not ok_rp:
        errors.append(f"Index entry '{sid}' {err_rp}")
    if "upstreamSourceIds" in entry and entry["upstreamSourceIds"] is not None:
        uids = entry["upstreamSourceIds"]
        if not isinstance(uids, list) or any(not _is_int(x) for x in uids):
            errors.append(f"Index entry '{sid}' upstreamSourceIds must be an array of integers")
    entry_attr = entry.get("attribution")
    if isinstance(entry_attr, str) and entry_attr.strip() and is_license_boilerplate_attribution(entry_attr):
        errors.append(f"Index entry '{sid}' attribution must not contain license boilerplate or placeholder text")
    if "requiresCloudflareBypass" in entry and not isinstance(entry["requiresCloudflareBypass"], bool):
        errors.append(f"Index entry '{sid}' requiresCloudflareBypass must be a boolean")
    if "sha256" in entry and entry["sha256"] is not None:
        val = entry["sha256"]
        if not isinstance(val, str) or not re.match(r"^[a-f0-9]{64}$", val):
            errors.append(f"Index entry '{sid}' sha256 must be a 64-char lowercase hex string")
    return errors


def recipe_to_index_entry(recipe):
    """Build a lightweight 17-field CatalogIndexEntry aligned with SourceRecipe.kt."""
    uids = []
    if _is_int(recipe.get("upstreamSourceId")):
        uids.append(recipe["upstreamSourceId"])
    for x in recipe.get("upstreamSourceIds") or []:
        if _is_int(x) and x not in uids:
            uids.append(x)
    uids = sorted(uids)
    vc = recipe.get("versionCode")
    if vc is None:
        vc = recipe.get("upstreamExtVersionCode")
    res = {
        "sourceId": recipe["sourceId"],
        "name": recipe["name"],
        "baseUrl": recipe["baseUrl"],
        "lang": recipe.get("lang", "en"),
        "version": int(recipe.get("version", 1)),
        "versionId": int(recipe.get("versionId", 1)),
        "preset": recipe.get("preset", "CSS_GENERIC"),
        "status": recipe.get("status", "ACTIVE"),
        "iconUrl": recipe.get("iconUrl"),
        "recipePath": recipe.get("recipePath") or f"recipes/{recipe['sourceId']}.json",
        "mode": recipe.get("mode") or "declarative",
        "pkgName": recipe.get("pkgName"),
        "versionCode": vc,
        "upstreamSourceId": recipe.get("upstreamSourceId"),
        "upstreamSourceIds": uids,
        "license": recipe.get("license"),
        "attribution": recipe.get("attribution"),
    }
    if "requiresCloudflareBypass" in recipe:
        res["requiresCloudflareBypass"] = bool(recipe["requiresCloudflareBypass"])
    if "sha256" in recipe and recipe["sha256"]:
        res["sha256"] = str(recipe["sha256"]).lower()
    return res


def validate_bundle(bundle, base_dir=BUNDLE_ROOT, expected_recipes_by_id=None):
    errors = []
    if not isinstance(bundle, dict):
        return False, ["Bundle root must be a JSON object"]
    sv = bundle.get("schemaVersion")
    if sv not in SUPPORTED_SCHEMA_VERSIONS:
        errors.append(f"Bundle schemaVersion must be in {SUPPORTED_SCHEMA_VERSIONS}")

    if sv == 2:
        entries = bundle.get("entries")
        if not isinstance(entries, list) or not entries:
            errors.append("v2 Bundle entries must be a non-empty array")
            return False, errors
        if bundle.get("recipes"):
            errors.append("v2 lightweight index.json must not embed inline recipes")

        try:
            _validate_with_cached_schema(bundle, base_dir, "catalog-index.v2.schema.json")
        except Exception as e:
            errors.append(f"Index JSON Schema validation failed: {getattr(e, 'message', e)}")

        seen_ids = set()
        bundle_map = {}
        for idx, entry in enumerate(entries):
            e_errs = validate_index_entry(entry)
            if e_errs:
                errors.extend(e_errs)
                continue
            sid = entry["sourceId"]
            if sid in seen_ids:
                errors.append(f"Duplicate sourceId '{sid}' at entries[{idx}]")
                continue
            seen_ids.add(sid)
            bundle_map[sid] = (
                entry.get("baseUrl"),
                entry.get("version"),
                entry.get("versionId"),
                entry.get("status"),
                entry.get("lang"),
                entry.get("preset"),
                entry.get("recipePath"),
                entry.get("versionCode"),
                tuple(sorted(entry.get("upstreamSourceIds") or [])),
                bool(entry.get("requiresCloudflareBypass", False)),
            )
            recipe_abs = os.path.join(base_dir, entry["recipePath"])
            if os.path.isdir(os.path.join(base_dir, "recipes")) and not os.path.isfile(recipe_abs):
                errors.append(f"Missing recipe file referenced by index: {entry['recipePath']}")
            elif os.path.isfile(recipe_abs) and entry.get("sha256"):
                try:
                    with open(recipe_abs, "rb") as rf:
                        raw = rf.read().replace(b"\r\n", b"\n")
                        actual_sha = hashlib.sha256(raw).hexdigest()
                    if entry["sha256"] != actual_sha:
                        errors.append(
                            f"Entry '{sid}' sha256 mismatch: index={entry['sha256']} actual={actual_sha}"
                        )
                except Exception as e:
                    errors.append(f"Entry '{sid}' could not read recipe for sha256: {e}")

        if expected_recipes_by_id is not None and bundle_map != expected_recipes_by_id:
            missing = sorted(set(expected_recipes_by_id) - set(bundle_map))
            extra = sorted(set(bundle_map) - set(expected_recipes_by_id))
            drifted = sorted(
                k for k in (set(expected_recipes_by_id) & set(bundle_map)) if expected_recipes_by_id[k] != bundle_map[k]
            )
            errors.append(f"index.json out of sync with recipes: missing={missing}, extra={extra}, drifted={drifted}")

        return len(errors) == 0, errors

    recipes = bundle.get("recipes")
    if not isinstance(recipes, list) or not recipes:
        errors.append("v1 Bundle recipes must be a non-empty array")
        return False, errors

    bundle_map = {}
    for idx, recipe in enumerate(recipes):
        if not isinstance(recipe, dict):
            errors.append(f"Bundle recipe[{idx}] must be an object")
            continue
        ok, r_errs = validate_recipe(recipe, base_dir=base_dir)
        if not ok:
            errors.append(f"Bundle recipe '{recipe.get('sourceId', idx)}' invalid: {r_errs}")
        sid = recipe.get("sourceId")
        if sid:
            bundle_map[sid] = (recipe.get("baseUrl"), recipe.get("version"))

    if expected_recipes_by_id is not None and bundle_map != expected_recipes_by_id:
        errors.append("v1 index.json out of sync with recipes")

    return len(errors) == 0, errors


def audit_bundle_isolation(bundle_root=BUNDLE_ROOT, extra_patterns=None):
    """Verify catalog-bundle/ contains zero tokens, local paths, or caller-forbidden patterns."""
    patterns = list(FORBIDDEN_PRIVACY_PATTERNS) + _compile_extra_forbidden_patterns(extra_patterns)
    violations = []
    skip_dirs = {".git", "__pycache__", ".pytest_cache", ".venv", "venv"}
    for root, dirs, files in os.walk(bundle_root):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in sorted(files):
            if fname.endswith((".pyc", ".png", ".jpg", ".webp")):
                continue
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, bundle_root)
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    text = f.read()
            except UnicodeDecodeError:
                continue
            for label, pat in patterns:
                if pat.search(text):
                    violations.append(f"{rel}: matched forbidden pattern '{label}'")
    return len(violations) == 0, violations


def validate_notice(bundle_root=BUNDLE_ROOT, recipes=None):
    errors = []
    license_path = os.path.join(bundle_root, "LICENSE")
    if not os.path.isfile(license_path):
        errors.append("Missing LICENSE file")
    else:
        with open(license_path, "r", encoding="utf-8") as lf:
            if not lf.read().strip():
                errors.append("LICENSE file is empty")

    notice_path = os.path.join(bundle_root, "NOTICE")
    if not os.path.isfile(notice_path):
        errors.append("Missing NOTICE file")
        return False, errors
    with open(notice_path, "r", encoding="utf-8") as f:
        text = f.read()
    if not text.strip():
        errors.append("NOTICE file is empty")
        return False, errors
    for line in text.splitlines():
        m_attr = re.match(r"^\s*Attribution\s*:\s*(.*)$", line, re.I)
        if m_attr:
            notice_attr = m_attr.group(1).strip()
            if not notice_attr:
                errors.append("NOTICE contains empty Attribution line")
            elif is_license_boilerplate_attribution(notice_attr):
                errors.append(f"NOTICE contains license boilerplate attribution: '{notice_attr}'")
    if recipes:
        repos = sorted({r.get("upstreamRepo") for r in recipes if r.get("upstreamRepo")})
        for repo in repos:
            if repo not in text:
                errors.append(f"NOTICE missing upstreamRepo attribution for '{repo}'")
        attributions = sorted({r.get("attribution") for r in recipes if r.get("attribution")})
        for attr in attributions:
            if is_license_boilerplate_attribution(attr):
                errors.append(f"Recipe attribution contains license boilerplate: '{attr}'")
            if attr not in text:
                errors.append(f"NOTICE missing contributor attribution '{attr}'")
        source_ids = sorted({r.get("sourceId") for r in recipes if r.get("sourceId")})
        for sid in source_ids:
            if sid not in text:
                errors.append(f"NOTICE missing recipe sourceId '{sid}'")
    return len(errors) == 0, errors


def validate_all(bundle_root=BUNDLE_ROOT, extra_patterns=None):
    recipes_dir = os.path.join(bundle_root, "recipes")
    index_path = os.path.join(bundle_root, "index.json")
    errors = []
    loaded_recipes = []
    expected_by_id = {}

    if not os.path.isdir(recipes_dir):
        return False, [f"Missing recipes directory: {recipes_dir}"]

    for fname in sorted(os.listdir(recipes_dir)):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(recipes_dir, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                recipe = json.load(f)
        except Exception as e:
            errors.append(f"{fname}: invalid JSON: {e}")
            continue
        ok, r_errs = validate_recipe(recipe, base_dir=bundle_root, expected_filename=fname)
        if not ok:
            errors.append(f"{fname}: {r_errs}")
            continue
        loaded_recipes.append(recipe)
        entry = recipe_to_index_entry(recipe)
        expected_by_id[entry["sourceId"]] = (
            entry["baseUrl"],
            entry["version"],
            entry["versionId"],
            entry["status"],
            entry["lang"],
            entry["preset"],
            entry["recipePath"],
            entry["versionCode"],
            tuple(sorted(entry["upstreamSourceIds"])),
            bool(entry.get("requiresCloudflareBypass", False)),
        )

    if not os.path.isfile(index_path):
        errors.append(f"Missing index.json: {index_path}")
    else:
        try:
            with open(index_path, "r", encoding="utf-8") as f:
                bundle = json.load(f)
            ok_b, errs_b = validate_bundle(bundle, base_dir=bundle_root, expected_recipes_by_id=expected_by_id)
            if not ok_b:
                errors.extend(errs_b)
            if isinstance(bundle, dict) and bundle.get("schemaVersion") == 2 and isinstance(bundle.get("entries"), list):
                recipes_by_sid = {r["sourceId"]: r for r in loaded_recipes if isinstance(r, dict) and r.get("sourceId")}
                for entry in bundle["entries"]:
                    if not isinstance(entry, dict):
                        continue
                    sid = entry.get("sourceId")
                    rec = recipes_by_sid.get(sid)
                    if rec is None:
                        continue
                    if entry.get("license") != rec.get("license"):
                        errors.append(
                            f"index.json license mismatch for '{sid}': {entry.get('license')!r} != {rec.get('license')!r}"
                        )
                    if entry.get("attribution") != rec.get("attribution"):
                        errors.append(
                            f"index.json attribution mismatch for '{sid}': "
                            f"{entry.get('attribution')!r} != {rec.get('attribution')!r}"
                        )
                    if bool(entry.get("requiresCloudflareBypass", False)) != bool(rec.get("requiresCloudflareBypass", False)):
                        errors.append(
                            f"index.json requiresCloudflareBypass mismatch for '{sid}': "
                            f"{entry.get('requiresCloudflareBypass')!r} != {rec.get('requiresCloudflareBypass')!r}"
                        )
        except Exception as e:
            errors.append(f"index.json invalid JSON: {e}")

    ok_n, errs_n = validate_notice(bundle_root, loaded_recipes)
    if not ok_n:
        errors.extend(errs_n)

    ok_iso, errs_iso = audit_bundle_isolation(bundle_root, extra_patterns=extra_patterns)
    if not ok_iso:
        errors.extend(errs_iso)

    return len(errors) == 0, errors


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Validate v2 catalog index, source recipes, NOTICE, fixtures, and bundle isolation.",
    )
    parser.add_argument(
        "--forbid-pattern",
        action="append",
        default=[],
        help="Additional regex or literal pattern forbidden inside the bundle (repeatable).",
    )
    args = parser.parse_args(argv)
    ok, errors = validate_all(BUNDLE_ROOT, extra_patterns=args.forbid_pattern)
    if not ok:
        for err in errors:
            print(f"ERROR: {err}")
        raise SystemExit(1)
    recipes_count = len([f for f in os.listdir(os.path.join(BUNDLE_ROOT, "recipes")) if f.endswith(".json")])
    print(f"OK: validated {recipes_count} recipes, index.json, NOTICE, fixtures, and bundle isolation.")
    raise SystemExit(0)


if __name__ == "__main__":
    main()
