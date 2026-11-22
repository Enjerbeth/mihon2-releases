"""Diagnostic classifier and Spanish R2 report generator for catalog-bundle/tools/sync_catalog.py."""

from collections import Counter
from datetime import datetime, timezone
import json
import re


WAF_STRONG_MARKERS = (
    "__cf_chl",
    "just a moment",
    "/cdn-cgi/challenge-platform",
    "cf-turnstile",
    "cf_chl_opt",
    "checking your browser",
    "attention required! | cloudflare",
    "ddos-guard",
    "sucuri",
    "_incapsula_",
    "ak_bmsc",
)

SUPPORTED_THEMES = frozenset(
    {
        "madara",
        "mangathemesia",
        "mangastream",
        "zesthub",
        "mmrcms",
        "fmreader",
        "zeistmanga",
        "foolslide",
        "mangacatalog",
        "solomanga",
        "iken",
        "heancms",
        "guya",
        "mangahub",
        "yiimanga",
        "yiimadara",
        "vinetheme",
        "galleryadults",
        "hentaihand",
        "mangabox",
        "hiper",
        "mangak",
        "mangadventure",
        "monochrome",
        "moonlighttl",
        "mangotheme",
        "mangawork",
        "gattsu",
        "greenshit",
        "wpcomics",
        "madaralegacy",
        "manhuarm",
    }
)

STATIC_DECOY_WEBVIEW_MARKERS = (
    "runWebView",
    "__reactContainer",
    "page_list.js",
    '"ph":',
    "__next_f",
)

PRIMITIVE_RECOMMENDATIONS = {
    "CUSTOM_THEME_ADAPTER": {
        "titulo": "Adaptadores de temas multisrc y selectores CSS extendidos",
        "primitiva": (
            "Nuevos presets/familias nativas para los temas multisrc de mayor volumen "
            "(p. ej. ZeistManga/Blogger, PizzaReader, FoolSlide, HeanCms, Iken, WPComics) "
            "y ampliación de RecipeSelectors (details/chapterDateFormat) + jsonApi.htmlExtract."
        ),
    },
    "JSON_API_OR_GRAPHQL": {
        "titulo": "Generación/soporte avanzado de JSON_API y GraphQL",
        "primitiva": (
            "Ampliar DeclarativeJsonPersonalSource (htmlExtract en JSON, pipelineSteps por fase "
            "list/details/chapters, descenso recursivo/JSON_CURSOR combinado con hasNextPath) "
            "y plantillas GraphQL."
        ),
    },
    "WEBVIEW_HEADLESS_INTERACT": {
        "titulo": "Extractor WebView acotado para catálogo/capítulos y SPA",
        "primitiva": (
            "WebViewStageSpec reutilizable (allowlist de extractores por framework para "
            "listados/capítulos SPA, React/Next.js RSC y páginas con señuelo DOM)."
        ),
    },
    "DYNAMIC_IMAGE_SCRAMBLE": {
        "titulo": "Descrambling dinámico de imágenes (Canvas/Bitmap)",
        "primitiva": (
            "Extender GridUnscrambleSpec con modos HASH_SEED / HEADER_SEED / STRIP_VERTICAL, "
            "seedFromRegex y política de franjas sobrantes (KEEP_EDGE / SPLIT_FIRST)."
        ),
    },
    "JS_RUNTIME_QUICKJS": {
        "titulo": "Motor JS embebido en sandbox (QuickJS)",
        "primitiva": (
            "PipelineStep.QuickJsEval usando quickjs-android (ya presente en libs.versions.toml) "
            "con sandbox sin red/FS, timeout estricto y límite de heap para deofuscación y tokens."
        ),
    },
    "AUTH_SESSION_OR_PREFS": {
        "titulo": "Pre-flight de sesión, CSRF/Bearer y preferencias",
        "primitiva": (
            "AuthPreFlightSpec cacheado con TTL (extracción de _token/nonce/Bearer -> {authToken}) "
            "y DeclarativeFilterSpec / configuración segura por fuente."
        ),
    },
    "DYNAMIC_CRYPTO_OR_KEY": {
        "titulo": "Criptografía dinámica y descompresión en pipeline",
        "primitiva": (
            "PipelineStep.DynamicAesDecrypt (soporte OpenSSL Salted__ / EVP_BytesToKey, AES-GCM, "
            "clave derivada de paso previo) y PipelineStep.Decompress (lz_string, gzip, deflate)."
        ),
    },
    "SIGNING_CUSTOM_VRF": {
        "titulo": "Firmas personalizadas de consultas/cabeceras (VRF / HMAC / Hash)",
        "primitiva": (
            "Ampliar CanonicalQuerySigner con algoritmos md5_salted, sha256_timestamp y "
            "plantillas configurables en query o headers."
        ),
    },
    "CHAPTERS_EMPTY": {
        "titulo": "Carátulas OK pero 0 capítulos detectados (`CHAPTERS_EMPTY`)",
        "primitiva": (
            "Selector `chapterSelector` roto/desfasado (reparable en CSS_GENERIC), "
            "carga AJAX de capítulos (`MADARA /ajax/chapters/`) o `jsonApi.chapters` incompleto."
        ),
    },
    "RATE_LIMIT_429": {
        "titulo": "Control declarativo de tasa (Rate Limiting / Retry-After)",
        "primitiva": (
            "Campo rateLimit (permits, periodMs) en SourceRecipe conectado a RateLimitInterceptor "
            "y manejo automático de HTTP 429 con Retry-After."
        ),
    },
    "CUSTOM_HTML_SELECTOR_OR_PARSER": {
        "titulo": "Selectores declarativos de detalles/capítulos y HTML complejo",
        "primitiva": (
            "Ampliar RecipeSelectors (descriptionSelector, authorSelector, genresSelector, "
            "chapterDateSelector, chapterDateFormat) y habilitar pipelineSteps en listado/capítulos."
        ),
    },
}


def is_cloudflare_origin_error(status_code):
    try:
        code = int(status_code or 0)
    except (TypeError, ValueError):
        return False
    return 520 <= code <= 530


def detect_waf_block(status_code, headers=None, body=""):
    """Detect genuine Cloudflare/anti-bot challenges without misclassifying 52x or 404."""
    try:
        code = int(status_code or 0)
    except (TypeError, ValueError):
        code = 0

    if is_cloudflare_origin_error(code):
        return False, ""

    hdr_map = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    cf_mitigated = hdr_map.get("cf-mitigated", "").strip().lower()
    body_text = body or ""
    body_lower = body_text.lower()

    if "challenge" in cf_mitigated or "cf-mitigated: challenge" in body_lower:
        return True, f"HTTP {code or 'WAF'} (cf-mitigated: challenge)"

    # Only treat 403/429/503 (or 200 explicit challenge shell) when strong WAF signatures exist.
    if code in (403, 429, 503, 200):
        hdr_blob = "\n".join(f"{k}: {v}" for k, v in hdr_map.items()).lower()
        combined = f"{hdr_blob}\n{body_lower}"
        for marker in WAF_STRONG_MARKERS:
            if marker in combined:
                if code == 200 and marker not in (
                    "__cf_chl",
                    "just a moment",
                    "/cdn-cgi/challenge-platform",
                    "cf-turnstile",
                    "cf_chl_opt",
                    "checking your browser",
                ):
                    continue
                return True, f"HTTP {code} ({marker})"

    return False, ""


def classify_down_reason(status_code=0, message="", body=""):
    """Classify non-WAF outage / dead source errors into clean sub-reasons."""
    msg = str(message or "")
    msg_lower = msg.lower()
    body_lower = str(body or "").lower()

    if "ssrf" in msg_lower:
        return "SSRF_REJECTED"
    if any(tok in msg_lower for tok in ("getaddrinfo", "nameresolutionerror", "name or service not known", "nodename")):
        return "DNS_ERROR"
    if any(tok in msg_lower for tok in ("timed out", "timeout")):
        return "TIMEOUT"
    if any(tok in msg_lower for tok in ("ssl", "certificate", "tlsv1", "handshake")):
        return "TLS_SSL_ERROR"
    if any(tok in msg_lower for tok in ("connectionrefused", "connectionreset", "remotedisconnected", "connection aborted", "eof")):
        return "CONNECTION_ERROR"

    try:
        code = int(status_code or 0)
    except (TypeError, ValueError):
        code = 0

    if is_cloudflare_origin_error(code):
        return f"CLOUDFLARE_ORIGIN_HTTP_{code}"
    if code >= 400:
        return f"HTTP_{code}"
    if code == 0 and msg:
        return "NETWORK_ERROR"
    if any(m in body_lower for m in ("comunicado oficial", "cierre definitivo", "permanently closed", "shutting down")):
        return "OFFICIAL_CLOSURE"
    return "UNKNOWN_DOWN"


def classify_missing_primitives(
    theme=None,
    gradle_text="",
    kotlin_text="",
    theme_kotlin_text="",
    http_status=0,
    html_sample="",
    headers=None,
    family=None,
):
    """Identify missing Kotlin engine primitives from upstream code and live responses."""
    norm_theme = (theme or "").strip().lower()
    kt_own = kotlin_text or ""
    kt_theme = theme_kotlin_text or ""
    kt_all = kt_own if (norm_theme and norm_theme in SUPPORTED_THEMES) else f"{kt_own}\n{kt_theme}"
    g_text = gradle_text or ""
    html = html_sample or ""
    html_lower = html.lower()

    capabilities = []
    reasons = []

    def _add(cap, reason):
        if cap not in capabilities:
            capabilities.append(cap)
        if reason and reason not in reasons:
            reasons.append(reason)

    # 1. QuickJS / JS evaluation / unpacker / Next.js RSC
    if any(tok in kt_all for tok in ("QuickJs", "quickjs", "evaluateJs", "Duktape", "Synchrony", "Unpacker")) or "lib:synchrony" in g_text.lower() or "lib:unpacker" in g_text.lower():
        _add("JS_RUNTIME_QUICKJS", "QuickJs/Synchrony/Unpacker en Kotlin")
    if "__next_f" in html or "__next_f" in kt_all:
        _add("JS_RUNTIME_QUICKJS", "Next.js RSC (__next_f)")
    if "eval(function(p,a,c,k" in html_lower:
        _add("JS_RUNTIME_QUICKJS", "JS obfuscado p,a,c,k")

    # 2. Custom VRF / Request Signing
    if (
        "VrfSigner" in kt_all
        or re.search(r'"vrf"', kt_all, re.I)
        or re.search(r"\b(signRequest|generateVrf|vrfToken)\b", kt_all, re.I)
    ):
        _add("SIGNING_CUSTOM_VRF", "Firma VRF / signRequest personalizado")

    # 3. Dynamic crypto / LZString
    if any(
        tok in kt_all
        for tok in ("Cipher", "SecretKeySpec", "CryptoJS", "Salted__", "PBKDF2", "LZString", "AES/GCM", "AES/ECB")
    ) or "lib:cryptoaes" in g_text.lower() or "lib:lzstring" in g_text.lower():
        _add("DYNAMIC_CRYPTO_OR_KEY", "Cifrado AES/Cipher/LZString en Kotlin")
    elif "AES" in kt_all or "crypto-aes" in g_text.lower():
        _add("DYNAMIC_CRYPTO_OR_KEY", "Uso de AES en Kotlin")

    # 4. Dynamic image descrambling / Canvas / Bitmap
    if any(
        tok in kt_all
        for tok in ("Bitmap.createBitmap", "Canvas(", "decodeStream", "ImageInterceptor", "publus", "speedbinb")
    ) or "lib:publus" in g_text.lower() or "lib:speedbinb" in g_text.lower() or "lib:dataimage" in g_text.lower():
        _add("DYNAMIC_IMAGE_SCRAMBLE", "Descramble de imagen (Canvas/Bitmap/Interceptor)")

    # 5. Auth / Session / ConfigurableSource preferences / CSRF
    has_hard_auth = any(tok in kt_all for tok in ("authToken", "Bearer", "login(", "Authorization:"))
    if int(http_status or 0) == 401 or has_hard_auth:
        _add("AUTH_SESSION_OR_PREFS", "Sesión requerida o HTTP 401")
    elif int(http_status or 0) == 403 and any(
        tok in kt_all for tok in ("ConfigurableSource", "SharedPreferences", "addPreferencesFromResource")
    ):
        _add("AUTH_SESSION_OR_PREFS", "ConfigurableSource / Credenciales requeridas")

    # 6. Rate limiting
    if int(http_status or 0) == 429:
        waf_hit, _ = detect_waf_block(http_status, headers=headers, body=html)
        if not waf_hit:
            _add("RATE_LIMIT_429", "HTTP 429 Too Many Requests")
    elif "rateLimitHost(" in kt_all or "rateLimit(" in kt_all:
        # Only cite if it failed or has other issues, keep secondary awareness
        pass

    # 7. WebView / React / JS Decoy
    decoy_hits = [m for m in STATIC_DECOY_WEBVIEW_MARKERS if m in kt_all or m in html]
    if "evaluateJavascript" in kt_all or "WebView(" in kt_all or decoy_hits:
        _add(
            "WEBVIEW_HEADLESS_INTERACT",
            f"WebView/JS decoy ({', '.join(decoy_hits) if decoy_hits else 'evaluateJavascript'})",
        )
    elif "data-inertia" in html and family != "INERTIA_SSR":
        _add("WEBVIEW_HEADLESS_INTERACT", "Inertia.js sin receta INERTIA_SSR")

    # 8. JSON API / GraphQL
    if any(tok in kt_all for tok in ("GraphQL", "graphql", "kotlinx.serialization", "Json.decodeFromString", "parseAs<", "Gson(", "Moshi", "@Serializable")):
        _add("JSON_API_OR_GRAPHQL", "Cliente JSON/GraphQL nativo sin receta JSON_API")
    else:
        stripped = html.lstrip()
        if int(http_status or 0) in range(200, 300) and (stripped.startswith("{") or stripped.startswith("[")):
            _add("JSON_API_OR_GRAPHQL", "Respuesta JSON sin receta JSON_API")

    # 9. Unmapped multisrc theme
    if norm_theme and norm_theme not in SUPPORTED_THEMES:
        _add(f"CUSTOM_THEME_ADAPTER:{norm_theme}", f"Tema lib-multisrc no soportado ({norm_theme})")

    # 10. Fallback custom HTML selector/parser if HTTP 200 HTML yielded < 3 items
    if not capabilities:
        _add("CUSTOM_HTML_SELECTOR_OR_PARSER", "Parser Kotlin propio o selectores HTML no estándar")

    # Pick primary capability prioritizing hard native blockers over theme label
    priority_order = (
        "JS_RUNTIME_QUICKJS",
        "SIGNING_CUSTOM_VRF",
        "DYNAMIC_CRYPTO_OR_KEY",
        "DYNAMIC_IMAGE_SCRAMBLE",
        "WEBVIEW_HEADLESS_INTERACT",
        "AUTH_SESSION_OR_PREFS",
        "RATE_LIMIT_429",
        "JSON_API_OR_GRAPHQL",
    )
    primary = None
    for p_cap in priority_order:
        if p_cap in capabilities:
            primary = p_cap
            break
    if primary is None:
        primary = capabilities[0]

    return primary, capabilities, reasons


def base_capability_key(cap):
    if cap and cap.startswith("CUSTOM_THEME_ADAPTER:"):
        return "CUSTOM_THEME_ADAPTER"
    return cap


def compute_primitive_summary(records):
    """Aggregate real source counts per missing Kotlin primitive from NEEDS_PRIMITIVE records."""
    needs = [r for r in records if r.get("category") == "NEEDS_PRIMITIVE"]
    primary_counts = Counter()
    total_mentions = Counter()
    theme_counts = Counter()
    examples_by_cap = {}

    for rec in needs:
        p_cap = rec.get("primaryCapability") or "CUSTOM_HTML_SELECTOR_OR_PARSER"
        p_base = base_capability_key(p_cap)
        primary_counts[p_base] += 1

        all_caps = rec.get("allCapabilities") or [p_cap]
        seen_bases = set()
        for c in all_caps:
            b = base_capability_key(c)
            if b not in seen_bases:
                seen_bases.add(b)
                total_mentions[b] += 1
                examples_by_cap.setdefault(b, [])
                if len(examples_by_cap[b]) < 6:
                    label = f"{rec.get('name')} ({rec.get('lang')})"
                    if label not in examples_by_cap[b]:
                        examples_by_cap[b].append(label)
            if c.startswith("CUSTOM_THEME_ADAPTER:"):
                theme_counts[c.split(":", 1)[1]] += 1

    ordered = sorted(
        set(primary_counts.keys()) | set(total_mentions.keys()),
        key=lambda k: (total_mentions[k], primary_counts[k], k),
        reverse=True,
    )

    rows = []
    for cap_key in ordered:
        meta = PRIMITIVE_RECOMMENDATIONS.get(
            cap_key,
            {
                "titulo": cap_key,
                "primitiva": f"Soporte declarativo para {cap_key}",
            },
        )
        rows.append(
            {
                "capability": cap_key,
                "title": meta["titulo"],
                "recommendedPrimitive": meta["primitiva"],
                "primarySourceCount": primary_counts[cap_key],
                "totalAffectedSources": total_mentions[cap_key],
                "examples": examples_by_cap.get(cap_key, []),
            }
        )

    return {
        "totalNeedsPrimitive": len(needs),
        "primitives": rows,
        "unmappedThemes": [{"theme": t, "count": cnt} for t, cnt in theme_counts.most_common()],
    }


def _fmt_source_line(rec):
    sid = rec.get("sourceId") or "-"
    name = rec.get("name") or sid
    lang = rec.get("lang") or "?"
    repo = rec.get("upstreamRepo") or "-"
    url = rec.get("finalUrl") or rec.get("baseUrl") or "-"
    detail = rec.get("detail") or rec.get("reason") or "-"
    extra = []
    if rec.get("domainAdopted") and rec.get("redirectedFrom") and rec.get("redirectedTo"):
        extra.append(f"dominio: `{rec['redirectedFrom']}` -> `{rec['redirectedTo']}`")
    elif rec.get("domainChangeFailed") and rec.get("redirectedFrom") and rec.get("redirectedTo"):
        extra.append(f"redirección: `{rec['redirectedFrom']}` -> `{rec['redirectedTo']}`")
    if rec.get("fallbackUsed"):
        extra.append(f"fallback desde `{rec.get('fallbackFromRepo', '?')}` ({rec.get('fallbackPrimaryFailure', '?')})")
    if rec.get("primaryCapability"):
        extra.append(f"capacidad: `{rec['primaryCapability']}`")
    extra_str = f" | {'; '.join(extra)}" if extra else ""
    return f"- **{name}** (`{sid}`, `{lang}`, repo `{repo}`) — `{url}` — {detail}{extra_str}"


def build_diagnostic_report_data(records, metadata):
    """Build structured JSON-serializable report data covering all 7 R2 categories."""
    viable = [r for r in records if r.get("category") == "VIABLE"]
    viable_direct = [r for r in viable if not r.get("domainAdopted") and not r.get("fallbackUsed")]
    viable_domain_adopted = [r for r in viable if r.get("domainAdopted")]
    viable_fallback = [r for r in viable if r.get("fallbackUsed")]
    viable_cf_bypass = [r for r in viable if r.get("requiresCloudflareBypass") or r.get("cloudflareBypass")]

    cloudflare = [r for r in records if r.get("category") == "CLOUDFLARE_ANTIBOT"]
    down = [r for r in records if r.get("category") == "DOWN_OR_NONEXISTENT"]
    domain_failed = [r for r in records if r.get("category") == "DOMAIN_CHANGE_FAILED"]
    needs_prim = [r for r in records if r.get("category") == "NEEDS_PRIMITIVE"]
    chapters_empty = [
        r
        for r in needs_prim
        if r.get("subReason") == "CHAPTERS_EMPTY" or r.get("primaryCapability") == "CHAPTERS_EMPTY"
    ]
    license_rejected = [r for r in records if r.get("category") == "REJECTED_LICENSE"]
    nsfw_excluded = [r for r in records if r.get("category") == "EXCLUDED_NSFW"]

    prim_summary = compute_primitive_summary(records)

    return {
        "generatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "metadata": metadata,
        "counts": {
            "totalEvaluated": len(records),
            "viable": len(viable),
            "viableDirect": len(viable_direct),
            "viableDomainAdopted": len(viable_domain_adopted),
            "viableFallbackRepo": len(viable_fallback),
            "viableCloudflareBypass": len(viable_cf_bypass),
            "cloudflareAntibot": len(cloudflare),
            "downOrNonexistent": len(down),
            "domainChangeTotal": len(viable_domain_adopted) + len(domain_failed),
            "domainChangeAdopted": len(viable_domain_adopted),
            "domainChangeFailed": len(domain_failed),
            "needsPrimitive": len(needs_prim),
            "chaptersEmpty": len(chapters_empty),
            "rejectedLicense": len(license_rejected),
            "excludedNsfw": len(nsfw_excluded),
        },
        "primitiveRecommendations": prim_summary,
        "categories": {
            "viable": viable,
            "cloudflareAntibot": cloudflare,
            "downOrNonexistent": down,
            "domainChangeAdopted": viable_domain_adopted,
            "domainChangeFailed": domain_failed,
            "needsPrimitive": needs_prim,
            "chaptersEmpty": chapters_empty,
            "rejectedLicense": license_rejected,
            "excludedNsfw": nsfw_excluded,
        },
    }


def build_diagnostic_report_markdown(records, metadata):
    """Render the classified diagnostic report in Spanish per requirement R2."""
    data = build_diagnostic_report_data(records, metadata)
    c = data["counts"]
    meta = data["metadata"]
    cats = data["categories"]
    prim = data["primitiveRecommendations"]

    lines = [
        "# Reporte Diagnóstico de Sincronización del Catálogo Declarativo",
        "",
        f"- **Fecha (UTC):** {data['generatedAt']}",
        f"- **Idiomas solicitados (`--langs`):** `{meta.get('langs', 'es,en,pt')}`",
        f"- **Filtro NSFW:** `{meta.get('nsfwPolicy', 'Solo ContentWarning.NSFW (3) y isNsfw/nsfw=true excluidos por defecto; MIXED (2) conservado')}`",
        f"- **Modo solo funcionales (`--only-working`):** `{meta.get('onlyWorking', True)}`",
        f"- **Incluir Cloudflare bypass (`--include-cloudflare`):** `{meta.get('includeCloudflare', False)}`",
        f"- **Repositorios upstream procesados:** {', '.join(meta.get('upstreams', [])) or 'N/A'}",
        f"- **Total de candidatos evaluados (tras deduplicación):** {c['totalEvaluated']}",
        "",
        "## Resumen Ejecutivo por Categoría (R2)",
        "",
        "| # | Categoría | Cantidad | Notas |",
        "|---|---|---:|---|",
        f"| 1 | **Viables / recreadas automáticamente** | **{c['viable']}** | Directas: {c['viableDirect']} · Auto-adoptaron dominio: {c['viableDomainAdopted']} · Cloudflare bypass: {c.get('viableCloudflareBypass', 0)} · Resueltas por fallback de repo: {c['viableFallbackRepo']} |",
        f"| 2 | **Bloqueadas por Cloudflare / anti-bot** | **{c['cloudflareAntibot']}** | Exige `cf-mitigated: challenge` o `403/429/503` con firma WAF real (no `52x`/`404`) |",
        f"| 3 | **Caídas o inexistentes** | **{c['downOrNonexistent']}** | DNS, timeout, TLS/SSL, `520..530`, `404/410/5xx` sin WAF, cierre oficial o deprecadas |",
        f"| 4 | **Cambio de dominio** | **{c['domainChangeTotal']}** | Auto-adoptadas en vivo: {c['domainChangeAdopted']} (incluidas en Viables) · Fallidas en destino: {c['domainChangeFailed']} |",
        f"| 5 | **Requieren capacidades o métricas especiales del motor** | **{c['needsPrimitive']}** | Desglose abajo por capacidad/primitiva faltante (incluye `CHAPTERS_EMPTY`: {c.get('chaptersEmpty', 0)}) |",
        f"| 6 | **Descartadas por licencia** | **{c['rejectedLicense']}** | Licencias no OSI (`GPL`/`AGPL`/`LGPL`/sin verificación) |",
        f"| 7 | **Excluidas por filtro NSFW (18+)** | **{c['excludedNsfw']}** | `ContentWarning.NSFW` (`3`) o `isNsfw/nsfw = true` |",
        "",
    ]

    # 1. Viables
    lines.extend([
        f"## 1. Viables / Recreadas Automáticamente ({c['viable']})",
        "",
    ])
    if cats["viable"]:
        for rec in cats["viable"]:
            lines.append(_fmt_source_line(rec))
    else:
        lines.append("_Ninguna fuente viable en esta corrida._")
    lines.append("")

    # 2. Cloudflare / anti-bot
    lines.extend([
        f"## 2. Bloqueadas por Cloudflare / Anti-Bot ({c['cloudflareAntibot']})",
        "",
    ])
    if cats["cloudflareAntibot"]:
        for rec in cats["cloudflareAntibot"]:
            lines.append(_fmt_source_line(rec))
    else:
        lines.append("_Ninguna fuente bloqueada por WAF/anti-bot._")
    lines.append("")

    # 3. Caídas o inexistentes
    lines.extend([
        f"## 3. Caídas o Inexistentes ({c['downOrNonexistent']})",
        "",
    ])
    down_subcounts = Counter(r.get("subReason") or "OTHER" for r in cats["downOrNonexistent"])
    if down_subcounts:
        lines.append(
            "Distribución por causa: "
            + ", ".join(f"`{k}`: {v}" for k, v in down_subcounts.most_common())
        )
        lines.append("")
    if cats["downOrNonexistent"]:
        for rec in cats["downOrNonexistent"]:
            lines.append(_fmt_source_line(rec))
    else:
        lines.append("_Ninguna fuente caída o inexistente._")
    lines.append("")

    # 4. Cambio de dominio
    lines.extend([
        f"## 4. Cambio de Dominio ({c['domainChangeTotal']} = {c['domainChangeAdopted']} auto-adoptadas + {c['domainChangeFailed']} fallidas)",
        "",
        f"### 4.1 Auto-adoptadas tras pasar prueba en vivo ({c['domainChangeAdopted']})",
        "",
    ])
    if cats["domainChangeAdopted"]:
        for rec in cats["domainChangeAdopted"]:
            lines.append(_fmt_source_line(rec))
    else:
        lines.append("_Ninguna redirección auto-adoptada._")
    lines.extend([
        "",
        f"### 4.2 Redirecciones que no pasaron la prueba en vivo o SSRF ({c['domainChangeFailed']})",
        "",
    ])
    if cats["domainChangeFailed"]:
        for rec in cats["domainChangeFailed"]:
            lines.append(_fmt_source_line(rec))
    else:
        lines.append("_Ninguna redirección fallida._")
    lines.append("")

    # 5. Capacidades especiales del motor
    lines.extend([
        f"## 5. Requieren Capacidades o Métricas Especiales del Motor ({c['needsPrimitive']})",
        "",
    ])
    if prim["primitives"]:
        lines.append("| Capacidad / Primitiva Faltante | Fuentes (Causa Primaria) | Total Menciones | Ejemplos |")
        lines.append("|---|---:|---:|---|")
        for row in prim["primitives"]:
            ex = ", ".join(row["examples"][:4]) or "-"
            lines.append(
                f"| `{row['capability']}` ({row['title']}) | {row['primarySourceCount']} | {row['totalAffectedSources']} | {ex} |"
            )
        lines.append("")
    if prim["unmappedThemes"]:
        lines.append(
            "**Temas `lib-multisrc` no mapeados detectados:** "
            + ", ".join(f"`{t['theme']}` ({t['count']})" for t in prim["unmappedThemes"][:25])
        )
        lines.append("")
    if cats.get("chaptersEmpty"):
        lines.extend([
            f"### 5.1 Carátulas OK pero 0 capítulos detectados (`CHAPTERS_EMPTY`: {len(cats['chaptersEmpty'])})",
            "",
        ])
        for rec in cats["chaptersEmpty"]:
            lines.append(_fmt_source_line(rec))
        lines.append("")
    if cats["needsPrimitive"]:
        for rec in cats["needsPrimitive"]:
            lines.append(_fmt_source_line(rec))
    else:
        lines.append("_Ninguna fuente pendiente por capacidades especiales._")
    lines.append("")

    # 6. Descartadas por licencia
    lines.extend([
        f"## 6. Descartadas por Licencia ({c['rejectedLicense']})",
        "",
    ])
    if cats["rejectedLicense"]:
        for rec in cats["rejectedLicense"]:
            lines.append(_fmt_source_line(rec))
    else:
        lines.append("_Ninguna fuente descartada por licencia._")
    lines.append("")

    # 7. Excluidas por NSFW
    lines.extend([
        f"## 7. Excluidas por Filtro NSFW 18+ ({c['excludedNsfw']})",
        "",
    ])
    if cats["excludedNsfw"]:
        for rec in cats["excludedNsfw"]:
            lines.append(_fmt_source_line(rec))
    else:
        lines.append("_Ninguna fuente excluida por NSFW._")
    lines.append("")

    # Recomendación priorizada de primitivas Kotlin
    lines.extend([
        "## Recomendación Priorizada de Primitivas Kotlin (Fase Posterior)",
        "",
        "Ordenada por **número real de fuentes afectadas** en esta ejecución automática:",
        "",
    ])
    if prim["primitives"]:
        lines.append("| Prioridad | Primitiva / Capacidad | Fuentes Afectadas (Total / Primaria) | Recomendación Técnica en Kotlin |")
        lines.append("|---:|---|---:|---|")
        for idx, row in enumerate(prim["primitives"], start=1):
            lines.append(
                f"| {idx} | **{row['title']}** (`{row['capability']}`) | {row['totalAffectedSources']} / {row['primarySourceCount']} | {row['recommendedPrimitive']} |"
            )
        lines.append("")
        if prim["unmappedThemes"]:
            top_themes = ", ".join(f"`{t['theme']}` ({t['count']})" for t in prim["unmappedThemes"][:10])
            lines.append(
                f"**Nota sobre temas `lib-multisrc` prioritarios:** los temas con mayor impacto directo en esta corrida fueron {top_themes}."
            )
            lines.append("")
    else:
        lines.append("_No se detectaron fuentes bloqueadas por capacidades faltantes del motor en esta corrida._")
        lines.append("")

    return "\n".join(lines)


def write_diagnostic_report(report_path, records, metadata):
    """Write Markdown report (and sibling .json when --report-out ends in .md)."""
    data = build_diagnostic_report_data(records, metadata)
    md_text = build_diagnostic_report_markdown(records, metadata)
    if report_path.lower().endswith(".json"):
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write("\n")
        return report_path, None

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(md_text)
    json_sidecar = re.sub(r"\.md$", "", report_path, flags=re.I) + ".json"
    with open(json_sidecar, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return report_path, json_sidecar
