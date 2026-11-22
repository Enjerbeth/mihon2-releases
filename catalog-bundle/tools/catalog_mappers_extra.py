"""catalog_mappers_extra.py — Modular declarative mappers for high-impact themes.

Keeps sync_catalog.py lean by hosting dedicated mappings for:
- guya (JSON_API)
- mangahub (GraphQL via JsonEndpointSpec)
- yiimanga / yiimadara (CSS_GENERIC)
- vinetheme (CSS_GENERIC)
- galleryadults (CSS_GENERIC)
- hentaihand (JSON_API)
- Automatic authPreFlight emission for simple CSRF / Bearer preflights.

Strictly stdlib: no mandatory external dependencies (e.g. no bs4).
"""

import re
from urllib.parse import urljoin

SUPPORTED_EXTRA_THEMES = {
    "guya",
    "mangahub",
    "yiimanga",
    "yiimadara",
    "vinetheme",
    "galleryadults",
    "hentaihand",
}

EXTRA_THEME_PRESET_MAP = {
    "guya": "JSON_API",
    "mangahub": "JSON_API",
    "yiimanga": "CSS_GENERIC",
    "yiimadara": "CSS_GENERIC",
    "vinetheme": "CSS_GENERIC",
    "galleryadults": "CSS_GENERIC",
    "hentaihand": "JSON_API",
}

EXTRA_THEME_SELECTORS = {
    "yiimanga": {
        "listSelector": "div.media, div.media-manga, div.content-manga",
        "titleSelector": "h3.title a, h4.title a, a.media-heading",
        "linkSelector": "h3.title a, h4.title a, a.media-heading",
        "coverSelector": "img.media-object, div.media-left img",
        "chapterSelector": "ul.chapters-list li, div.chapter-item",
        "pageImgSelector": "div.chapter-content img, div.page-break img",
        "nextPageSelector": "ul.pagination li.next a",
        "detailsTitleSelector": "h1.title, h1.manga-title",
        "detailsCoverSelector": "div.manga-poster img, div.media-left img",
        "descriptionSelector": "div.description, div.manga-description",
        "authorSelector": "div.author, span.author",
        "statusSelector": "div.status, span.status",
    },
    "yiimadara": {
        "listSelector": "div.page-item-detail, div.manga-item",
        "titleSelector": "div.item-title a, h3.title a",
        "linkSelector": "div.item-title a, h3.title a",
        "coverSelector": "div.item-thumb img",
        "chapterSelector": "li.wp-manga-chapter, div.chapter-item",
        "pageImgSelector": "div.page-break img, div.text-left img",
        "detailsTitleSelector": "div.post-title h1, h1.entry-title",
        "detailsCoverSelector": "div.summary_image img",
        "descriptionSelector": "div.description-summary",
    },
    "vinetheme": {
        "listSelector": "div.col-6.col-md-3, div.col-6.col-sm-3, div.manga-card",
        "titleSelector": "h3.manga-title a, a.manga-name",
        "linkSelector": "h3.manga-title a, a.manga-name",
        "coverSelector": "img.manga-poster, img.lazyload",
        "chapterSelector": "div.chapter-list a, ul.list-chapters li a",
        "pageImgSelector": "div.reading-content img, div.viewer-content img",
        "nextPageSelector": "a.next.page-numbers",
        "detailsTitleSelector": "h1.manga-detail-name, h1.title",
        "detailsCoverSelector": "div.manga-poster img",
        "descriptionSelector": "div.manga-description, div.synopsis",
    },
    "galleryadults": {
        "listSelector": "div.gallery, div.thumb-container, div.item",
        "titleSelector": "div.caption a, a.cover",
        "linkSelector": "a.cover, div.caption a",
        "coverSelector": "img.lazyload, img.cover-image",
        "chapterSelector": "div.chapter-list a, a.read-btn",
        "pageImgSelector": "div.image-container img, div#image-container img",
        "detailsTitleSelector": "h1.title, h2.title",
        "detailsCoverSelector": "div#cover img, div.cover img",
        "descriptionSelector": "div#tags, div.tags",
    },
}


def build_guya_json_api(base_url):
    clean_base = base_url.rstrip("/")
    return {
        "apiBaseUrl": clean_base,
        "popularRequest": {
            "method": "GET",
            "pathTemplate": "/api/get_all_series/",
            "headers": {"Accept": "application/json", "Referer": f"{clean_base}/"},
        },
        "latestRequest": {
            "method": "GET",
            "pathTemplate": "/api/get_all_series/",
            "headers": {"Accept": "application/json", "Referer": f"{clean_base}/"},
        },
        "searchRequest": {
            "method": "GET",
            "pathTemplate": "/api/get_all_series/",
            "headers": {"Accept": "application/json", "Referer": f"{clean_base}/"},
        },
        "detailsRequest": {
            "method": "GET",
            "pathTemplate": "/api/series/{slug}/",
            "headers": {"Accept": "application/json", "Referer": f"{clean_base}/"},
        },
        "chaptersRequest": {
            "method": "GET",
            "pathTemplate": "/api/series/{slug}/",
            "headers": {"Accept": "application/json", "Referer": f"{clean_base}/"},
        },
        "mangaList": {
            "itemsPath": "$.*",
            "titlePaths": ["$.title", "$.slug"],
            "slugPath": "$.slug",
            "urlTemplate": "/read/manga/{slug}/",
            "coverBaseUrl": clean_base,
            "coverPaths": ["$.cover"],
            "pagination": {
                "mode": "PAGE_NUMBER",
                "startPage": 1,
                "pageSize": 100,
            },
        },
        "details": {
            "rootPath": "$",
            "titlePaths": ["$.title"],
            "descriptionPaths": ["$.description"],
            "coverPaths": ["$.cover"],
            "authorsPath": "$.author",
            "artistsPath": "$.artist",
        },
        "chapters": {
            "itemsPath": "$.chapters.*",
            "namePath": "$.title",
            "numberPath": "$.chapter",
            "datePath": "$.release_date",
        },
        "pages": {
            "itemsPath": "$.groups.*[*]",
            "imageUrlPath": "$.*",
        },
    }


def build_mangahub_graphql_json_api(base_url):
    clean_base = base_url.rstrip("/")
    api_url = "https://api.mhub.life"
    gql_popular = (
        'query search($q: String, $offset: Int, $limit: Int) {'
        ' search(x: m01, q: $q, offset: $offset, limit: $limit) {'
        ' rows { id title slug image } total } }'
    )
    return {
        "apiBaseUrl": api_url,
        "popularRequest": {
            "method": "POST",
            "pathTemplate": "/graphql",
            "contentType": "application/json",
            "headers": {"Accept": "application/json", "Origin": clean_base, "Referer": f"{clean_base}/"},
            "graphqlQuery": gql_popular,
            "graphqlVariablesTemplate": '{"offset":{offset},"limit":30}',
            "bodyTemplate": '{"query":"' + gql_popular.replace('"', '\\"') + '","variables":{"offset":{offset},"limit":30}}',
        },
        "latestRequest": {
            "method": "POST",
            "pathTemplate": "/graphql",
            "contentType": "application/json",
            "headers": {"Accept": "application/json", "Origin": clean_base, "Referer": f"{clean_base}/"},
            "graphqlQuery": gql_popular,
            "graphqlVariablesTemplate": '{"offset":{offset},"limit":30}',
            "bodyTemplate": '{"query":"' + gql_popular.replace('"', '\\"') + '","variables":{"offset":{offset},"limit":30}}',
        },
        "searchRequest": {
            "method": "POST",
            "pathTemplate": "/graphql",
            "contentType": "application/json",
            "headers": {"Accept": "application/json", "Origin": clean_base, "Referer": f"{clean_base}/"},
            "graphqlQuery": gql_popular,
            "graphqlVariablesTemplate": '{"q":"{query}","offset":{offset},"limit":30}',
            "bodyTemplate": '{"query":"' + gql_popular.replace('"', '\\"') + '","variables":{"q":"{query}","offset":{offset},"limit":30}}',
        },
        "mangaList": {
            "itemsPath": "$.data.search.rows[*]",
            "titlePaths": ["$.title"],
            "urlTemplate": "/manga/{slug}",
            "slugPath": "$.slug",
            "idPath": "$.id",
            "coverPaths": ["$.image"],
            "coverBaseUrl": "https://img.mhub.life",
            "pagination": {
                "mode": "OFFSET_LIMIT",
                "startPage": 0,
                "pageSize": 30,
            },
        },
        "chapters": {
            "itemsPath": "$.data.manga.chapters[*]",
            "namePath": "$.title",
            "numberPath": "$.number",
            "idPath": "$.id",
        },
        "pages": {
            "itemsPath": "$.data.chapter.pages[*]",
            "imageUrlPath": "$.p",
        },
    }


def build_hentaihand_json_api(base_url):
    clean_base = base_url.rstrip("/")
    return {
        "apiBaseUrl": clean_base,
        "popularRequest": {
            "method": "GET",
            "pathTemplate": "/api/comics?page={page}&sort=popular",
            "headers": {"Accept": "application/json", "Referer": f"{clean_base}/"},
        },
        "latestRequest": {
            "method": "GET",
            "pathTemplate": "/api/comics?page={page}&sort=datetime",
            "headers": {"Accept": "application/json", "Referer": f"{clean_base}/"},
        },
        "searchRequest": {
            "method": "GET",
            "pathTemplate": "/api/comics?page={page}&q={query}",
            "headers": {"Accept": "application/json", "Referer": f"{clean_base}/"},
        },
        "mangaList": {
            "itemsPath": "$.data[*]",
            "titlePaths": ["$.title"],
            "urlTemplate": "/comic/{slug}",
            "slugPath": "$.slug",
            "idPath": "$.id",
            "coverPaths": ["$.image.thumb", "$.thumb"],
            "pagination": {
                "mode": "PAGE_NUMBER",
                "startPage": 1,
                "pageSize": 24,
            },
        },
        "details": {
            "rootPath": "$",
            "titlePaths": ["$.title"],
            "descriptionPaths": ["$.description"],
        },
        "chapters": {
            "itemsPath": "$",
            "namePath": "$.title",
            "urlTemplate": "/comic/{slug}/reader",
        },
        "pages": {
            "itemsPath": "$.images[*]",
            "imageUrlPath": "$.source_url",
        },
    }


def detect_and_build_auth_preflight(kotlin_text, base_url):
    """Detect simple CSRF or Bearer preflight token patterns in Kotlin source."""
    if not kotlin_text or not base_url:
        return None
    clean_base = base_url.rstrip("/")

    # Pattern 1: CSRF token in meta tag or HTML input
    csrf_patterns = [
        (r'csrf-token["\']?\s*content=["\']?([^"\'\s>]+)', "REGEX", r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)'),
        (r'_token["\']?\s*value=["\']?([^"\'\s>]+)', "REGEX", r'<input[^>]*name=["\']_token["\'][^>]*value=["\']([^"\']+)'),
        (r'name=["\']authenticity_token["\'][^>]*value=["\']([^"\']+)', "REGEX", r'<input[^>]*name=["\']authenticity_token["\'][^>]*value=["\']([^"\']+)'),
    ]
    for kt_cue, mode, pat in csrf_patterns:
        if kt_cue in kotlin_text or ("csrf" in kotlin_text.lower() and "token" in kotlin_text.lower()):
            return {
                "url": f"{clean_base}/",
                "method": "GET",
                "headers": {"Referer": f"{clean_base}/"},
                "extractMode": mode,
                "extractPattern": pat,
                "cacheTtlSeconds": 1800,
                "targetHeader": "X-CSRF-TOKEN",
                "valuePrefix": "",
            }

    # Pattern 2: Bearer auth token via endpoint
    if "api/auth/token" in kotlin_text or "api/v1/auth" in kotlin_text:
        return {
            "url": f"{clean_base}/api/auth/token",
            "method": "POST",
            "headers": {"Accept": "application/json", "Referer": f"{clean_base}/"},
            "extractMode": "JSON_PATH",
            "extractPattern": "$.token",
            "cacheTtlSeconds": 3600,
            "targetHeader": "Authorization",
            "valuePrefix": "Bearer ",
        }

    return None


_GENERIC_CSS_DEFAULTS = {
    "listSelector": "article, div.manga-item, div.page-item-detail",
    "titleSelector": "h3 a, h4 a, a",
    "linkSelector": "a",
    "chapterSelector": "li a, div.chapter-item a",
    "pageImgSelector": "div.reading-content img, div#readerarea img",
}


def apply_extra_theme_to_recipe(recipe, theme, base_url, kotlin_text=""):
    """Apply specialized extra theme configuration and optional authPreFlight."""
    norm_theme = (theme or "").strip().lower()
    clean_base = base_url.rstrip("/")

    if norm_theme == "guya":
        recipe["preset"] = "JSON_API"
        recipe["jsonApi"] = build_guya_json_api(clean_base)
        recipe["catalogPath"] = "/api/get_all_series/"
        recipe["maxHtmlBytes"] = max(int(recipe.get("maxHtmlBytes") or 0), 3145728)
    elif norm_theme == "mangahub":
        recipe["preset"] = "JSON_API"
        recipe["jsonApi"] = build_mangahub_graphql_json_api(clean_base)
        recipe["catalogPath"] = "/graphql"
    elif norm_theme == "hentaihand":
        recipe["preset"] = "JSON_API"
        recipe["jsonApi"] = build_hentaihand_json_api(clean_base)
        recipe["catalogPath"] = "/api/comics"
    elif norm_theme in EXTRA_THEME_SELECTORS:
        recipe["preset"] = "CSS_GENERIC"
        selectors = dict(EXTRA_THEME_SELECTORS[norm_theme])
        for k, v in (recipe.get("selectors") or {}).items():
            if v and isinstance(v, str) and v.strip() and v != _GENERIC_CSS_DEFAULTS.get(k):
                selectors[k] = v
        recipe["selectors"] = selectors

    preflight = detect_and_build_auth_preflight(kotlin_text, clean_base)
    if preflight:
        recipe["authPreFlight"] = preflight

    return recipe
