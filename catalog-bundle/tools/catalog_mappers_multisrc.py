"""catalog_mappers_multisrc.py — Declarative mappers for lib-multisrc themes.

Provides modular declarative presets and selector mappings for:
- mangabox (Mangakakalot / Manganato / Katamanga family)
- hiper (Hiperdex / HiperManga WordPress variant)
- mangak (MangaK family)
- mangadventure (MangAdventure Django REST API)
- monochrome (Monochrome CMS / Headless API)
- moonlighttl (Moonlight Translations theme)
- mangotheme (MangaTheme WordPress variant)
- mangawork (MangaWork / MangaReader variant)
- gattsu (Gattsu theme)
- greenshit (GreenShit theme)
- wpcomics (WPComics / NetTruyen engine)
- madaralegacy (Legacy Madara themes)
- manhuarm (ManhuaRM theme)
- keyoapp (KeyoApp theme)

Strictly Python stdlib: no external dependencies.
"""

from urllib.parse import urljoin

SUPPORTED_MULTISRC_THEMES = frozenset(
    {
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
        "keyoapp",
    }
)

MULTISRC_THEME_PRESET_MAP = {
    "mangabox": "CSS_GENERIC",
    "hiper": "CSS_GENERIC",
    "mangak": "CSS_GENERIC",
    "mangadventure": "JSON_API",
    "monochrome": "CSS_GENERIC",
    "moonlighttl": "CSS_GENERIC",
    "mangotheme": "CSS_GENERIC",
    "mangawork": "CSS_GENERIC",
    "gattsu": "CSS_GENERIC",
    "greenshit": "CSS_GENERIC",
    "wpcomics": "CSS_GENERIC",
    "madaralegacy": "CSS_GENERIC",
    "manhuarm": "CSS_GENERIC",
    "keyoapp": "CSS_GENERIC",
}

MULTISRC_THEME_SELECTORS = {
    "mangabox": {
        "listSelector": "div.list-truyen-item-wrap, div.content-genres-item, div.story_item, div.item",
        "titleSelector": "h3 a, a.genres-item-name, a.story_name",
        "linkSelector": "h3 a, a.genres-item-name, a.story_name",
        "coverSelector": "img.img-loading, a img, img.story_img",
        "chapterSelector": "ul.row-content-chapter li, div.chapter-list div.row, div.list-chapter p.chapter",
        "pageImgSelector": "div.container-chapter-reader img, div.panel-read-story img",
        "nextPageSelector": "a.page-blue.page-last, a.page_next, a.next",
        "detailsTitleSelector": "div.story-info-right h1, div.panel-story-info h1",
        "detailsCoverSelector": "span.info-image img, div.story-info-left img",
        "descriptionSelector": "div.panel-story-info-description, div#noidungm, div.story-info-right-extent",
        "authorSelector": "table.variations-tableInfo tr:has(td.table-label:contains(Author)) td.table-value a, li:contains(Author) a",
        "genresSelector": "table.variations-tableInfo tr:has(td.table-label:contains(Genres)) td.table-value a, li:contains(Genres) a",
        "statusSelector": "table.variations-tableInfo tr:has(td.table-label:contains(Status)) td.table-value, li:contains(Status)",
        "chapterNameSelector": "a.chapter-name, a",
        "chapterDateSelector": "span.chapter-time, span.text-nowrap",
        "chapterDateFormat": "MMM dd,yyyy",
    },
    "hiper": {
        "listSelector": "div.page-item-detail, div.manga-item, div.c-tabs-item__content",
        "titleSelector": "div.item-title a, h3.title a, h4.title a",
        "linkSelector": "div.item-title a, h3.title a, h4.title a",
        "coverSelector": "div.item-thumb img, div.c-image-hover img",
        "chapterSelector": "li.wp-manga-chapter, div.chapter-item",
        "pageImgSelector": "div.page-break img, div.reading-content img",
        "nextPageSelector": "a.nextpostslink, a.next",
        "detailsTitleSelector": "div.post-title h1, h1.entry-title",
        "detailsCoverSelector": "div.summary_image img",
        "descriptionSelector": "div.description-summary, div.summary__content",
        "authorSelector": "div.author-content a",
        "genresSelector": "div.genres-content a",
        "statusSelector": "div.post-status div.summary-content",
        "chapterNameSelector": "a",
        "chapterDateSelector": "span.chapter-release-date",
    },
    "mangak": {
        "listSelector": "div.item, div.grid-item, div.thumb-item, div.entry",
        "titleSelector": "h3.title a, a.manga-title, h2.entry-title a",
        "linkSelector": "h3.title a, a.manga-title, h2.entry-title a",
        "coverSelector": "img.thumb, img.cover, div.entry-thumb img",
        "chapterSelector": "div.chapter-list a, ul.chapters li a, div.list-chapters a",
        "pageImgSelector": "div.chapter-content img, div.page-chapter img, div.reading-content img",
        "nextPageSelector": "a.next, div.pagination a.next",
        "detailsTitleSelector": "h1.title, h1.entry-title",
        "detailsCoverSelector": "div.manga-cover img, div.thumb img",
        "descriptionSelector": "div.synopsis, div.entry-content, div.description",
        "authorSelector": "div.author a, span.author a",
        "statusSelector": "div.status, span.status",
    },
    "monochrome": {
        "listSelector": "div.manga-card, div.comic-item, div.book-card, div.card",
        "titleSelector": "h3.title a, h4.title a, a.comic-title",
        "linkSelector": "h3.title a, h4.title a, a.comic-title",
        "coverSelector": "img.cover, div.thumbnail img",
        "chapterSelector": "ul.chapters li a, div.chapter-item a",
        "pageImgSelector": "div.chapter-pages img, div.reader-images img",
        "nextPageSelector": "a.pagination-next",
        "detailsTitleSelector": "h1.comic-title, h1.title",
        "detailsCoverSelector": "div.comic-cover img",
        "descriptionSelector": "div.comic-description, div.description",
    },
    "moonlighttl": {
        "listSelector": "div.page-item-detail, div.post-item, div.col-6.col-md-3",
        "titleSelector": "h3.title a, h4.title a, div.post-title a",
        "linkSelector": "h3.title a, h4.title a, div.post-title a",
        "coverSelector": "div.item-thumb img, img.post-thumb",
        "chapterSelector": "li.wp-manga-chapter, ul.chapters-list li",
        "pageImgSelector": "div.reading-content img, div.page-break img",
        "detailsTitleSelector": "div.post-title h1, h1.entry-title",
        "detailsCoverSelector": "div.summary_image img",
        "descriptionSelector": "div.description-summary",
    },
    "mangotheme": {
        "listSelector": "div.bsx, div.animepost, div.manga-card",
        "titleSelector": "a div.tt, h4.title a, div.title a",
        "linkSelector": "a[itemprop='url'], a",
        "coverSelector": "img.ts-post-image, img.lazyload",
        "chapterSelector": "div.eph-num a, ul.clstyle li a",
        "pageImgSelector": "div#readerarea img",
        "nextPageSelector": "a.r, a.next",
        "detailsTitleSelector": "h1.entry-title",
        "detailsCoverSelector": "div.thumb img",
        "descriptionSelector": "div.entry-content[itemprop='description'], div.synp",
    },
    "mangawork": {
        "listSelector": "div.listupd div.bsx, div.manga-item",
        "titleSelector": "div.bigor div.tt a, h3.title a",
        "linkSelector": "div.bigor div.tt a, a",
        "coverSelector": "div.limit img",
        "chapterSelector": "div.eph-num a, ul.clstyle li a",
        "pageImgSelector": "div#readerarea img",
        "detailsTitleSelector": "h1.entry-title",
        "detailsCoverSelector": "div.thumb img",
        "descriptionSelector": "div.entry-content, div.desc",
    },
    "gattsu": {
        "listSelector": "div.post-item, div.manga-card, div.comic-item",
        "titleSelector": "h3.entry-title a, h4.entry-title a",
        "linkSelector": "h3.entry-title a, h4.entry-title a",
        "coverSelector": "img.post-image, img.attachment-thumbnail",
        "chapterSelector": "ul.chapters li a, div.chapter-list a",
        "pageImgSelector": "div.entry-content img, div.reader-content img",
        "detailsTitleSelector": "h1.entry-title",
        "detailsCoverSelector": "div.entry-thumb img",
        "descriptionSelector": "div.entry-content p, div.description",
    },
    "greenshit": {
        "listSelector": "div.page-item-detail, div.manga-item",
        "titleSelector": "div.item-title a, h3.title a",
        "linkSelector": "div.item-title a, h3.title a",
        "coverSelector": "div.item-thumb img",
        "chapterSelector": "li.wp-manga-chapter, div.chapter-item",
        "pageImgSelector": "div.page-break img, div.reading-content img",
        "detailsTitleSelector": "div.post-title h1",
        "detailsCoverSelector": "div.summary_image img",
        "descriptionSelector": "div.description-summary",
    },
    "wpcomics": {
        "listSelector": "div.item, div.row-item, div.manga-box",
        "titleSelector": "h3 a, figcaption h3 a, a.jumbo",
        "linkSelector": "h3 a, figcaption h3 a, a.jumbo",
        "coverSelector": "div.image img, div.thumb img",
        "chapterSelector": "div.list-chapter ul li a, nav.chapter-list ul li a",
        "pageImgSelector": "div.page-chapter img, div.reading-detail img",
        "nextPageSelector": "a.next, ul.pagination li.active + li a",
        "detailsTitleSelector": "h1.title-detail, h1.title",
        "detailsCoverSelector": "div.col-image img",
        "descriptionSelector": "div.detail-content, div.shortened",
        "authorSelector": "li.author p.col-xs-8 a",
        "statusSelector": "li.status p.col-xs-8",
        "genresSelector": "li.kind p.col-xs-8 a",
    },
    "madaralegacy": {
        "listSelector": "div.page-item-detail, div.manga-item",
        "titleSelector": "div.item-title a, h5.title a",
        "linkSelector": "div.item-title a, h5.title a",
        "coverSelector": "div.item-thumb img",
        "chapterSelector": "li.wp-manga-chapter, div.chapter-item",
        "pageImgSelector": "div.page-break img, div.reading-content img",
        "detailsTitleSelector": "div.post-title h1, h1.entry-title",
        "detailsCoverSelector": "div.summary_image img",
        "descriptionSelector": "div.description-summary, div.summary__content",
        "authorSelector": "div.author-content a",
        "genresSelector": "div.genres-content a",
        "statusSelector": "div.post-status div.summary-content",
    },
    "manhuarm": {
        "listSelector": "div.box div.item, div.manga-card, div.col-series",
        "titleSelector": "h3.title a, a.name",
        "linkSelector": "h3.title a, a.name",
        "coverSelector": "div.thumb img, img.lazy",
        "chapterSelector": "div.chapter-item a, ul.chapters li a",
        "pageImgSelector": "div.chapter-content img, div.reading-content img",
        "nextPageSelector": "a.next",
        "detailsTitleSelector": "h1.title, h1.name",
        "detailsCoverSelector": "div.cover img",
        "descriptionSelector": "div.desc, div.description",
        "authorSelector": "div.author a",
        "statusSelector": "div.status",
    },
    "keyoapp": {
        "listSelector": "div.grid > div.group, article.ru-card, div.grid div.group, a.group[href]",
        "titleSelector": "a.grid h3, h2.ru-title a, h3, h2",
        "linkSelector": "a[href*='/series/'], h2.ru-title > a, a[href]",
        "coverSelector": "img.ru-cover-img, img, *[style*=background-image]",
        "chapterSelector": "a.chapter-row[href], #chapters > a, #chapters > div",
        "pageImgSelector": "#strip-reader img.reader-page, #pages > img",
        "nextPageSelector": "button[aria-label='Next recently updated page']:not([disabled]), a.next-page, a.next",
        "detailsTitleSelector": "div.grid > h1, h1",
        "detailsCoverSelector": "meta[property=og:image], div.series-poster img, img.ru-cover-img",
        "descriptionSelector": "#series-desc, #expand_content p, div.synopsis",
        "authorSelector": "div:has(span:containsOwn(Author)) ~ div, span.text-xs:containsOwn(Author)",
        "statusSelector": "div.text-xs:containsOwn(Status) + div span.text-sm, div:has(span:containsOwn(Status)) ~ div",
        "genresSelector": "a[href*='?browse&tag'], div:has(>h1) a[href*='genre=']",
    },
}


def build_mangadventure_json_api(base_url):
    """Builds a declarative JSON_API specification for MangAdventure CMS."""
    clean_base = base_url.rstrip("/")
    return {
        "apiBaseUrl": clean_base,
        "popularRequest": {
            "method": "GET",
            "pathTemplate": "/api/v1/series/",
            "headers": {"Accept": "application/json", "Referer": f"{clean_base}/"},
        },
        "latestRequest": {
            "method": "GET",
            "pathTemplate": "/api/v1/series/",
            "headers": {"Accept": "application/json", "Referer": f"{clean_base}/"},
        },
        "searchRequest": {
            "method": "GET",
            "pathTemplate": "/api/v1/series/?query={query}",
            "headers": {"Accept": "application/json", "Referer": f"{clean_base}/"},
        },
        "detailsRequest": {
            "method": "GET",
            "pathTemplate": "{detailsUrl}",
            "headers": {"Accept": "application/json", "Referer": f"{clean_base}/"},
        },
        "chaptersRequest": {
            "method": "GET",
            "pathTemplate": "/api/v1/chapters/?series={seriesSlug}",
            "headers": {"Accept": "application/json", "Referer": f"{clean_base}/"},
        },
        "pagesRequest": {
            "method": "GET",
            "pathTemplate": "/api/v1/chapters/{chapterId}/",
            "headers": {"Accept": "application/json", "Referer": f"{clean_base}/"},
        },
        "mangaList": {
            "itemsPath": "$.results[*]",
            "titlePath": "$.title",
            "urlPath": "$.url",
            "coverPath": "$.cover",
        },
        "details": {
            "titlePath": "$.title",
            "coverPath": "$.cover",
            "descriptionPath": "$.description",
            "authorPath": "$.authors[*]",
            "artistPath": "$.artists[*]",
            "genresPath": "$.categories[*]",
            "statusPath": "$.status",
        },
        "chapters": {
            "itemsPath": "$.results[*]",
            "namePath": "$.title",
            "urlPath": "$.url",
            "numberPath": "$.number",
            "datePath": "$.published",
            "dateFormat": "yyyy-MM-dd'T'HH:mm:ss'Z'",
        },
        "pages": {
            "itemsPath": "$.pages[*].url",
        },
    }


_GENERIC_CSS_DEFAULTS = {
    "listSelector": "article, div.manga-item, div.page-item-detail",
    "titleSelector": "h3 a, h4 a, a",
    "linkSelector": "a",
    "chapterSelector": "li a, div.chapter-item a",
    "pageImgSelector": "div.reading-content img, div#readerarea img",
}


def apply_multisrc_theme_to_recipe(recipe, theme, base_url, kotlin_text=""):
    """Applies theme-specific declarative presets and selectors for lib-multisrc sources."""
    if theme not in SUPPORTED_MULTISRC_THEMES:
        return False

    recipe["multisrcTheme"] = theme
    preset = MULTISRC_THEME_PRESET_MAP.get(theme, "CSS_GENERIC")
    recipe["preset"] = preset

    if theme == "mangadventure":
        recipe["jsonApi"] = build_mangadventure_json_api(base_url)
        recipe["catalogPath"] = "/api/v1/series/"
        recipe["selectors"] = None
        return True

    # CSS_GENERIC themes
    theme_sels = MULTISRC_THEME_SELECTORS.get(theme, {})
    current_sels = recipe.get("selectors") or {}
    merged_sels = dict(theme_sels)
    # Preserve existing manual overrides if distinct from CSS_GENERIC defaults
    for k, v in current_sels.items():
        if v and isinstance(v, str) and v.strip() and v != _GENERIC_CSS_DEFAULTS.get(k):
            merged_sels[k] = v
    recipe["selectors"] = merged_sels

    # Common request path configuration by theme
    if theme == "mangabox":
        if "popularRequest" not in recipe or not recipe.get("popularRequest"):
            recipe["popularRequest"] = {
                "method": "GET",
                "pathTemplate": "/manga_list?type=topview&category=all&state=all&page={page}",
                "firstPagePathTemplate": "/manga_list?type=topview&category=all&state=all&page=1",
            }
        if "latestRequest" not in recipe or not recipe.get("latestRequest"):
            recipe["latestRequest"] = {
                "method": "GET",
                "pathTemplate": "/manga_list?type=latest&category=all&state=all&page={page}",
                "firstPagePathTemplate": "/manga_list?type=latest&category=all&state=all&page=1",
            }
        if "searchRequest" not in recipe or not recipe.get("searchRequest"):
            recipe["searchRequest"] = {
                "method": "GET",
                "pathTemplate": "/search/story/{query}?page={page}",
                "firstPagePathTemplate": "/search/story/{query}",
            }
        recipe["catalogPath"] = "/manga_list"

    elif theme in ("hiper", "madaralegacy", "greenshit"):
        if "popularRequest" not in recipe or not recipe.get("popularRequest"):
            recipe["popularRequest"] = {
                "method": "GET",
                "pathTemplate": "/manga/?m_orderby=views&page={page}",
                "firstPagePathTemplate": "/manga/?m_orderby=views",
            }
        if "latestRequest" not in recipe or not recipe.get("latestRequest"):
            recipe["latestRequest"] = {
                "method": "GET",
                "pathTemplate": "/manga/?m_orderby=latest&page={page}",
                "firstPagePathTemplate": "/manga/?m_orderby=latest",
            }
        recipe["catalogPath"] = "/manga/"

    elif theme == "wpcomics":
        if "popularRequest" not in recipe or not recipe.get("popularRequest"):
            recipe["popularRequest"] = {
                "method": "GET",
                "pathTemplate": "/hot?page={page}",
                "firstPagePathTemplate": "/hot",
            }
        recipe["catalogPath"] = "/hot"

    elif theme == "keyoapp":
        is_v2 = "KeyoappV2" in (kotlin_text or "")
        if is_v2:
            if "popularRequest" not in recipe or not recipe.get("popularRequest"):
                recipe["popularRequest"] = {
                    "method": "GET",
                    "pathTemplate": "/?_ajax=recent-chapters&page={page}",
                    "firstPagePathTemplate": "/?_ajax=recent-chapters&page=1",
                }
            if "latestRequest" not in recipe or not recipe.get("latestRequest"):
                recipe["latestRequest"] = {
                    "method": "GET",
                    "pathTemplate": "/?_ajax=recent-chapters&page={page}",
                    "firstPagePathTemplate": "/?_ajax=recent-chapters&page=1",
                }
            if "searchRequest" not in recipe or not recipe.get("searchRequest"):
                recipe["searchRequest"] = {
                    "method": "GET",
                    "pathTemplate": "/?browse=1&q={query}",
                }
            recipe["catalogPath"] = "/?_ajax=recent-chapters&page=1"
            recipe["useHomeFallback"] = True
        else:
            if "popularRequest" not in recipe or not recipe.get("popularRequest"):
                recipe["popularRequest"] = {
                    "method": "GET",
                    "pathTemplate": "/latest/",
                    "firstPagePathTemplate": "/latest/",
                }
            if "latestRequest" not in recipe or not recipe.get("latestRequest"):
                recipe["latestRequest"] = {
                    "method": "GET",
                    "pathTemplate": "/latest/",
                    "firstPagePathTemplate": "/latest/",
                }
            if "searchRequest" not in recipe or not recipe.get("searchRequest"):
                recipe["searchRequest"] = {
                    "method": "GET",
                    "pathTemplate": "/series?q={query}",
                }
            recipe["catalogPath"] = "/latest/"
            recipe["useHomeFallback"] = True

    return True
