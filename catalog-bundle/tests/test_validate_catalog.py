import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tools")))

from validate_catalog import (  # noqa: E402
    BUNDLE_ROOT,
    check_redos,
    is_license_boilerplate_attribution,
    recipe_to_index_entry,
    validate_bundle,
    validate_index_entry,
    validate_lang_tag,
    validate_notice,
    validate_recipe,
    validate_relative_recipe_path,
    validate_ssrf,
)


class TestValidateCatalogV2(unittest.TestCase):
    def _base_v2_recipe(self, **overrides):
        recipe = {
            "schemaVersion": 2,
            "sourceId": "example_madara",
            "name": "Example Madara",
            "baseUrl": "https://example.org",
            "lang": "en",
            "version": 1,
            "versionId": 1,
            "preset": "MADARA",
            "status": "ACTIVE",
            "maxHtmlBytes": 1048576,
            "recipePath": "recipes/example_madara.json",
            "mode": "declarative",
            "license": "Apache-2.0",
            "attribution": "Example Contributors",
            "selectors": {
                "listSelector": "div.manga-item",
                "titleSelector": "h3.title a",
                "linkSelector": "h3.title a",
            },
            "pipelineSteps": [
                {"op": "css_select", "selector": "div.reading-content img"},
            ],
        }
        recipe.update(overrides)
        return recipe

    def test_valid_v2_recipe_and_fixture(self):
        recipe = self._base_v2_recipe()
        valid, errs = validate_recipe(recipe, base_dir=BUNDLE_ROOT, expected_filename="example_madara.json")
        self.assertTrue(valid, f"Expected valid v2 recipe, got: {errs}")

        bad_name, name_errs = validate_recipe(recipe, base_dir=BUNDLE_ROOT, expected_filename="wrong_name.json")
        self.assertFalse(bad_name)
        self.assertTrue(any("Filename mismatch" in e for e in name_errs))

    def test_strict_ssrf_and_port_443_parity(self):
        bad_urls = [
            "http://example.org",
            "https://example.org:8443/manga",
            "https://127.0.0.1/manga",
            "https://169.254.169.254/latest",
            "https://100.64.0.1/api",
            "https://10.0.0.1/api",
            "https://172.16.0.1/api",
            "https://192.168.1.1/api",
            "https://localhost/test",
            "https://sub.localhost/test",
            "https://[::1]/test",
            "https://[fc00::1]/test",
            "https://[fe80::1]/test",
            "https://[::ffff:127.0.0.1]/test",
            "https://$sub.novelcool.com",
            "https://user:pass@example.org",
        ]
        for url in bad_urls:
            ok, _ = validate_ssrf(url)
            self.assertFalse(ok, f"Expected SSRF rejection for {url}")

        for good_url in ("https://example.org", "https://es.novelcool.com:443/manga"):
            ok, err = validate_ssrf(good_url)
            self.assertTrue(ok, f"Expected valid HTTPS URL for {good_url}, got {err}")

    def test_structural_redos_detection(self):
        for pat in (r"(a+)+$", r"(.*)*foo", r"(\w+)+", r"(a{1,5})+", r"((ab)+c)*"):
            self.assertTrue(check_redos(pat), f"Expected ReDoS detection for {pat}")

        for safe_pat in (r"^https://example\.org/manga/([a-z0-9-]+)$", r"[a-z]+\d{1,4}"):
            self.assertFalse(check_redos(safe_pat), f"False positive ReDoS for {safe_pat}")

    def test_bcp47_lang_and_relative_recipe_path(self):
        for valid_lang in ("es", "en", "es-419", "pt-BR", "zh-Hans", "all", "other"):
            self.assertTrue(validate_lang_tag(valid_lang)[0], valid_lang)

        for bad_lang in ("x", "too-long-lang-tag", "123", "es_MX"):
            self.assertFalse(validate_lang_tag(bad_lang)[0], bad_lang)

        self.assertTrue(validate_relative_recipe_path("recipes/es.mangafire.json")[0])
        for bad_path in ("", "/recipes/a.json", "../secret.json", "recipes\\a.json", "https://evil.org/a.json", "C:a.json"):
            self.assertFalse(validate_relative_recipe_path(bad_path)[0], bad_path)

    def test_pipeline_limits_and_forbid_webview_step(self):
        too_many = self._base_v2_recipe(pipelineSteps=[{"op": "trim_normalize"} for _ in range(13)])
        ok, errs = validate_recipe(too_many, base_dir=BUNDLE_ROOT)
        self.assertFalse(ok)
        self.assertTrue(any("exceed 12" in e for e in errs))

        wv_step = self._base_v2_recipe(pipelineSteps=[{"op": "webview_capture"}])
        ok_w, errs_w = validate_recipe(wv_step, base_dir=BUNDLE_ROOT)
        self.assertFalse(ok_w)
        self.assertTrue(any("Unauthorized operation 'webview_capture'" in e for e in errs_w))

    def test_crypto_headers_and_query_signer_validation(self):
        bad_aes = self._base_v2_recipe(pipelineSteps=[{"op": "aes_cbc_decrypt", "keyHex": "012345"}])
        self.assertFalse(validate_recipe(bad_aes, base_dir=BUNDLE_ROOT)[0])

        good_aes = self._base_v2_recipe(
            pipelineSteps=[{"op": "aes_cbc_decrypt", "keyHex": "0123456789abcdef0123456789abcdef"}]
        )
        self.assertTrue(validate_recipe(good_aes, base_dir=BUNDLE_ROOT)[0])

        bad_host = self._base_v2_recipe(headers={"Host": "evil.example"})
        self.assertFalse(validate_recipe(bad_host, base_dir=BUNDLE_ROOT)[0])

        bad_crlf = self._base_v2_recipe(headers={"X-Test": "abc\r\nInjected: 1"})
        self.assertFalse(validate_recipe(bad_crlf, base_dir=BUNDLE_ROOT)[0])

        table = base64.b64encode(bytes(range(256))).decode("ascii")
        key = base64.b64encode(b"secret").decode("ascii")
        qs_recipe = self._base_v2_recipe(
            sourceId="test_qs_good",
            recipePath="recipes/test_qs_good.json",
            preset="JSON_API",
            selectors={"listSelector": "$.data[*]"},
            pipelineSteps=[{"op": "json_path", "expression": "$.data.items[*]"}],
            querySigner={
                "algorithm": "sbox_xor_cbc",
                "pathPrefix": "/api",
                "stripPathPrefix": True,
                "paramName": "vrf",
                "stages": [{"tableBase64": table, "keyBase64": key, "iv": 90}],
            },
        )
        self.assertTrue(validate_recipe(qs_recipe, base_dir=BUNDLE_ROOT)[0])

    def test_v2_lightweight_bundle_validation_and_drift_detection(self):
        import json
        import tempfile

        r1 = self._base_v2_recipe(sourceId="es.alpha", lang="es", recipePath="recipes/es.alpha.json", versionCode=10)
        entry = recipe_to_index_entry(r1)
        expected = {
            "es.alpha": (
                entry["baseUrl"],
                entry["version"],
                entry["versionId"],
                entry["status"],
                entry["lang"],
                entry["preset"],
                entry["recipePath"],
                entry["versionCode"],
                tuple(entry["upstreamSourceIds"]),
                bool(entry.get("requiresCloudflareBypass", False)),
            )
        }
        v2_bundle = {
            "schemaVersion": 2,
            "generatedAt": "2026-11-21T18:00:00Z",
            "catalogRevision": 7,
            "entries": [entry],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            os.makedirs(os.path.join(tmpdir, "recipes"))
            with open(os.path.join(tmpdir, "recipes", "es.alpha.json"), "w", encoding="utf-8") as f:
                json.dump(r1, f)

            ok, errs = validate_bundle(v2_bundle, base_dir=tmpdir, expected_recipes_by_id=expected)
            self.assertTrue(ok, f"Expected valid v2 bundle, got: {errs}")

            # Reject inline recipes in v2 lightweight index
            bloated = dict(v2_bundle, recipes=[r1])
            self.assertFalse(validate_bundle(bloated, base_dir=tmpdir)[0])

            # Detect drift against recipes
            drifted_expected = dict(expected)
            drifted_expected["es.alpha"] = ("https://changed.example",) + expected["es.alpha"][1:]
            self.assertFalse(
                validate_bundle(v2_bundle, base_dir=tmpdir, expected_recipes_by_id=drifted_expected)[0]
            )

    def test_v2_engine_blocks_validation_and_bounds(self):
        complex_recipe = self._base_v2_recipe(
            sourceId="es.complex_engine",
            recipePath="recipes/es.complex_engine.json",
            preset="JSON_API",
            family="STANDARD",
            popularRequest={
                "method": "POST",
                "pathTemplate": "/api/search",
                "headers": {"Referer": "{baseUrl}/"},
                "bodyTemplate": "{\"page\":{page}}",
                "contentType": "application/json",
            },
            jsonApi={
                "apiBaseUrl": "https://api.example.org",
                "mangaList": {
                    "itemsPath": "$.data[*]",
                    "titlePaths": ["$.title"],
                    "coverBaseUrl": "https://cdn.example.org",
                    "pagination": {
                        "mode": "JSON_CURSOR",
                        "startPage": 0,
                        "pageSize": 25,
                        "nextCursorPath": "$.meta.cursor",
                        "maxPages": 100,
                    },
                },
            },
            pipelineSteps=[
                {"op": "grid_unscramble", "columns": 2, "rows": 2, "seed": 77, "format": "WEBP"},
            ],
        )
        ok, errs = validate_recipe(complex_recipe, base_dir=BUNDLE_ROOT)
        self.assertTrue(ok, f"Expected valid complex recipe, got: {errs}")

        # Reject SSRF on apiBaseUrl and coverBaseUrl
        bad_api = dict(complex_recipe, jsonApi=dict(complex_recipe["jsonApi"], apiBaseUrl="http://127.0.0.1"))
        self.assertFalse(validate_recipe(bad_api, base_dir=BUNDLE_ROOT)[0])

        # Reject pagination bounds
        bad_pag = dict(
            complex_recipe,
            jsonApi={
                "mangaList": {
                    "itemsPath": "$.data[*]",
                    "pagination": {"mode": "PAGE_NUMBER", "pageSize": 201, "maxPages": 20},
                }
            },
        )
        self.assertFalse(validate_recipe(bad_pag, base_dir=BUNDLE_ROOT)[0])

        # Reject Inertia host with scheme and Qwik ReDoS
        bad_inertia = self._base_v2_recipe(
            preset="CSS_GENERIC",
            family="INERTIA_SSR",
            inertia={"urlRewriteHosts": ["https://legacy.example"]},
        )
        self.assertFalse(validate_recipe(bad_inertia, base_dir=BUNDLE_ROOT)[0])

        bad_qwik = self._base_v2_recipe(
            preset="CSS_GENERIC",
            family="QWIK_SERIES",
            qwik={
                "searchQrlHash": "abc",
                "defaultSearchChunk": "q-1.js",
                "coverOriginRegex": "(a+)+",
            },
        )
        self.assertFalse(validate_recipe(bad_qwik, base_dir=BUNDLE_ROOT)[0])

    def test_validate_notice_verifies_license_and_attributions(self):
        import tempfile

        sample_recipes = [
            self._base_v2_recipe(
                sourceId="es.sample_one",
                upstreamRepo="keiyoushi/extensions-source",
                attribution="The Tachiyomi / Keiyoushi Contributors",
            )
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            # Missing LICENSE and NOTICE
            ok0, errs0 = validate_notice(tmpdir, recipes=sample_recipes)
            self.assertFalse(ok0)
            self.assertTrue(any("Missing LICENSE file" in e for e in errs0))

            with open(os.path.join(tmpdir, "LICENSE"), "w", encoding="utf-8") as lf:
                lf.write("Apache License Version 2.0\n")
            with open(os.path.join(tmpdir, "NOTICE"), "w", encoding="utf-8") as nf:
                nf.write(
                    "Source: keiyoushi/extensions-source\n"
                    "Attribution: The Tachiyomi / Keiyoushi Contributors\n"
                    "Recipes: es.sample_one\n"
                )
            ok1, errs1 = validate_notice(tmpdir, recipes=sample_recipes)
            self.assertTrue(ok1, f"Expected valid NOTICE+LICENSE, got: {errs1}")

            # Missing recipe attribution or sourceId in NOTICE must fail
            with open(os.path.join(tmpdir, "NOTICE"), "w", encoding="utf-8") as nf:
                nf.write("Source: keiyoushi/extensions-source\n")
            ok2, errs2 = validate_notice(tmpdir, recipes=sample_recipes)
            self.assertFalse(ok2)
            self.assertTrue(any("missing contributor attribution" in e for e in errs2))
            self.assertTrue(any("missing recipe sourceId" in e for e in errs2))

    def test_rejects_license_boilerplate_in_recipe_index_and_notice(self):
        import tempfile

        apache_clause = "You must retain, in the Source form of any Derivative Works"
        self.assertTrue(is_license_boilerplate_attribution(apache_clause))
        self.assertTrue(is_license_boilerplate_attribution("<year> <owner>"))
        self.assertFalse(is_license_boilerplate_attribution("The Tachiyomi / Keiyoushi Contributors"))

        bad_recipe = self._base_v2_recipe(
            sourceId="es.bad_attr",
            recipePath="recipes/es.bad_attr.json",
            upstreamRepo="keiyoushi/extensions-source",
            attribution=apache_clause,
        )
        ok_r, errs_r = validate_recipe(bad_recipe, base_dir=BUNDLE_ROOT)
        self.assertFalse(ok_r)
        self.assertTrue(any("boilerplate" in e for e in errs_r))

        bad_placeholder_recipe = self._base_v2_recipe(attribution="<year> <owner>")
        self.assertFalse(validate_recipe(bad_placeholder_recipe, base_dir=BUNDLE_ROOT)[0])

        bad_entry = recipe_to_index_entry(bad_recipe)
        errs_e = validate_index_entry(bad_entry)
        self.assertTrue(any("boilerplate" in e for e in errs_e))

        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "LICENSE"), "w", encoding="utf-8") as lf:
                lf.write("Apache License Version 2.0\n")
            with open(os.path.join(tmpdir, "NOTICE"), "w", encoding="utf-8") as nf:
                nf.write(
                    "Source: keiyoushi/extensions-source\n"
                    f"Attribution: {apache_clause}\n"
                    "Recipes: es.bad_attr\n"
                )
            # Even when recipe and NOTICE both carry the same boilerplate, validate_notice must fail.
            ok_n, errs_n = validate_notice(tmpdir, recipes=[bad_recipe])
            self.assertFalse(ok_n)
            self.assertTrue(any("boilerplate" in e for e in errs_n))

    def test_extended_recipe_selectors_cf_bypass_and_json_api_specs(self):
        recipe = self._base_v2_recipe(
            sourceId="es.extended_selectors",
            recipePath="recipes/es.extended_selectors.json",
            requiresCloudflareBypass=True,
            selectors={
                "listSelector": "div.manga-item",
                "titleSelector": "h3.title a",
                "linkSelector": "h3.title a",
                "detailsTitleSelector": "h1.entry-title",
                "detailsCoverSelector": "div.thumb img",
                "descriptionSelector": "div.desc p",
                "authorSelector": "span.author",
                "artistSelector": "span.artist",
                "genresSelector": "div.genres a",
                "statusSelector": "div.status span",
                "chapterNameSelector": "span.chapter-title",
                "chapterDateSelector": "span.chapter-date",
                "chapterDateFormat": "dd/MM/yyyy",
            },
            jsonApi={
                "apiBaseUrl": "https://api.extended.example",
                "mangaList": {
                    "itemsPath": "$.items[*]",
                    "htmlExtract": {
                        "titleSelector": "h2.title",
                        "urlSelector": "a.link",
                        "coverSelector": "img.poster",
                        "dateSelector": "span.date",
                    },
                },
                "chapters": {
                    "itemsPath": "$.chapters[*]",
                    "htmlExtract": {
                        "titleSelector": "a.chapter-link",
                    },
                },
                "pages": {
                    "itemsPath": "$.images[*]",
                    "imageUrlPath": "$.url",
                    "pipelineSteps": [
                        {"op": "trim_normalize"},
                        {"op": "grid_unscramble", "columns": 2, "rows": 2},
                    ],
                },
            },
        )
        ok, errs = validate_recipe(recipe, base_dir=BUNDLE_ROOT)
        self.assertTrue(ok, f"Expected valid extended recipe, got: {errs}")

        entry = recipe_to_index_entry(recipe)
        self.assertTrue(entry.get("requiresCloudflareBypass"))
        errs_entry = validate_index_entry(entry)
        self.assertEqual(errs_entry, [])

        # Forbid webview_capture inside jsonApi.pages.pipelineSteps
        bad_wv_recipe = self._base_v2_recipe(
            sourceId="es.bad_wv",
            recipePath="recipes/es.bad_wv.json",
            jsonApi={
                "pages": {
                    "itemsPath": "$.images[*]",
                    "pipelineSteps": [
                        {"op": "webview_capture"},
                    ],
                },
            },
        )
        ok_wv, errs_wv = validate_recipe(bad_wv_recipe, base_dir=BUNDLE_ROOT)
        self.assertFalse(ok_wv)
        self.assertTrue(any("Unauthorized operation 'webview_capture'" in e for e in errs_wv))

    def test_auth_preflight_graphql_and_phase_pipeline_steps(self):
        recipe = self._base_v2_recipe(
            sourceId="es.ronda2_spec",
            recipePath="recipes/es.ronda2_spec.json",
            authPreFlight={
                "url": "https://example.org/api/csrf",
                "method": "GET",
                "headers": {"Accept": "application/json"},
                "extractMode": "REGEX",
                "extractPattern": 'csrf_token="([^"]+)"',
                "cacheTtlSeconds": 1200,
                "targetHeader": "X-CSRF-TOKEN",
            },
            popularRequest={
                "method": "POST",
                "pathTemplate": "/graphql",
                "graphqlQuery": "query { items { id } }",
                "graphqlVariablesTemplate": '{"page":{page}}',
            },
            jsonApi={
                "apiBaseUrl": "https://api.example.org",
                "mangaList": {
                    "itemsPath": "$.data[*]",
                    "pipelineSteps": [{"op": "trim_normalize"}],
                },
                "chapters": {
                    "itemsPath": "$.chapters[*]",
                    "pipelineSteps": [{"op": "trim_normalize"}],
                },
            },
        )
        ok, errs = validate_recipe(recipe, base_dir=BUNDLE_ROOT)
        self.assertTrue(ok, f"Expected valid ronda 2 recipe, got: {errs}")

        # SSRF in authPreFlight must be rejected
        bad_preflight = dict(recipe, authPreFlight=dict(recipe["authPreFlight"], url="https://127.0.0.1/csrf"))
        ok_b, errs_b = validate_recipe(bad_preflight, base_dir=BUNDLE_ROOT)
        self.assertFalse(ok_b)
        self.assertTrue(any("SSRF violation" in e for e in errs_b))

        # Rejection of invalid extractMode
        bad_mode = dict(recipe, authPreFlight=dict(recipe["authPreFlight"], extractMode="INVALID_MODE"))
        ok_m, errs_m = validate_recipe(bad_mode, base_dir=BUNDLE_ROOT)
        self.assertFalse(ok_m)
        self.assertTrue(any("extractMode" in e for e in errs_m))

    def test_account_sync_and_ronda3_signing_and_pipeline(self):
        recipe = self._base_v2_recipe(
            sourceId="es.ronda3_spec",
            recipePath="recipes/es.ronda3_spec.json",
            accountSync={
                "loginUrl": "https://example.org/login",
                "loggedOutStatusCodes": [401, 403],
                "loggedOutBodyMarkers": ["Please log in"],
                "loggedOutRedirectContains": ["/login"],
                "maxPagesPerSection": 10,
                "sections": [
                    {
                        "kind": "FAVORITES",
                        "format": "HTML",
                        "itemsSelector": "div.book-item",
                        "urlSelector": "a.book-link",
                        "titleSelector": "h3.title",
                        "request": {
                            "method": "GET",
                            "pathTemplate": "/my/library",
                            "headers": {"Accept": "text/html"},
                        },
                        "pagination": {
                            "mode": "PAGE_NUMBER",
                            "startPage": 1,
                            "pageSize": 20,
                            "maxPages": 5,
                        },
                    }
                ],
            },
            listPipelineSteps=[{"op": "regex_extract", "pattern": "manga_id=([0-9]+)"}],
            chaptersPipelineSteps=[{"op": "trim_normalize"}],
            querySigner={
                "algorithm": "md5_salted",
                "paramName": "token",
                "pathPrefix": "/api",
                "hmacSecret": "my-salt-secret",
            },
        )
        ok, errs = validate_recipe(recipe, base_dir=BUNDLE_ROOT)
        self.assertTrue(ok, f"Expected valid ronda 3 recipe, got: {errs}")

        # sha256_timestamp querySigner should also be valid
        recipe_sha = dict(recipe, querySigner={"algorithm": "sha256_timestamp", "paramName": "sig", "pathPrefix": "/v1"})
        ok_sha, errs_sha = validate_recipe(recipe_sha, base_dir=BUNDLE_ROOT)
        self.assertTrue(ok_sha, f"Expected valid sha256_timestamp recipe, got: {errs_sha}")

        # Forbid Cookie or Authorization in accountSync section request headers
        bad_cred_headers = dict(
            recipe,
            accountSync=dict(
                recipe["accountSync"],
                sections=[
                    dict(
                        recipe["accountSync"]["sections"][0],
                        request={"method": "GET", "pathTemplate": "/my/library", "headers": {"Cookie": "session=123"}},
                    )
                ],
            ),
        )
        ok_cred, errs_cred = validate_recipe(bad_cred_headers, base_dir=BUNDLE_ROOT)
        self.assertFalse(ok_cred)
        self.assertTrue(any("must not contain credential header 'Cookie'" in e for e in errs_cred))

        # SSRF in loginUrl must be rejected
        bad_login_ssrf = dict(
            recipe,
            accountSync=dict(recipe["accountSync"], loginUrl="http://127.0.0.1/login"),
        )
        ok_ssrf, errs_ssrf = validate_recipe(bad_login_ssrf, base_dir=BUNDLE_ROOT)
        self.assertFalse(ok_ssrf)
        self.assertTrue(any("accountSync.loginUrl SSRF violation" in e for e in errs_ssrf))

        # Empty sections must be rejected
        bad_sections = dict(recipe, accountSync=dict(recipe["accountSync"], sections=[]))
        ok_sec, errs_sec = validate_recipe(bad_sections, base_dir=BUNDLE_ROOT)
        self.assertFalse(ok_sec)
        self.assertTrue(any("accountSync.sections must be an array of 1..6" in e for e in errs_sec))

    def test_quickjs_eval_and_extended_grid_unscramble(self):
        recipe = self._base_v2_recipe(
            sourceId="es.ronda4_spec",
            recipePath="recipes/es.ronda4_spec.json",
            pipelineSteps=[
                {
                    "op": "quickjs_eval",
                    "preset": "CUSTOM",
                    "script": "var out = input.split('').reverse().join('');",
                    "outputVar": "out",
                    "timeoutMs": 3000,
                },
                {
                    "op": "quickjs_eval",
                    "preset": "PACKER",
                    "script": "var unpacked = unpackPacker(input); unpacked;",
                    "outputVar": "unpacked",
                    "timeoutMs": 2500,
                },
                {
                    "op": "grid_unscramble",
                    "columns": 4,
                    "rows": 4,
                    "mode": "STRIP_VERTICAL",
                    "remainderPolicy": "KEEP_EDGE",
                    "seedHeaderName": "X-Seed",
                    "hashSeedTemplate": "salt:{seed}",
                    "hashAlgorithm": "SHA-256",
                },
                {
                    "op": "grid_unscramble",
                    "mode": "PUBLUS",
                    "blockWidth": 64,
                    "blockHeight": 64,
                    "rotations": [0, 90, 180, 270],
                    "seedFromUrlRegex": r"chapter/(\d+)/",
                },
            ],
        )
        ok, errs = validate_recipe(recipe, base_dir=BUNDLE_ROOT)
        self.assertTrue(ok, f"Expected valid ronda 4/phase 2 recipe, got: {errs}")

        # Forbid dangerous tokens in quickjs_eval
        for tok_script in (
            "fetch('https://evil.com')",
            "new XMLHttpRequest()",
            "new WebSocket('wss://x')",
            "Packages.java.lang.Runtime",
            "java.io.File",
            "android.os.Process",
            "System.exit(1)",
            "Runtime.getRuntime().exec('ls')",
        ):
            bad_qjs_token = self._base_v2_recipe(
                sourceId="es.bad_qjs",
                recipePath="recipes/es.bad_qjs.json",
                pipelineSteps=[{"op": "quickjs_eval", "script": tok_script}],
            )
            ok_tok, errs_tok = validate_recipe(bad_qjs_token, base_dir=BUNDLE_ROOT)
            self.assertFalse(ok_tok, f"Expected rejection for {tok_script}")
            self.assertTrue(any("forbidden security token" in e for e in errs_tok))

        # Reject invalid preset and invalid outputVar
        bad_preset = self._base_v2_recipe(
            pipelineSteps=[{"op": "quickjs_eval", "preset": "BOGUS", "script": "var x=1;"}]
        )
        self.assertFalse(validate_recipe(bad_preset, base_dir=BUNDLE_ROOT)[0])
        bad_outvar = self._base_v2_recipe(
            pipelineSteps=[{"op": "quickjs_eval", "script": "var x=1;", "outputVar": "1invalid-var"}]
        )
        self.assertFalse(validate_recipe(bad_outvar, base_dir=BUNDLE_ROOT)[0])

        # Reject timeoutMs > 3000
        bad_qjs_timeout = self._base_v2_recipe(
            sourceId="es.bad_qjs_t",
            recipePath="recipes/es.bad_qjs_t.json",
            pipelineSteps=[{"op": "quickjs_eval", "script": "var a = 1;", "timeoutMs": 3001}],
        )
        ok_t, errs_t = validate_recipe(bad_qjs_timeout, base_dir=BUNDLE_ROOT)
        self.assertFalse(ok_t)
        self.assertTrue(any("timeoutMs must be between 1 and 3000" in e for e in errs_t))

    def test_phase2_crypto_unscramble_signer_jsonpath_and_details_pipeline(self):
        key_hex_32 = "00112233445566778899aabbccddeeff"
        iv_hex_32 = "ffeeddccbbaa99887766554433221100"
        recipe = self._base_v2_recipe(
            sourceId="es.phase2_all",
            recipePath="recipes/es.phase2_all.json",
            preset="JSON_API",
            selectors={"listSelector": "$..series[*]"},
            pipelineSteps=[
                {"op": "aes_ecb_decrypt", "keyHex": key_hex_32},
                {
                    "op": "dynamic_crypto",
                    "algorithm": "AES_CBC",
                    "keyHex": key_hex_32,
                    "ivHex": iv_hex_32,
                    "keyRegex": r"key=([a-f0-9]{32})",
                    "ivRegex": r"iv=([a-f0-9]{32})",
                    "inputFormat": "BASE64",
                    "outputFormat": "UTF8",
                },
                {"op": "lz_string", "mode": "URI_COMPONENT"},
                {"op": "gzip_decompress"},
                {"op": "deflate_decompress"},
                {"op": "decompress", "algorithm": "LZ_STRING_BASE64"},
                {"op": "json_path", "expression": "$..items[?(@.type=='manga')].slug"},
                {"op": "json_path", "expression": "data[].title"},
                {
                    "op": "grid_unscramble",
                    "mode": "SPEEDBINB",
                    "blockWidth": 32,
                    "blockHeight": 32,
                    "rotations": [0, 180],
                    "seedUrlRegex": r"/p/(\d+)\.jpg",
                },
            ],
            querySigner={
                "algorithm": "hmac_sha1",
                "pathPrefix": "/api",
                "target": "HEADER",
                "headerName": "X-Signature",
                "timestampHeaderName": "X-Timestamp",
                "timestampFormat": "EPOCH_MILLIS",
                "signTemplate": "{method}:{path}:{timestamp}:{secret}",
                "hmacSecret": "top-secret-key",
            },
            jsonApi={
                "apiBaseUrl": "https://api.example.org",
                "mangaList": {"itemsPath": "data[].items[*]"},
                "details": {
                    "rootPath": "$.data",
                    "titlePaths": ["$..title"],
                    "pipelineSteps": [
                        {"op": "quickjs_eval", "preset": "NEXT_RSC"},
                        {"op": "json_path", "expression": "$.props..manga"},
                    ],
                },
            },
        )
        ok, errs = validate_recipe(recipe, base_dir=BUNDLE_ROOT)
        self.assertTrue(ok, f"Expected valid phase 2 recipe, got: {errs}")

        # Test sha1_salted signer too
        sha1_qs = dict(recipe, querySigner={"algorithm": "sha1_salted", "paramName": "sig", "pathPrefix": "/api", "hmacSecret": "salt"})
        self.assertTrue(validate_recipe(sha1_qs, base_dir=BUNDLE_ROOT)[0])

        # Reject HEADER target without headerName
        bad_qs = dict(recipe, querySigner={"algorithm": "hmac_sha1", "hmacSecret": "abc", "target": "HEADER"})
        self.assertFalse(validate_recipe(bad_qs, base_dir=BUNDLE_ROOT)[0])

        # Reject ReDoS in dynamic_crypto and grid_unscramble
        redos_dc = self._base_v2_recipe(
            pipelineSteps=[{"op": "dynamic_crypto", "algorithm": "AES_CBC", "keyRegex": "(a+)+", "ivPrepend": True}]
        )
        self.assertFalse(validate_recipe(redos_dc, base_dir=BUNDLE_ROOT)[0])

        redos_grid = self._base_v2_recipe(
            pipelineSteps=[{"op": "grid_unscramble", "mode": "PUBLUS", "blockWidth": 32, "seedFromUrlRegex": "(.*)*x"}]
        )
        self.assertFalse(validate_recipe(redos_grid, base_dir=BUNDLE_ROOT)[0])

        # Reject invalid rotation angle and invalid hex
        bad_rot = self._base_v2_recipe(
            pipelineSteps=[{"op": "grid_unscramble", "mode": "PUBLUS", "blockWidth": 32, "rotations": [45]}]
        )
        self.assertFalse(validate_recipe(bad_rot, base_dir=BUNDLE_ROOT)[0])

        bad_hex = self._base_v2_recipe(
            pipelineSteps=[{"op": "dynamic_crypto", "algorithm": "AES_ECB", "keyHex": "not-hex-zz"}]
        )
        self.assertFalse(validate_recipe(bad_hex, base_dir=BUNDLE_ROOT)[0])

        # Reject webview_capture inside jsonApi.details.pipelineSteps
        bad_det_wv = self._base_v2_recipe(
            preset="JSON_API",
            jsonApi={
                "details": {
                    "rootPath": "$",
                    "pipelineSteps": [{"op": "webview_capture"}],
                }
            },
        )
        self.assertFalse(validate_recipe(bad_det_wv, base_dir=BUNDLE_ROOT)[0])

        # Reject malformed JSONPath / JMESPath
        for bad_expr in ("$...bad", "$.data[unclosed", "$.data[?()]", "plain_without_brackets"):
            bad_jp = self._base_v2_recipe(pipelineSteps=[{"op": "json_path", "expression": bad_expr}])
            self.assertFalse(validate_recipe(bad_jp, base_dir=BUNDLE_ROOT)[0], f"Expected rejection for {bad_expr}")

        # Reject pipelineSteps repeating selectors.listSelector and empty GraphQL endpoints when ACTIVE
        contaminated = self._base_v2_recipe(
            selectors={"listSelector": "div.bsx"},
            pipelineSteps=[{"op": "css_select", "selector": "div.bsx", "attribute": "innerHTML"}],
        )
        ok_cont, errs_cont = validate_recipe(contaminated, base_dir=BUNDLE_ROOT)
        self.assertFalse(ok_cont)
        self.assertTrue(any("repeats selectors.listSelector" in e for e in errs_cont))

        empty_gql = self._base_v2_recipe(
            preset="JSON_API",
            selectors=None,
            jsonApi={
                "apiBaseUrl": "https://example.org",
                "popularRequest": {"method": "GET", "pathTemplate": "/graphql"},
            },
        )
        ok_gql, errs_gql = validate_recipe(empty_gql, base_dir=BUNDLE_ROOT)
        self.assertFalse(ok_gql)
        self.assertTrue(any("without bodyTemplate, graphqlQuery" in e for e in errs_gql))


if __name__ == "__main__":
    unittest.main()
