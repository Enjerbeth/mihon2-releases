import contextlib
import copy
import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import urllib.error

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tools")))

import sync_catalog  # noqa: E402
from validate_catalog import validate_bundle, validate_recipe  # noqa: E402


def _encode_varint(val):
    out = bytearray()
    v = int(val)
    if v < 0:
        v &= (1 << 64) - 1
    while True:
        byte = v & 0x7F
        v >>= 7
        if v:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _pb_bytes(fnum, data):
    return _encode_varint((fnum << 3) | 2) + _encode_varint(len(data)) + data


def _pb_varint(fnum, val):
    return _encode_varint((fnum << 3) | 0) + _encode_varint(val)


def build_synthetic_index_pb(repo_name, extensions):
    ext_blobs = bytearray()
    for ext in extensions:
        sub = bytearray()
        sub += _pb_bytes(1, ext["name"].encode("utf-8"))
        sub += _pb_bytes(2, ext["pkgName"].encode("utf-8"))
        apk_msg = _pb_bytes(1, b"https://example.org/app.apk") + _pb_bytes(2, ext["iconUrl"].encode("utf-8"))
        sub += _pb_bytes(3, apk_msg)
        sub += _pb_bytes(4, b"1.6")
        sub += _pb_varint(5, ext["versionCode"])
        sub += _pb_bytes(6, ext.get("versionName", "1.6.1").encode("utf-8"))
        if ext.get("contentWarning") is not None:
            sub += _pb_varint(7, int(ext["contentWarning"]))
        for src in ext["sources"]:
            s_msg = (
                _pb_varint(1, src["sourceId"])
                + _pb_bytes(2, src["name"].encode("utf-8"))
                + _pb_bytes(3, src["lang"].encode("utf-8"))
                + _pb_bytes(4, src["baseUrl"].encode("utf-8"))
            )
            for m_url in src.get("mirrors") or []:
                s_msg += _pb_bytes(5, m_url.encode("utf-8"))
            sub += _pb_bytes(8, s_msg)
        ext_blobs += _pb_bytes(1, bytes(sub))

    root = _pb_bytes(1, repo_name.encode("utf-8")) + _pb_bytes(101, bytes(ext_blobs))
    return gzip.compress(root)


def _init_local_git_repo(repo_dir, license_text=None, files=None, commit_date="2026-10-01T12:00:00Z"):
    os.makedirs(repo_dir, exist_ok=True)
    if license_text is not None:
        with open(os.path.join(repo_dir, "LICENSE"), "w", encoding="utf-8") as f:
            f.write(license_text)
    for rel_path, content in (files or {}).items():
        abs_path = os.path.join(repo_dir, rel_path)
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        with open(abs_path, "w", encoding="utf-8") as f:
            f.write(content)
    env = dict(os.environ)
    env["GIT_AUTHOR_DATE"] = commit_date
    env["GIT_COMMITTER_DATE"] = commit_date
    subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test Bot"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "bot@example.org"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "Initial"], cwd=repo_dir, env=env, check=True, capture_output=True)


class TestSyncCatalogV2(unittest.TestCase):
    def test_shallow_git_clone_and_osi_license_verification(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            apache_origin = os.path.join(tmpdir, "origin_apache")
            _init_local_git_repo(
                apache_origin,
                license_text="Apache License\nVersion 2.0, January 2004\nCopyright 2026 Apache Sample Contributors\n",
                files={
                    "src/es/demoscan/build.gradle.kts": (
                        'name = "Demo Scan"\n'
                        'theme = "madara"\n'
                        'versionCode = 12\n'
                        'lang = "es"\n'
                        'baseUrl = "https://demoscan.example"\n'
                    ),
                    "src/es/demoscan/src/DemoScan.kt": (
                        'class DemoScan : Madara("Demo Scan", baseUrl, "es") { override val mangaSubString = "series" }'
                    ),
                },
            )
            cloned_apache = os.path.join(tmpdir, "cloned_apache")
            sync_catalog.clone_or_open_repo(apache_origin, cloned_apache)
            info = sync_catalog.read_extension_from_repo(cloned_apache, "src/es/demoscan")
            self.assertTrue(info["licenseOk"])
            self.assertEqual(info["license"], "Apache-2.0")
            self.assertEqual(info["gradle"]["theme"], "madara")
            self.assertEqual(info["kotlinHint"]["catalogPath"], "/series")

            # GPL / AGPL / SSPL / All rights reserved / missing license must be rejected
            for bad_name, bad_lic in [
                ("gpl", "GNU GENERAL PUBLIC LICENSE\nVersion 3\nGPL-3.0"),
                ("agpl", "GNU AFFERO GENERAL PUBLIC LICENSE\nAGPL-3.0"),
                ("sspl", "Server Side Public License (SSPL)"),
                ("arr", "Copyright 2026 Someone. All rights reserved."),
                ("missing", None),
            ]:
                bad_dir = os.path.join(tmpdir, f"repo_{bad_name}")
                os.makedirs(bad_dir, exist_ok=True)
                if bad_lic is not None:
                    with open(os.path.join(bad_dir, "LICENSE"), "w", encoding="utf-8") as f:
                        f.write(bad_lic)
                ok, code, _ = sync_catalog.verify_repo_license(bad_dir)
                self.assertFalse(ok, f"Expected rejection for {bad_name}, got {code}")

            mit_dir = os.path.join(tmpdir, "repo_mit")
            os.makedirs(mit_dir, exist_ok=True)
            with open(os.path.join(mit_dir, "LICENSE"), "w", encoding="utf-8") as f:
                f.write(
                    'MIT License\nCopyright (c) 2026 MIT Sample Authors\n'
                    'Permission is hereby granted, free of charge...\n'
                    'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND\n'
                )
            ok_mit, spdx_mit, attr_mit = sync_catalog.verify_repo_license(mit_dir)
            self.assertTrue(ok_mit)
            self.assertEqual(spdx_mit, "MIT")
            self.assertIn("MIT Sample Authors", attr_mit)

    def test_cross_repo_deduplication_prioritizes_highest_version_and_merges_ids(self):
        candidates = [
            {
                "upstreamRepo": "FelipeGFA/fonte-extensoes",
                "repoPriority": 1,
                "sourceId": 1001,
                "name": "Scan Alpha",
                "lang": "es",
                "baseUrl": "https://www.scanalpha.example",
                "versionCode": 105001,
                "versionId": 1,
                "pkgName": "eu.kanade.tachiyomi.extension.es.scanalpha",
            },
            {
                "upstreamRepo": "keiyoushi/extensions-source",
                "repoPriority": 2,
                "sourceId": 2002,
                "name": "Scan Alpha",
                "lang": "es",
                "baseUrl": "https://scanalpha.example",
                "versionCode": 106020,
                "versionId": 1,
                "pkgName": "eu.kanade.tachiyomi.extension.es.scanalpha",
            },
            {
                "upstreamRepo": "keiyoushi/extensions-source",
                "repoPriority": 2,
                "sourceId": 3003,
                "name": "Scan Beta",
                "lang": "en",
                "baseUrl": "https://scanbeta.example",
                "versionCode": 104000,
                "versionId": 2,
                "pkgName": "eu.kanade.tachiyomi.extension.en.scanbeta",
            },
        ]
        merged = sync_catalog.merge_candidates(candidates)
        self.assertEqual(len(merged), 2)
        alpha = [c for c in merged if c["name"] == "Scan Alpha"][0]
        self.assertEqual(alpha["versionCode"], 106020)
        self.assertEqual(alpha["upstreamSourceId"], 2002)
        self.assertEqual(alpha["upstreamSourceIds"], [1001, 2002])

    def test_http_smoke_test_enforces_three_items_and_protection_degradation(self):
        madara_recipe = {
            "sourceId": "es.smoketest",
            "name": "Smoke Test",
            "baseUrl": "https://smoketest.example",
            "catalogPath": "/manga",
            "preset": "MADARA",
            "selectors": {
                "listSelector": "div.page-item-detail",
                "titleSelector": "h3.h5 a",
                "linkSelector": "h3.h5 a",
            },
        }
        good_html = (
            '<div class="page-item-detail"><h3 class="h5"><a href="/m/1">One</a></h3></div>'
            '<div class="page-item-detail"><h3 class="h5"><a href="/m/2">Two</a></h3></div>'
            '<div class="page-item-detail"><h3 class="h5"><a href="/m/3">Three</a></h3></div>'
        )
        ok, count, _, updates = sync_catalog.run_http_smoke_test(
            madara_recipe,
            fetcher=lambda _u: (200, good_html, "HTTP 200"),
            is_existing_active=False,
        )
        self.assertTrue(ok)
        self.assertEqual(count, 3)
        self.assertEqual(updates["status"], "ACTIVE")

        # Only 2 items -> must NOT stay ACTIVE
        two_html = (
            '<div class="page-item-detail"><h3 class="h5"><a href="/m/1">One</a></h3></div>'
            '<div class="page-item-detail"><h3 class="h5"><a href="/m/2">Two</a></h3></div>'
        )
        ok2, count2, _, updates2 = sync_catalog.run_http_smoke_test(
            madara_recipe,
            fetcher=lambda _u: (200, two_html, "HTTP 200"),
            is_existing_active=True,
        )
        self.assertFalse(ok2)
        self.assertEqual(count2, 2)
        self.assertEqual(updates2["status"], "DISABLED")

        # JS decoy -> requiresWebViewCapture=True and DRAFT
        decoy_html = '<html><script>self.__next_f.push([1,"data"]);</script></html>'
        ok3, _, _, updates3 = sync_catalog.run_http_smoke_test(
            madara_recipe,
            fetcher=lambda _u: (200, decoy_html, "HTTP 200"),
            is_existing_active=True,
        )
        self.assertFalse(ok3)
        self.assertEqual(updates3["status"], "DRAFT")
        self.assertTrue(updates3["requiresWebViewCapture"])

        # Cloudflare 403 -> QUARANTINED for existing active, DRAFT for new
        ok4, _, _, updates4 = sync_catalog.run_http_smoke_test(
            madara_recipe,
            fetcher=lambda _u: (403, "<title>Just a moment...</title>", "HTTP 403"),
            is_existing_active=True,
        )
        self.assertFalse(ok4)
        self.assertEqual(updates4["status"], "QUARANTINED")

        # JSON_API >= 3 items
        json_recipe = {
            "sourceId": "es.jsontest",
            "name": "JSON Test",
            "baseUrl": "https://api.example",
            "catalogPath": "/list",
            "preset": "JSON_API",
            "selectors": {"listSelector": "$.data.items[*]"},
        }
        json_body = json.dumps({"data": {"items": [{"title": "A"}, {"title": "B"}, {"title": "C"}]}})
        ok5, count5, _, updates5 = sync_catalog.run_http_smoke_test(
            json_recipe,
            fetcher=lambda _u: (200, json_body, "HTTP 200"),
            is_existing_active=False,
        )
        self.assertTrue(ok5)
        self.assertEqual(count5, 3)
        self.assertEqual(updates5["status"], "ACTIVE")

        # JSON_API with jsonApi.apiBaseUrl + popularRequest template & POST body
        captured_calls = []

        def api_fetcher(url, method="GET", headers=None, body=None):
            captured_calls.append((url, method, headers, body))
            return 200, json.dumps({"results": [{"id": 1}, {"id": 2}, {"id": 3}]}), "HTTP 200"

        json_api_recipe = {
            "sourceId": "es.jsonapi_popular",
            "name": "JSON API Popular",
            "baseUrl": "https://web.example.org",
            "lang": "es-419",
            "preset": "JSON_API",
            "headers": {"Referer": "{baseUrl}/"},
            "selectors": {"listSelector": "div.unused"},
            "jsonApi": {
                "apiBaseUrl": "https://api.example.org",
                "defaultOrg": "org42",
                "langMap": {"es-419": "es-la"},
                "popularRequest": {
                    "method": "POST",
                    "pathTemplate": "/v1/series?page={page}&lang={lang}&org={org}",
                    "headers": {"X-Org": "{org}"},
                    "bodyTemplate": "{\"page\":{page},\"offset\":{offset}}",
                    "contentType": "application/json",
                },
                "mangaList": {
                    "itemsPath": "$.results[*]",
                    "pagination": {"mode": "PAGE_NUMBER", "startPage": 1, "pageSize": 20},
                },
            },
        }
        ok6, count6, _, updates6 = sync_catalog.run_http_smoke_test(
            json_api_recipe,
            fetcher=api_fetcher,
            is_existing_active=False,
        )
        self.assertTrue(ok6)
        self.assertEqual(count6, 3)
        self.assertEqual(updates6["status"], "ACTIVE")
        self.assertEqual(len(captured_calls), 1)
        called_url, called_method, called_headers, called_body = captured_calls[0]
        self.assertEqual(called_url, "https://api.example.org/v1/series?page=1&lang=es-la&org=org42")
        self.assertEqual(called_method, "POST")
        self.assertEqual(called_headers.get("Referer"), "https://web.example.org/")
        self.assertEqual(called_headers.get("X-Org"), "org42")
        self.assertEqual(called_headers.get("Content-Type"), "application/json")
        self.assertEqual(called_body, "{\"page\":1,\"offset\":0}")

    def test_verify_repo_license_header_scoping_and_unverified_slug_rejection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_dir = os.path.join(tmpdir, "repo_apache_body_mention")
            os.makedirs(repo_dir, exist_ok=True)
            with open(os.path.join(repo_dir, "LICENSE"), "w", encoding="utf-8") as f:
                f.write("Apache License\nVersion 2.0, January 2004\nCopyright 2026 Clean Header Authors\n")

            # Mentioning GPL or proprietary inside Kotlin code body (after package/class) must not trigger false rejection
            kt_with_body_comment = (
                "package eu.kanade.tachiyomi.extension.es.demo\n"
                "class DemoSource {\n"
                "    // Filter out proprietary or GPL-3.0 banner strings from site description\n"
                '    val ignored = "All rights reserved"\n'
                "}\n"
            )
            ok, spdx, attr = sync_catalog.verify_repo_license(
                repo_dir,
                kotlin_texts=[kt_with_body_comment],
            )
            self.assertTrue(ok)
            self.assertEqual(spdx, "Apache-2.0")
            self.assertIn("Clean Header Authors", attr)

            # SPDX-License-Identifier: GPL-3.0-only in header must still be rejected
            kt_gpl_header = "// SPDX-License-Identifier: GPL-3.0-only\npackage demo\nclass Demo\n"
            ok_gpl, code_gpl, _ = sync_catalog.verify_repo_license(repo_dir, kotlin_texts=[kt_gpl_header])
            self.assertFalse(ok_gpl)
            self.assertIn("REJECTED", code_gpl)

            # generate_recipe_from_slug without verified repo_meta must refuse generation
            pb_data = build_synthetic_index_pb(
                "keiyoushi/extensions-source",
                [
                    {
                        "name": "Unverified Slug Source",
                        "pkgName": "eu.kanade.tachiyomi.extension.es.unverifiedslug",
                        "iconUrl": "https://example.org/icon.png",
                        "versionCode": 10,
                        "sources": [
                            {
                                "sourceId": 999111222,
                                "name": "Unverified Slug Source",
                                "lang": "es",
                                "baseUrl": "https://unverifiedslug.example",
                            }
                        ],
                    }
                ],
            )
            lookup = sync_catalog.build_upstream_lookup(
                [("keiyoushi/extensions-source", sync_catalog.decode_index_pb(pb_data))],
                langs="es",
                repo_dirs={},
            )
            rec, msg = sync_catalog.generate_recipe_from_slug(
                "unverifiedslug",
                recipes_dir=os.path.join(tmpdir, "recipes"),
                upstream_lookup=lookup,
                repo_dirs={},
            )
            self.assertIsNone(rec)
            self.assertIn("SKIP_UNVERIFIED_LICENSE", msg)

    def test_sync_preserves_manual_selectors_updates_domain_and_writes_v2_bundle_and_notice(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recipes_dir = os.path.join(tmpdir, "recipes")
            os.makedirs(recipes_dir)
            index_path = os.path.join(tmpdir, "index.json")
            notice_path = os.path.join(tmpdir, "NOTICE")
            repo_dir = os.path.join(tmpdir, "keiyoushi_repo")

            _init_local_git_repo(
                repo_dir,
                license_text="Apache License\nVersion 2.0, January 2004\nCopyright 2026 Tachiyomi Contributors\n",
                files={
                    "src/es/ikigaimangas/build.gradle.kts": (
                        'name = "Ikigai Mangas"\n'
                        'theme = "madara"\n'
                        'versionCode = 45\n'
                        'lang = "es"\n'
                        'baseUrl = "https://new-ikigai.example"\n'
                    ),
                    "src/es/ikigaimangas/src/Ikigai.kt": 'class Ikigai : HttpSource()',
                },
            )

            manual_selectors = {
                "listSelector": "section.custom-grid article",
                "titleSelector": "h2.custom-title",
                "linkSelector": "a.custom-link",
            }
            manual_steps = [
                {"op": "referer_bind", "refererUrl": "https://old-ikigai.example/"},
                {"op": "trim_normalize", "collapseWhitespace": True},
            ]
            recipe_file = os.path.join(recipes_dir, "ikigai_mangas.json")
            with open(recipe_file, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "schemaVersion": 2,
                        "sourceId": "ikigai_mangas",
                        "name": "Ikigai Mangas",
                        "baseUrl": "https://old-ikigai.example",
                        "lang": "es",
                        "version": 1,
                        "versionId": 1,
                        "preset": "CSS_GENERIC",
                        "status": "ACTIVE",
                        "maxHtmlBytes": 2097152,
                        "recipePath": "recipes/ikigai_mangas.json",
                        "mode": "declarative",
                        "headers": {"Referer": "https://old-ikigai.example/"},
                        "selectors": manual_selectors,
                        "pipelineSteps": manual_steps,
                        "upstreamSourceId": 3546919326830738510,
                        "upstreamSourceIds": [3546919326830738510],
                        "license": "Apache-2.0",
                        "attribution": "The Tachiyomi / Keiyoushi Contributors",
                    },
                    f,
                )

            pb_data = build_synthetic_index_pb(
                "keiyoushi/extensions-source",
                [
                    {
                        "name": "Ikigai Mangas",
                        "pkgName": "eu.kanade.tachiyomi.extension.es.ikigaimangas",
                        "iconUrl": "https://cdn.jsdelivr.net/gh/keiyoushi/extensions-source@main/src/es/ikigaimangas/res/ic.png",
                        "versionCode": 45,
                        "sources": [
                            {
                                "sourceId": 3546919326830738510,
                                "name": "Ikigai Mangas",
                                "lang": "es",
                                "baseUrl": "https://new-ikigai.example",
                            }
                        ],
                    }
                ],
            )
            pb_path = os.path.join(tmpdir, "index.pb")
            with open(pb_path, "wb") as f:
                f.write(pb_data)

            rc = sync_catalog.main(
                [
                    "--recipes-dir",
                    recipes_dir,
                    "--index-out",
                    index_path,
                    "--notice-out",
                    notice_path,
                    "--index-pb",
                    pb_path,
                    "--local-repo",
                    f"keiyoushi/extensions-source={repo_dir}",
                    "--apply",
                    "--force-upstream-url",
                ]
            )
            self.assertEqual(rc, 0)

            with open(recipe_file, "r", encoding="utf-8") as f:
                updated = json.load(f)
            self.assertEqual(updated["baseUrl"], "https://new-ikigai.example")
            self.assertEqual(updated["version"], 2)
            self.assertEqual(updated["versionCode"], 45)
            # Manual selectors and custom pipeline preserved
            self.assertEqual(updated["selectors"], manual_selectors)
            self.assertEqual(len(updated["pipelineSteps"]), 2)
            self.assertEqual(updated["pipelineSteps"][0]["refererUrl"], "https://new-ikigai.example/")
            self.assertTrue(validate_recipe(updated, base_dir=tmpdir, expected_filename="ikigai_mangas.json")[0])

            with open(index_path, "r", encoding="utf-8") as f:
                bundle = json.load(f)
            self.assertEqual(bundle["schemaVersion"], 2)
            self.assertNotIn("recipes", bundle)
            self.assertEqual(len(bundle["entries"]), 1)
            self.assertEqual(bundle["entries"][0]["recipePath"], "recipes/ikigai_mangas.json")
            self.assertTrue(validate_bundle(bundle, base_dir=tmpdir)[0])

            with open(notice_path, "r", encoding="utf-8") as f:
                notice_text = f.read()
            self.assertIn("keiyoushi/extensions-source", notice_text)
            self.assertIn("ikigai_mangas", notice_text)

    def test_decode_index_pb_converts_negative_64bit_signed_source_id(self):
        pb_bytes = build_synthetic_index_pb(
            "SampleRepo",
            [
                {
                    "name": "Signed Source",
                    "pkgName": "eu.kanade.tachiyomi.extension.es.signedsrc",
                    "iconUrl": "",
                    "versionCode": 3,
                    "sources": [
                        {
                            "sourceId": -3546919326830738510,
                            "name": "Negative Signed",
                            "lang": "es",
                            "baseUrl": "https://neg.example",
                        },
                        {
                            "sourceId": -(1 << 63),
                            "name": "Min Int64",
                            "lang": "es",
                            "baseUrl": "https://minint64.example",
                        },
                        {
                            "sourceId": 3546919326830738510,
                            "name": "Positive Signed",
                            "lang": "es",
                            "baseUrl": "https://pos.example",
                        },
                    ],
                }
            ],
        )
        decoded = sync_catalog.decode_index_pb(pb_bytes)
        ids = [s["sourceId"] for s in decoded["extensions"][0]["sources"]]
        self.assertEqual(ids, [-3546919326830738510, -(1 << 63), 3546919326830738510])

    def test_partial_upstream_resilience_continues_on_single_failure_and_fails_if_all_fail(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recipes_dir = os.path.join(tmpdir, "recipes")
            os.makedirs(recipes_dir)
            index_path = os.path.join(tmpdir, "index.json")
            notice_path = os.path.join(tmpdir, "NOTICE")
            healthy_repo = os.path.join(tmpdir, "healthy_origin")

            _init_local_git_repo(
                healthy_repo,
                license_text="Apache License\nVersion 2.0, January 2004\nCopyright 2026 Healthy Contributors\n",
                files={
                    "src/es/healthysource/build.gradle.kts": (
                        'name = "Healthy Source"\n'
                        'theme = "madara"\n'
                        'versionCode = 10\n'
                        'lang = "es"\n'
                        'baseUrl = "https://healthy-new.example"\n'
                    ),
                    "src/es/healthysource/src/Healthy.kt": "class Healthy : HttpSource()",
                },
            )

            recipe_file = os.path.join(recipes_dir, "es.healthysource.json")
            with open(recipe_file, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "schemaVersion": 2,
                        "sourceId": "es.healthysource",
                        "name": "Healthy Source",
                        "baseUrl": "https://healthy-old.example",
                        "lang": "es",
                        "version": 1,
                        "versionId": 1,
                        "preset": "MADARA",
                        "status": "ACTIVE",
                        "maxHtmlBytes": 2097152,
                        "recipePath": "recipes/es.healthysource.json",
                        "mode": "declarative",
                        "selectors": {
                            "listSelector": "div.page-item-detail",
                            "titleSelector": "h3.h5 a",
                            "linkSelector": "h3.h5 a",
                        },
                        "pipelineSteps": [{"op": "referer_bind", "refererUrl": "https://healthy-old.example/"}],
                        "upstreamSourceId": 777001,
                        "upstreamSourceIds": [777001],
                        "license": "Apache-2.0",
                        "attribution": "The Tachiyomi / Keiyoushi Contributors",
                    },
                    f,
                )

            healthy_pb = build_synthetic_index_pb(
                "keiyoushi/extensions-source",
                [
                    {
                        "name": "Healthy Source",
                        "pkgName": "eu.kanade.tachiyomi.extension.es.healthysource",
                        "iconUrl": "https://cdn.jsdelivr.net/gh/keiyoushi/extensions-source@main/src/es/healthysource/res/ic.png",
                        "versionCode": 10,
                        "sources": [
                            {
                                "sourceId": 777001,
                                "name": "Healthy Source",
                                "lang": "es",
                                "baseUrl": "https://healthy-new.example",
                            }
                        ],
                    }
                ],
            )

            broken_git_url = os.path.join(tmpdir, "does_not_exist.git")
            upstreams_partial = [
                {
                    "name": "broken",
                    "repo_slug": "FelipeGFA/fonte-extensoes",
                    "git_url": broken_git_url,
                    "index_pb_url": "https://broken.invalid/index.pb",
                    "priority": 1,
                    "default_attribution": "Broken Contributors",
                },
                {
                    "name": "healthy",
                    "repo_slug": "keiyoushi/extensions-source",
                    "git_url": healthy_repo,
                    "index_pb_url": "https://healthy.invalid/index.pb",
                    "priority": 2,
                    "default_attribution": "The Tachiyomi / Keiyoushi Contributors",
                },
            ]

            def fake_fetch(url, timeout=15):
                if "broken.invalid" in url:
                    raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
                return healthy_pb

            out_partial = io.StringIO()
            with mock.patch.object(sync_catalog, "DEFAULT_UPSTREAMS", upstreams_partial), mock.patch.object(
                sync_catalog, "fetch_url_bytes", side_effect=fake_fetch
            ), contextlib.redirect_stdout(out_partial):
                rc = sync_catalog.main(
                    [
                        "--clone-upstreams",
                        "--recipes-dir",
                        recipes_dir,
                        "--index-out",
                        index_path,
                        "--notice-out",
                        notice_path,
                        "--apply",
                        "--force-upstream-url",
                    ]
                )

            self.assertEqual(rc, 0, out_partial.getvalue())
            self.assertIn("WARN:", out_partial.getvalue())
            self.assertIn("FelipeGFA/fonte-extensoes", out_partial.getvalue())
            with open(recipe_file, "r", encoding="utf-8") as f:
                updated = json.load(f)
            self.assertEqual(updated["baseUrl"], "https://healthy-new.example")
            self.assertEqual(updated["versionCode"], 10)

            # All upstreams fail to clone -> must fail cleanly with non-zero exit code
            upstreams_all_broken = [upstreams_partial[0]]
            out_all_clone_fail = io.StringIO()
            with mock.patch.object(sync_catalog, "DEFAULT_UPSTREAMS", upstreams_all_broken), mock.patch.object(
                sync_catalog, "fetch_url_bytes", side_effect=fake_fetch
            ), contextlib.redirect_stdout(out_all_clone_fail):
                rc_clone_fail = sync_catalog.main(
                    [
                        "--clone-upstreams",
                        "--recipes-dir",
                        recipes_dir,
                        "--index-out",
                        index_path,
                        "--notice-out",
                        notice_path,
                    ]
                )
            self.assertNotEqual(rc_clone_fail, 0)
            self.assertIn("ERROR:", out_all_clone_fail.getvalue())

            # All upstreams fail index.pb fetch -> must fail cleanly with non-zero exit code
            out_all_fetch_fail = io.StringIO()
            with mock.patch.object(sync_catalog, "DEFAULT_UPSTREAMS", upstreams_all_broken), mock.patch.object(
                sync_catalog, "fetch_url_bytes", side_effect=fake_fetch
            ), contextlib.redirect_stdout(out_all_fetch_fail):
                rc_fetch_fail = sync_catalog.main(
                    [
                        "--recipes-dir",
                        recipes_dir,
                        "--index-out",
                        index_path,
                        "--notice-out",
                        notice_path,
                    ]
                )
            self.assertNotEqual(rc_fetch_fail, 0)
            self.assertIn("ERROR:", out_all_fetch_fail.getvalue())

    def test_git_commit_timestamp_beats_repo_priority_and_cross_repo_fallback_recovers_live_failure(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            keiyoushi_origin = os.path.join(tmpdir, "keiyoushi_origin")
            felipe_origin = os.path.join(tmpdir, "felipe_origin")
            apache = "Apache License\nVersion 2.0, January 2004\nCopyright 2026 Upstream Contributors\n"

            # Keiyoushi is older (2026-08-01), but has a working live URL
            _init_local_git_repo(
                keiyoushi_origin,
                license_text=apache,
                commit_date="2026-08-01T12:00:00Z",
                files={
                    "src/es/dualscan/build.gradle.kts": (
                        'keiyoushi {\n'
                        '  name = "Dual Scan"\n'
                        '  theme = "madara"\n'
                        '  versionCode = 12\n'
                        '  contentWarning = ContentWarning.SAFE\n'
                        '  source {\n'
                        '    lang = "es"\n'
                        '    baseUrl { mirrors("https://alive-keiyoushi.example") }\n'
                        '  }\n'
                        '}\n'
                    ),
                    "src/es/dualscan/src/DualScan.kt": "class DualScan : Madara()",
                },
            )

            # FelipeGFA is newer (2026-10-15) even with lower repoPriority=1, so it MUST be tried first;
            # its URL will return 500 in live probe, triggering automatic fallback to Keiyoushi.
            _init_local_git_repo(
                felipe_origin,
                license_text=apache,
                commit_date="2026-10-15T12:00:00Z",
                files={
                    "src/es/dualscan/build.gradle.kts": (
                        'val mainHost = "https://dead-felipe.example"\n'
                        'keiyoushi {\n'
                        '  name = "Dual Scan"\n'
                        '  theme = "madara"\n'
                        '  versionCode = 12\n'
                        '  contentWarning = ContentWarning.MIXED\n'
                        '  source {\n'
                        '    lang = "es"\n'
                        '    baseUrl { mirrors(mainHost) }\n'
                        '  }\n'
                        '}\n'
                    ),
                    "src/es/dualscan/src/DualScan.kt": "class DualScan : Madara()",
                },
            )

            k_clone = os.path.join(tmpdir, "k_clone")
            f_clone = os.path.join(tmpdir, "f_clone")
            sync_catalog.clone_or_open_repo(keiyoushi_origin, k_clone)
            sync_catalog.clone_or_open_repo(felipe_origin, f_clone)

            sid_k = sync_catalog.compute_keiyoushi_source_id("Dual Scan", "es", 1)
            k_pb = sync_catalog.decode_index_pb(
                build_synthetic_index_pb(
                    "keiyoushi/extensions-source",
                    [
                        {
                            "name": "Dual Scan",
                            "pkgName": "eu.kanade.tachiyomi.extension.es.dualscan",
                            "iconUrl": "https://cdn.jsdelivr.net/gh/keiyoushi/extensions-source@main/src/es/dualscan/res/ic.png",
                            "versionCode": 12,
                            "contentWarning": 1,
                            "sources": [
                                {
                                    "sourceId": sid_k,
                                    "name": "Dual Scan",
                                    "lang": "es",
                                    "baseUrl": "https://alive-keiyoushi.example",
                                }
                            ],
                        }
                    ],
                )
            )
            f_pb = sync_catalog.decode_index_pb(
                build_synthetic_index_pb(
                    "FelipeGFA/fonte-extensoes",
                    [
                        {
                            "name": "Dual Scan",
                            "pkgName": "eu.kanade.tachiyomi.extension.es.dualscan",
                            "iconUrl": "https://cdn.jsdelivr.net/gh/FelipeGFA/fonte-extensoes@main/src/es/dualscan/res/ic.png",
                            "versionCode": 12,
                            "contentWarning": 2,
                            "sources": [
                                {
                                    "sourceId": sid_k,
                                    "name": "Dual Scan",
                                    "lang": "es",
                                    "baseUrl": "https://dead-felipe.example",
                                }
                            ],
                        }
                    ],
                )
            )

            catalog = sync_catalog.build_upstream_catalog(
                [("keiyoushi/extensions-source", k_pb), ("FelipeGFA/fonte-extensoes", f_pb)],
                langs="es",
                repo_dirs={
                    "keiyoushi/extensions-source": k_clone,
                    "FelipeGFA/fonte-extensoes": f_clone,
                },
            )
            self.assertEqual(len(catalog["candidates"]), 1)
            winner = catalog["candidates"][0]
            self.assertEqual(winner["upstreamRepo"], "FelipeGFA/fonte-extensoes")
            self.assertGreater(winner["lastCommitTs"], winner["alternatives"][0]["lastCommitTs"])
            self.assertEqual(winner["alternatives"][0]["upstreamRepo"], "keiyoushi/extensions-source")

            good_madara = (
                '<div class="page-item-detail"><h3 class="h5"><a href="/m/1">Uno</a></h3></div>'
                '<div class="page-item-detail"><h3 class="h5"><a href="/m/2">Dos</a></h3></div>'
                '<div class="page-item-detail"><h3 class="h5"><a href="/m/3">Tres</a></h3></div>'
            )
            call_order = []

            def fallback_fetcher(url, method="GET", headers=None, body=None):
                call_order.append(url)
                if "dead-felipe.example" in url:
                    return 500, "Server Error", "HTTP 500"
                return 200, good_madara, "HTTP 200"

            recipes_dir = os.path.join(tmpdir, "recipes")
            report_md = os.path.join(tmpdir, "report.md")
            summary = sync_catalog.sync_all_catalog(
                recipes_dir=recipes_dir,
                upstream_catalog=catalog,
                repo_dirs={
                    "keiyoushi/extensions-source": k_clone,
                    "FelipeGFA/fonte-extensoes": f_clone,
                },
                apply=True,
                probe_live=True,
                only_working=True,
                include_nsfw=False,
                langs="es",
                fetcher=fallback_fetcher,
                report_out=report_md,
            )
            self.assertTrue(any("dead-felipe.example" in u for u in call_order))
            self.assertTrue(any("alive-keiyoushi.example" in u for u in call_order))
            self.assertEqual(len(summary["activeRecipes"]), 1)
            self.assertEqual(summary["activeRecipes"][0]["baseUrl"], "https://alive-keiyoushi.example")
            self.assertEqual(summary["activeRecipes"][0]["upstreamRepo"], "keiyoushi/extensions-source")
            self.assertEqual(summary["reportData"]["counts"]["viableFallbackRepo"], 1)
            self.assertTrue(os.path.isfile(report_md))

    def test_nsfw_default_exclusion_and_bcp47_and_langs_all(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_dir = os.path.join(tmpdir, "repo")
            apache = "Apache License\nVersion 2.0, January 2004\nCopyright 2026 Contributors\n"
            _init_local_git_repo(
                repo_dir,
                license_text=apache,
                files={
                    "src/pt/ptbrscan/build.gradle.kts": (
                        'name = "PTBR Scan"\n'
                        'theme = "madara"\n'
                        'versionCode = 20\n'
                        'contentWarning = ContentWarning.SAFE\n'
                        'source { lang = "pt-BR"; baseUrl = "https://ptbrscan.example" }\n'
                    ),
                    "src/pt/ptbrscan/src/PtBr.kt": "class PtBr : Madara()",
                    "src/es/es419scan/build.gradle.kts": (
                        'name = "Latam Scan"\n'
                        'theme = "mangathemesia"\n'
                        'versionCode = 21\n'
                        'contentWarning = ContentWarning.MIXED\n'
                        'source { lang = "es-419"; baseUrl = "https://es419scan.example" }\n'
                    ),
                    "src/es/es419scan/src/Es419.kt": "class Es419 : MangaThemesia()",
                    "src/es/nsfwgradle/build.gradle.kts": (
                        'name = "NSFW Gradle"\n'
                        'theme = "madara"\n'
                        'versionCode = 22\n'
                        'isNsfw = true\n'
                        'source { lang = "es"; baseUrl = "https://nsfwgradle.example" }\n'
                    ),
                    "src/es/nsfwgradle/src/NsfwG.kt": "class NsfwG : Madara()",
                    "src/fr/frscan/build.gradle.kts": (
                        'name = "FR Scan"\n'
                        'theme = "madara"\n'
                        'versionCode = 23\n'
                        'contentWarning = ContentWarning.SAFE\n'
                        'source { lang = "fr"; baseUrl = "https://frscan.example" }\n'
                    ),
                    "src/fr/frscan/src/FrScan.kt": "class FrScan : Madara()",
                    "src/all/multiscan/build.gradle.kts": (
                        'name = "Multi Scan"\n'
                        'theme = "madara"\n'
                        'versionCode = 24\n'
                        'contentWarning = ContentWarning.NSFW\n'
                        'source { lang = "all"; baseUrl = "https://multiscan.example" }\n'
                    ),
                    "src/all/multiscan/src/MultiScan.kt": "class MultiScan : Madara() { override val nsfw = true }",
                },
            )

            pb = sync_catalog.decode_index_pb(
                build_synthetic_index_pb(
                    "keiyoushi/extensions-source",
                    [
                        {
                            "name": "PTBR Scan",
                            "pkgName": "eu.kanade.tachiyomi.extension.pt.ptbrscan",
                            "iconUrl": "https://cdn.jsdelivr.net/gh/keiyoushi/extensions-source@main/src/pt/ptbrscan/res/ic.png",
                            "versionCode": 20,
                            "contentWarning": 1,
                            "sources": [{"sourceId": 101, "name": "PTBR Scan", "lang": "pt-BR", "baseUrl": "https://ptbrscan.example"}],
                        },
                        {
                            "name": "Latam Scan",
                            "pkgName": "eu.kanade.tachiyomi.extension.es.es419scan",
                            "iconUrl": "https://cdn.jsdelivr.net/gh/keiyoushi/extensions-source@main/src/es/es419scan/res/ic.png",
                            "versionCode": 21,
                            "contentWarning": 2,
                            "sources": [{"sourceId": 102, "name": "Latam Scan", "lang": "es-419", "baseUrl": "https://es419scan.example"}],
                        },
                        {
                            "name": "NSFW Pb",
                            "pkgName": "eu.kanade.tachiyomi.extension.es.nsfwpb",
                            "iconUrl": "https://cdn.jsdelivr.net/gh/keiyoushi/extensions-source@main/src/es/nsfwgradle/res/ic.png",
                            "versionCode": 22,
                            "contentWarning": 3,
                            "sources": [{"sourceId": 103, "name": "NSFW Pb", "lang": "es", "baseUrl": "https://nsfwpb.example"}],
                        },
                        {
                            "name": "FR Scan",
                            "pkgName": "eu.kanade.tachiyomi.extension.fr.frscan",
                            "iconUrl": "https://cdn.jsdelivr.net/gh/keiyoushi/extensions-source@main/src/fr/frscan/res/ic.png",
                            "versionCode": 23,
                            "contentWarning": 1,
                            "sources": [{"sourceId": 104, "name": "FR Scan", "lang": "fr", "baseUrl": "https://frscan.example"}],
                        },
                        {
                            "name": "Multi Scan",
                            "pkgName": "eu.kanade.tachiyomi.extension.all.multiscan",
                            "iconUrl": "https://cdn.jsdelivr.net/gh/keiyoushi/extensions-source@main/src/all/multiscan/res/ic.png",
                            "versionCode": 24,
                            "contentWarning": 3,
                            "sources": [{"sourceId": 105, "name": "Multi Scan", "lang": "all", "baseUrl": "https://multiscan.example"}],
                        },
                    ],
                )
            )

            # With langs="es,en,pt": pt-BR & es-419 included, fr & all excluded; NSFW excluded by default
            cat_es_en_pt = sync_catalog.build_upstream_catalog(
                [("keiyoushi/extensions-source", pb)],
                langs="es,en,pt",
                repo_dirs={"keiyoushi/extensions-source": repo_dir},
            )
            langs_found = {c["lang"] for c in cat_es_en_pt["candidates"]}
            self.assertEqual(langs_found, {"pt-BR", "es-419", "es"})

            good_html = (
                '<div class="page-item-detail"><h3 class="h5"><a href="/m/1">A</a></h3></div>'
                '<div class="page-item-detail"><h3 class="h5"><a href="/m/2">B</a></h3></div>'
                '<div class="page-item-detail"><h3 class="h5"><a href="/m/3">C</a></h3></div>'
                '<div class="listupd"><div class="bsx"><a href="/m/1"><div class="tt">A</div></a></div>'
                '<div class="bsx"><a href="/m/2"><div class="tt">B</div></a></div>'
                '<div class="bsx"><a href="/m/3"><div class="tt">C</div></a></div></div>'
            )

            res_no_nsfw = sync_catalog.sync_all_catalog(
                recipes_dir=os.path.join(tmpdir, "rec1"),
                upstream_catalog=cat_es_en_pt,
                repo_dirs={"keiyoushi/extensions-source": repo_dir},
                apply=True,
                probe_live=True,
                include_nsfw=False,
                langs="es,en,pt",
                fetcher=lambda _u: (200, good_html, "HTTP 200"),
            )
            self.assertEqual(len(res_no_nsfw["activeRecipes"]), 2)  # pt-BR + es-419 (MIXED kept)
            self.assertEqual(res_no_nsfw["reportData"]["counts"]["excludedNsfw"], 1)

            # With langs="all" and include_nsfw=True: fr and all are also processed
            cat_all = sync_catalog.build_upstream_catalog(
                [("keiyoushi/extensions-source", pb)],
                langs="all",
                repo_dirs={"keiyoushi/extensions-source": repo_dir},
            )
            self.assertEqual({c["lang"] for c in cat_all["candidates"]}, {"pt-BR", "es-419", "es", "fr", "all"})
            res_all_nsfw = sync_catalog.sync_all_catalog(
                recipes_dir=os.path.join(tmpdir, "rec2"),
                upstream_catalog=cat_all,
                repo_dirs={"keiyoushi/extensions-source": repo_dir},
                apply=True,
                probe_live=True,
                include_nsfw=True,
                langs="all",
                fetcher=lambda _u: (200, good_html, "HTTP 200"),
            )
            self.assertEqual(len(res_all_nsfw["activeRecipes"]), 5)
            self.assertEqual(res_all_nsfw["reportData"]["counts"]["excludedNsfw"], 0)

    def test_redirect_auto_adoption_and_failed_redirect_and_ssrf_rejection(self):
        recipe = sync_catalog.build_recipe_dict(
            source_id="es.redirectdemo",
            name="Redirect Demo",
            base_url="https://old-domain.example",
            preset="MADARA",
            lang="es",
            catalog_path="/manga",
        )
        good_html = (
            '<div class="page-item-detail"><h3 class="h5"><a href="/m/1">One</a></h3></div>'
            '<div class="page-item-detail"><h3 class="h5"><a href="/m/2">Two</a></h3></div>'
            '<div class="page-item-detail"><h3 class="h5"><a href="/m/3">Three</a></h3></div>'
        )

        # 1. Valid domain redirect passing smoke test on destination -> auto-adopt!
        def redirect_ok_fetcher(url, method="GET", headers=None, body=None):
            if "old-domain.example" in url:
                return 200, "<html>redirected</html>", "HTTP 200", "https://new-domain.example/"
            self.assertEqual(headers.get("Referer"), "https://new-domain.example/")
            return 200, good_html, "HTTP 200", "https://new-domain.example/manga"

        ok, cnt, msg, updates, details = sync_catalog.run_http_smoke_test(
            recipe,
            fetcher=redirect_ok_fetcher,
            return_details=True,
        )
        self.assertTrue(ok, msg)
        self.assertEqual(cnt, 3)
        self.assertEqual(updates["baseUrl"], "https://new-domain.example")
        self.assertEqual(updates["headers"]["Referer"], "https://new-domain.example/")
        self.assertEqual(updates["pipelineSteps"][0]["refererUrl"], "https://new-domain.example/")
        self.assertIn("https://old-domain.example", updates["mirrors"])
        self.assertIn("https://new-domain.example", updates["mirrors"])
        self.assertTrue(details["domainAdopted"])

        # 2. Domain redirect failing smoke test on destination (404 / CF) -> DOMAIN_CHANGE_FAILED
        def redirect_fail_fetcher(url, method="GET", headers=None, body=None):
            if "old-domain.example" in url:
                return 200, "", "HTTP 200", "https://broken-new.example/"
            return 404, "Not Found", "HTTP 404", "https://broken-new.example/manga"

        ok_f, _, msg_f, upd_f, det_f = sync_catalog.run_http_smoke_test(
            recipe,
            fetcher=redirect_fail_fetcher,
            return_details=True,
        )
        self.assertFalse(ok_f)
        self.assertIn("DOMAIN_CHANGE_FAILED", msg_f)
        self.assertEqual(det_f["category"], "DOMAIN_CHANGE_FAILED")
        self.assertNotIn("baseUrl", upd_f)

        # 3. Redirect to private/localhost IP -> SSRF rejected
        def redirect_ssrf_fetcher(url, method="GET", headers=None, body=None):
            return 200, "", "HTTP 200", "https://127.0.0.1/admin"

        ok_s, _, msg_s, _, det_s = sync_catalog.run_http_smoke_test(
            recipe,
            fetcher=redirect_ssrf_fetcher,
            return_details=True,
        )
        self.assertFalse(ok_s)
        self.assertEqual(det_s["category"], "DOMAIN_CHANGE_FAILED")
        self.assertIn("SSRF", msg_s)

    def test_diagnostic_classifier_separates_waf_vs_down_vs_primitives_and_smoke_v2_engines(self):
        # HTTP 525 or 404 with server: cloudflare MUST NOT be classified as WAF anti-bot
        waf_525, _ = sync_catalog.detect_waf_block(525, headers={"server": "cloudflare"}, body="SSL handshake failed")
        self.assertFalse(waf_525)
        waf_404, _ = sync_catalog.detect_waf_block(404, headers={"server": "cloudflare"}, body="404 Not Found")
        self.assertFalse(waf_404)
        waf_real, reason_real = sync_catalog.detect_waf_block(
            403,
            headers={"server": "cloudflare", "cf-mitigated": "challenge"},
            body="<html><title>Just a moment...</title></html>",
        )
        self.assertTrue(waf_real)
        self.assertIn("cf-mitigated", reason_real)

        # Verify INERTIA_SSR + popularRequest on CSS_GENERIC + querySigner sbox_xor_cbc
        inertia_recipe = {
            "sourceId": "es.inertiatest",
            "name": "Inertia Test",
            "baseUrl": "https://inertia.example",
            "preset": "CSS_GENERIC",
            "family": "INERTIA_SSR",
            "popularRequest": {"method": "GET", "firstPagePathTemplate": "/manga/?order=vistas"},
            "inertia": {
                "scriptSelector": "script[data-page]",
                "seriesListPath": "$.props.series[*]",
            },
            "selectors": {"listSelector": "div.unused"},
        }
        reqs = sync_catalog.build_smoke_requests(inertia_recipe)
        self.assertEqual(reqs[0][0], "https://inertia.example/manga/?order=vistas")
        inertia_html = (
            '<html><script data-page="app" type="application/json">'
            '{"props":{"series":[{"title":"One","slug":"one"},{"title":"Two","slug":"two"},{"title":"Three","slug":"three"}]}}'
            '</script></html>'
        )
        items = sync_catalog.extract_items_for_smoke(inertia_recipe, inertia_html)
        self.assertEqual(len(items), 3)

        # Simulation of environment without BeautifulSoup (CI test parity)
        orig_bs4 = sync_catalog.BeautifulSoup
        try:
            sync_catalog.BeautifulSoup = None
            items_no_bs4 = sync_catalog.extract_items_for_smoke(inertia_recipe, inertia_html)
            self.assertEqual(len(items_no_bs4), 3)

            # Test when JSON is embedded directly in data-page attribute
            inertia_html_attr = (
                '<div id="app" data-page=\'{"props":{"series":[{"title":"A"},{"title":"B"},{"title":"C"}]}}\'></div>'
            )
            items_attr = sync_catalog.extract_items_for_smoke(inertia_recipe, inertia_html_attr)
            self.assertEqual(len(items_attr), 3)
        finally:
            sync_catalog.BeautifulSoup = orig_bs4

        # Verify querySigner parity (sbox_xor_cbc) adds vrf param
        with open(os.path.join(os.path.dirname(__file__), "..", "recipes", "es.mangafire.json"), "r", encoding="utf-8") as f:
            mf_recipe = json.load(f)
        mf_reqs = sync_catalog.build_smoke_requests(mf_recipe)
        self.assertIn("&vrf=", mf_reqs[0][0])

        # Verify R2 diagnostic report counts & prioritized Kotlin primitives
        records = [
            {"sourceId": "es.ok", "name": "Ok", "lang": "es", "upstreamRepo": "keiyoushi/extensions-source", "baseUrl": "https://ok.example", "category": "VIABLE"},
            {"sourceId": "es.redir", "name": "Redir", "lang": "es", "upstreamRepo": "keiyoushi/extensions-source", "baseUrl": "https://new.example", "category": "VIABLE", "domainAdopted": True, "redirectedFrom": "https://old.example", "redirectedTo": "https://new.example"},
            {"sourceId": "es.cf", "name": "CF", "lang": "es", "upstreamRepo": "keiyoushi/extensions-source", "baseUrl": "https://cf.example", "category": "CLOUDFLARE_ANTIBOT", "detail": "HTTP 403 (just a moment)"},
            {"sourceId": "es.down", "name": "Down525", "lang": "es", "upstreamRepo": "keiyoushi/extensions-source", "baseUrl": "https://down.example", "category": "DOWN_OR_NONEXISTENT", "subReason": "CLOUDFLARE_ORIGIN_HTTP_525", "detail": "HTTP 525"},
            {"sourceId": "es.qjs1", "name": "Qjs1", "lang": "es", "upstreamRepo": "keiyoushi/extensions-source", "baseUrl": "https://q1.example", "category": "NEEDS_PRIMITIVE", "primaryCapability": "JS_RUNTIME_QUICKJS", "allCapabilities": ["JS_RUNTIME_QUICKJS", "CUSTOM_THEME_ADAPTER:keyoapp"]},
            {"sourceId": "es.qjs2", "name": "Qjs2", "lang": "en", "upstreamRepo": "keiyoushi/extensions-source", "baseUrl": "https://q2.example", "category": "NEEDS_PRIMITIVE", "primaryCapability": "JS_RUNTIME_QUICKJS", "allCapabilities": ["JS_RUNTIME_QUICKJS"]},
            {"sourceId": "es.lic", "name": "Lic", "lang": "es", "upstreamRepo": "keiyoushi/extensions-source", "baseUrl": "https://lic.example", "category": "REJECTED_LICENSE", "detail": "REJECTED_NON_OSI"},
            {"sourceId": "es.nsfw", "name": "Nsfw", "lang": "es", "upstreamRepo": "keiyoushi/extensions-source", "baseUrl": "https://nsfw.example", "category": "EXCLUDED_NSFW", "detail": "ContentWarning.NSFW"},
        ]
        md = sync_catalog.build_diagnostic_report_markdown(records, {"langs": "es,en,pt", "onlyWorking": True, "upstreams": ["keiyoushi/extensions-source"]})
        self.assertIn("Viables / recreadas automáticamente", md)
        self.assertIn("Bloqueadas por Cloudflare / anti-bot", md)
        self.assertIn("Caídas o inexistentes", md)
        self.assertIn("Cambio de dominio", md)
        self.assertIn("Requieren capacidades o métricas especiales del motor", md)
        self.assertIn("Descartadas por licencia", md)
        self.assertIn("Excluidas por filtro NSFW (18+)", md)
        self.assertIn("Recomendación Priorizada de Primitivas Kotlin", md)
        self.assertIn("JS_RUNTIME_QUICKJS", md)

    def test_apache2_license_boilerplate_does_not_overwrite_fallback_attribution(self):
        full_apache2_license = (
            "                                 Apache License\n"
            "                           Version 2.0, January 2004\n"
            "                        http://www.apache.org/licenses/\n\n"
            "   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION\n\n"
            '   1. Definitions.\n\n'
            '      "Work" shall mean the work of authorship, whether in Source or\n'
            "      Object form, made available under the License, as indicated by a\n"
            "      copyright notice that is included in or attached to the work\n"
            "      (an example is provided in the Appendix below).\n\n"
            "   4. Redistribution. You may reproduce and distribute copies of the\n"
            "      Work or Derivative Works thereof in any medium, with or without\n"
            "      modifications, and in Source or Object form, provided that You\n"
            "      meet the following conditions:\n\n"
            "      (a) You must give any other recipients of the Work or\n"
            "          Derivative Works a copy of this License; and\n\n"
            "      (b) You must cause any modified files to carry prominent notices\n"
            "          stating that You changed the files; and\n\n"
            "      (c) You must retain, in the Source form of any Derivative Works\n"
            "          that You distribute, all copyright, patent, trademark, and\n"
            "          attribution notices from the Source form of the Work,\n"
            "          excluding those notices that do not pertain to any part of\n"
            "          the Derivative Works; and\n\n"
            '      (d) If the Work includes a "NOTICE" text file as part of its\n'
            "          distribution, then any Derivative Works that You distribute must\n"
            "          include a readable copy of the attribution notices contained\n"
            "          within such NOTICE file...\n\n"
            "   APPENDIX: How to apply the Apache License to your work.\n\n"
            "      Copyright [yyyy] [name of copyright owner]\n"
        )
        real_license_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "LICENSE"))
        with open(real_license_path, "r", encoding="utf-8") as lf:
            real_apache2_license = lf.read()

        self.assertEqual(
            sync_catalog._extract_copyright_attribution(
                [real_apache2_license], fallback="The Tachiyomi / Keiyoushi Contributors"
            ),
            "The Tachiyomi / Keiyoushi Contributors",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            repo_dir = os.path.join(tmpdir, "repo_apache_full")
            os.makedirs(repo_dir, exist_ok=True)
            with open(os.path.join(repo_dir, "LICENSE"), "w", encoding="utf-8") as f:
                f.write(full_apache2_license + "\n" + real_apache2_license)

            ok, spdx, attr = sync_catalog.verify_repo_license(
                repo_dir,
                gradle_text='name = "Demo"\n',
                kotlin_texts=['package demo\nclass Demo : Madara()\n'],
                fallback_attribution="The Tachiyomi / Keiyoushi Contributors",
            )
            self.assertTrue(ok)
            self.assertEqual(spdx, "Apache-2.0")
            self.assertEqual(attr, "The Tachiyomi / Keiyoushi Contributors")
            self.assertNotIn("notice that is included", attr.lower())
            self.assertNotIn("you must retain", attr.lower())
            self.assertNotIn("derivative works", attr.lower())

            notice_path = os.path.join(tmpdir, "NOTICE")
            sync_catalog.write_notice(
                notice_path,
                [
                    {
                        "sourceId": "es.demo",
                        "upstreamRepo": "keiyoushi/extensions-source",
                        "license": spdx,
                        "attribution": attr,
                    }
                ],
            )
            with open(notice_path, "r", encoding="utf-8") as f:
                notice_txt = f.read()
            self.assertIn("Attribution: The Tachiyomi / Keiyoushi Contributors", notice_txt)
            self.assertNotIn("notice that is included", notice_txt.lower())
            self.assertNotIn("you must retain", notice_txt.lower())
            self.assertNotIn("derivative works", notice_txt.lower())

    def test_mit_and_bsd_license_boilerplate_and_precedence(self):
        mit_template = (
            "MIT License\n\n"
            "Copyright (c) <year> <copyright holders>\n"
            "Copyright (c) [year] [fullname]\n\n"
            "Permission is hereby granted, free of charge, to any person obtaining a copy\n"
            "of this software and associated documentation files...\n"
            "The above copyright notice and this permission notice shall be included in all\n"
            "copies or substantial portions of the Software.\n"
            'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.\n'
        )
        bsd_template = (
            "BSD 3-Clause License\n\n"
            "Copyright (c) <year>, <owner>\n"
            "1. Redistributions of source code must retain the above copyright notice.\n"
            "2. Redistributions in binary form must reproduce the above copyright notice.\n"
            "3. Neither the name of the copyright holder nor the names of its contributors...\n"
        )
        self.assertEqual(
            sync_catalog._extract_copyright_attribution([mit_template], fallback="FALLBACK"),
            "FALLBACK",
        )
        self.assertEqual(
            sync_catalog._extract_copyright_attribution([bsd_template], fallback="FALLBACK"),
            "FALLBACK",
        )
        self.assertEqual(
            sync_catalog._extract_copyright_attribution(
                ["Copyright (c) 2024, Acme BSD Contributors\nRedistribution and use in source and binary forms"],
                fallback="FALLBACK",
            ),
            "Acme BSD Contributors",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            repo_mit_tmpl = os.path.join(tmpdir, "repo_mit_tmpl")
            os.makedirs(repo_mit_tmpl, exist_ok=True)
            with open(os.path.join(repo_mit_tmpl, "LICENSE"), "w", encoding="utf-8") as f:
                f.write(mit_template)
            ok, spdx, attr = sync_catalog.verify_repo_license(
                repo_mit_tmpl,
                gradle_text='name = "Demo"\n',
                kotlin_texts=['package demo\nclass Demo : Madara()\n'],
                fallback_attribution="Fallback MIT Org",
            )
            self.assertEqual((ok, spdx, attr), (True, "MIT", "Fallback MIT Org"))

            # Precedence: header_texts > license_texts > fallback
            repo_prec = os.path.join(tmpdir, "repo_prec")
            os.makedirs(repo_prec, exist_ok=True)
            with open(os.path.join(repo_prec, "LICENSE"), "w", encoding="utf-8") as f:
                f.write("MIT License\n\nCopyright (c) 2023 License File Author\n" + mit_template)
            ok_h, spdx_h, attr_h = sync_catalog.verify_repo_license(
                repo_prec,
                gradle_text='// Copyright (c) 2025 Header Author\nname = "Demo"\n',
                kotlin_texts=['package demo\nclass Demo : Madara()\n'],
                fallback_attribution="Fallback MIT Org",
            )
            self.assertEqual((ok_h, spdx_h, attr_h), (True, "MIT", "Header Author"))

            ok_l, spdx_l, attr_l = sync_catalog.verify_repo_license(
                repo_prec,
                gradle_text='name = "Demo"\n',
                kotlin_texts=['package demo\nclass Demo : Madara()\n'],
                fallback_attribution="Fallback MIT Org",
            )
            self.assertEqual((ok_l, spdx_l, attr_l), (True, "MIT", "License File Author"))

    def test_dual_repo_both_fail_preserves_primary_diagnosis_and_metadata(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            keiyoushi_origin = os.path.join(tmpdir, "k_origin")
            felipe_origin = os.path.join(tmpdir, "f_origin")
            apache = "Apache License\nVersion 2.0, January 2004\n"

            # Newer primary in Keiyoushi (2026-10-20) -> fails in live with CLOUDFLARE_ANTIBOT
            _init_local_git_repo(
                keiyoushi_origin,
                license_text=apache,
                commit_date="2026-10-20T12:00:00Z",
                files={
                    "src/es/cfboth/build.gradle.kts": (
                        'name = "CF Both"\n'
                        'theme = "madara"\n'
                        'versionCode = 20\n'
                        'source { lang = "es"; baseUrl = "https://primary-cf.example" }\n'
                    ),
                    "src/es/cfboth/src/CfBoth.kt": "class CfBoth : Madara()",
                },
            )
            # Older fallback in FelipeGFA (2026-06-01) -> fails in live with DNS_ERROR
            _init_local_git_repo(
                felipe_origin,
                license_text=apache,
                commit_date="2026-06-01T12:00:00Z",
                files={
                    "src/es/cfboth/build.gradle.kts": (
                        'name = "CF Both"\n'
                        'theme = "madara"\n'
                        'versionCode = 10\n'
                        'source { lang = "es"; baseUrl = "https://old-dead.example" }\n'
                    ),
                    "src/es/cfboth/src/CfBoth.kt": "class CfBoth : Madara()",
                },
            )

            k_clone = os.path.join(tmpdir, "k_clone")
            f_clone = os.path.join(tmpdir, "f_clone")
            sync_catalog.clone_or_open_repo(keiyoushi_origin, k_clone)
            sync_catalog.clone_or_open_repo(felipe_origin, f_clone)

            sid = sync_catalog.compute_keiyoushi_source_id("CF Both", "es", 1)
            k_pb = sync_catalog.decode_index_pb(
                build_synthetic_index_pb(
                    "keiyoushi/extensions-source",
                    [
                        {
                            "name": "CF Both",
                            "pkgName": "eu.kanade.tachiyomi.extension.es.cfboth",
                            "iconUrl": "https://cdn.jsdelivr.net/gh/keiyoushi/extensions-source@main/src/es/cfboth/res/ic.png",
                            "versionCode": 20,
                            "contentWarning": 1,
                            "sources": [{"sourceId": sid, "name": "CF Both", "lang": "es", "baseUrl": "https://primary-cf.example"}],
                        }
                    ],
                )
            )
            f_pb = sync_catalog.decode_index_pb(
                build_synthetic_index_pb(
                    "FelipeGFA/fonte-extensoes",
                    [
                        {
                            "name": "CF Both",
                            "pkgName": "eu.kanade.tachiyomi.extension.es.cfboth",
                            "iconUrl": "https://cdn.jsdelivr.net/gh/FelipeGFA/fonte-extensoes@main/src/es/cfboth/res/ic.png",
                            "versionCode": 10,
                            "contentWarning": 1,
                            "sources": [{"sourceId": sid, "name": "CF Both", "lang": "es", "baseUrl": "https://old-dead.example"}],
                        }
                    ],
                )
            )
            catalog = sync_catalog.build_upstream_catalog(
                [("keiyoushi/extensions-source", k_pb), ("FelipeGFA/fonte-extensoes", f_pb)],
                langs="es",
                repo_dirs={
                    "keiyoushi/extensions-source": k_clone,
                    "FelipeGFA/fonte-extensoes": f_clone,
                },
            )

            def both_fail_fetcher(url, method="GET", headers=None, body=None):
                if "primary-cf.example" in url:
                    return 403, "<html><title>Just a moment...</title></html>", "HTTP 403", url, {"cf-mitigated": "challenge"}
                raise urllib.error.URLError("getaddrinfo failed")

            summary = sync_catalog.sync_all_catalog(
                recipes_dir=os.path.join(tmpdir, "recipes"),
                upstream_catalog=catalog,
                repo_dirs={
                    "keiyoushi/extensions-source": k_clone,
                    "FelipeGFA/fonte-extensoes": f_clone,
                },
                apply=True,
                probe_live=True,
                only_working=True,
                langs="es",
                fetcher=both_fail_fetcher,
            )
            counts = summary["reportData"]["counts"]
            self.assertEqual(counts["viable"], 0)
            self.assertEqual(counts["cloudflareAntibot"], 1)
            self.assertEqual(counts["downOrNonexistent"], 0)
            cf_recs = summary["reportData"]["categories"]["cloudflareAntibot"]
            self.assertEqual(len(cf_recs), 1)
            self.assertEqual(cf_recs[0]["upstreamRepo"], "keiyoushi/extensions-source")
            self.assertEqual(cf_recs[0]["baseUrl"], "https://primary-cf.example")
            self.assertTrue(cf_recs[0].get("fallbackAttempted"))

    def test_kotlin_dsl_interpolation_and_concatenation_in_build_gradle(self):
        gradle_text = (
            'val sub = "multi-one"\n'
            'private val baseDomain = "https://" + sub + ".example"\n'
            'val domain = "dollar.example"\n'
            'val path = "manga"\n'
            'val host = "concat.example"\n'
            'val chained = "https://$domain/$path"\n'
            'extension {\n'
            '  name = "DSL Demo"\n'
            '  theme = "madara"\n'
            '  source {\n'
            '    lang = "es"\n'
            '    baseUrl {\n'
            '      mirrors("https://$domain", "https://${domain}/alt", baseDomain)\n'
            '    }\n'
            '  }\n'
            '  source {\n'
            '    lang = "en"\n'
            '    baseUrl = "https://$domain/$path"\n'
            '  }\n'
            '  source {\n'
            '    lang = "pt"\n'
            '    baseUrl {\n'
            '      custom("https://${domain}/pt")\n'
            '    }\n'
            '  }\n'
            '  source {\n'
            '    lang = "es-419"\n'
            '    baseUrl {\n'
            '      mirrors("https://" + host, chained)\n'
            '    }\n'
            '  }\n'
            '}\n'
        )
        parsed = sync_catalog.parse_extension_build_gradle(gradle_text)
        self.assertEqual(len(parsed["sources"]), 4)
        self.assertEqual(parsed["sources"][0]["baseUrl"], "https://dollar.example")
        self.assertEqual(
            parsed["sources"][0]["mirrors"],
            ["https://dollar.example", "https://dollar.example/alt", "https://multi-one.example"],
        )
        self.assertEqual(parsed["sources"][1]["baseUrl"], "https://dollar.example/manga")
        self.assertEqual(parsed["sources"][2]["baseUrl"], "https://dollar.example/pt")
        self.assertEqual(parsed["sources"][3]["baseUrl"], "https://concat.example")
        self.assertEqual(
            parsed["sources"][3]["mirrors"],
            ["https://concat.example", "https://dollar.example/manga"],
        )

        # Also test top-level custom(...) without source {} block
        gradle_no_source = (
            'val host = "top.example"\n'
            'name = "Top Custom"\n'
            'lang = "es"\n'
            'custom("https://" + host + "/reader")\n'
        )
        parsed_top = sync_catalog.parse_extension_build_gradle(gradle_no_source)
        self.assertEqual(parsed_top["baseUrl"], "https://top.example/reader")
        self.assertEqual(parsed_top["mirrors"], ["https://top.example/reader"])

    def test_supported_theme_insufficient_items_isolates_kt_theme(self):
        shared_madara_kt = (
            "abstract class Madara { "
            "val aes = Cipher.getInstance(\"AES/GCM\"); "
            "val dto = Json.decodeFromString<String>(body); "
            "}"
        )
        # Supported theme (madara) failing with INSUFFICIENT_ITEMS must inspect only kt_own, not kt_theme
        prim, all_caps, _ = sync_catalog.classify_missing_primitives(
            theme="madara",
            kotlin_text="class MyScan : Madara()",
            theme_kotlin_text=shared_madara_kt,
            http_status=200,
            html_sample="<html><body><div>empty</div></body></html>",
        )
        self.assertEqual(prim, "CUSTOM_HTML_SELECTOR_OR_PARSER")
        self.assertEqual(all_caps, ["CUSTOM_HTML_SELECTOR_OR_PARSER"])
        self.assertNotIn("DYNAMIC_CRYPTO_OR_KEY", all_caps)
        self.assertNotIn("JSON_API_OR_GRAPHQL", all_caps)

        # Unmapped theme (keyoapp) MUST still inspect theme_kotlin_text
        prim_u, all_u, _ = sync_catalog.classify_missing_primitives(
            theme="keyoapp",
            kotlin_text="class MyKeyo : Keyoapp()",
            theme_kotlin_text="abstract class Keyoapp { val qjs = QuickJs.create() }",
            http_status=200,
            html_sample="<html><body><div>ok</div></body></html>",
        )
        self.assertEqual(prim_u, "JS_RUNTIME_QUICKJS")
        self.assertIn("CUSTOM_THEME_ADAPTER:keyoapp", all_u)

    def test_sync_all_prepopulates_used_source_ids_and_isolates_worker_exceptions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recipes_dir = os.path.join(tmpdir, "recipes")
            os.makedirs(recipes_dir, exist_ok=True)
            existing = sync_catalog.build_recipe_dict(
                source_id="es.collision",
                name="Original Existing",
                base_url="https://existing-original.example",
                preset="MADARA",
                lang="es",
                upstream_source_id=9001,
                upstream_repo="keiyoushi/extensions-source",
                status="ACTIVE",
            )
            with open(os.path.join(recipes_dir, "es.collision.json"), "w", encoding="utf-8") as f:
                json.dump(existing, f)

            repo_dir = os.path.join(tmpdir, "repo")
            _init_local_git_repo(
                repo_dir,
                license_text="Apache License\nVersion 2.0, January 2004\n",
                files={
                    "src/es/collision/build.gradle.kts": (
                        'name = "Brand New Unrelated"\n'
                        'theme = "madara"\n'
                        'versionCode = 5\n'
                        'source { lang = "es"; baseUrl = "https://unrelated.example" }\n'
                    ),
                    "src/es/collision/src/Unrelated.kt": "class Unrelated : Madara()",
                },
            )
            pb = sync_catalog.decode_index_pb(
                build_synthetic_index_pb(
                    "keiyoushi/extensions-source",
                    [
                        {
                            "name": "Brand New Unrelated",
                            "pkgName": "eu.kanade.tachiyomi.extension.es.collision",
                            "iconUrl": "https://cdn.jsdelivr.net/gh/keiyoushi/extensions-source@main/src/es/collision/res/ic.png",
                            "versionCode": 5,
                            "contentWarning": 1,
                            "sources": [{"sourceId": 9999, "name": "Brand New Unrelated", "lang": "es", "baseUrl": "https://unrelated.example"}],
                        }
                    ],
                )
            )
            catalog = sync_catalog.build_upstream_catalog(
                [("keiyoushi/extensions-source", pb)],
                langs="es",
                repo_dirs={"keiyoushi/extensions-source": repo_dir},
            )
            good_html = (
                '<div class="page-item-detail"><h3 class="h5"><a href="/m/1">A</a></h3></div>'
                '<div class="page-item-detail"><h3 class="h5"><a href="/m/2">B</a></h3></div>'
                '<div class="page-item-detail"><h3 class="h5"><a href="/m/3">C</a></h3></div>'
            )

            def flaky_fetcher(url, method="GET", headers=None, body=None):
                if "unrelated.example" in url:
                    raise ValueError("Simulated malformed URL exception")
                return 200, good_html, "HTTP 200"

            summary = sync_catalog.sync_all_catalog(
                recipes_dir=recipes_dir,
                upstream_catalog=catalog,
                repo_dirs={"keiyoushi/extensions-source": repo_dir},
                apply=True,
                probe_live=True,
                only_working=True,
                langs="es",
                fetcher=flaky_fetcher,
            )
            # Original orphan survived AND new unrelated candidate did not hijack "es.collision"
            self.assertEqual([r["sourceId"] for r in summary["activeRecipes"]], ["es.collision"])
            self.assertEqual(summary["activeRecipes"][0]["name"], "Original Existing")
            down_recs = summary["reportData"]["categories"]["downOrNonexistent"]
            self.assertEqual(len(down_recs), 1)
            self.assertNotEqual(down_recs[0]["sourceId"], "es.collision")

    def test_extract_copyright_attribution_handles_symbol_c_and_block_comment_close(self):
        self.assertEqual(
            sync_catalog._extract_copyright_attribution(["// © 2025 Bar\npackage x"], fallback="FALLBACK"),
            "Bar",
        )
        self.assertEqual(
            sync_catalog._extract_copyright_attribution(["/* Copyright (c) 2024 Foo */"], fallback="FALLBACK"),
            "Foo",
        )
        self.assertEqual(
            sync_catalog._extract_copyright_attribution(["// (c) 2024 Baz"], fallback="FALLBACK"),
            "Baz",
        )
        self.assertEqual(
            sync_catalog._extract_copyright_attribution(["/* © 2025 Quux */"], fallback="FALLBACK"),
            "Quux",
        )
        self.assertEqual(
            sync_catalog._extract_copyright_attribution(["(c) 2023 Qux"], fallback="FALLBACK"),
            "Qux",
        )
        self.assertEqual(
            sync_catalog._extract_copyright_attribution(["(C) 2023 Qux"], fallback="FALLBACK"),
            "Qux",
        )
        self.assertEqual(
            sync_catalog._extract_copyright_attribution(["// Copyright (c) 2024 7Seas Scans"], fallback="FALLBACK"),
            "7Seas Scans",
        )
        self.assertEqual(
            sync_catalog._extract_copyright_attribution(["/* Copyright 2024-present Acme Org */"], fallback="FALLBACK"),
            "Acme Org",
        )
        self.assertEqual(
            sync_catalog._extract_copyright_attribution(
                ["/* Copyright (c) 2024–present, 1999 Comics */"], fallback="FALLBACK"
            ),
            "1999 Comics",
        )
        self.assertEqual(
            sync_catalog._extract_copyright_attribution(["/* © 2024-present 99 Manga */"], fallback="FALLBACK"),
            "99 Manga",
        )
        self.assertEqual(
            sync_catalog._extract_copyright_attribution(["// Copyright 2020-2025 3B Studios"], fallback="FALLBACK"),
            "3B Studios",
        )
        self.assertEqual(
            sync_catalog._extract_copyright_attribution(["// © 2025", "// © copyright holder"], fallback="FALLBACK"),
            "FALLBACK",
        )
        self.assertEqual(
            sync_catalog._extract_copyright_attribution(
                [
                    "      (c) You must retain, in the Source form of any Derivative Works",
                    "(c) all copyright notices must be kept",
                    "// Copyright (c) 2024-present",
                    "// Copyright (c) 2024 [Your Name]",
                ],
                fallback="FALLBACK",
            ),
            "FALLBACK",
        )

    def test_dual_repo_primary_rejected_license_and_secondary_404_preserves_primary_diagnosis(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            keiyoushi_origin = os.path.join(tmpdir, "k_origin")
            felipe_origin = os.path.join(tmpdir, "f_origin")
            gpl = "GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n"
            apache = "Apache License\nVersion 2.0, January 2004\nCopyright 2026 Contributors\n"

            _init_local_git_repo(
                keiyoushi_origin,
                license_text=gpl,
                commit_date="2026-10-20T12:00:00Z",
                files={
                    "src/es/duallic/build.gradle.kts": (
                        'name = "Dual Lic"\n'
                        'theme = "madara"\n'
                        'versionCode = 20\n'
                        'source { lang = "es"; baseUrl = "https://primary-gpl.example" }\n'
                    ),
                    "src/es/duallic/src/DualLic.kt": "class DualLic : Madara()",
                },
            )
            _init_local_git_repo(
                felipe_origin,
                license_text=apache,
                commit_date="2026-06-01T12:00:00Z",
                files={
                    "src/es/duallic/build.gradle.kts": (
                        'name = "Dual Lic"\n'
                        'theme = "madara"\n'
                        'versionCode = 10\n'
                        'source { lang = "es"; baseUrl = "https://secondary-404.example" }\n'
                    ),
                    "src/es/duallic/src/DualLic.kt": "class DualLic : Madara()",
                },
            )

            k_clone = os.path.join(tmpdir, "k_clone")
            f_clone = os.path.join(tmpdir, "f_clone")
            sync_catalog.clone_or_open_repo(keiyoushi_origin, k_clone)
            sync_catalog.clone_or_open_repo(felipe_origin, f_clone)

            sid = sync_catalog.compute_keiyoushi_source_id("Dual Lic", "es", 1)
            k_pb = sync_catalog.decode_index_pb(
                build_synthetic_index_pb(
                    "keiyoushi/extensions-source",
                    [
                        {
                            "name": "Dual Lic",
                            "pkgName": "eu.kanade.tachiyomi.extension.es.duallic",
                            "iconUrl": "https://cdn.jsdelivr.net/gh/keiyoushi/extensions-source@main/src/es/duallic/res/ic.png",
                            "versionCode": 20,
                            "contentWarning": 1,
                            "sources": [{"sourceId": sid, "name": "Dual Lic", "lang": "es", "baseUrl": "https://primary-gpl.example"}],
                        }
                    ],
                )
            )
            f_pb = sync_catalog.decode_index_pb(
                build_synthetic_index_pb(
                    "FelipeGFA/fonte-extensoes",
                    [
                        {
                            "name": "Dual Lic",
                            "pkgName": "eu.kanade.tachiyomi.extension.es.duallic",
                            "iconUrl": "https://cdn.jsdelivr.net/gh/FelipeGFA/fonte-extensoes@main/src/es/duallic/res/ic.png",
                            "versionCode": 10,
                            "contentWarning": 1,
                            "sources": [{"sourceId": sid, "name": "Dual Lic", "lang": "es", "baseUrl": "https://secondary-404.example"}],
                        }
                    ],
                )
            )
            catalog = sync_catalog.build_upstream_catalog(
                [("keiyoushi/extensions-source", k_pb), ("FelipeGFA/fonte-extensoes", f_pb)],
                langs="es",
                repo_dirs={
                    "keiyoushi/extensions-source": k_clone,
                    "FelipeGFA/fonte-extensoes": f_clone,
                },
            )

            summary = sync_catalog.sync_all_catalog(
                recipes_dir=os.path.join(tmpdir, "recipes"),
                upstream_catalog=catalog,
                repo_dirs={
                    "keiyoushi/extensions-source": k_clone,
                    "FelipeGFA/fonte-extensoes": f_clone,
                },
                apply=True,
                probe_live=True,
                only_working=True,
                langs="es",
                fetcher=lambda _u, **_kw: (404, "Not Found", "HTTP 404"),
            )
            counts = summary["reportData"]["counts"]
            self.assertEqual(counts["rejectedLicense"], 1)
            self.assertEqual(counts["downOrNonexistent"], 0)
            lic_recs = summary["reportData"]["categories"]["rejectedLicense"]
            self.assertEqual(len(lic_recs), 1)
            self.assertEqual(lic_recs[0]["category"], "REJECTED_LICENSE")
            self.assertEqual(lic_recs[0]["upstreamRepo"], "keiyoushi/extensions-source")
            self.assertEqual(lic_recs[0]["baseUrl"], "https://primary-gpl.example")
            self.assertTrue(lic_recs[0].get("fallbackAttempted"))
            self.assertTrue(any("404" in msg for msg in lic_recs[0].get("fallbackFailures", [])))

    def test_allocate_source_id_exhausted_collisions_returns_unique_id(self):
        used = {"es.dup", "es.dup_dup", "es.dup_v1", "es.dup_1"}
        initial_used = set(used)
        cand = {
            "lang": "es",
            "name": "Dup",
            "sourceId": 100001,
            "versionId": 1,
            "openSource": ("keiyoushi/extensions-source", "src/es/dup", "src/es/dup", "dup"),
        }
        first_alloc = sync_catalog._allocate_source_id(cand, used)
        self.assertNotIn(first_alloc, initial_used)
        self.assertIn(first_alloc, used)

        second_alloc = sync_catalog._allocate_source_id(cand, used)
        self.assertNotEqual(second_alloc, first_alloc)
        self.assertNotIn(second_alloc, initial_used)
        self.assertIn(second_alloc, used)

    def test_probe_http_meta_refresh_and_js_redirects_with_ssrf_checks(self):
        # 1 hop meta refresh
        def fake_fetcher_meta(url, **kw):
            if url == "https://initial.example/catalog":
                body = '<html><head><meta http-equiv="refresh" content="0; url=/target-catalog"></head><body>Redirecting</body></html>'
                return 200, body, "OK"
            elif url == "https://initial.example/target-catalog":
                body = "<div>" + "".join(f'<div class="manga-item"><a href="/m/{i}">Manga {i}</a></div>' for i in range(5)) + "</div>"
                return 200, body, "OK"
            return 404, "Not Found", "Not Found"

        res = sync_catalog.probe_http_sample_detailed("https://initial.example/catalog", fetcher=fake_fetcher_meta)
        self.assertEqual(res["status_code"], 200)
        self.assertEqual(res["final_url"], "https://initial.example/target-catalog")
        self.assertEqual(len(res["redirect_chain"]), 1)

        # JS redirect to evil SSRF host must abort redirect loop and retain safe URL
        def fake_fetcher_evil_ssrf(url, **kw):
            if url == "https://initial.example/catalog":
                body = '<script>window.location.replace("https://127.0.0.1/admin");</script>'
                return 200, body, "OK"
            return 200, "Should not reach", "OK"

        res_evil = sync_catalog.probe_http_sample_detailed("https://initial.example/catalog", fetcher=fake_fetcher_evil_ssrf)
        self.assertNotEqual(res_evil["final_url"], "https://127.0.0.1/admin")
        self.assertEqual(res_evil.get("error_type"), "SSRF_REDIRECT_REJECTED")

    def test_http_smoke_test_mirror_fallback(self):
        recipe = {
            "sourceId": "es.mirror_test",
            "name": "Mirror Test",
            "lang": "es",
            "baseUrl": "https://broken-primary.example",
            "mirrors": ["https://working-mirror.example"],
            "preset": "MADARA",
            "selectors": {
                "listSelector": "div.manga-item",
                "titleSelector": "h3 a",
                "linkSelector": "h3 a",
            },
        }

        def fake_fetcher_mirrors(url, **kw):
            if "broken-primary.example" in url:
                return 503, "Service Unavailable", "HTTP 503"
            if "working-mirror.example" in url:
                items_html = "".join(f'<div class="manga-item"><h3><a href="/m/{i}">Manga {i}</a></h3></div>' for i in range(5))
                return 200, f"<html><body>{items_html}</body></html>", "OK"
            return 404, "Not Found", "HTTP 404"

        ok, cnt, msg, upd, det = sync_catalog.run_http_smoke_test(recipe, fetcher=fake_fetcher_mirrors, return_details=True)
        self.assertTrue(ok)
        self.assertGreaterEqual(cnt, 3)
        self.assertEqual(upd.get("baseUrl"), "https://working-mirror.example")
        self.assertTrue(det.get("domainAdopted"))

    def test_include_cloudflare_antibot_marked_active_with_bypass(self):
        recipe = {
            "sourceId": "es.cf_source",
            "name": "CF Source",
            "lang": "es",
            "baseUrl": "https://cf-protected.example",
            "preset": "MADARA",
            "selectors": {
                "listSelector": "div.manga-item",
                "titleSelector": "h3 a",
                "linkSelector": "h3 a",
            },
        }

        cf_html = "<html><title>Just a moment...</title><body>Checking your browser before accessing cf-protected.example...</body></html>"

        def fake_fetcher_cf(url, **kw):
            return 403, cf_html, "HTTP 403 Forbidden"

        # Without include_cloudflare: must fail
        ok_no_cf, _, msg_no_cf, _, det_no_cf = sync_catalog.run_http_smoke_test(
            recipe, fetcher=fake_fetcher_cf, return_details=True, include_cloudflare=False
        )
        self.assertFalse(ok_no_cf)
        self.assertEqual(det_no_cf.get("category"), "CLOUDFLARE_ANTIBOT")

        # With include_cloudflare: must succeed as active with requiresCloudflareBypass=True (and never webview capture)
        ok_cf, cnt_cf, msg_cf, upd_cf, det_cf = sync_catalog.run_http_smoke_test(
            recipe, fetcher=fake_fetcher_cf, return_details=True, include_cloudflare=True
        )
        self.assertTrue(ok_cf)
        self.assertTrue(det_cf.get("requiresCloudflareBypass"))
        self.assertFalse(upd_cf.get("requiresWebViewCapture", False))
        self.assertFalse(det_cf.get("requiresWebViewCapture", False))

    def test_new_multisrc_themes_detection(self):
        # 1. zeistmanga preset -> JSON_API
        zeist_cand = {
            "name": "Zeist Manga Source",
            "lang": "en",
            "sourceId": 80001,
            "baseUrl": "https://zeist.example",
            "upstreamRepo": "keiyoushi/extensions-source",
            "openSource": ("keiyoushi/extensions-source", "src/en/zeist", "src/en/zeist", "zeist"),
        }
        recipe_z, _, kind_z, _ = sync_catalog._build_candidate_recipe_for_attempt(
            zeist_cand,
            source_id="en.zeist",
            repo_dirs={},
            gradle_theme="zeistmanga",
        )
        self.assertEqual(kind_z, "DECLARATIVE")
        self.assertEqual(recipe_z["preset"], "JSON_API")
        self.assertEqual(recipe_z["jsonApi"]["apiBaseUrl"], "https://zeist.example")
        self.assertIn("feeds/posts/default", recipe_z["jsonApi"]["popularRequest"]["pathTemplate"])

        # 2. foolslide preset -> CSS_GENERIC with extended selectors
        fool_cand = {
            "name": "Foolslide Source",
            "lang": "es",
            "sourceId": 80002,
            "baseUrl": "https://fool.example",
            "upstreamRepo": "keiyoushi/extensions-source",
            "openSource": ("keiyoushi/extensions-source", "src/es/fool", "src/es/fool", "fool"),
        }
        recipe_f, _, kind_f, _ = sync_catalog._build_candidate_recipe_for_attempt(
            fool_cand,
            source_id="es.fool",
            repo_dirs={},
            gradle_theme="foolslide",
        )
        self.assertEqual(kind_f, "DECLARATIVE")
        self.assertEqual(recipe_f["preset"], "CSS_GENERIC")
        self.assertIn("detailsTitleSelector", recipe_f["selectors"])

        # 3. iken with crypto -> NEEDS_PRIMITIVE
        with tempfile.TemporaryDirectory() as tmp_repo:
            with open(os.path.join(tmp_repo, "LICENSE"), "w", encoding="utf-8") as f:
                f.write("Apache License\nVersion 2.0\nCopyright 2026 Upstream Contributors\n")
            kt_dir = os.path.join(tmp_repo, "src", "en", "ikencrypto")
            src_sub = os.path.join(kt_dir, "src")
            os.makedirs(src_sub, exist_ok=True)
            with open(os.path.join(src_sub, "IkenCrypto.kt"), "w", encoding="utf-8") as f:
                f.write('class IkenCrypto : Iken("Iken Crypto", baseUrl) {\n  val cipher = javax.crypto.Cipher.getInstance("AES")\n}\n')
            with open(os.path.join(kt_dir, "build.gradle.kts"), "w", encoding="utf-8") as f:
                f.write('theme = "iken"\n')

            iken_cand = {
                "name": "Iken Crypto",
                "lang": "en",
                "sourceId": 80003,
                "baseUrl": "https://iken.example",
                "upstreamRepo": "keiyoushi/extensions-source",
                "openSource": ("keiyoushi/extensions-source", "src/en/ikencrypto", "src/en/ikencrypto", "ikencrypto"),
            }
            recipe_i, _, kind_i, err_i = sync_catalog._build_candidate_recipe_for_attempt(
                iken_cand,
                source_id="en.ikencrypto",
                repo_dirs={"keiyoushi/extensions-source": tmp_repo},
                gradle_theme="iken",
            )
            self.assertEqual(kind_i, "STATIC_NEEDS_PRIMITIVE")
            self.assertTrue(any(tok in err_i for tok in ("CRYPTO", "Cipher", "AES")))

    def test_extra_themes_mappers_and_auth_preflight(self):
        from catalog_mappers_extra import (
            detect_and_build_auth_preflight,
            apply_extra_theme_to_recipe,
        )

        # 1. guya theme
        guya_cand = {
            "name": "Guya Source",
            "lang": "en",
            "sourceId": 90001,
            "baseUrl": "https://guya.moe",
            "upstreamRepo": "keiyoushi/extensions-source",
            "openSource": ("keiyoushi/extensions-source", "src/en/guya", "src/en/guya", "guya"),
        }
        recipe_g, _, kind_g, _ = sync_catalog._build_candidate_recipe_for_attempt(
            guya_cand,
            source_id="en.guya",
            repo_dirs={},
            gradle_theme="guya",
        )
        self.assertEqual(kind_g, "DECLARATIVE")
        self.assertEqual(recipe_g["preset"], "JSON_API")
        self.assertEqual(recipe_g["catalogPath"], "/api/get_all_series/")

        # 2. mangahub GraphQL theme
        mhub_cand = {
            "name": "MangaHub Source",
            "lang": "en",
            "sourceId": 90002,
            "baseUrl": "https://mangahub.io",
            "upstreamRepo": "keiyoushi/extensions-source",
            "openSource": ("keiyoushi/extensions-source", "src/en/mangahub", "src/en/mangahub", "mangahub"),
        }
        recipe_m, _, kind_m, _ = sync_catalog._build_candidate_recipe_for_attempt(
            mhub_cand,
            source_id="en.mangahub",
            repo_dirs={},
            gradle_theme="mangahub",
        )
        self.assertEqual(kind_m, "DECLARATIVE")
        self.assertEqual(recipe_m["preset"], "JSON_API")
        self.assertIn("graphqlQuery", recipe_m["jsonApi"]["popularRequest"])

        # 3. yiimanga CSS theme
        yii_cand = {
            "name": "Yii Source",
            "lang": "es",
            "sourceId": 90003,
            "baseUrl": "https://yiimanga.example",
            "upstreamRepo": "keiyoushi/extensions-source",
            "openSource": ("keiyoushi/extensions-source", "src/es/yiimanga", "src/es/yiimanga", "yiimanga"),
        }
        recipe_y, _, kind_y, _ = sync_catalog._build_candidate_recipe_for_attempt(
            yii_cand,
            source_id="es.yiimanga",
            repo_dirs={},
            gradle_theme="yiimanga",
        )
        self.assertEqual(kind_y, "DECLARATIVE")
        self.assertEqual(recipe_y["preset"], "CSS_GENERIC")
        self.assertIn("detailsTitleSelector", recipe_y["selectors"])

        # 4. detect_and_build_auth_preflight
        kt_csrf = 'val token = doc.select("meta[name=csrf-token]").attr("content")'
        preflight_csrf = detect_and_build_auth_preflight(kt_csrf, "https://example.org")
        self.assertIsNotNone(preflight_csrf)
        self.assertEqual(preflight_csrf["targetHeader"], "X-CSRF-TOKEN")
        self.assertEqual(preflight_csrf["method"], "GET")

        kt_bearer = 'POST to "https://example.org/api/auth/token"'
        preflight_bearer = detect_and_build_auth_preflight(kt_bearer, "https://example.org")
        self.assertIsNotNone(preflight_bearer)
        self.assertEqual(preflight_bearer["targetHeader"], "Authorization")
        self.assertEqual(preflight_bearer["extractMode"], "JSON_PATH")

    def test_multisrc_themes_mappers_and_account_sync_preservation(self):
        from catalog_mappers_multisrc import (
            SUPPORTED_MULTISRC_THEMES,
            apply_multisrc_theme_to_recipe,
        )

        self.assertIn("mangabox", SUPPORTED_MULTISRC_THEMES)
        self.assertIn("mangadventure", SUPPORTED_MULTISRC_THEMES)

        # 1. mangabox
        mb_cand = {
            "name": "MangaBox Test",
            "lang": "en",
            "sourceId": 80001,
            "baseUrl": "https://manganato.example",
            "upstreamRepo": "keiyoushi/extensions-source",
            "openSource": ("keiyoushi/extensions-source", "src/en/mangabox", "src/en/mangabox", "mangabox"),
        }
        recipe_mb, _, kind_mb, _ = sync_catalog._build_candidate_recipe_for_attempt(
            mb_cand,
            source_id="en.mangabox",
            repo_dirs={},
            gradle_theme="mangabox",
        )
        self.assertEqual(kind_mb, "DECLARATIVE")
        self.assertEqual(recipe_mb["preset"], "CSS_GENERIC")
        self.assertIn("chapterDateSelector", recipe_mb["selectors"])
        self.assertEqual(recipe_mb["selectors"]["chapterDateFormat"], "MMM dd,yyyy")

        # 2. mangadventure
        ma_cand = {
            "name": "MangAdventure Test",
            "lang": "en",
            "sourceId": 80002,
            "baseUrl": "https://arc-relight.example",
            "upstreamRepo": "keiyoushi/extensions-source",
            "openSource": ("keiyoushi/extensions-source", "src/en/mangadventure", "src/en/mangadventure", "mangadventure"),
        }
        recipe_ma, _, kind_ma, _ = sync_catalog._build_candidate_recipe_for_attempt(
            ma_cand,
            source_id="en.mangadventure",
            repo_dirs={},
            gradle_theme="mangadventure",
        )
        self.assertEqual(kind_ma, "DECLARATIVE")
        self.assertEqual(recipe_ma["preset"], "JSON_API")
        self.assertIn("jsonApi", recipe_ma)
        self.assertIn("mangaList", recipe_ma["jsonApi"])

        # 3. accountSync preservation from existing recipe
        existing_with_sync = {
            "schemaVersion": 2,
            "sourceId": "es.apollcomics",
            "name": "ApollComics",
            "baseUrl": "https://apollcomics.example",
            "lang": "es",
            "version": 1,
            "preset": "CSS_GENERIC",
            "status": "ACTIVE",
            "maxHtmlBytes": 2097152,
            "recipePath": "recipes/es.apollcomics.json",
            "accountSync": {
                "loginUrl": "https://apollcomics.example/wp-login.php",
                "sections": [{"kind": "FAVORITES", "itemsSelector": "div.item", "urlSelector": "a"}],
            },
        }
        cand_sync = {
            "name": "ApollComics",
            "lang": "es",
            "sourceId": 80003,
            "baseUrl": "https://apollcomics.example",
            "upstreamRepo": "keiyoushi/extensions-source",
            "openSource": ("keiyoushi/extensions-source", "src/es/apollcomics", "src/es/apollcomics", "madara"),
        }
        recipe_synced, _, _, _ = sync_catalog._build_candidate_recipe_for_attempt(
            cand_sync,
            source_id="es.apollcomics",
            existing_recipe=existing_with_sync,
            repo_dirs={},
            gradle_theme="madara",
        )
        self.assertIsNotNone(recipe_synced.get("accountSync"))
        self.assertEqual(recipe_synced["accountSync"]["loginUrl"], "https://apollcomics.example/wp-login.php")

    def test_phase2_synthetic_primitives_and_rsc_packer_smoke_extraction(self):
        # 1. Iken with Next.js __next_f should synthesize quickjs_eval (NEXT_RSC) instead of blind STATIC_NEEDS_PRIMITIVE
        with tempfile.TemporaryDirectory() as tmp_repo:
            with open(os.path.join(tmp_repo, "LICENSE"), "w", encoding="utf-8") as f:
                f.write("Apache License\nVersion 2.0\nCopyright 2026 Upstream Contributors\n")
            kt_dir = os.path.join(tmp_repo, "src", "en", "ikenrsc")
            src_sub = os.path.join(kt_dir, "src")
            os.makedirs(src_sub, exist_ok=True)
            with open(os.path.join(src_sub, "IkenRsc.kt"), "w", encoding="utf-8") as f:
                f.write(
                    'class IkenRsc : Iken("Iken RSC", baseUrl) {\n'
                    '  val marker = "__next_f"\n'
                    '}\n'
                )
            with open(os.path.join(kt_dir, "build.gradle.kts"), "w", encoding="utf-8") as f:
                f.write('theme = "iken"\n')

            iken_rsc_cand = {
                "name": "Iken RSC",
                "lang": "en",
                "sourceId": 80100,
                "baseUrl": "https://ikenrsc.example",
                "upstreamRepo": "keiyoushi/extensions-source",
                "openSource": ("keiyoushi/extensions-source", "src/en/ikenrsc", "src/en/ikenrsc", "ikenrsc"),
            }
            rec_rsc, _, kind_rsc, err_rsc = sync_catalog._build_candidate_recipe_for_attempt(
                iken_rsc_cand,
                source_id="en.ikenrsc",
                repo_dirs={"keiyoushi/extensions-source": tmp_repo},
                gradle_theme="iken",
            )
            self.assertEqual(kind_rsc, "DECLARATIVE", err_rsc)
            self.assertEqual(rec_rsc["preset"], "JSON_API")
            self.assertTrue(any(s.get("op") == "quickjs_eval" and s.get("preset") == "NEXT_RSC" for s in rec_rsc["pipelineSteps"]))
            self.assertTrue(validate_recipe(rec_rsc, base_dir=os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))[0])

            # Smoke test on Next.js __next_f payload with real items succeeds as ACTIVE
            rsc_html = (
                '<html><script>self.__next_f.push([1,"1a:{\\"data\\":[{\\"title\\":\\"One\\",\\"slug\\":\\"one\\"},'
                '{\\"title\\":\\"Two\\",\\"slug\\":\\"two\\"},{\\"title\\":\\"Three\\",\\"slug\\":\\"three\\"}]}"])</script></html>'
            )
            ok_s, cnt_s, _, upd_s = sync_catalog.run_http_smoke_test(
                rec_rsc,
                fetcher=lambda _u: (200, rsc_html, "HTTP 200"),
                is_existing_active=False,
            )
            self.assertTrue(ok_s)
            self.assertGreaterEqual(cnt_s, 3)
            self.assertEqual(upd_s["status"], "ACTIVE")

        # 2. Smoke test on Dean Edwards eval(function(p,a,c,k...)) Packer payload extracts HTML/JSON items
        packer_recipe = {
            "sourceId": "es.packer_smoke",
            "name": "Packer Smoke",
            "baseUrl": "https://packer.example",
            "catalogPath": "/manga",
            "preset": "CSS_GENERIC",
            "selectors": {
                "listSelector": "div.manga-item",
                "titleSelector": "a",
                "linkSelector": "a",
            },
            "pipelineSteps": [{"op": "quickjs_eval", "preset": "PACKER"}],
        }
        packer_html = (
            "<script>eval(function(p,a,c,k,e,d){return p}"
            "('<0 1=\"2-3\"><4 5=\"/6/7\">8</4></0><0 1=\"2-3\"><4 5=\"/6/9\">a</4></0><0 1=\"2-3\"><4 5=\"/6/b\">c</4></0>',"
            "13,13,'div|class|manga|item|a|href|m|1|One|2|Two|3|Three'.split('|'),0,{}))</script>"
        )
        ok_p, cnt_p, _, upd_p = sync_catalog.run_http_smoke_test(
            packer_recipe,
            fetcher=lambda _u: (200, packer_html, "HTTP 200"),
            is_existing_active=False,
        )
        self.assertTrue(ok_p)
        self.assertEqual(cnt_p, 3)
        self.assertEqual(upd_p["status"], "ACTIVE")

        # 3. Recursive JSONPath ($..) and JMESPath ([]) parity in extract_json_path
        nested = json.dumps({"payload": {"nested": {"series": [{"title": "Alpha"}, {"title": "Beta"}, {"title": "Gamma"}]}}})
        self.assertEqual(len(sync_catalog.extract_json_path(nested, "$..series[*]")), 3)
        self.assertEqual(sync_catalog.extract_json_path(nested, "payload.nested.series[].title"), ["Alpha", "Beta", "Gamma"])

        # 4. QuerySigner HEADER mode in build_smoke_requests
        hdr_signed_recipe = {
            "sourceId": "es.hdr_sign",
            "name": "Header Signed",
            "baseUrl": "https://signed.example",
            "catalogPath": "/api/list?page=1",
            "preset": "CSS_GENERIC",
            "querySigner": {
                "algorithm": "hmac_sha1",
                "pathPrefix": "/api",
                "target": "HEADER",
                "headerName": "X-Signature",
                "timestampHeaderName": "X-Timestamp",
                "timestampFormat": "EPOCH_SECONDS",
                "hmacSecret": "secret123",
            },
        }
        reqs = sync_catalog.build_smoke_requests(hdr_signed_recipe)
        self.assertEqual(len(reqs), 1)
        self.assertIn("X-Signature", reqs[0][2])
        self.assertIn("X-Timestamp", reqs[0][2])
        self.assertNotIn("vrf=", reqs[0][0])

    def test_phase3_audit_gaps_iken_mangafire_danke_keyoapp_and_js_redirect_guard(self):
        from validate_catalog import extract_html_items, validate_recipe

        # 1. Iken JSON_API uses $.posts[*], postTitle, featuredImage, {slug}/{id}, /api/query, /api/post, /api/chapters, /api/chapter
        iken_cand = {
            "sourceId": 990001,
            "name": "Hive Scans Test",
            "lang": "en",
            "baseUrl": "https://hivescans.example",
            "upstreamRepo": "keiyoushi/extensions-source",
            "repoMeta": {
                "licenseOk": True,
                "license": "Apache-2.0",
                "attribution": "Test Contributors",
                "gradle": {"theme": "iken", "versionId": 1, "baseUrl": "https://hivescans.example", "mirrors": []},
                "kotlinText": "class SanaLike : Iken() { override val perPage = 30 }",
                "themeKotlinText": "abstract class Iken : KeiSource()",
                "gradleText": 'theme = "iken"',
            },
        }
        rec_iken, _, kind_iken, err_iken = sync_catalog._build_candidate_recipe_for_attempt(
            iken_cand,
            source_id="en.hivescans_test",
        )
        self.assertEqual(kind_iken, "DECLARATIVE", err_iken)
        self.assertEqual(rec_iken["preset"], "JSON_API")
        self.assertEqual(rec_iken["jsonApi"]["popularRequest"]["pathTemplate"], "/api/query?perPage=30&orderBy=totalViews&orderDirection=desc&page={page}")
        self.assertEqual(rec_iken["jsonApi"]["mangaList"]["itemsPath"], "$.posts[*]")
        self.assertEqual(rec_iken["jsonApi"]["mangaList"]["titlePaths"][0], "$.postTitle")
        self.assertEqual(rec_iken["jsonApi"]["mangaList"]["coverPaths"][0], "$.featuredImage")
        self.assertEqual(rec_iken["jsonApi"]["mangaList"]["urlTemplate"], "{slug}/{id}")
        self.assertEqual(rec_iken["jsonApi"]["details"]["rootPath"], "$.post")
        self.assertEqual(rec_iken["jsonApi"]["chapters"]["itemsPath"], "$.post.chapters[*]")
        self.assertEqual(rec_iken["jsonApi"]["pages"]["itemsPath"], "$.chapter.images[*]")
        iken_payload = json.dumps({"posts": [{"id": i, "slug": f"s-{i}", "postTitle": f"Post {i}", "featuredImage": f"https://img.example/{i}.png"} for i in range(1, 5)]})
        self.assertEqual(len(sync_catalog.extract_items_for_smoke(rec_iken, iken_payload)), 4)

        # 2. Multi-language dedicated inheritance for MangaFire (including pt-BR -> pt-br) and mismatched-domain rejection
        with tempfile.TemporaryDirectory() as tmpdir:
            es_mf = {
                "schemaVersion": 2,
                "sourceId": "es.mangafire",
                "name": "MangaFire",
                "baseUrl": "https://mangafire.to",
                "lang": "es",
                "version": 1,
                "versionId": 1,
                "preset": "JSON_API",
                "status": "ACTIVE",
                "maxHtmlBytes": 2097152,
                "recipePath": "recipes/es.mangafire.json",
                "license": "Apache-2.0",
                "attribution": "Test",
                "pkgName": "eu.kanade.tachiyomi.extension.all.mangafire",
                "upstreamSourceId": 8098539940032331958,
                "upstreamSourceIds": [8098539940032331958],
                "jsonApi": {
                    "langMap": {"es-419": "es-la", "pt-BR": "pt-br"},
                    "popularRequest": {"method": "GET", "pathTemplate": "/api/titles?languages[]={lang}&page={page}"},
                    "mangaList": {"itemsPath": "$.items[*]", "titlePaths": ["$.title"], "urlTemplate": "/title/{id}-{slug}"},
                },
                "querySigner": {"algorithm": "hmac_sha1", "pathPrefix": "/api", "hmacSecret": "abc"},
            }
            with open(os.path.join(tmpdir, "es.mangafire.json"), "w", encoding="utf-8") as mf:
                json.dump(es_mf, mf)

            for sid, lang_val, uid, expected_q_lang in [
                ("en.mangafire", "en", 990010, "en"),
                ("pt-br.mangafire", "pt-br", 990011, "pt-br"),
            ]:
                mf_cand = {
                    "sourceId": uid,
                    "name": "MangaFire",
                    "lang": lang_val,
                    "baseUrl": "https://mangafire.to",
                    "pkgName": "eu.kanade.tachiyomi.extension.all.mangafire",
                    "upstreamRepo": "keiyoushi/extensions-source",
                    "repoMeta": {
                        "licenseOk": True,
                        "license": "Apache-2.0",
                        "attribution": "Test",
                        "gradle": {"theme": None, "versionId": 1, "baseUrl": "https://mangafire.to", "mirrors": []},
                        "kotlinText": "class MangaFire : HttpSource() { /* MangaFire VRF */ }",
                        "themeKotlinText": "",
                    },
                }
                rec_mf, _, kind_mf, err_mf = sync_catalog._build_candidate_recipe_for_attempt(
                    mf_cand,
                    source_id=sid,
                    recipes_dir=tmpdir,
                )
                self.assertEqual(kind_mf, "DECLARATIVE", err_mf)
                self.assertEqual(rec_mf["sourceId"], sid)
                self.assertEqual(rec_mf["lang"], lang_val)
                self.assertEqual(rec_mf["upstreamSourceIds"], [uid])
                self.assertEqual(rec_mf["querySigner"]["algorithm"], "hmac_sha1")
                reqs_mf = sync_catalog.build_smoke_requests(rec_mf)
                self.assertIn(f"languages[]={expected_q_lang}", reqs_mf[0][0])

            # Mismatched pkg + domain must NOT inherit MangaFire recipe
            bogus_mf_cand = {
                "sourceId": 990012,
                "name": "MangaFire",
                "lang": "en",
                "baseUrl": "https://unrelated-fake-domain.example",
                "pkgName": "eu.kanade.tachiyomi.extension.en.other",
                "upstreamRepo": "keiyoushi/extensions-source",
                "repoMeta": {
                    "licenseOk": True,
                    "license": "Apache-2.0",
                    "attribution": "Test",
                    "gradle": {"theme": None, "versionId": 1, "baseUrl": "https://unrelated-fake-domain.example", "mirrors": []},
                    "kotlinText": "class MangaFire : HttpSource()",
                    "themeKotlinText": "",
                },
            }
            rec_bogus, _, kind_bogus, _ = sync_catalog._build_candidate_recipe_for_attempt(
                bogus_mf_cand,
                source_id="en.fake_mf",
                recipes_dir=tmpdir,
            )
            self.assertIsNone(rec_bogus)
            self.assertEqual(kind_bogus, "STATIC_NEEDS_PRIMITIVE")

        # 3. Guya / Danke raises maxHtmlBytes to 3 MiB and propagates max_bytes to probe_http_sample_detailed
        danke_cand = {
            "sourceId": 990020,
            "name": "Danke Test",
            "lang": "en",
            "baseUrl": "https://danke.example",
            "upstreamRepo": "keiyoushi/extensions-source",
            "repoMeta": {
                "licenseOk": True,
                "license": "Apache-2.0",
                "attribution": "Test",
                "gradle": {"theme": "guya", "versionId": 1, "baseUrl": "https://danke.example", "mirrors": []},
                "kotlinText": "class DankeTest : Guya()",
                "themeKotlinText": "",
            },
        }
        rec_danke, _, kind_danke, _ = sync_catalog._build_candidate_recipe_for_attempt(danke_cand, "en.danke_test")
        self.assertEqual(kind_danke, "DECLARATIVE")
        self.assertEqual(rec_danke["maxHtmlBytes"], 3145728)
        self.assertEqual(rec_danke["jsonApi"]["mangaList"]["titlePaths"], ["$.title", "$.slug"])
        seen_max_bytes = []

        def fake_probe(url, **kw):
            seen_max_bytes.append(kw.get("max_bytes"))
            payload = {f"Series {i}": {"slug": f"s-{i}", "cover": f"/c/{i}.png"} for i in range(4)}
            return {"status_code": 200, "body": json.dumps(payload), "message": "HTTP 200", "final_url": url, "headers": {}, "redirect_chain": [], "error_type": None}

        with mock.patch.object(sync_catalog, "probe_http_sample_detailed", side_effect=fake_probe):
            ok_d, cnt_d, _, _ = sync_catalog.run_http_smoke_test(rec_danke)
        self.assertTrue(ok_d)
        self.assertEqual(cnt_d, 4)
        self.assertEqual(seen_max_bytes, [3145728])

        # 4. Keyoapp v1/v2 selectors survive CSS_GENERIC defaults, a[title] fallback works, and JS search handlers don't trigger redirect
        k_v1_cand = {
            "sourceId": 990030,
            "name": "Keyo V1 Test",
            "lang": "en",
            "baseUrl": "https://keyov1.example",
            "upstreamRepo": "keiyoushi/extensions-source",
            "repoMeta": {
                "licenseOk": True,
                "license": "Apache-2.0",
                "attribution": "Test",
                "gradle": {"theme": "keyoapp", "versionId": 1, "baseUrl": "https://keyov1.example", "mirrors": []},
                "kotlinText": "class KewnLike : Keyoapp()",
                "themeKotlinText": "abstract class Keyoapp { fun parseGenres() { QuickJs.create() } }",
            },
        }
        rec_kv1, _, kind_kv1, _ = sync_catalog._build_candidate_recipe_for_attempt(k_v1_cand, "en.keyov1")
        self.assertEqual(kind_kv1, "DECLARATIVE")
        self.assertEqual(rec_kv1["catalogPath"], "/latest/")
        self.assertIn("div.grid > div.group", rec_kv1["selectors"]["listSelector"])
        self.assertIn("a.grid h3", rec_kv1["selectors"]["titleSelector"])

        # Keyoapp card without h3 extracts title from link's title attr cleanly
        kewn_like_html = '<div class="grid">' + "".join(
            f'<div class="group latest-poster"><a href="/series/s-{i}/" title="Series {i}"></a></div>'
            for i in range(4)
        ) + "</div>"
        extracted_kv1 = extract_html_items(kewn_like_html, rec_kv1["selectors"])
        self.assertEqual([x["title"] for x in extracted_kv1], ["Series 0", "Series 1", "Series 2", "Series 3"])

        # KeyoappV2 uses _ajax=recent-chapters
        k_v2_cand = copy.deepcopy(k_v1_cand)
        k_v2_cand["repoMeta"]["kotlinText"] = "class AsmoLike : KeyoappV2()"
        rec_kv2, _, kind_kv2, _ = sync_catalog._build_candidate_recipe_for_attempt(k_v2_cand, "en.keyov2")
        self.assertEqual(kind_kv2, "DECLARATIVE")
        self.assertEqual(rec_kv2["catalogPath"], "/?_ajax=recent-chapters&page=1")

        # Full HTML page with >=5 links and search JS `location.href = '/series?q='` must NOT trigger false JS redirect
        large_page = (
            "<html><body>"
            + "".join(f'<a href="/series/{i}">Series {i}</a>' for i in range(6))
            + "<script>function search(q){ location.href = '/series?q=' + q; }</script></body></html>"
        )
        self.assertIsNone(sync_catalog._extract_html_or_js_redirect(large_page, "https://keyov1.example/latest/"))

    def test_second_level_chapter_probe_manhwaonline_nav_filter_jsonapi_madara_and_audit(self):
        from catalog_diagnostics import build_diagnostic_report_markdown

        # 1. Anti-navigation & anti-self-link filtering
        manhwa_recipe = {
            "schemaVersion": 2,
            "sourceId": "es.manhwaonline",
            "name": "ManhwaOnline",
            "baseUrl": "https://manhwa-online.example",
            "lang": "es",
            "version": 1,
            "versionId": 1,
            "preset": "CSS_GENERIC",
            "status": "ACTIVE",
            "maxHtmlBytes": 2097152,
            "catalogPath": "/manga",
            "recipePath": "recipes/es.manhwaonline.json",
            "license": "Apache-2.0",
            "attribution": "Test Contributors",
            "selectors": {
                "listSelector": "article, div.manga-item, div.page-item-detail",
                "titleSelector": "h3 a, h4 a, a",
                "linkSelector": "a",
                "chapterSelector": "li a, div.chapter-item a",
                "pageImgSelector": "div.reading-content img, div#readerarea img",
            },
        }
        list_html = "".join(
            f'<div class="manga-item"><h3><a href="/manga/series-{i}/">Series {i}</a></h3></div>'
            for i in range(1, 5)
        )
        sample_urls = sync_catalog.extract_sample_manga_urls(manhwa_recipe, list_html, limit=2)
        self.assertEqual(
            sample_urls,
            [
                "https://manhwa-online.example/manga/series-1/",
                "https://manhwa-online.example/manga/series-2/",
            ],
        )

        # Nav/header/footer/genre/login/self-link must yield 0 chapters
        nav_only_html = """
        <html><body>
          <header><ul><li><a href="/manga/series-1/capitulo-99/">Header Fake</a></li></ul></header>
          <nav><ul><li><a href="/genre/accion">Género Acción</a></li><li><a href="/login">Login</a></li></ul></nav>
          <main>
            <ul>
              <li><a href="/genre/romance">Romance</a></li>
              <li><a href="/search?q=x">Search</a></li>
              <li><a href="/manga/series-1/#comments">Self</a></li>
              <li><a href="#top">Anchor</a></li>
            </ul>
            <a class="chapter-link" href="/manga/series-1/capitulo-15/">Último capítulo</a>
            <section id="capitulos">
              <div class="chapter-list-full">
                <a class="chapter-link" href="/manga/series-1/capitulo-15/">Capítulo 15</a>
                <a class="chapter-link" href="/manga/series-1/capitulo-14/">Capítulo 14</a>
                <a class="chapter-link" href="/manga/series-1/capitulo-13/">Capítulo 13</a>
              </div>
            </section>
          </main>
          <script>var s='/cdn-cgi/challenge-platform/scripts/jsd/main.js';</script>
          <footer><ul><li><a href="/manga/series-1/capitulo-0/">Footer Fake</a></li></ul></footer>
        </body></html>
        """
        self.assertEqual(
            sync_catalog.extract_chapters_for_smoke(
                manhwa_recipe,
                nav_only_html,
                "https://manhwa-online.example/manga/series-1/",
            ),
            [],
        )
        self.assertEqual(
            sync_catalog.detect_chapter_selector_in_html(
                nav_only_html,
                "https://manhwa-online.example/manga/series-1/",
            ),
            "div.chapter-list-full a.chapter-link",
        )

        def fetcher_manhwa(url, **kw):
            if url == "https://manhwa-online.example/manga":
                return 200, list_html, "OK"
            if url.startswith("https://manhwa-online.example/manga/series-2"):
                return 200, nav_only_html.replace("/manga/series-1/", "/manga/series-2/"), "OK"
            if url.startswith("https://manhwa-online.example/manga/series-"):
                return 200, nav_only_html, "OK"
            return 404, "Not Found", "Not Found"

        # Dry run detects CHAPTERS_EMPTY + suggests fix; auto_fix_selector repairs recipe
        dry_probe = sync_catalog.probe_chapters_for_recipe(manhwa_recipe, list_html, fetcher=fetcher_manhwa, auto_fix_selector=False)
        self.assertFalse(dry_probe["ok"])
        self.assertEqual(dry_probe["category"], "NEEDS_PRIMITIVE")
        self.assertEqual(dry_probe["subReason"], "CHAPTERS_EMPTY")
        self.assertEqual(dry_probe["suggestedSelector"], "div.chapter-list-full a.chapter-link")

        ok_s, cnt_s, msg_s, upd_s, det_s = sync_catalog.run_http_smoke_test(
            copy.deepcopy(manhwa_recipe),
            fetcher=fetcher_manhwa,
            return_details=True,
            probe_chapters=True,
            auto_fix_chapters=True,
        )
        self.assertTrue(ok_s)
        self.assertEqual(cnt_s, 4)
        self.assertEqual(det_s["chaptersFound"], 3)
        self.assertEqual(upd_s["selectors"]["chapterSelector"], "div.chapter-list-full a.chapter-link")

        # 2. JSON_API chapter extraction + probe
        json_recipe = {
            "sourceId": "es.json_ch",
            "name": "JsonChapters",
            "baseUrl": "https://jsonch.example",
            "lang": "es",
            "preset": "JSON_API",
            "jsonApi": {
                "apiBaseUrl": "https://jsonch.example",
                "popularRequest": {"method": "GET", "pathTemplate": "/api/series?page={page}"},
                "chaptersRequest": {"method": "GET", "pathTemplate": "/api/series/{slug}/chapters"},
                "mangaList": {"itemsPath": "$.data[*]", "titlePaths": ["$.title"], "slugPath": "$.slug", "urlTemplate": "/series/{slug}"},
                "chapters": {"itemsPath": "$.chapters[*]", "namePath": "$.name", "numberPath": "$.number", "idPath": "$.id"},
            },
        }
        json_list_body = json.dumps({"data": [{"slug": f"alpha-{i}", "title": f"Alpha {i}"} for i in range(1, 4)]})
        json_ch_body = json.dumps({"chapters": [{"id": 10, "number": "2", "name": "Ch 2"}, {"id": 9, "number": "1", "name": "Ch 1"}]})
        self.assertEqual(
            len(sync_catalog.extract_chapters_for_smoke(json_recipe, json_ch_body, "https://jsonch.example/series/alpha-1")),
            2,
        )

        def fetcher_json(url, **kw):
            if "/chapters" in url:
                return 200, json_ch_body, "OK"
            return 200, json_list_body, "OK"

        j_probe = sync_catalog.probe_chapters_for_recipe(json_recipe, json_list_body, fetcher=fetcher_json)
        self.assertTrue(j_probe["ok"])
        self.assertEqual(j_probe["chaptersFound"], 2)

        # 3. MADARA fallback POST <manga_url>/ajax/chapters/
        madara_recipe = {
            "sourceId": "es.madara_ajax",
            "name": "MadaraAjax",
            "baseUrl": "https://madaraajax.example",
            "lang": "es",
            "preset": "MADARA",
            "catalogPath": "/manga",
            "selectors": sync_catalog.PRESET_DEFAULT_SELECTORS["MADARA"],
        }
        madara_list = "".join(
            f'<div class="page-item-detail"><h3 class="h5"><a href="/manga/work-{i}/">Work {i}</a></h3></div>'
            for i in range(1, 4)
        )
        seen_ajax = []

        def fetcher_madara(url, method="GET", **kw):
            seen_ajax.append((method, url))
            if url.endswith("/ajax/chapters/") and method == "POST":
                return 200, '<ul><li class="wp-manga-chapter"><a href="/manga/work-1/cap-2/">Cap 2</a></li><li class="wp-manga-chapter"><a href="/manga/work-1/cap-1/">Cap 1</a></li></ul>', "OK"
            if "/manga/work-" in url:
                return 200, "<html><body><h1>Work</h1><div id='manga-chapters-holder'></div></body></html>", "OK"
            return 404, "", "Not Found"

        m_probe = sync_catalog.probe_chapters_for_recipe(madara_recipe, madara_list, fetcher=fetcher_madara)
        self.assertTrue(m_probe["ok"])
        self.assertEqual(m_probe["chaptersFound"], 2)
        self.assertIn(("POST", "https://madaraajax.example/manga/work-1/ajax/chapters/"), seen_ajax)

        # 4. Cloudflare real challenge on manga page -> CLOUDFLARE_ANTIBOT, never CHAPTERS_EMPTY
        def fetcher_cf(url, **kw):
            return 403, "<html><title>Just a moment...</title><div>cf-turnstile</div></html>", "Forbidden"

        cf_probe = sync_catalog.probe_chapters_for_recipe(manhwa_recipe, list_html, fetcher=fetcher_cf, auto_fix_selector=True)
        self.assertFalse(cf_probe["ok"])
        self.assertEqual(cf_probe["category"], "CLOUDFLARE_ANTIBOT")

        # 5. audit_chapters_catalog (--audit-chapters dry + --apply) + R2 CHAPTERS_EMPTY section
        with tempfile.TemporaryDirectory() as tmpdir:
            rdir = os.path.join(tmpdir, "recipes")
            os.makedirs(rdir, exist_ok=True)
            with open(os.path.join(rdir, "es.manhwaonline.json"), "w", encoding="utf-8") as f:
                json.dump(manhwa_recipe, f)
            broken_ch_recipe = copy.deepcopy(manhwa_recipe)
            broken_ch_recipe["sourceId"] = "es.brokench"
            broken_ch_recipe["name"] = "BrokenCh"
            broken_ch_recipe["recipePath"] = "recipes/es.brokench.json"
            broken_ch_recipe["baseUrl"] = "https://brokench.example"
            broken_ch_recipe["upstreamSourceIds"] = [999991]
            with open(os.path.join(rdir, "es.brokench.json"), "w", encoding="utf-8") as f:
                json.dump(broken_ch_recipe, f)

            def audit_fetcher(url, **kw):
                if url.startswith("https://manhwa-online.example"):
                    return fetcher_manhwa(url, **kw)
                if url == "https://brokench.example/manga":
                    return 200, "".join(f'<div class="manga-item"><h3><a href="/manga/b-{i}/">B {i}</a></h3></div>' for i in range(4)), "OK"
                return 200, "<html><body><h1>Empty Chapters</h1></body></html>", "OK"

            rep_md = os.path.join(tmpdir, "audit.md")
            dry_audit = sync_catalog.audit_chapters_catalog(
                rdir,
                index_path=os.path.join(tmpdir, "index.json"),
                notice_path=os.path.join(tmpdir, "NOTICE"),
                apply=False,
                workers=2,
                fetcher=audit_fetcher,
                report_out=rep_md,
            )
            self.assertEqual(dry_audit["reportData"]["counts"]["chaptersEmpty"], 2)
            with open(rep_md, "r", encoding="utf-8") as rf:
                md_txt = rf.read()
            self.assertIn("CHAPTERS_EMPTY", md_txt)
            self.assertIn("Carátulas OK pero 0 capítulos detectados", md_txt)

            apply_audit = sync_catalog.audit_chapters_catalog(
                rdir,
                index_path=os.path.join(tmpdir, "index.json"),
                notice_path=os.path.join(tmpdir, "NOTICE"),
                apply=True,
                workers=2,
                fetcher=audit_fetcher,
            )
            self.assertEqual(apply_audit["fixedFiles"], ["es.manhwaonline.json"])
            self.assertEqual(apply_audit["reportData"]["counts"]["viable"], 1)
            self.assertEqual(apply_audit["reportData"]["counts"]["chaptersEmpty"], 1)
            with open(os.path.join(rdir, "es.manhwaonline.json"), "r", encoding="utf-8") as f:
                saved = json.load(f)
            self.assertEqual(saved["selectors"]["chapterSelector"], "div.chapter-list-full a.chapter-link")
            self.assertTrue(os.path.isfile(os.path.join(tmpdir, "index.json")))

    def test_v2_bundle_generates_and_validates_sha256_in_entries(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            schema_src = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "schema"))
            if os.path.isdir(schema_src):
                shutil.copytree(schema_src, os.path.join(tmpdir, "schema"))

            rdir = os.path.join(tmpdir, "recipes")
            os.makedirs(rdir, exist_ok=True)
            dummy_recipe = {
                "schemaVersion": 2,
                "sourceId": "es.sha256test",
                "name": "Sha256 Test",
                "baseUrl": "https://sha256test.example",
                "lang": "es",
                "version": 1,
                "versionId": 1,
                "preset": "CSS_GENERIC",
                "status": "ACTIVE",
                "catalogPath": "/manga",
                "selectors": {
                    "listSelector": "article.item",
                    "titleSelector": "h3 a",
                    "linkSelector": "a",
                },
                "recipePath": "recipes/es.sha256test.json",
                "mode": "declarative",
                "upstreamSourceIds": [987654321],
                "license": "Apache-2.0",
                "attribution": "The Tachiyomi / Keiyoushi Contributors",
            }
            recipe_file = os.path.join(rdir, "es.sha256test.json")
            with open(recipe_file, "w", encoding="utf-8", newline="\n") as f:
                json.dump(dummy_recipe, f, indent=2, ensure_ascii=False)
                f.write("\n")

            with open(recipe_file, "rb") as f:
                expected_sha = hashlib.sha256(f.read().replace(b"\r\n", b"\n")).hexdigest()

            index_path = os.path.join(tmpdir, "index.json")
            bundle = sync_catalog.write_v2_bundle(rdir, index_path)

            self.assertEqual(len(bundle["entries"]), 1)
            entry = bundle["entries"][0]
            self.assertEqual(entry["sourceId"], "es.sha256test")
            self.assertEqual(entry["sha256"], expected_sha)
            self.assertEqual(len(entry["sha256"]), 64)

            valid, errs = validate_bundle(bundle, base_dir=tmpdir)
            self.assertTrue(valid, f"Expected valid bundle, got errors: {errs}")
            self.assertEqual(errs, [])

            # Verify CRLF on disk normalizes to identical LF sha256
            with open(recipe_file, "rb") as rf:
                crlf_content = rf.read().replace(b"\n", b"\r\n")
            with open(recipe_file, "wb") as wf:
                wf.write(crlf_content)

            valid_crlf, errs_crlf = validate_bundle(bundle, base_dir=tmpdir)
            self.assertTrue(valid_crlf, f"Expected CRLF-normalized bundle validation to pass: {errs_crlf}")

            # Alter recipe file content on disk without updating index.json
            with open(recipe_file, "a", encoding="utf-8", newline="\n") as f:
                f.write("\n// altered content\n")

            valid_mismatch, errs_mismatch = validate_bundle(bundle, base_dir=tmpdir)
            self.assertFalse(valid_mismatch)
            self.assertTrue(
                any("sha256 mismatch" in err for err in errs_mismatch),
                f"Expected sha256 mismatch error in {errs_mismatch}",
            )


if __name__ == "__main__":
    unittest.main()
