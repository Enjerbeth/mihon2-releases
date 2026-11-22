"""test_kt_extractor.py — Unit tests for static analysis and Kotlin recipe extractor."""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tools")))

from catalog_kt_extractor import (
    extract_crypto_steps,
    extract_html_selectors,
    extract_image_unscramble_steps,
    extract_json_api_spec,
    extract_query_signer_spec,
    extract_quickjs_steps,
    extract_request_path,
    extract_selector,
    extract_string_literal,
    synthesize_recipe_from_kotlin,
)
from validate_catalog import BUNDLE_ROOT, validate_recipe


class TestKtExtractor(unittest.TestCase):

    def test_extract_string_literal(self):
        kt = '''
        override val baseUrl = "https://example.com"
        val customPath: String = "/series"
        '''
        self.assertEqual(extract_string_literal(kt, "baseUrl"), "https://example.com")
        self.assertEqual(extract_string_literal(kt, "customPath"), "/series")

    def test_extract_selector_property_and_function(self):
        kt_prop = 'override val popularMangaSelector = "div.bsx"'
        self.assertEqual(extract_selector(kt_prop, "popularMangaSelector"), "div.bsx")

        kt_func = 'override fun popularMangaSelector(): String = "div.film_list-wrap .flw-item"'
        self.assertEqual(extract_selector(kt_func, "popularMangaSelector"), "div.film_list-wrap .flw-item")

        kt_body = '''
        override fun mangaDetailsParse(document: Document): SManga {
            val manga = SManga.create()
            manga.title = document.selectFirst("h1.entry-title")?.text() ?: ""
            return manga
        }
        '''
        self.assertEqual(extract_selector(kt_body, "mangaDetailsParse"), "h1.entry-title")

    def test_extract_request_path_and_pagination(self):
        kt = '''
        override fun popularMangaRequest(page: Int): Request {
            return GET("$baseUrl/manga?page=$page", headers)
        }
        '''
        req = extract_request_path(kt, "popularMangaRequest")
        self.assertIsNotNone(req)
        self.assertEqual(req["method"], "GET")
        self.assertEqual(req["pathTemplate"], "/manga?page={page}")
        self.assertTrue(req["hasPage"])

    def test_extract_html_selectors_realistic(self):
        kt = '''
        class MangaStream : ParsedHttpSource() {
            override val popularMangaSelector = "div.listupd div.bsx"
            override val popularMangaNextPageSelector = "a.r"
            override val chapterListSelector = "div.bxcl ul li"

            override fun pageListParse(document: Document): List<Page> {
                return document.select("div#readerarea img").mapIndexed { i, img ->
                    Page(i, imageUrl = img.attr("abs:src"))
                }
            }
        }
        '''
        sels = extract_html_selectors(kt)
        self.assertEqual(sels.get("listSelector"), "div.listupd div.bsx")
        self.assertEqual(sels.get("nextPageSelector"), "a.r")
        self.assertEqual(sels.get("chapterSelector"), "div.bxcl ul li")
        self.assertEqual(sels.get("pageImgSelector"), "div#readerarea img")

    def test_extract_json_api_spec(self):
        kt = '''
        class ApiSource : HttpSource() {
            override fun popularMangaRequest(page: Int): Request = GET("$baseUrl/api/v1/comics?page=$page")

            override fun popularMangaParse(response: Response): MangasPage {
                val json = json.decodeFromString<JsonObject>(response.body.string())
                val data = json.getJSONArray("data")
                return MangasPage(emptyList(), false)
            }
        }
        '''
        api_spec = extract_json_api_spec(kt, "https://api.example.com")
        self.assertIsNotNone(api_spec)
        self.assertNotIn("popularMapping", api_spec)
        self.assertEqual(api_spec["mangaList"]["itemsPath"], "$.data[*]")
        self.assertEqual(api_spec["popularRequest"]["pathTemplate"], "/api/v1/comics?page={page}")
        for key in (
            "mangaList",
            "details",
            "chapters",
            "pages",
            "popularRequest",
            "latestRequest",
            "searchRequest",
            "detailsRequest",
            "chaptersRequest",
            "pagesRequest",
        ):
            self.assertIn(key, api_spec)

    def test_extract_graphql_json_api_spec(self):
        kt = r'''
        class GraphqlSource : HttpSource() {
            private val POPULAR_QUERY = """
                query search($page: Int) {
                    search(page: $page) {
                        rows { id title slug }
                    }
                }
            """
            override fun popularMangaRequest(page: Int): Request {
                val body = buildJsonObject {
                    put("query", POPULAR_QUERY)
                    put("variables", buildJsonObject { put("page", page) })
                }
                return POST("$baseUrl/graphql", headers, body.toString().toRequestBody())
            }
            override fun searchMangaRequest(page: Int, query: String, filters: FilterList): Request {
                val body = buildJsonObject {
                    put("query", POPULAR_QUERY)
                    put("variables", buildJsonObject { put("q", query); put("page", page) })
                }
                return POST("$baseUrl/graphql", headers, body.toString().toRequestBody())
            }
        }
        '''
        recipe = synthesize_recipe_from_kotlin(
            kotlin_text=kt,
            source_id="es.graphql_demo",
            name="GraphQL Demo",
            base_url="https://graphql.example.org",
            lang="es",
        )
        self.assertIsNotNone(recipe)
        self.assertEqual(recipe["preset"], "JSON_API")
        pop_req = recipe["jsonApi"]["popularRequest"]
        self.assertEqual(pop_req["method"], "POST")
        self.assertEqual(pop_req["pathTemplate"], "/graphql")
        self.assertIn("query search", pop_req["graphqlQuery"])
        self.assertEqual(pop_req["graphqlVariablesTemplate"], '{"page":{page}}')
        self.assertEqual(recipe["jsonApi"]["mangaList"]["itemsPath"], "$.data.search.rows[*]")
        ok, errs = validate_recipe(recipe, base_dir=BUNDLE_ROOT)
        self.assertTrue(ok, f"GraphQL synthesized recipe invalid: {errs}")

    def test_synthesize_recipe_from_kotlin_html(self):
        kt = '''
        class SampleScan : ParsedHttpSource() {
            override val popularMangaSelector = "div.media-item"
            override val popularMangaNextPageSelector = "a.next-page"
            override val chapterListSelector = "ul.chapters li"
            override fun pageListParse(doc: Document): List<Page> = doc.select("div.pages img").map { Page(0) }
        }
        '''
        recipe = synthesize_recipe_from_kotlin(
            kotlin_text=kt,
            source_id="es.samplescan",
            name="Sample Scan",
            base_url="https://samplescan.org",
            lang="es",
            pkg_name="eu.kanade.tachiyomi.extension.es.samplescan",
            version_code=100,
            upstream_source_id=123456789,
        )
        self.assertIsNotNone(recipe)
        self.assertEqual(recipe["sourceId"], "es.samplescan")
        self.assertEqual(recipe["preset"], "CSS_GENERIC")
        self.assertEqual(recipe["selectors"]["listSelector"], "div.media-item")
        self.assertEqual(recipe["selectors"]["pageImgSelector"], "div.pages img")
        self.assertEqual(recipe["upstreamSourceId"], 123456789)
        self.assertTrue(validate_recipe(recipe, base_dir=BUNDLE_ROOT)[0])

    def test_synthesize_recipe_from_kotlin_json(self):
        kt = '''
        class SampleJsonScan : HttpSource() {
            override fun popularMangaRequest(page: Int): Request = GET("$baseUrl/api/posts?page=$page")
            override fun popularMangaParse(response: Response): MangasPage {
                val obj = JSONObject(response.body.string())
                val arr = obj.getJSONArray("items")
                return MangasPage(emptyList(), false)
            }
        }
        '''
        recipe = synthesize_recipe_from_kotlin(
            kotlin_text=kt,
            source_id="en.samplejson",
            name="Sample JSON",
            base_url="https://api.samplejson.org",
            lang="en",
        )
        self.assertIsNotNone(recipe)
        self.assertEqual(recipe["preset"], "JSON_API")
        self.assertNotIn("popularMapping", recipe["jsonApi"])
        self.assertEqual(recipe["jsonApi"]["mangaList"]["itemsPath"], "$.items[*]")
        self.assertEqual(recipe["jsonApi"]["popularRequest"]["pathTemplate"], "/api/posts?page={page}")
        ok, errs = validate_recipe(recipe, base_dir=BUNDLE_ROOT)
        self.assertTrue(ok, f"Synthesized JSON recipe invalid: {errs}")

    def test_automatic_primitive_mappers_quickjs_crypto_scramble_and_signer(self):
        # 1. JS_RUNTIME_QUICKJS: PACKER & NEXT_RSC & CUSTOM
        kt_packer = '''
        class PackerSource : ParsedHttpSource() {
            override val popularMangaSelector = "div.manga"
            override fun pageListParse(doc: Document): List<Page> {
                val script = doc.selectFirst("script")?.data() ?: ""
                val unpacked = Unpacker.unpack(script)
                return emptyList()
            }
        }
        '''
        rec_packer = synthesize_recipe_from_kotlin(kt_packer, "es.packer", "Packer", "https://packer.example", "es")
        self.assertIsNotNone(rec_packer)
        self.assertEqual(rec_packer["pipelineSteps"][0]["op"], "quickjs_eval")
        self.assertEqual(rec_packer["pipelineSteps"][0]["preset"], "PACKER")
        self.assertTrue(validate_recipe(rec_packer, base_dir=BUNDLE_ROOT)[0])

        kt_rsc = '''
        class NextRscSource : HttpSource() {
            val chunk = doc.select("script").filter { it.data().contains("__next_f") }
        }
        '''
        rec_rsc = synthesize_recipe_from_kotlin(kt_rsc, "es.rsc", "NextRSC", "https://rsc.example", "es")
        self.assertIsNotNone(rec_rsc)
        self.assertEqual(rec_rsc["pipelineSteps"][0]["preset"], "NEXT_RSC")
        self.assertTrue(validate_recipe(rec_rsc, base_dir=BUNDLE_ROOT)[0])

        self.assertEqual(extract_quickjs_steps("val q = QuickJs.create()"), [])

        # 2. DYNAMIC_CRYPTO_OR_KEY: AES/ECB, AES/CBC, CryptoAES, LZString
        kt_crypto = '''
        class CryptoSource : ParsedHttpSource() {
            override val popularMangaSelector = "div.item"
            private val keyBytes = "0123456789abcdef0123456789abcdef".toByteArray()
            private val secretKey = SecretKeySpec("0123456789abcdef".toByteArray(), "AES")
            val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
            val text = LZString.decompressFromBase64(raw)
        }
        '''
        rec_crypto = synthesize_recipe_from_kotlin(kt_crypto, "es.crypto", "Crypto", "https://crypto.example", "es")
        self.assertIsNotNone(rec_crypto)
        ops = [s["op"] for s in rec_crypto["pipelineSteps"]]
        self.assertIn("dynamic_crypto", ops)
        self.assertIn("lz_string", ops)
        self.assertTrue(validate_recipe(rec_crypto, base_dir=BUNDLE_ROOT)[0])

        kt_salted = '''
        class SaltedSource : ParsedHttpSource() {
            override val popularMangaSelector = "div.item"
            val pass = "s3cr3tPass"
            val dec = CryptoAES.decrypt(cipherData, pass)
        }
        '''
        salted_steps = extract_crypto_steps(kt_salted)
        self.assertEqual(salted_steps[0], {"op": "openssl_salted_decrypt", "password": "s3cr3tPass"})

        # Unextractable cipher (no key) must return None
        kt_unextractable_crypto = '''
        class BadCrypto : ParsedHttpSource() {
            override val popularMangaSelector = "div.item"
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        }
        '''
        self.assertIsNone(synthesize_recipe_from_kotlin(kt_unextractable_crypto, "es.badc", "BadC", "https://badc.example", "es"))

        # 3. DYNAMIC_IMAGE_SCRAMBLE: PUBLUS & GRID Canvas
        kt_publus = '''
        class PublusSource : ParsedHttpSource() {
            override val popularMangaSelector = "div.item"
            private val blockWidth = 64
            private val blockHeight = 64
            val interceptor = PublusInterceptor()
        }
        '''
        rec_pub = synthesize_recipe_from_kotlin(kt_publus, "es.pub", "Publus", "https://pub.example", "es")
        self.assertIsNotNone(rec_pub)
        g_step = rec_pub["pipelineSteps"][0]
        self.assertEqual(g_step["op"], "grid_unscramble")
        self.assertEqual(g_step["mode"], "PUBLUS")
        self.assertEqual(g_step["blockWidth"], 64)
        self.assertTrue(validate_recipe(rec_pub, base_dir=BUNDLE_ROOT)[0])

        kt_canvas = '''
        class CanvasSource : ParsedHttpSource() {
            override val popularMangaSelector = "div.item"
            private val cols = 4
            private val rows = 5
            fun unscramble(src: Bitmap) { val out = Bitmap.createBitmap(w, h, cfg); val c = Canvas(out) }
        }
        '''
        c_steps = extract_image_unscramble_steps(kt_canvas)
        self.assertEqual(c_steps[0]["mode"], "GRID")
        self.assertEqual(c_steps[0]["columns"], 4)
        self.assertEqual(c_steps[0]["rows"], 5)

        # 4. SIGNING_CUSTOM_VRF: HMAC-SHA1 header & HMAC-SHA256 query with literal secret
        kt_signer = '''
        class SignedSource : HttpSource() {
            private val hmacSecret = "my-vrf-secret"
            override fun popularMangaRequest(page: Int): Request = GET("$baseUrl/api/list?page=$page")
            override fun popularMangaParse(response: Response): MangasPage {
                val obj = JSONObject(response.body.string())
                val arr = obj.getJSONArray("data")
                return MangasPage(emptyList(), false)
            }
            fun sign(path: String): String {
                val mac = Mac.getInstance("HmacSHA1")
                mac.init(SecretKeySpec(hmacSecret.toByteArray(), "HmacSHA1"))
                return ""
            }
            val req = Request.Builder().addHeader("X-Signature", signature).addHeader("X-Timestamp", ts).build()
        }
        '''
        rec_signed = synthesize_recipe_from_kotlin(kt_signer, "es.signed", "Signed", "https://signed.example", "es")
        self.assertIsNotNone(rec_signed)
        qs = rec_signed["querySigner"]
        self.assertEqual(qs["algorithm"], "hmac_sha1")
        self.assertEqual(qs["target"], "HEADER")
        self.assertEqual(qs["headerName"], "X-Signature")
        self.assertEqual(qs["timestampHeaderName"], "X-Timestamp")
        self.assertEqual(qs["hmacSecret"], "my-vrf-secret")
        self.assertTrue(validate_recipe(rec_signed, base_dir=BUNDLE_ROOT)[0])
        self.assertIsNone(extract_query_signer_spec('val mac = Mac.getInstance("HmacSHA256")'))

    def test_optional_filter_quickjs_does_not_block_core_declarative_source(self):
        from catalog_kt_extractor import has_unresolved_native_primitives

        kt_filter_only_qjs = '''
        import app.cash.quickjs.QuickJs
        class KeyoLike : ParsedHttpSource() {
            override fun latestUpdatesSelector() = "div.grid > div.group"
            protected open fun parseGenres(document: Document): Map<String, String> {
                val script = document.selectFirst("script")?.data() ?: return emptyMap()
                return QuickJs.create().use { it.evaluate("JSON.stringify([])") }.toString().parseAs()
            }
        }
        '''
        unresolved, reasons = has_unresolved_native_primitives(kt_filter_only_qjs, recipe={"preset": "CSS_GENERIC"})
        self.assertFalse(unresolved, f"Unexpected unresolved blockers for filter-only QuickJs: {reasons}")

        kt_core_qjs = '''
        import app.cash.quickjs.QuickJs
        class ReaderQjs : ParsedHttpSource() {
            override fun pageListParse(document: Document): List<Page> {
                val res = QuickJs.create().use { it.evaluate("solve()") }
                return emptyList()
            }
        }
        '''
        unresolved_core, reasons_core = has_unresolved_native_primitives(kt_core_qjs, recipe={"preset": "CSS_GENERIC"})
        self.assertTrue(unresolved_core)
        self.assertIn("QUICKJS", reasons_core)


if __name__ == "__main__":
    unittest.main()
