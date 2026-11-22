import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tools")))

from validate_catalog import (  # noqa: E402
    BUNDLE_ROOT,
    audit_bundle_isolation,
    is_license_boilerplate_attribution,
    validate_all,
)


class TestBundleIsolationAndMigration(unittest.TestCase):
    def test_real_bundle_passes_full_validation_and_has_consistent_v2_recipes(self):
        ok, errors = validate_all(BUNDLE_ROOT)
        self.assertTrue(ok, f"Bundle validation failed: {errors}")

        recipes_dir = os.path.join(BUNDLE_ROOT, "recipes")
        recipe_files = sorted(f for f in os.listdir(recipes_dir) if f.endswith(".json"))
        self.assertGreater(len(recipe_files), 0)

        with open(os.path.join(BUNDLE_ROOT, "index.json"), "r", encoding="utf-8") as f:
            index_data = json.load(f)
        self.assertEqual(index_data["schemaVersion"], 2)
        self.assertNotIn("recipes", index_data)
        self.assertEqual(len(index_data["entries"]), len(recipe_files))

        entries_by_sid = {e["sourceId"]: e for e in index_data["entries"]}

        # Verify filename == <sourceId>.json, no unsanitized mirror placeholders, and attribution/license integrity
        for fname in recipe_files:
            with open(os.path.join(recipes_dir, fname), "r", encoding="utf-8") as rf:
                r = json.load(rf)
            self.assertEqual(r["schemaVersion"], 2)
            self.assertEqual(fname, f"{r['sourceId']}.json")
            self.assertEqual(r["recipePath"], f"recipes/{r['sourceId']}.json")
            self.assertTrue(all("$" not in str(m) for m in r.get("mirrors", [])))
            attr = r.get("attribution", "")
            self.assertTrue(isinstance(attr, str) and bool(attr.strip()), fname)
            self.assertFalse(is_license_boilerplate_attribution(attr), f"{fname}: {attr!r}")
            entry = entries_by_sid[r["sourceId"]]
            self.assertEqual(entry.get("attribution"), r.get("attribution"), fname)
            self.assertEqual(entry.get("license"), r.get("license"), fname)

        with open(os.path.join(BUNDLE_ROOT, "NOTICE"), "r", encoding="utf-8") as nf:
            for line in nf:
                if line.strip().lower().startswith("attribution:"):
                    notice_attr = line.split(":", 1)[1].strip()
                    self.assertTrue(notice_attr)
                    self.assertFalse(is_license_boilerplate_attribution(notice_attr), notice_attr)

    def test_isolation_audit_clean_and_detects_violations(self):
        ok, violations = audit_bundle_isolation(BUNDLE_ROOT)
        self.assertTrue(ok, f"Isolation violations found: {violations}")

        with tempfile.TemporaryDirectory() as tmpdir:
            bad_file = os.path.join(tmpdir, "leaky.json")
            # Construct synthetic generic test samples dynamically so self-scan stays clean.
            synthetic_owner = "example-" + "private-owner"
            synthetic_repo = "example-" + "private-repo"
            synthetic_local_path = "/" + "Users/" + "alice/workspace/catalog"
            synthetic_linux_path = "/" + "home/" + "alice/workspace"
            synthetic_file_uri = "file://" + "/" + "home/" + "bob/notes.txt"
            synthetic_email = "maintainer" + "@gmail." + "com"
            synthetic_token = "ghp" + "_ExampleSyntheticToken12345"
            with open(bad_file, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "url": f"https://github.com/{synthetic_owner}/{synthetic_repo}",
                        "localPath": synthetic_local_path,
                        "linuxPath": synthetic_linux_path,
                        "fileUri": synthetic_file_uri,
                        "email": synthetic_email,
                        "token": synthetic_token,
                    },
                    f,
                )

            ok_generic, generic_hits = audit_bundle_isolation(tmpdir)
            self.assertFalse(ok_generic)
            self.assertGreaterEqual(len(generic_hits), 4)
            self.assertTrue(any("local_linux_home_path" in h for h in generic_hits))
            self.assertTrue(any("local_macos_users_path" in h for h in generic_hits))

            with tempfile.TemporaryDirectory() as clean_dir:
                clean_file = os.path.join(clean_dir, "clean_api.json")
                with open(clean_file, "w", encoding="utf-8") as cf:
                    json.dump(
                        {
                            "popular": "/api/home/best-comics",
                            "latest": "/api/home/latest-comics?page={page}",
                            "fullUrl": "https://example.org/home/news",
                            "usersEndpoint": "/v1/Users/profile",
                        },
                        cf,
                    )
                ok_clean, clean_hits = audit_bundle_isolation(clean_dir)
                self.assertTrue(ok_clean, f"Unexpected false positive on API subpaths: {clean_hits}")

            ok_cli_arg, arg_hits = audit_bundle_isolation(
                tmpdir,
                extra_patterns=[synthetic_owner, synthetic_repo],
            )
            self.assertFalse(ok_cli_arg)
            self.assertTrue(any(synthetic_owner in h for h in arg_hits))
            self.assertTrue(any(synthetic_repo in h for h in arg_hits))

            with mock.patch.dict(
                os.environ,
                {"CATALOG_FORBIDDEN_PATTERNS": f"{synthetic_owner};{synthetic_repo}"},
            ):
                ok_env, env_hits = audit_bundle_isolation(tmpdir)
                self.assertFalse(ok_env)
                self.assertTrue(any(synthetic_owner in h for h in env_hits))
                self.assertTrue(any(synthetic_repo in h for h in env_hits))

        validator_script = os.path.join(BUNDLE_ROOT, "tools", "validate_catalog.py")
        proc = subprocess.run(
            [
                sys.executable,
                "-B",
                validator_script,
                "--forbid-pattern",
                synthetic_owner,
                "--forbid-pattern",
                synthetic_repo,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_sync_catalog_has_zero_github_rest_api_calls(self):
        sync_path = os.path.join(BUNDLE_ROOT, "tools", "sync_catalog.py")
        with open(sync_path, "r", encoding="utf-8") as f:
            code = f.read()
        self.assertNotIn("api.github.com", code)
        self.assertIn("--depth", code)

    def test_isolation_and_validator_handle_invalid_inputs_safely(self):
        from validate_catalog import validate_recipe

        # Invalid/non-string recipe and invalid bundle root must fail safely without uncaught exceptions
        ok_bad, errs_bad = validate_recipe("not-a-dict", base_dir="/nonexistent/bundle/path")
        self.assertFalse(ok_bad)
        self.assertTrue(errs_bad)

        # Dynamically constructed regex metacharacter pattern must be safely escaped without crashing audit_bundle_isolation
        invalid_regex_pattern = "[unclosed_" + "regex_" + "literal"
        ok_iso, violations = audit_bundle_isolation(BUNDLE_ROOT, extra_patterns=[invalid_regex_pattern])
        self.assertTrue(ok_iso, f"Unexpected violation on escaped invalid regex arg: {violations}")


if __name__ == "__main__":
    unittest.main()
