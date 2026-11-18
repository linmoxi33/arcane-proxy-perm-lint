import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from arcane_proxy_perm_lint import analyze  # noqa: E402

BIN = os.path.join(ROOT, "bin", "arcane-proxy-perm-lint")
PERM = "/agents/{id}"


def doc(endpoints, permissions=("containers:list", "images:list", "system:read")):
    resources = [
        {"key": "r", "actions": [{"key": "a", "permission": p} for p in permissions]}
    ]
    return {"resources": resources, "endpoints": endpoints}


def ep(path, method="GET", **kw):
    base = {"method": method, "path": path}
    base.update(kw)
    return base


class AnalyzeTests(unittest.TestCase):
    def test_clean_catalog_is_ok(self):
        report = analyze(
            doc(
                [
                    ep(PERM + "/containers", access="permission", permission="containers:list"),
                    ep(PERM + "/health", access="public"),
                ]
            )
        )
        self.assertTrue(report["summary"]["ok"])
        self.assertEqual(report["summary"]["uncovered"], 0)
        self.assertEqual(report["summary"]["dangling"], 0)

    def test_authenticated_is_uncovered(self):
        report = analyze(doc([ep(PERM + "/registries", access="authenticated")]))
        self.assertFalse(report["summary"]["ok"])
        self.assertEqual(report["uncovered"][0]["path"], PERM + "/registries")
        self.assertIn("requiredPermission", report["uncovered"][0]["reason"])

    def test_globaladmin_is_uncovered(self):
        report = analyze(doc([ep(PERM + "/system/info", access="globalAdmin")]))
        self.assertEqual([u["path"] for u in report["uncovered"]], [PERM + "/system/info"])

    def test_sudo_is_uncovered(self):
        report = analyze(doc([ep(PERM + "/system/prune", method="POST", access="sudo")]))
        self.assertEqual(report["uncovered"][0]["access"], "sudo")

    def test_permission_access_is_covered(self):
        report = analyze(
            doc([ep(PERM + "/c", access="permission", permission="containers:list")])
        )
        self.assertEqual(report["summary"]["covered"], 1)
        self.assertEqual(report["summary"]["uncovered"], 0)

    def test_action_permissions_is_covered(self):
        report = analyze(
            doc(
                [
                    ep(
                        PERM + "/images/tags",
                        access="actionPermissions",
                        actionParam="action",
                        actionPermissions={"list": "images:list"},
                    )
                ]
            )
        )
        self.assertEqual(report["summary"]["covered"], 1)

    def test_public_is_covered(self):
        report = analyze(doc([ep(PERM + "/health", access="public")]))
        self.assertEqual(report["summary"]["covered"], 1)
        self.assertEqual(report["summary"]["uncovered"], 0)

    def test_dangling_permission_detected(self):
        report = analyze(
            doc([ep(PERM + "/legacy", access="permission", permission="ghost:read")])
        )
        self.assertEqual(report["dangling"][0]["permission"], "ghost:read")
        self.assertFalse(report["summary"]["ok"])

    def test_non_agent_paths_are_ignored(self):
        report = analyze(
            doc([ep("/api/users", access="authenticated")], permissions=("users:list",))
        )
        self.assertEqual(report["summary"]["ignoredNonAgent"], 1)
        self.assertEqual(report["summary"]["agentEndpoints"], 0)
        self.assertTrue(report["summary"]["ok"])

    def test_bare_list_input_is_accepted(self):
        report = analyze(
            [
                ep(PERM + "/containers", access="permission", permission="containers:list"),
                ep(PERM + "/registries", access="authenticated"),
            ]
        )
        self.assertEqual(report["summary"]["uncovered"], 1)

    def test_prefix_override(self):
        report = analyze(
            doc([ep("/v2/agents/{id}/registries", access="authenticated")]),
            prefix="/v2/agents/{id}",
        )
        self.assertEqual(report["summary"]["agentEndpoints"], 1)
        self.assertEqual(report["summary"]["uncovered"], 1)

    def test_permission_access_with_empty_permission_is_uncovered(self):
        report = analyze(doc([ep(PERM + "/x", access="permission", permission="")]))
        self.assertEqual(report["summary"]["uncovered"], 1)


class CliBehaviorTests(unittest.TestCase):
    def _write(self, payload):
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        with handle:
            json.dump(payload, handle)
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def _run(self, *args):
        return subprocess.run(
            [sys.executable, BIN, *args],
            capture_output=True,
            text=True,
        )

    def test_cli_clean_catalog_exit_0_and_json_parses(self):
        path = self._write(
            doc([ep(PERM + "/containers", access="permission", permission="containers:list")])
        )
        result = self._run(path, "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        parsed = json.loads(result.stdout)
        self.assertTrue(parsed["summary"]["ok"])

    def test_cli_uncovered_exit_1(self):
        path = self._write(doc([ep(PERM + "/registries", access="authenticated")]))
        result = self._run(path, "--json")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["summary"]["uncovered"], 1)

    def test_cli_bad_json_exit_2(self):
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        with handle:
            handle.write("{not json")
        self.addCleanup(os.unlink, handle.name)
        result = self._run(handle.name)
        self.assertEqual(result.returncode, 2)

    def test_cli_missing_file_exit_2(self):
        result = self._run("/nonexistent/permissions.json")
        self.assertEqual(result.returncode, 2)

    def test_cli_human_output_mentions_uncovered(self):
        path = self._write(doc([ep(PERM + "/registries", access="authenticated")]))
        result = self._run(path)
        self.assertEqual(result.returncode, 1)
        self.assertIn("UNCOVERED", result.stdout)
        self.assertIn("registries", result.stdout)


if __name__ == "__main__":
    unittest.main()