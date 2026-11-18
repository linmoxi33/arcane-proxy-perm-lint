#!/usr/bin/env python3
"""arcane-proxy-perm-lint

Cross-implementation consistency checker for getarcaneapp/arcane.

Arcane exposes two parallel permission implementations for its agent surface:

1. The *contract*: the JSON emitted by ``arcane permissions`` (``PermissionExport``),
   which describes every endpoint and the permission it is supposed to require.
2. The *runtime*: ``authz.PermissionMatcher`` (backend/pkg/authz/permission_matcher.go),
   which the agent-proxy middleware (backend/internal/middleware/environment.go)
   consults before forwarding a request to a remote agent.  When ``Lookup`` finds no
   rule, the request is denied with 403 "no known permission mapping".

The matcher is populated by ``PermissionMatcher.CollectFromHumaAPI``
(backend/pkg/authz/permission_matcher_huma.go) and it only registers a rule when an
operation has ``arcane:requiredPermission`` metadata, ``arcane:actionPermissions``
metadata, or an empty security list.  Operations that are merely *authenticated*
(or gated by globalAdmin / sudo / agent token) are silently skipped, so the exported
contract and the runtime matcher disagree -- and the affected routes 403 through a
remote agent.  See upstream issue #4821.

This tool loads the ``arcane permissions`` export and reports the agent-surface
endpoints the runtime matcher cannot resolve, plus permissions that are referenced
but absent from the catalog.  Pure stdlib, fully offline.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List, Optional, Tuple

TOOL_NAME = "arcane-proxy-perm-lint"
TOOL_VERSION = "1.0.0"

DEFAULT_PREFIX = "/agents/{id}"

# Exit codes are part of the public contract.
EXIT_OK = 0
EXIT_ISSUES = 1
EXIT_USAGE = 2

# Access levels that the matcher explicitly handles.
ACCESS_PERMISSION = "permission"
ACCESS_ACTION_PERMISSIONS = "actionPermissions"
ACCESS_PUBLIC = "public"


def _iter_endpoints(doc: Any) -> List[Dict[str, Any]]:
    """Accept either a full PermissionExport object or a bare list of endpoints."""
    if isinstance(doc, dict):
        endpoints = doc.get("endpoints")
        if endpoints is None:
            raise ValueError("permission export object has no 'endpoints' key")
        if not isinstance(endpoints, list):
            raise ValueError("'endpoints' must be a list")
        return endpoints
    if isinstance(doc, list):
        return doc
    raise ValueError("permission export must be a JSON object or a list of endpoints")


def _known_permissions(doc: Any) -> set:
    """Collect every permission key declared in the catalog's resources."""
    known: set = set()
    if isinstance(doc, dict):
        for resource in doc.get("resources", []) or []:
            for action in resource.get("actions", []) or []:
                perm = action.get("permission")
                if perm:
                    known.add(perm)
    return known


def _on_agent_surface(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix + "/")


def _covered(endpoint: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """Mirror the runtime matcher's registration rule.

    CollectFromHumaAPI registers a rule iff the operation has
    actionPermissions, a requiredPermission, or an empty security list (public).
    Returns (covered, reason_when_not_covered).
    """
    permission = endpoint.get("permission") or ""
    action_permissions = endpoint.get("actionPermissions") or {}
    access = endpoint.get("access") or ""

    if permission:
        return True, None
    if action_permissions:
        return True, None
    if access == ACCESS_PUBLIC:
        return True, None

    if access == ACCESS_PERMISSION:
        return False, "declares access=permission but carries an empty permission"
    if access == ACCESS_ACTION_PERMISSIONS:
        return False, "declares access=actionPermissions but carries no action mappings"
    if access == "authenticated":
        return False, (
            "authenticated endpoint carries no arcane:requiredPermission, so the "
            "proxy matcher registers no rule"
        )
    if access == "globalAdmin":
        return False, "globalAdmin-gated endpoint has no permission mapping; matcher skips it"
    if access == "sudo":
        return False, "sudo-gated endpoint has no permission mapping; matcher skips it"
    if access in ("agentToken", "webhookToken", "subjectToken"):
        return False, f"{access}-gated endpoint has no permission mapping; matcher skips it"
    return False, "no access metadata and no permission; matcher registers no rule"


def _referenced_permissions(endpoint: Dict[str, Any]) -> List[str]:
    """Every permission an endpoint cites, in stable order, de-duplicated."""
    refs: List[str] = []
    perm = endpoint.get("permission")
    if perm:
        refs.append(perm)
    for value in sorted((endpoint.get("actionPermissions") or {}).values()):
        if value and value not in refs:
            refs.append(value)
    for condition in endpoint.get("conditionalPermissions") or []:
        cperm = condition.get("permission")
        if cperm and cperm not in refs:
            refs.append(cperm)
    return refs


def analyze(doc: Any, prefix: str = DEFAULT_PREFIX) -> Dict[str, Any]:
    """Run the consistency analysis and return a JSON-serialisable report."""
    endpoints = _iter_endpoints(doc)
    known = _known_permissions(doc)

    uncovered: List[Dict[str, Any]] = []
    dangling: List[Dict[str, Any]] = []
    covered_count = 0
    non_agent = 0

    for endpoint in endpoints:
        path = endpoint.get("path") or ""
        method = (endpoint.get("method") or "").upper()
        if not _on_agent_surface(path, prefix):
            non_agent += 1
            continue

        ok, reason = _covered(endpoint)
        if not ok:
            uncovered.append(
                {
                    "method": method,
                    "path": path,
                    "access": endpoint.get("access") or "",
                    "reason": reason,
                }
            )
            continue

        covered_count += 1
        for perm in _referenced_permissions(endpoint):
            if perm not in known:
                dangling.append(
                    {
                        "method": method,
                        "path": path,
                        "permission": perm,
                        "reason": "permission is referenced by an endpoint but absent from the catalog",
                    }
                )

    uncovered.sort(key=lambda e: (e["path"], e["method"]))
    dangling.sort(key=lambda e: (e["path"], e["method"], e["permission"]))

    agent_endpoints = covered_count + len(uncovered)
    return {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "prefix": prefix,
        "summary": {
            "agentEndpoints": agent_endpoints,
            "covered": covered_count,
            "uncovered": len(uncovered),
            "dangling": len(dangling),
            "ignoredNonAgent": non_agent,
            "ok": not uncovered and not dangling,
        },
        "uncovered": uncovered,
        "dangling": dangling,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "Report agent-proxy endpoints whose permission mapping the runtime "
            "matcher never registers (403 'no known permission mapping')."
        ),
    )
    parser.add_argument("input", help="path to an `arcane permissions` JSON export")
    parser.add_argument(
        "--prefix",
        default=DEFAULT_PREFIX,
        help=f"agent-surface path prefix (default: {DEFAULT_PREFIX})",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="emit the machine-readable report as JSON on stdout",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        with open(args.input, "r", encoding="utf-8") as handle:
            doc = json.load(handle)
    except OSError as exc:
        print(f"{TOOL_NAME}: cannot read input: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except json.JSONDecodeError as exc:
        print(f"{TOOL_NAME}: invalid JSON in input: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except ValueError as exc:
        print(f"{TOOL_NAME}: invalid permission export: {exc}", file=sys.stderr)
        return EXIT_USAGE

    try:
        report = analyze(doc, prefix=args.prefix)
    except ValueError as exc:
        print(f"{TOOL_NAME}: invalid permission export: {exc}", file=sys.stderr)
        return EXIT_USAGE

    summary = report["summary"]
    if args.as_json:
        json.dump(report, sys.stdout, indent=2, sort_keys=False)
        sys.stdout.write("\n")
    else:
        print(
            f"agent endpoints: {summary['agentEndpoints']}  "
            f"covered: {summary['covered']}  "
            f"uncovered: {summary['uncovered']}  "
            f"dangling: {summary['dangling']}"
        )
        for item in report["uncovered"]:
            print(f"  UNCOVERED {item['method']} {item['path']} [{item['access']}]: {item['reason']}")
        for item in report["dangling"]:
            print(f"  DANGLING  {item['method']} {item['path']} -> {item['permission']}: {item['reason']}")

    if summary["uncovered"] or summary["dangling"]:
        return EXIT_ISSUES
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
