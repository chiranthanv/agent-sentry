"""Validate policy and resources before any state is reserved."""

import hashlib
import json
import re
from urllib.parse import urlsplit


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def integer(value, name, low=0, high=1_000_000):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an integer in [{low}, {high}]")
    return value


def keys(value, required, optional=()):
    if (
        not isinstance(value, dict)
        or set(value) - set(required) - set(optional)
        or set(required) - set(value)
    ):
        raise ValueError(
            f"Expected fields {sorted(required)}; optional {sorted(optional)}"
        )


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", value):
        raise ValueError(
            "Identifier must contain 1-100 ASCII letters, digits, dots, underscores or hyphens"
        )
    return value


TOOLS = {"file.read", "file.write", "http.get", "mail.send"}


def valid_path(path):
    if not isinstance(path, str) or not path or len(path) > 512:
        return False
    # A portable virtual path, not an OS sandbox. Executors must use the same representation.
    if any(c in path for c in "\\:%\x00") or path.startswith("/"):
        return False
    return all(
        p not in {"", ".", ".."} and not p.endswith((".", " ")) for p in path.split("/")
    )


def validate_policy(policy):
    keys(policy, {"name", "max_calls", "max_units", "tools"})
    identifier(policy["name"])
    integer(policy["max_calls"], "max_calls")
    integer(policy["max_units"], "max_units")
    if not isinstance(policy["tools"], dict) or not policy["tools"]:
        raise ValueError("tools must be a nonempty object")
    for tool, rule in policy["tools"].items():
        if tool not in TOOLS:
            raise ValueError(f"Unsupported tool: {tool}")
        scope_key = (
            "roots"
            if tool.startswith("file.")
            else "hosts"
            if tool == "http.get"
            else "recipients"
        )
        keys(rule, {"units", "approval", scope_key})
        integer(rule["units"], "units", 1)
        if type(rule["approval"]) is not bool:
            raise ValueError("approval must be boolean")
        scope = rule[scope_key]
        if not isinstance(scope, list) or not scope or len(scope) > 100:
            raise ValueError("Scope must contain 1-100 entries")
        for item in scope:
            if scope_key == "roots" and not valid_path(item):
                raise ValueError("Invalid virtual root")
            if scope_key == "hosts" and (
                not isinstance(item, str)
                or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", item)
            ):
                raise ValueError(
                    "Use a lowercase exact DNS hostname without a port or wildcard"
                )
            if scope_key == "recipients" and (
                not isinstance(item, str)
                or not re.fullmatch(r"[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+", item)
            ):
                raise ValueError("Invalid exact email recipient")
    # Detach from caller mutations and reject non-JSON values.
    return json.loads(canonical(policy))


def scope_reason(tool, args, rule):
    """Return a stable denial reason, or None for an in-scope call."""
    try:
        if tool.startswith("file."):
            keys(args, {"path"}, {"content"} if tool == "file.write" else ())
            if tool == "file.write" and (
                "content" not in args
                or not isinstance(args["content"], str)
                or len(args["content"]) > 16_384
            ):
                return "invalid_arguments"
            path = args["path"]
            if not valid_path(path):
                return "invalid_path"
            if not any(
                path == root or path.startswith(root + "/") for root in rule["roots"]
            ):
                return "path_outside_scope"
        elif tool == "http.get":
            keys(args, {"url"})
            url = args["url"]
            if (
                not isinstance(url, str)
                or len(url) > 2048
                or any(ord(c) < 33 for c in url)
                or "\\" in url
            ):
                return "invalid_url"
            parts = urlsplit(url)
            if (
                parts.scheme != "https"
                or parts.username is not None
                or parts.password is not None
                or parts.port not in (None, 443)
                or parts.fragment
            ):
                return "invalid_url"
            if parts.hostname not in rule["hosts"]:
                return "host_outside_scope"
        elif tool == "mail.send":
            keys(args, {"to", "subject", "body"})
            if not all(isinstance(v, str) and len(v) <= 16_384 for v in args.values()):
                return "invalid_arguments"
            if args["to"] not in rule["recipients"]:
                return "recipient_outside_scope"
    except (ValueError, TypeError):
        return "invalid_arguments"
    return None
