from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import psycopg

from . import config


@dataclass
class Finding:
    rule: str
    severity: str  # low | medium | high | critical
    summary: str
    details: dict[str, Any]


# --- secret_file_access -----------------------------------------------------

# Ordered roughly by how bad it is if this file leaks. First match wins.
SECRET_PATH_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\.aws[/\\]credentials", re.I), "critical"),
    (re.compile(r"id_rsa(\.pub)?$", re.I), "critical"),
    (re.compile(r"\.pem$", re.I), "critical"),
    (re.compile(r"\.git-credentials$", re.I), "high"),
    (re.compile(r"\.ssh[/\\]", re.I), "high"),
    (re.compile(r"(^|[/\\])\.env(\.\w+)?$", re.I), "high"),
    (re.compile(r"credentials\.json$", re.I), "high"),
    (re.compile(r"\.npmrc$", re.I), "medium"),
]


def _secret_path_severity(path: str) -> str | None:
    for pattern, severity in SECRET_PATH_PATTERNS:
        if pattern.search(path):
            return severity
    return None


def secret_file_access(event: dict, conn: psycopg.Connection) -> list[Finding]:
    if event["type"] != "file_read":
        return []
    path = event["payload"].get("path")
    if not isinstance(path, str):
        return []
    severity = _secret_path_severity(path)
    if severity is None:
        return []
    return [
        Finding(
            rule="secret_file_access",
            severity=severity,
            summary=f"Agent read a likely secret-bearing file: {path}",
            details={"path": path},
        )
    ]


# --- rapid_sensitive_reads ---------------------------------------------------


def rapid_sensitive_reads(event: dict, conn: psycopg.Connection) -> list[Finding]:
    if event["type"] != "file_read":
        return []
    path = event["payload"].get("path")
    if not isinstance(path, str) or _secret_path_severity(path) is None:
        return []

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT payload ->> 'path' AS path
            FROM events
            WHERE agent_id = %s
              AND type = 'file_read'
              AND occurred_at <= %s
              AND occurred_at > %s - make_interval(secs => %s)
            """,
            (
                event["agent_id"],
                event["occurred_at"],
                event["occurred_at"],
                config.SENSITIVE_READ_WINDOW_SECONDS,
            ),
        )
        rows = cur.fetchall()

    count = sum(
        1
        for row in rows
        if isinstance(row["path"], str) and _secret_path_severity(row["path"])
    )
    if count < config.SENSITIVE_READ_THRESHOLD:
        return []
    return [
        Finding(
            rule="rapid_sensitive_reads",
            severity="high",
            summary=(
                f"{count} sensitive file reads by this agent in the last "
                f"{config.SENSITIVE_READ_WINDOW_SECONDS}s"
            ),
            details={
                "count": count,
                "window_seconds": config.SENSITIVE_READ_WINDOW_SECONDS,
                "path": path,
            },
        )
    ]


# --- shell_download_execute --------------------------------------------------

SHELL_DOWNLOAD_EXEC_PATTERNS = [
    re.compile(r"(curl|wget)\s+[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh|python[0-9.]*)\b", re.I),
    re.compile(r"base64\s+(-d|--decode)[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh)\b", re.I),
    re.compile(r"(curl|wget)\s+[^\n]*-[oO]\s*\S+\s*(&&|;)\s*(sudo\s+)?(sh|bash|chmod\s+\+x)\b", re.I),
]


def shell_download_execute(event: dict, conn: psycopg.Connection) -> list[Finding]:
    if event["type"] != "shell_command":
        return []
    command = event["payload"].get("command")
    if not isinstance(command, str):
        return []
    for pattern in SHELL_DOWNLOAD_EXEC_PATTERNS:
        if pattern.search(command):
            return [
                Finding(
                    rule="shell_download_execute",
                    severity="critical",
                    summary="Shell command downloads and executes remote code",
                    details={"command": command},
                )
            ]
    return []


# --- disallowed_network_request ----------------------------------------------

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _hostname(url: str) -> str | None:
    parsed = urlparse(url if "://" in url else f"//{url}")
    return parsed.hostname


def disallowed_network_request(event: dict, conn: psycopg.Connection) -> list[Finding]:
    if event["type"] != "http_request":
        return []
    url = event["payload"].get("url")
    if not isinstance(url, str):
        return []
    host = _hostname(url)
    if not host:
        return []
    host = host.lower()
    if host in config.ALLOWED_DOMAINS:
        return []
    # a raw IP skips domain-based allowlisting entirely, treat it as worse
    severity = "high" if _IP_RE.match(host) else "medium"
    return [
        Finding(
            rule="disallowed_network_request",
            severity=severity,
            summary=f"Request to a domain not on the allowlist: {host}",
            details={"url": url, "host": host},
        )
    ]


# --- elevated_tool_call -------------------------------------------------------

ELEVATED_NAME_RE = re.compile(r"(sudo|chmod|chown|grant|elevate|admin|root|permission)", re.I)
ELEVATED_ARG_KEYS = {"sudo", "root", "admin", "elevated", "privileged"}
BROAD_SCOPE_VALUES = {"/", "/*", "**", "*", "c:\\", "c:/"}


def elevated_tool_call(event: dict, conn: psycopg.Connection) -> list[Finding]:
    if event["type"] != "tool_call":
        return []
    name = event["payload"].get("name")
    args = event["payload"].get("args")
    args = args if isinstance(args, dict) else {}

    reasons: list[str] = []
    if isinstance(name, str) and ELEVATED_NAME_RE.search(name):
        reasons.append(f"tool name '{name}' suggests elevated privileges")
    for key, value in args.items():
        if isinstance(key, str) and key.lower() in ELEVATED_ARG_KEYS and value:
            reasons.append(f"arg '{key}' requests elevated access")
        if isinstance(value, str) and value.strip().lower() in BROAD_SCOPE_VALUES:
            reasons.append(f"arg '{key}' targets a broad filesystem scope ({value!r})")

    if not reasons:
        return []
    return [
        Finding(
            rule="elevated_tool_call",
            severity="high",
            summary=f"Tool call requests elevated privileges or broad access: {name}",
            details={"name": name, "args": args, "reasons": reasons},
        )
    ]


ALL_RULES = [
    secret_file_access,
    rapid_sensitive_reads,
    shell_download_execute,
    disallowed_network_request,
    elevated_tool_call,
]
