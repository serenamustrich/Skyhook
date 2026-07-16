#!/usr/bin/env python3
"""Export Mihomo/Sparkle proxy delay probes in a Supercore-comparable shape."""

from __future__ import annotations

import argparse
import json
import subprocess
import urllib.parse
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List


SYSTEM_PROXIES = {
    "DIRECT",
    "REJECT",
    "GLOBAL",
    "PASS",
    "REJECT-DROP",
    "COMPATIBLE",
}
SYSTEM_PROXY_TYPES = {"Direct", "Reject", "RejectDrop", "Pass", "Compatible"}


def read_json(urlopen: urllib.request.OpenerDirector, request: urllib.request.Request) -> Dict[str, Any]:
    with urlopen.open(request) as response:
        data = response.read()
        text = data.decode("utf-8")
        return json.loads(text)


def request_json(opener: urllib.request.OpenerDirector, request: urllib.request.Request, timeout_seconds: float) -> Dict[str, Any]:
    request.timeout = timeout_seconds
    return read_json(opener, request)


def request_json_unix_socket(
    unix_socket: str,
    base_url: str,
    path: str,
    headers: Dict[str, str],
    timeout_seconds: float,
) -> Dict[str, Any]:
    target = make_api_url(base_url, path)
    command = [
        "curl",
        "--silent",
        "--show-error",
        "--max-time",
        f"{timeout_seconds}",
        "--include",
        "--request",
        "GET",
        "--write-out",
        "\nHTTP_STATUS:%{http_code}",
        "--unix-socket",
        unix_socket,
        target,
    ]
    for key, value in headers.items():
        command.extend(["-H", f"{key}: {value}"])

    proc = subprocess.run(command, capture_output=True, text=True)
    output = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()
    if proc.returncode != 0:
        raise RuntimeError(stderr or output)

    if "HTTP_STATUS:" not in output:
        raise RuntimeError(f"invalid curl response: {output}")

    body_text, status_text = output.rsplit("HTTP_STATUS:", 1)
    status = int((status_text or "0").strip())

    if "\r\n\r\n" in body_text:
        _, body = body_text.split("\r\n\r\n", 1)
    elif "\n\n" in body_text:
        _, body = body_text.split("\n\n", 1)
    else:
        body = body_text

    if status >= 400:
        raise urllib.error.HTTPError(
            target,
            status,
            body[:1024],
            headers={
                "Content-Type": "application/json",
            },
            fp=None,
        )
    return json.loads(body)


def decode_failure_kind(error_message: str | None, status_code: int | None = None) -> str | None:
    if error_message is None and status_code is None:
        return None
    if status_code is not None and status_code >= 500:
        return "http_status"
    if status_code is not None and status_code >= 400:
        return "http_status"
    if not error_message:
        return "probe_failed"
    msg = error_message.lower()
    if "timeout" in msg:
        return "timeout"
    if "not found" in msg:
        return "outbound_not_found"
    if "unsupported" in msg or "not supported" in msg:
        return "protocol_unsupported"
    if "dns" in msg:
        return "dns_error"
    if "tls" in msg:
        return "tls_error"
    return "probe_failed"


def make_api_url(base_url: str, path: str) -> str:
    path = path.lstrip("/")
    return f"{base_url.rstrip('/')}/{path}"


def request_delay(
    opener: urllib.request.OpenerDirector | None,
    unix_socket: str | None,
    base_url: str,
    secret: str,
    name: str,
    timeout_ms: int,
    url: str,
) -> Dict[str, Any]:
    encoded_name = urllib.parse.quote(name, safe="")
    path = f"proxies/{encoded_name}/delay?timeout={timeout_ms}&url={urllib.parse.quote(url, safe='')}"
    headers = {}
    if secret:
        headers["Authorization"] = f"Bearer {secret}"

    timeout_seconds = max(0.5, timeout_ms / 1000.0 + 1.5)
    try:
        if unix_socket:
            payload = request_json_unix_socket(
                unix_socket=unix_socket,
                base_url=base_url,
                path=path,
                headers=headers,
                timeout_seconds=timeout_seconds,
            )
        else:
            request = urllib.request.Request(make_api_url(base_url, path), method="GET")
            if secret:
                request.add_header("Authorization", f"Bearer {secret}")
            payload = request_json(opener, request, timeout_seconds)

        delay = payload.get("delay")
        if isinstance(delay, int):
            return {
                "name": name,
                "success": delay >= 0,
                "latency_ms": delay,
                "failure_kind": None if delay >= 0 else "probe_failed",
                "error": None,
            }
        return {
            "name": name,
            "success": False,
            "latency_ms": None,
            "failure_kind": "probe_failed",
            "error": f"unexpected delay payload: {payload!r}",
        }
    except urllib.error.HTTPError as error:
        try:
            body = error.read().decode("utf-8") if error.fp is not None else error.msg
        except Exception:
            body = str(error)
        return {
            "name": name,
            "success": False,
            "latency_ms": None,
            "failure_kind": decode_failure_kind(body, status_code=error.code),
            "error": body or str(error),
        }
    except Exception as error:
        message = str(error)
        return {
            "name": name,
            "success": False,
            "latency_ms": None,
            "failure_kind": decode_failure_kind(message),
            "error": message,
        }


def list_nodes(
    opener: urllib.request.OpenerDirector | None,
    base_url: str,
    secret: str,
    unix_socket: str | None = None,
) -> List[str]:
    headers = {}
    if secret:
        headers["Authorization"] = f"Bearer {secret}"

    if unix_socket:
        payload = request_json_unix_socket(
            unix_socket=unix_socket,
            base_url=base_url,
            path="proxies",
            headers=headers,
            timeout_seconds=5.0,
        )
    else:
        request = urllib.request.Request(make_api_url(base_url, "proxies"), method="GET")
        if secret:
            request.add_header("Authorization", f"Bearer {secret}")
        payload = request_json(opener, request, timeout_seconds=5.0)

    proxies = payload.get("proxies", {})
    if not isinstance(proxies, dict):
        return []

    leaves: List[str] = []
    for name, value in proxies.items():
        if not isinstance(name, str) or not isinstance(value, dict):
            continue
        if name in SYSTEM_PROXIES:
            continue
        if value.get("type") in SYSTEM_PROXY_TYPES:
            continue
        all_members = value.get("all")
        if isinstance(all_members, list) and all_members:
            # Group node
            continue
        leaves.append(name)
    return sorted(leaves)


def read_names_file(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as handle:
        return [line.strip() for line in handle if line.strip()]


def export_probe(
    base_url: str,
    secret: str,
    timeout_ms: int,
    probe_test_url: str,
    max_workers: int,
    names_file: str | None = None,
    unix_socket: str | None = None,
) -> List[Dict[str, Any]]:
    opener = None if unix_socket else urllib.request.build_opener()

    if names_file:
        nodes = read_names_file(names_file)
    else:
        nodes = list_nodes(opener, base_url, secret, unix_socket=unix_socket)

    if not nodes:
        return []

    results: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, max_workers)) as executor:
        futures = [
            executor.submit(
                request_delay,
                opener,
                unix_socket,
                base_url,
                secret,
                name,
                timeout_ms,
                probe_test_url,
            )
            for name in nodes
        ]
        for future in as_completed(futures):
            record = future.result()
            if record is not None:
                results.append(record)

    results.sort(key=lambda item: item["name"].lower())
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Export mihomo/sparkle probe result samples")
    parser.add_argument("--base-url", default="http://127.0.0.1:9090", help="Mihomo external-controller base url, e.g. http://127.0.0.1:9090")
    parser.add_argument("--unix-socket", default=None, help="Mihomo external-controller Unix socket path, e.g. /tmp/mihomo.sock")
    parser.add_argument("--secret", default="", help="Mihomo external-controller secret (Bearer token)")
    parser.add_argument("--timeout-ms", type=int, default=500, help="Probe timeout in ms")
    parser.add_argument("--url", default="http://www.gstatic.com/generate_204", help="Probe URL")
    parser.add_argument("--output", required=True, help="Output JSON path")
    parser.add_argument("--names", default=None, help="Optional file of node names to probe, one name per line")
    parser.add_argument("--max-workers", type=int, default=32, help="并发请求数")
    args = parser.parse_args()

    if args.unix_socket is None and not args.base_url:
        raise SystemExit("must provide --base-url (http mode) or --unix-socket (unix mode)")

    results = export_probe(
        base_url=args.base_url,
        secret=args.secret,
        timeout_ms=args.timeout_ms,
        probe_test_url=args.url,
        max_workers=args.max_workers,
        names_file=args.names,
        unix_socket=args.unix_socket,
    )
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(
            results,
            handle,
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
        )
    print(f"Exported {len(results)} probe entries to {args.output}")


if __name__ == "__main__":
    main()
