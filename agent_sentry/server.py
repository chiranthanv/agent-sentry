"""Loopback-only development API; approvals stay in the operator CLI."""

import hmac
import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from urllib.parse import parse_qs, urlsplit

from .policy import keys
from .store import Conflict

LOG = logging.getLogger(__name__)


def strict_json(raw):
    def pairs(items):
        obj = {}
        for key, value in items:
            if key in obj:
                raise ValueError("Duplicate JSON field")
            obj[key] = value
        return obj

    def invalid(value):
        raise ValueError(f"Non-finite JSON number: {value}")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def make_server(store, token, port=8765):
    if not isinstance(token, str) or len(token) < 32 or not token.isascii():
        raise ValueError("API token must have at least 32 ASCII characters")

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def log_message(self, fmt, *args):
            # Do not log request targets, bodies, Authorization, or URL queries.
            LOG.info("http method=%s", self.command)

        def send(self, status, data, content_type="application/json"):
            body = (
                json.dumps(data, allow_nan=False).encode()
                if content_type == "application/json"
                else data
            )
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
            )
            self.end_headers()
            self.wfile.write(body)

        def dispatch(self):
            expected_hosts = {
                f"127.0.0.1:{self.server.server_port}",
                f"localhost:{self.server.server_port}",
            }
            if self.headers.get("Host") not in expected_hosts:
                self.send(403, {"error": "Invalid Host"})
                return
            origin = self.headers.get("Origin")
            if origin and origin not in {"http://" + h for h in expected_hosts}:
                self.send(403, {"error": "Cross-origin requests are disabled"})
                return
            target = urlsplit(self.path)
            assets = {
                "/": ("dashboard.html", "text/html; charset=utf-8"),
                "/app.js": ("app.js", "application/javascript"),
                "/style.css": ("style.css", "text/css"),
            }
            if self.command == "GET" and target.path in assets:
                filename, content_type = assets[target.path]
                self.send(
                    200,
                    files("agent_sentry.web").joinpath(filename).read_bytes(),
                    content_type,
                )
                return
            supplied = self.headers.get("Authorization", "")
            if (
                len(self.headers.get_all("Authorization", [])) != 1
                or not supplied.isascii()
                or not hmac.compare_digest(supplied, "Bearer " + token)
            ):
                self.send(401, {"error": "Bearer token required"})
                return
            if self.command == "GET":
                if target.path == "/v1/sessions":
                    self.send(200, {"sessions": store.sessions()})
                elif target.path == "/v1/events":
                    query = parse_qs(target.query)
                    if set(query) - {"after", "limit"} or any(
                        len(v) != 1 for v in query.values()
                    ):
                        raise ValueError("Invalid pagination")
                    self.send(
                        200,
                        {
                            "events": store.events(
                                int(query.get("after", [0])[0]),
                                int(query.get("limit", [100])[0]),
                            )
                        },
                    )
                elif target.path == "/v1/verify":
                    self.send(200, store.verify())
                else:
                    self.send(404, {"error": "Not found"})
            elif target.path == "/v1/authorize":
                lengths = self.headers.get_all("Content-Length", [])
                if self.headers.get("Transfer-Encoding") or len(lengths) != 1:
                    raise ValueError(
                        "One Content-Length is required; chunking is unsupported"
                    )
                length = int(lengths[0])
                if not 1 <= length <= 65_536:
                    self.send(413, {"error": "Body must be 1-65536 bytes"})
                    return
                if (
                    self.headers.get("Content-Type", "").split(";")[0].strip()
                    != "application/json"
                ):
                    self.send(415, {"error": "Use application/json"})
                    return
                data = strict_json(self.rfile.read(length))
                keys(data, {"session", "request_id", "tool", "arguments"}, {"approval"})
                self.send(200, store.authorize(**data))
            else:
                self.send(404, {"error": "Not found"})

        def handle_request(self):
            try:
                self.dispatch()
            except Conflict as exc:
                self.send(409, {"error": str(exc)})
            except KeyError:
                self.send(404, {"error": "Unknown session"})
            except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
                self.send(400, {"error": str(exc)[:200]})
            except (BrokenPipeError, ConnectionError, TimeoutError):
                return
            except Exception:
                LOG.exception("Request failed")
                self.send(500, {"error": "Internal server error"})

        do_GET = handle_request
        do_POST = handle_request

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    return server
