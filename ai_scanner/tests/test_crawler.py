from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlsplit

import requests

from crawler import WebCrawler, canonicalize_url


def test_canonicalize_url_collapses_fragment_slash_and_query_order() -> None:
    first = canonicalize_url("http://EXAMPLE.test/path/?b=2&a=1#section")
    second = canonicalize_url("http://example.test/path?a=1&b=2")
    assert first == second == "http://example.test/path?a=1&b=2"


class _EndpointHandler(BaseHTTPRequestHandler):
    seen: list[str] = []
    cookies: list[str] = []

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        query = parse_qs(urlsplit(self.path).query)
        self.__class__.seen.append(self.path)
        self.__class__.cookies.append(self.headers.get("Cookie", ""))
        if path != "/notices.php":
            body = "<html><p>outside</p></html>"
        elif not query:
            body = """<html>
              <a href='/notices.php?mode=write'>write</a>
              <a href='/notices.php?mode=view&id=1'>view1</a>
              <a href='/notices.php?mode=view&id=2'>view2</a>
              <a href='/resources.php'>outside</a>
              <form action='/resources.php' method='post'><input name='outside'></form>
              <form action='/notices.php?mode=edit&id=9' method='get'>
                <input name='keyword'>
              </form>
            </html>"""
        elif query.get("mode") == ["write"]:
            body = """<html><form action='/notices.php?mode=write' method='post' enctype='multipart/form-data'>
              <input type='hidden' name='action' value='create'>
              <input name='title'><textarea name='content'></textarea>
              <input type='file' name='attachment'>
            </form></html>"""
        else:
            body = "<html><p>same endpoint variation</p></html>"
        encoded = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *_args: object) -> None:
        return


def test_endpoint_scope_discovers_same_path_modes_and_deduplicates_ids() -> None:
    _EndpointHandler.seen = []
    _EndpointHandler.cookies = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _EndpointHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        target = f"http://127.0.0.1:{server.server_port}/notices.php"
        session = requests.Session()
        session.headers["Cookie"] = "PHPSESSID=endpoint-test"
        result = WebCrawler(session, max_depth=2, max_pages=10, delay_ms=0).crawl(
            target, scan_mode="endpoint", follow_links=True
        )
        paths = [urlsplit(page.url).path for page in result.pages]
        assert paths and set(paths) == {"/notices.php"}
        urls = [page.url for page in result.pages]
        assert sum("mode=view" in url for url in urls) == 1
        assert any("mode=write" in url for url in urls)
        assert any("mode=edit" in url for url in urls)
        assert len(result.pages) <= 10
        assert _EndpointHandler.cookies and all(cookie == "PHPSESSID=endpoint-test" for cookie in _EndpointHandler.cookies)
        assert all(urlsplit(form.action).path == "/notices.php" for form in result.forms)
        write_form = next(form for form in result.forms if "mode=write" in form.url)
        assert [item.name for item in write_form.inputs] == ["action", "title", "content", "attachment"]
        assert not any("resources.php" in request for request in _EndpointHandler.seen)
    finally:
        server.shutdown()
        thread.join(timeout=2)
