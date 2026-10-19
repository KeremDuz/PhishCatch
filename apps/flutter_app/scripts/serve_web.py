from __future__ import annotations

import argparse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class FlutterWebHandler(SimpleHTTPRequestHandler):
    def end_headers(self):  # type: ignore[override]
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def send_head(self):  # type: ignore[override]
        path = self.translate_path(self.path)
        requested = Path(path)
        if not requested.exists() and "." not in Path(self.path.split("?", 1)[0]).name:
            self.path = "/index.html"
        return super().send_head()


def main() -> int:
    parser = argparse.ArgumentParser(description="Serve Flutter web build with SPA fallback.")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--directory", default="build/web")
    args = parser.parse_args()

    directory = Path(args.directory).resolve()
    handler = lambda *handler_args, **handler_kwargs: FlutterWebHandler(  # noqa: E731
        *handler_args,
        directory=str(directory),
        **handler_kwargs,
    )
    server = ThreadingHTTPServer((args.host, args.port), handler)
    print(f"Serving {directory} on http://{args.host}:{args.port}")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
