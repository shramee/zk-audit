#!/usr/bin/env python3
"""Render docs/x-ray/architecture.json to architecture.svg.

Deterministic, standard library only. Colors are CSS classes with a light
default and a prefers-color-scheme: dark override; every element sits on an
opaque background, so the diagram stays readable when a viewer ignores the
media query.

Usage: python3 gen_architecture.py [architecture.json] [architecture.svg]
"""
import json
import os
import sys
from xml.sax.saxutils import escape

HERE = os.path.dirname(os.path.abspath(__file__))

STYLE = """
.bg{fill:#ffffff}
.t{font:600 13px -apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;fill:#1f2328}
.s{font:italic 11px -apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;fill:#57606a}
.l{font:11px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;fill:#1f2328}
.h{font:700 16px -apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;fill:#1f2328}
.f{font:11px -apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;fill:#57606a}
.e{fill:none;stroke:#0969da;stroke-width:1.4}
.el{font:10.5px -apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;fill:#0550ae}
.ah{fill:#0969da}
.b{fill:none;stroke:#cf222e;stroke-width:1.2;stroke-dasharray:6 4}
.bl{font:600 10.5px -apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;fill:#cf222e}
.k-actor{fill:#f6f8fa;stroke:#57606a}
.k-external{fill:#f6f8fa;stroke:#8c959f;stroke-dasharray:3 2}
.k-kb{fill:#fbefff;stroke:#8250df}
.k-core{fill:#ddf4ff;stroke:#0969da}
.k-tool{fill:#dafbe1;stroke:#1a7f37}
.k-out{fill:#fff8c5;stroke:#9a6700}
.k-repo{fill:#ffebe9;stroke:#cf222e}
.k-agent{fill:#f6f8fa;stroke:#57606a}
.k-exec{fill:#ffebe9;stroke:#cf222e}
@media (prefers-color-scheme: dark){
.bg{fill:#0d1117}
.t,.l,.h{fill:#e6edf3}
.s,.f{fill:#9198a1}
.e{stroke:#4493f8}
.el{fill:#79c0ff}
.ah{fill:#4493f8}
.b{stroke:#f85149}
.bl{fill:#ff7b72}
.k-actor,.k-agent{fill:#161b22;stroke:#8b949e}
.k-external{fill:#161b22;stroke:#6e7681}
.k-kb{fill:#271a3d;stroke:#a371f7}
.k-core{fill:#0c2d4a;stroke:#4493f8}
.k-tool{fill:#0f2a1a;stroke:#3fb950}
.k-out{fill:#2e2510;stroke:#d29922}
.k-repo,.k-exec{fill:#2d1214;stroke:#f85149}
}
"""


def text(x, y, cls, s):
    return f'<text x="{x}" y="{y}" class="{cls}">{escape(s)}</text>'


def render(spec):
    w, h = spec["width"], spec["height"]
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-labelledby="title">',
        f'<title id="title">{escape(spec["title"])}</title>',
        f"<style>{STYLE}</style>",
        '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        '<path d="M0,0 L10,5 L0,10 z" class="ah"/></marker></defs>',
        f'<rect class="bg" x="0" y="0" width="{w}" height="{h}"/>',
        text(20, 30, "h", spec["title"]),
        text(20, 50, "f", spec["subtitle"]),
    ]
    for b in spec["boundaries"]:
        out.append(f'<rect class="b" x="{b["x"]}" y="{b["y"]}" width="{b["w"]}" height="{b["h"]}" rx="8"/>')
        out.append(text(b["x"] + 8, b["y"] + b["h"] - 6, "bl", b["label"]))
    for n in spec["nodes"]:
        x, y = n["x"], n["y"]
        out.append(f'<rect class="k-{n["kind"]}" x="{x}" y="{y}" width="{n["w"]}" height="{n["h"]}" rx="6" stroke-width="1.2"/>')
        out.append(text(x + 10, y + 20, "t", n["title"]))
        out.append(text(x + 10, y + 36, "s", n["sub"]))
        for i, line in enumerate(n.get("lines", [])):
            out.append(text(x + 10, y + 56 + 16 * i, "l", line))
    for e in spec["edges"]:
        pts = " ".join(f"{px},{py}" for px, py in e["points"])
        out.append(f'<polyline class="e" points="{pts}" marker-end="url(#arrow)"/>')
        if e["label"]:
            out.append(text(e["lx"], e["ly"], "el", e["label"]))
    fy = h - 18 * len(spec["footer"]) - 6
    for i, line in enumerate(spec["footer"]):
        out.append(text(20, fy + 18 * i, "f", line))
    out.append("</svg>")
    return "\n".join(out) + "\n"


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "architecture.json")
    dst = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "architecture.svg")
    with open(src, encoding="utf-8") as f:
        spec = json.load(f)
    with open(dst, "w", encoding="utf-8") as f:
        f.write(render(spec))


if __name__ == "__main__":
    main()
