"""Generate docs/CODEBASE_EXPLAINED.pdf without external PDF dependencies."""

from __future__ import annotations

import textwrap
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE = PROJECT_ROOT / "docs" / "CODEBASE_EXPLAINED.md"
OUTPUT = PROJECT_ROOT / "docs" / "CODEBASE_EXPLAINED.pdf"

PAGE_WIDTH = 612
PAGE_HEIGHT = 792
LEFT = 54
TOP = 738
LINE_HEIGHT = 12
FONT_SIZE = 9
TITLE_SIZE = 18
HEADER_SIZE = 12
MAX_CHARS = 94


def main() -> int:
    lines = SOURCE.read_text(encoding="utf-8").splitlines()
    pages: list[list[tuple[str, int]]] = []
    current: list[tuple[str, int]] = []
    y_lines = 0

    for raw_line in lines:
        style = _style_for_line(raw_line)
        cleaned = _clean_line(raw_line)
        wrapped = _wrap_line(cleaned, style)
        if not wrapped:
            wrapped = [""]
        for line in wrapped:
            if y_lines >= 55:
                pages.append(current)
                current = []
                y_lines = 0
            current.append((line, style))
            y_lines += 1
    if current:
        pages.append(current)

    pdf = _build_pdf(pages)
    OUTPUT.write_bytes(pdf)
    print(f"Wrote {OUTPUT}")
    return 0


def _style_for_line(line: str) -> int:
    if line.startswith("# "):
        return TITLE_SIZE
    if line.startswith("## "):
        return HEADER_SIZE
    return FONT_SIZE


def _clean_line(line: str) -> str:
    if line.startswith("# "):
        return line[2:]
    if line.startswith("## "):
        return line[3:]
    if line.startswith("### "):
        return line[4:]
    return line


def _wrap_line(line: str, style: int) -> list[str]:
    if not line:
        return []
    width = 72 if style >= HEADER_SIZE else MAX_CHARS
    return textwrap.wrap(line, width=width, replace_whitespace=False, drop_whitespace=False)


def _build_pdf(pages: list[list[tuple[str, int]]]) -> bytes:
    objects: list[bytes] = []

    def add(obj: bytes) -> int:
        objects.append(obj)
        return len(objects)

    font_obj = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    page_refs = []
    for page in pages:
        content = _page_content(page)
        content_obj = add(
            b"<< /Length " + str(len(content)).encode("ascii") + b" >>\nstream\n" + content + b"\nendstream"
        )
        page_refs.append((content_obj, None))

    pages_obj_index = len(objects) + len(page_refs) + 1
    page_obj_nums = []
    for content_obj, _ in page_refs:
        page_obj_nums.append(
            add(
                (
                    f"<< /Type /Page /Parent {pages_obj_index} 0 R "
                    f"/MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] "
                    f"/Resources << /Font << /F1 {font_obj} 0 R >> >> "
                    f"/Contents {content_obj} 0 R >>"
                ).encode("ascii")
            )
        )

    kids = " ".join(f"{num} 0 R" for num in page_obj_nums)
    pages_obj = add(f"<< /Type /Pages /Kids [{kids}] /Count {len(page_obj_nums)} >>".encode("ascii"))
    catalog_obj = add(f"<< /Type /Catalog /Pages {pages_obj} 0 R >>".encode("ascii"))

    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode("ascii"))
        output.extend(obj)
        output.extend(b"\nendobj\n")

    xref_offset = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        (
            "trailer\n"
            f"<< /Size {len(objects) + 1} /Root {catalog_obj} 0 R >>\n"
            "startxref\n"
            f"{xref_offset}\n"
            "%%EOF\n"
        ).encode("ascii")
    )
    return bytes(output)


def _page_content(page: list[tuple[str, int]]) -> bytes:
    commands = ["BT", f"{LEFT} {TOP} Td"]
    current_size = FONT_SIZE
    commands.append(f"/F1 {current_size} Tf")
    for index, (line, size) in enumerate(page):
        if index > 0:
            commands.append(f"0 -{LINE_HEIGHT} Td")
        if size != current_size:
            commands.append(f"/F1 {size} Tf")
            current_size = size
        commands.append(f"({_escape_pdf_text(line)}) Tj")
    commands.append("ET")
    return "\n".join(commands).encode("latin-1", errors="replace")


def _escape_pdf_text(text: str) -> str:
    safe = text.encode("latin-1", errors="replace").decode("latin-1")
    return safe.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


if __name__ == "__main__":
    raise SystemExit(main())
