#!/usr/bin/env python3
"""Build a clean PDF from attested-custody-preprint.md.

Usage:
  python3 whitepaper/build_pdf.py
"""

from __future__ import annotations

import re
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    ListFlowable,
    ListItem,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

SCRIPT_DIR = Path(__file__).resolve().parent
SRC = SCRIPT_DIR / "attested-custody-preprint.md"
OUT = SCRIPT_DIR / "attested-custody-preprint.pdf"


def add_page_num(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 9)
    canvas.drawRightString(7.7 * inch, 0.45 * inch, f"Page {doc.page}")
    canvas.restoreState()


def is_ordered_item(line: str) -> bool:
    return re.match(r"^\s*\d+\.\s+", line) is not None


def is_bullet_item(line: str) -> bool:
    return re.match(r"^\s*[-*]\s+", line) is not None


def is_table_row(line: str) -> bool:
    return line.strip().startswith("|")


def escape_inline(text: str) -> str:
    p = text
    p = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", p)
    p = re.sub(r"\*(.+?)\*", r"<i>\1</i>", p)
    p = p.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    p = p.replace("&lt;b&gt;", "<b>").replace("&lt;/b&gt;", "</b>")
    p = p.replace("&lt;i&gt;", "<i>").replace("&lt;/i&gt;", "</i>")
    return p


def parse_blocks(text: str):
    lines = text.splitlines()
    blocks = []
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        stripped = line.strip()

        if not stripped:
            i += 1
            continue

        if stripped.startswith("```"):
            i += 1
            code = []
            while i < len(lines) and not lines[i].strip().startswith("```"):
                code.append(lines[i].rstrip("\n"))
                i += 1
            if i < len(lines):
                i += 1
            blocks.append(("code", "\n".join(code)))
            continue

        if stripped == "---":
            blocks.append(("hr", ""))
            i += 1
            continue

        if line.startswith("# "):
            blocks.append(("title", line[2:].strip()))
            i += 1
            continue
        if line.startswith("## "):
            blocks.append(("h1", line[3:].strip()))
            i += 1
            continue
        if line.startswith("### "):
            blocks.append(("h2", line[4:].strip()))
            i += 1
            continue

        if is_bullet_item(line):
            items = []
            while i < len(lines):
                cur = lines[i].rstrip()
                if not cur.strip():
                    i += 1
                    break
                if is_bullet_item(cur):
                    items.append(re.sub(r"^\s*[-*]\s+", "", cur).strip())
                elif items:
                    items[-1] += " " + cur.strip()
                else:
                    break
                i += 1
            blocks.append(("ul", items))
            continue

        if is_ordered_item(line):
            items = []
            while i < len(lines):
                cur = lines[i].rstrip()
                if not cur.strip():
                    i += 1
                    break
                if is_ordered_item(cur):
                    items.append(re.sub(r"^\s*\d+\.\s+", "", cur).strip())
                elif items:
                    items[-1] += " " + cur.strip()
                else:
                    break
                i += 1
            blocks.append(("ol", items))
            continue

        if is_table_row(line):
            rows = []
            while i < len(lines) and is_table_row(lines[i].rstrip()):
                rows.append(lines[i].rstrip())
                i += 1
            blocks.append(("table", rows))
            continue

        para = [line.strip()]
        i += 1
        while i < len(lines):
            nxt = lines[i].rstrip()
            n = nxt.strip()
            if (
                not n
                or n == "---"
                or nxt.startswith("# ")
                or nxt.startswith("## ")
                or nxt.startswith("### ")
                or is_bullet_item(nxt)
                or is_ordered_item(nxt)
                or is_table_row(nxt)
                or n.startswith("```")
            ):
                break
            para.append(nxt.strip())
            i += 1
        blocks.append(("p", " ".join(para)))
    return blocks


def build():
    text = SRC.read_text(encoding="utf-8")
    blocks = parse_blocks(text)

    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="TitleCenter",
            parent=styles["Title"],
            alignment=TA_CENTER,
            spaceAfter=12,
        )
    )
    styles.add(
        ParagraphStyle(
            name="H1",
            parent=styles["Heading1"],
            fontSize=14,
            spaceBefore=10,
            spaceAfter=6,
        )
    )
    styles.add(
        ParagraphStyle(
            name="H2",
            parent=styles["Heading2"],
            fontSize=12,
            spaceBefore=8,
            spaceAfter=4,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Body",
            parent=styles["BodyText"],
            fontSize=10.5,
            leading=13,
            spaceAfter=4,
        )
    )
    styles.add(
        ParagraphStyle(
            name="CodeBlock",
            parent=styles["Code"],
            fontSize=8.8,
            leading=10.5,
            leftIndent=8,
            rightIndent=8,
            backColor=colors.whitesmoke,
            spaceBefore=4,
            spaceAfter=6,
        )
    )

    story = []

    for kind, data in blocks:
        if kind == "title":
            story.append(Paragraph(escape_inline(data), styles["TitleCenter"]))
            continue
        if kind == "h1":
            story.append(Paragraph(escape_inline(data), styles["H1"]))
            continue
        if kind == "h2":
            story.append(Paragraph(escape_inline(data), styles["H2"]))
            continue
        if kind == "hr":
            story.append(Spacer(1, 0.12 * inch))
            continue
        if kind == "code":
            story.append(Preformatted(data, styles["CodeBlock"]))
            continue
        if kind == "p":
            story.append(Paragraph(escape_inline(data), styles["Body"]))
            continue
        if kind in {"ul", "ol"}:
            items = [
                ListItem(Paragraph(escape_inline(item), styles["Body"]))
                for item in data
                if item
            ]
            if items:
                story.append(
                    ListFlowable(
                        items,
                        bulletType="bullet" if kind == "ul" else "1",
                        leftIndent=16,
                    )
                )
                story.append(Spacer(1, 0.04 * inch))
            continue
        if kind == "table":
            raw_rows = data
            rows = []
            for idx, row in enumerate(raw_rows):
                cols = [c.strip() for c in row.strip().strip("|").split("|")]
                if idx == 1 and all(re.match(r"^:?-{2,}:?$", c) for c in cols):
                    continue
                rows.append(cols)
            if rows:
                max_cols = max(len(r) for r in rows)
                for r in rows:
                    while len(r) < max_cols:
                        r.append("")
                tbl = Table(rows, hAlign="LEFT")
                tbl.setStyle(
                    TableStyle(
                        [
                            ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 9),
                            ("FONT", (0, 1), (-1, -1), "Helvetica", 8.7),
                            ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f2f2f2")),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("LEFTPADDING", (0, 0), (-1, -1), 4),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                        ]
                    )
                )
                story.append(tbl)
                story.append(Spacer(1, 0.06 * inch))

    doc = SimpleDocTemplate(
        str(OUT),
        pagesize=LETTER,
        rightMargin=0.8 * inch,
        leftMargin=0.8 * inch,
        topMargin=0.8 * inch,
        bottomMargin=0.7 * inch,
    )
    doc.build(story, onFirstPage=add_page_num, onLaterPages=add_page_num)
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    build()
