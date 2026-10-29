"""Render the Markdown audit report to a paginated PDF using ReportLab."""
from html import escape
from pathlib import Path
import re

import reportlab
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import LongTable, PageBreak, Paragraph, Preformatted, SimpleDocTemplate, Spacer, TableStyle

ROOT = Path(__file__).resolve().parents[1]


def inline(value):
    value = escape(value)
    value = re.sub(r"`([^`]+)`", r'<font name="Courier" size="8">\1</font>', value)
    value = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", value)
    value = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<link href="\2" color="#155b4c">\1</link>', value)
    return value


def main():
    source = ROOT / "reports" / "SYSTEM_REPORT.md"
    destination = source.with_suffix(".pdf")
    # Embed ReportLab's bundled fonts for consistent rendering on other computers.
    fonts = Path(reportlab.__file__).resolve().parent / "fonts"
    for name, filename in (("LabSans", "Vera.ttf"), ("LabSans-Bold", "VeraBd.ttf"), ("LabSans-Italic", "VeraIt.ttf"), ("LabSans-BoldItalic", "VeraBI.ttf")):
        pdfmetrics.registerFont(TTFont(name, str(fonts / filename)))
    pdfmetrics.registerFontFamily("LabSans", normal="LabSans", bold="LabSans-Bold", italic="LabSans-Italic", boldItalic="LabSans-BoldItalic")
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportBody", fontName="LabSans", fontSize=9.3, leading=14.3, spaceAfter=9, textColor=colors.HexColor("#20382f")))
    styles.add(ParagraphStyle(name="ReportTitle", fontName="LabSans-Bold", fontSize=27, leading=33, textColor=colors.HexColor("#155b4c"), spaceAfter=22))
    styles.add(ParagraphStyle(name="ReportH2", fontName="LabSans-Bold", fontSize=16, leading=22, spaceBefore=14, spaceAfter=12, keepWithNext=True, textColor=colors.HexColor("#155b4c")))
    styles.add(ParagraphStyle(name="ReportH3", fontName="LabSans-Bold", fontSize=10.5, leading=15, spaceBefore=10, spaceAfter=7, keepWithNext=True))
    styles.add(ParagraphStyle(name="ReportBullet", parent=styles["ReportBody"], leftIndent=12, firstLineIndent=-9))
    styles.add(ParagraphStyle(name="ReportCode", fontName="Courier", fontSize=7.5, leading=11, backColor=colors.HexColor("#f0f4ee"), borderPadding=8, spaceBefore=7, spaceAfter=14))
    styles.add(ParagraphStyle(name="ReportCell", parent=styles["ReportBody"], fontSize=8, leading=11, spaceAfter=0))
    doc = SimpleDocTemplate(str(destination), pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm, topMargin=24 * mm, bottomMargin=22 * mm, title="Custom ML Network IDS - CodeAlpha Task 4", author="CodeAlpha Custom Network IDS", subject="Custom capture, rules, ML benchmark, live verification, and limitations")
    story, lines = [], source.read_text().splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        if line.startswith("```"):
            block = []
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                block.append(lines[i])
                i += 1
            story.append(Preformatted("\n".join(block), styles["ReportCode"], maxLineLength=94, splitChars=" /", newLineChars="    "))
        elif line.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                cells = [cell.strip() for cell in lines[i].strip().strip("|").split("|")]
                if not all(re.fullmatch(r"[: -]+", cell) for cell in cells):
                    rows.append([Paragraph(inline(cell), styles["ReportCell"]) for cell in cells])
                i += 1
            count = len(rows[0])
            widths = [doc.width / count] * count
            if count == 4:
                widths = [doc.width * ratio for ratio in (0.14, 0.40, 0.16, 0.30)]
            table = LongTable(rows, colWidths=widths, repeatRows=1, hAlign="LEFT")
            table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dcece1")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd6cc")), ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7), ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7)]))
            story.extend([table, Spacer(1, 10)])
            continue
        elif line.startswith("# "):
            story.append(Paragraph(inline(line[2:]), styles["ReportTitle"]))
        elif line.startswith("## "):
            if line.startswith(("## Detection", "## Machine", "## Verification", "## Operating")):
                story.append(PageBreak())
            story.append(Paragraph(inline(line[3:]), styles["ReportH2"]))
        elif line.startswith("### "):
            story.append(Paragraph(inline(line[4:]), styles["ReportH3"]))
        elif line.startswith("- "):
            story.append(Paragraph("• " + inline(line[2:]), styles["ReportBullet"]))
        else:
            paragraph = [line]
            while i + 1 < len(lines) and lines[i + 1].strip() and not lines[i + 1].startswith(("#", "- ", "|", "```")):
                i += 1
                paragraph.append(lines[i])
            story.append(Paragraph(inline(" ".join(paragraph)), styles["ReportBody"]))
        i += 1

    def page_decoration(canvas, document):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#b8cebe"))
        canvas.line(20 * mm, 281 * mm, 190 * mm, 281 * mm)
        canvas.setFont("LabSans-Bold", 8)
        canvas.setFillColor(colors.HexColor("#155b4c"))
        canvas.drawString(20 * mm, 285 * mm, "CODEALPHA / TASK 04")
        canvas.setFont("LabSans", 8)
        canvas.drawRightString(190 * mm, 285 * mm, "CUSTOM NETWORK IDS + ML")
        canvas.setFillColor(colors.HexColor("#607569"))
        canvas.drawString(20 * mm, 13 * mm, "Local training system | Measured results | 29 October 2026")
        canvas.drawRightString(190 * mm, 13 * mm, f"{document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=page_decoration, onLaterPages=page_decoration)
    print(f"Created {destination.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
