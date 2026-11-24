"""Text extraction with stable locators (page / line) so every citation can be checked."""
from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass

CHUNK_LINES = 12


@dataclass
class Line:
    page: int | None
    line_no: int          # 1-based within page (or document if no pages)
    section: str
    text: str


def extract_lines(kind: str, data: bytes) -> tuple[list[Line], str]:
    if kind == "pdf":
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(data))
        out: list[Line] = []
        for pno, page in enumerate(reader.pages, start=1):
            txt = page.extract_text() or ""
            out += _lines(txt, page=pno)
        note = "" if out else "no extractable text (scanned PDF? OCR not enabled)"
        return out, note
    if kind == "docx":
        import docx
        d = docx.Document(io.BytesIO(data))
        out, section, n = [], "", 0
        for para in d.paragraphs:
            t = para.text.strip()
            if not t:
                continue
            if para.style is not None and para.style.name.lower().startswith("heading"):
                section = t
            n += 1
            out.append(Line(None, n, section, t))
        for ti, table in enumerate(d.tables, start=1):
            for row in table.rows:
                t = " | ".join(c.text.strip() for c in row.cells)
                if t.strip(" |"):
                    n += 1
                    out.append(Line(None, n, f"table {ti}", t))
        return out, ""
    if kind == "xlsx":
        import openpyxl
        wb = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
        out, n = [], 0
        for ws in wb.worksheets:
            for row in ws.iter_rows(values_only=True):
                vals = [str(v) for v in row if v is not None]
                if vals:
                    n += 1
                    out.append(Line(None, n, f"sheet {ws.title}", " | ".join(vals)))
        return out, ""
    if kind in ("png", "jpg"):
        return [], "image stored; OCR not enabled in this deployment - requires human review"
    text = data.decode("utf-8-sig")
    if kind == "json":
        try:
            text = json.dumps(json.loads(text), indent=1, sort_keys=True)
        except json.JSONDecodeError:
            pass
    if kind == "csv":
        rows = list(csv.reader(io.StringIO(text)))
        text = "\n".join(" | ".join(r) for r in rows)
    return _lines(text, page=None), ""


def _lines(text: str, page: int | None) -> list[Line]:
    out, section = [], ""
    for i, raw in enumerate(text.splitlines(), start=1):
        t = raw.strip()
        if not t:
            continue
        if re.match(r"^(#+\s|\d+(\.\d+)*\s+[A-Z])", t) and len(t) < 120:
            section = t.lstrip("# ")
        out.append(Line(page, i, section, t))
    return out


def chunk(lines: list[Line], size: int = CHUNK_LINES) -> list[dict]:
    chunks, cur = [], []
    for ln in lines:
        if cur and (ln.page != cur[0].page or len(cur) >= size):
            chunks.append(cur)
            cur = []
        cur.append(ln)
    if cur:
        chunks.append(cur)
    return [{"page": c[0].page, "section": c[0].section, "line_start": c[0].line_no,
             "line_end": c[-1].line_no, "text": "\n".join(f"{l.line_no}\t{l.text}" for l in c)} for c in chunks]


def classify_kind(filename: str, lines: list[Line]) -> str:
    name = filename.lower()
    head = " ".join(l.text.lower() for l in lines[:40])
    rules = [
        ("training_record", ("training", "attendance", "completion")),
        ("vulnerability_report", ("vulnerab", "nessus", "cve-", "scan report")),
        ("configuration", ("config", "gpo", "policy setting", "conditional access", "baseline", "\"enabled\"", "settings")),
        ("log_export", ("log", "event id", "audit trail", "syslog")),
        ("access_review", ("access review", "recertification")),
        ("incident_response_plan", ("incident response plan",)),
        ("ssp", ("system security plan",)),
        ("network_diagram", ("diagram", "topology")),
        ("procedure", ("procedure", "sop", "step 1")),
        ("policy", ("policy", "shall", "must")),
    ]
    for kind, keys in rules:
        if any(k in name for k in keys):
            return kind
    for kind, keys in rules:
        if any(k in head for k in keys):
            return kind
    return "other"


def line_text(lines_text: str, line_no: int) -> str | None:
    for row in lines_text.splitlines():
        n, _, t = row.partition("\t")
        if n == str(line_no):
            return t
    return None
