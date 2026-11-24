"""Secure intake for uploaded evidence: type detection by content (not extension),
size and archive limits, macro and XXE rejection, malware scan hook, storage."""
from __future__ import annotations

import hashlib
import io
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path

from ..config import get_settings

ALLOWED_EXT = {".pdf", ".docx", ".xlsx", ".csv", ".txt", ".json", ".xml", ".png", ".jpg", ".jpeg", ".log", ".md"}
MAX_ZIP_ENTRIES = 2000
MAX_ZIP_UNCOMPRESSED = 200 * 1024 * 1024
MAX_ZIP_RATIO = 100
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
CLASSIFICATIONS = {"PUBLIC", "INTERNAL", "FCI", "CUI"}


class RejectedFile(ValueError):
    pass


@dataclass
class Validated:
    detected_type: str
    sha256: str
    size: int


class MalwareScanner:
    """Interface. Production: Microsoft Defender for Storage on the quarantine container
    or a ClamAV sidecar. The built-in scanner only catches the EICAR test signature."""

    def scan(self, data: bytes) -> str | None:
        return "EICAR-Test-Signature" if EICAR in data else None


def _check_zip(data: bytes, kind: str) -> None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as e:
        raise RejectedFile("corrupt Office container") from e
    infos = zf.infolist()
    if len(infos) > MAX_ZIP_ENTRIES:
        raise RejectedFile("too many archive entries")
    total = sum(i.file_size for i in infos)
    if total > MAX_ZIP_UNCOMPRESSED or total > max(1, len(data)) * MAX_ZIP_RATIO:
        raise RejectedFile("archive expands too much (possible zip bomb)")
    names = [i.filename for i in infos]
    if any(n.startswith("/") or ".." in Path(n).parts for n in names):
        raise RejectedFile("unsafe path in archive")
    if any(n.lower().endswith("vbaproject.bin") for n in names):
        raise RejectedFile("macro-enabled documents are not accepted")
    if "[Content_Types].xml" not in names:
        raise RejectedFile("not an Office Open XML document")
    main = "word/document.xml" if kind == "docx" else "xl/workbook.xml"
    if main not in names:
        raise RejectedFile(f"content does not match .{kind}")
    for n in names:
        if n.endswith(".xml") or n.endswith(".rels"):
            head = zf.read(n)[:4096]
            if b"<!DOCTYPE" in head or b"<!ENTITY" in head:
                raise RejectedFile("XML DTD/entities are not allowed")


def detect_and_validate(filename: str, data: bytes, scanner: MalwareScanner | None = None) -> Validated:
    s = get_settings()
    if len(data) == 0:
        raise RejectedFile("empty file")
    if len(data) > s.max_upload_bytes:
        raise RejectedFile("file too large")
    if "/" in filename or "\\" in filename or filename.startswith("."):
        raise RejectedFile("invalid filename")
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXT:
        raise RejectedFile(f"file type {ext or '(none)'} not accepted")
    hit = (scanner or MalwareScanner()).scan(data)
    if hit:
        raise RejectedFile(f"malware detected: {hit}")

    if data.startswith(b"%PDF-"):
        kind = "pdf"
    elif data.startswith(b"PK\x03\x04"):
        kind = ext.lstrip(".")
        if kind not in ("docx", "xlsx"):
            raise RejectedFile("archive content does not match extension")
        _check_zip(data, kind)
    elif data.startswith(b"\x89PNG\r\n\x1a\n"):
        kind = "png"
    elif data.startswith(b"\xff\xd8\xff"):
        kind = "jpg"
    else:
        if b"\x00" in data[:8192]:
            raise RejectedFile("binary content does not match a supported type")
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError as e:
            raise RejectedFile("text files must be UTF-8") from e
        kind = {".json": "json", ".xml": "xml", ".csv": "csv"}.get(ext, "txt")
        if kind == "xml" and re.search(r"<!(DOCTYPE|ENTITY)", text, re.I):
            raise RejectedFile("XML DTD/entities are not allowed")
    expected = {"pdf": {".pdf"}, "docx": {".docx"}, "xlsx": {".xlsx"}, "png": {".png"},
                "jpg": {".jpg", ".jpeg"}}
    if kind in expected and ext not in expected[kind]:
        raise RejectedFile("content does not match extension")
    if kind in {"txt", "json", "xml", "csv"} and ext in {".pdf", ".docx", ".xlsx", ".png", ".jpg", ".jpeg"}:
        raise RejectedFile("content does not match extension")
    return Validated(kind, hashlib.sha256(data).hexdigest(), len(data))


class BlobStore:
    """Local content-addressed store, tenant-prefixed. Production: Azure Blob with
    private endpoint, CMK encryption and immutability policy."""

    def __init__(self, root: Path | None = None):
        self.root = Path(root or get_settings().data_dir) / "blobs"

    def put(self, tenant_id: str, sha256: str, data: bytes) -> str:
        key = f"{tenant_id}/{sha256[:2]}/{sha256}"
        p = self.root / key
        p.parent.mkdir(parents=True, exist_ok=True)
        if not p.exists():
            p.write_bytes(data)
        return key

    def get(self, tenant_id: str, key: str) -> bytes:
        if not key.startswith(tenant_id + "/"):
            raise PermissionError("cross-tenant blob access")
        return (self.root / key).read_bytes()
