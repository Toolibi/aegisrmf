"""Load a folder of evidence into a running AegisRMF API and run the analysis, in one command.

First run (creates your organization, system and assessment; prints your API key):
    python tools/load_folder.py "C:\\path\\to\\evidence" --system "Engineering enclave" --bootstrap-token <token>

Later runs (add more files to the same system and re-run analysis):
    python tools/load_folder.py "C:\\path\\to\\more" --api-key aeg_...

Supported files: PDF (text, not scanned), DOCX, XLSX, CSV, TXT, MD, JSON, XML, PNG/JPG (stored, no OCR). Max 25 MB each.
Only upload documents you are allowed to use. Do not load real CUI into a test setup.
"""
from __future__ import annotations

import argparse
import json
import mimetypes
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ALLOWED = {".pdf", ".docx", ".xlsx", ".csv", ".txt", ".md", ".json", ".xml", ".png", ".jpg", ".jpeg", ".log"}


def call(api, method, path, key=None, body=None, headers=None, raw=None, ctype=None):
    h = dict(headers or {})
    if key:
        h["Authorization"] = f"Bearer {key}"
    data = raw
    if body is not None:
        data, ctype = json.dumps(body).encode(), "application/json"
    if ctype:
        h["Content-Type"] = ctype
    req = urllib.request.Request(api.rstrip("/") + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        try:
            detail = json.loads(detail).get("detail", detail)
        except ValueError:
            pass
        raise SystemExit(f"API error {e.code} on {method} {path}: {detail}") from None
    except urllib.error.URLError as e:
        raise SystemExit(f"Cannot reach the API at {api} ({e.reason}). Is uvicorn running?") from None


def multipart(path: Path, classification: str):
    b = uuid.uuid4().hex
    ctype = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    parts = [
        f'--{b}\r\nContent-Disposition: form-data; name="classification"\r\n\r\n{classification}\r\n'.encode(),
        f'--{b}\r\nContent-Disposition: form-data; name="file"; filename="{path.name}"\r\nContent-Type: {ctype}\r\n\r\n'.encode(),
        path.read_bytes(), f"\r\n--{b}--\r\n".encode(),
    ]
    return b"".join(parts), f"multipart/form-data; boundary={b}"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder")
    ap.add_argument("--api", default="http://127.0.0.1:8000")
    ap.add_argument("--api-key", help="existing key (skip organization setup)")
    ap.add_argument("--bootstrap-token", help="AEGIS_BOOTSTRAP_TOKEN the API was started with (first run)")
    ap.add_argument("--org", default="My Organization (test)")
    ap.add_argument("--slug", default="my-org")
    ap.add_argument("--system", default="Test system")
    ap.add_argument("--classification", default="INTERNAL", choices=["PUBLIC", "INTERNAL", "FCI", "CUI"])
    a = ap.parse_args()

    folder = Path(a.folder)
    files = sorted(p for p in folder.rglob("*") if p.is_file() and p.suffix.lower() in ALLOWED)
    if not files:
        raise SystemExit(f"No supported files found in {folder}")

    key = a.api_key
    if not key:
        if not a.bootstrap_token:
            raise SystemExit("First run needs --bootstrap-token (or pass --api-key to reuse an organization).")
        t = call(a.api, "POST", "/v1/tenants", body={"name": a.org, "slug": a.slug, "owner_email": f"owner@{a.slug}.example",
                                                      "owner_name": "Owner"}, headers={"X-Bootstrap-Token": a.bootstrap_token})
        key = t["api_key"]
        print(f"\nOrganization created. YOUR API KEY (save it; shown once):\n  {key}\n")

    systems = call(a.api, "GET", "/v1/systems", key)
    system = next((s for s in systems if s["name"] == a.system), None) or call(
        a.api, "POST", "/v1/systems", key, body={"name": a.system, "data_types": ["FCI", "CUI"]})
    assessments = [x for x in call(a.api, "GET", "/v1/assessments", key) if x["system_id"] == system["id"]]
    assessment = assessments[0] if assessments else call(a.api, "POST", "/v1/assessments", key, body={"system_id": system["id"]})

    print(f"System: {system['name']}   Assessment: {assessment['id']}\nUploading {len(files)} file(s):")
    for p in files:
        raw, ctype = multipart(p, a.classification)
        req = urllib.request.Request(a.api.rstrip("/") + f"/v1/systems/{system['id']}/evidence", data=raw, method="POST",
                                     headers={"Authorization": f"Bearer {key}", "Content-Type": ctype})
        try:
            with urllib.request.urlopen(req) as r:
                e = json.loads(r.read())
            note = f"  {e['evidence_kind']}, text {'extracted' if e['text_extracted'] else 'NOT extracted: ' + e['extraction_note']}"
            if e["injection_flags"]:
                note += "  (flagged: text addressed to an AI was found; excluded from analysis)"
            print(f"  OK       {p.name}{note}")
        except urllib.error.HTTPError as err:
            try:
                detail = json.loads(err.read()).get("detail")
            except ValueError:
                detail = err.reason
            print(f"  SKIPPED  {p.name}: {detail}")

    res = call(a.api, "POST", f"/v1/assessments/{assessment['id']}/analyze", key)
    call(a.api, "POST", f"/v1/assessments/{assessment['id']}/findings/propose", key)
    print(f"\nAnalysis done: {res['proposed_links']} new evidence links proposed for review.")
    if res["skipped"]:
        for s in res["skipped"]:
            print(f"  Not sent to AI: {s['reason']}")
    print("Open the dashboard (http://localhost:3000), connect with the key above, and go to Evidence review.")


if __name__ == "__main__":
    sys.exit(main())
