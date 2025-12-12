from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request, Header

app = FastAPI(title="HWP Text Extractor", version="1.0.0")

KST = timezone(timedelta(hours=9))

HEADING_PATTERNS = [
    re.compile(r"^\s*(\d+(?:[\.\-]\d+)*)([.)]?)\s+(.+?)\s*$"),            # 1. / 1-1 / 1.2
    re.compile(r"^\s*\(?([가-힣])\)?[.)]\s+(.+?)\s*$"),                     # 가. / (가)
    re.compile(r"^\s*([ⅠⅡⅢⅣⅤⅥⅦⅧⅨⅩIVXLC]+)[.)]\s+(.+?)\s*$"),              # 로마 숫자
]

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def run_hwp5txt(input_path: str) -> str:
    cmds = [
        ["hwp5txt", input_path],
        [sys.executable, "-m", "hwp5txt", input_path],
    ]
    last = None
    for cmd in cmds:
        p = subprocess.run(cmd, capture_output=True, text=True)
        # 성공
        if p.returncode == 0:
            return p.stdout
        # 실패 기록
        last = {
            "cmd": cmd,
            "returncode": p.returncode,
            "stdout": p.stdout[-2000:],
            "stderr": p.stderr[-2000:],
        }
    raise RuntimeError(f"Failed to run hwp5txt. Last: {json.dumps(last, ensure_ascii=False)}")

def normalize_text(t: str) -> str:
    t = t.replace("\r\n", "\n").replace("\r", "\n")
    t = re.sub(r"[ \u00A0]{2,}", " ", t)
    t = re.sub(r"\n{3,}", "\n\n", t)
    return t.strip()

def classify_line_as_heading(line: str):
    s = line.strip()
    if not s:
        return None
    if len(s) > 80:
        return None

    for pat in HEADING_PATTERNS:
        m = pat.match(s)
        if not m:
            continue
        groups = m.groups()
        if len(groups) == 3:
            number, _, title = groups
            level = min(6, 1 + number.count(".") + number.count("-"))
            return {"text": s, "level": level, "number": number, "title": title}
        if len(groups) == 2:
            number, title = groups
            return {"text": s, "level": 2, "number": number, "title": title}

    if s.endswith(":") and 2 <= len(s) <= 40:
        return {"text": s, "level": 2, "number": None, "title": s[:-1].strip()}

    return None

def build_blocks_from_text(text: str):
    parts = re.split(r"\n\s*\n", text)
    blocks = []
    for part in parts:
        p = part.strip()
        if not p:
            continue

        first_line = p.split("\n", 1)[0].strip()
        heading = classify_line_as_heading(first_line)

        if heading and len(p) == len(first_line):
            blocks.append({
                "type": "heading",
                "level": heading["level"],
                "text": heading["text"],
                "number": heading["number"],
                "title": heading["title"],
            })
        else:
            compact = re.sub(r"\s*\n\s*", " ", p).strip()
            blocks.append({"type": "paragraph", "text": compact, "raw": p})
    return blocks

def build_sections(blocks):
    sections = []
    current = None

    def new_section(h):
        return {"heading": h, "blocks": [], "plain_text": ""}

    for b in blocks:
        if b["type"] == "heading":
            current = new_section({
                "text": b["text"],
                "level": b.get("level", 1),
                "number": b.get("number"),
                "title": b.get("title"),
            })
            sections.append(current)
        else:
            if current is None:
                current = new_section({"text": "ROOT", "level": 0, "number": None, "title": "ROOT"})
                sections.append(current)
            current["blocks"].append(b)

    for s in sections:
        texts = []
        for b in s["blocks"]:
            if b["type"] == "paragraph":
                texts.append(b["text"])
        s["plain_text"] = "\n".join(texts).strip()

    return sections

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/extract")
async def extract_anyfile(request: Request, authorization: str | None = Header(None)):
    token = os.environ.get("API_TOKEN")
    if token:
        if not authorization or authorization != f"Bearer {token}":
            raise HTTPException(status_code=401, detail="Unauthorized")

    form = await request.form()
    # 1) 파일 읽기
    try:
        content = await file.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read upload: {e}")

    if not content:
        raise HTTPException(status_code=400, detail="Empty file")

    orig_name = filename or file.filename or "unknown.hwp"
    file_hash = sha256_bytes(content)
    doc_id = f"sha256:{file_hash}"

    # 2) 임시 파일로 저장 후 hwp5txt 실행
    try:
        with tempfile.TemporaryDirectory() as td:
            in_path = os.path.join(td, "input.hwp")
            with open(in_path, "wb") as f:
                f.write(content)

            raw_text = run_hwp5txt(in_path)
            text = normalize_text(raw_text)

    except Exception as e:
        # 변환 실패는 422로 내보내면 n8n에서 분기하기 좋습니다.
        raise HTTPException(status_code=422, detail=f"Extract failed: {e}")

    # 3) 구조화
    blocks = build_blocks_from_text(text)
    sections = build_sections(blocks)

    doc = {
        "doc_id": doc_id,
        "source": {
            "filename": orig_name,
            "ingested_at": datetime.now(KST).isoformat(),
            "file_sha256": file_hash,
            "extractor": "pyhwp(hwp5txt)",
        },
        "stats": {
            "num_chars": len(text),
            "num_blocks": len(blocks),
            "num_sections": len(sections),
            "num_headings": sum(1 for b in blocks if b["type"] == "heading"),
        },
        "text": text,
        "blocks": blocks,
        "sections": sections,
        "warnings": []
    }

    if doc["stats"]["num_chars"] < 500:
        doc["warnings"].append({"code": "TOO_SHORT", "message": "추출 텍스트가 짧습니다. 문서 손상/특수요소/비정상 가능."})
    if doc["stats"]["num_headings"] == 0 and doc["stats"]["num_chars"] > 2000:
        doc["warnings"].append({"code": "NO_HEADINGS", "message": "긴 문서인데 헤딩 감지 0. 섹션 분리 약할 수 있음."})

    return JSONResponse(doc)
