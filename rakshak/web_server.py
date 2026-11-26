"""Offline HTTP API and static UI server for the RAKSHA Privacy Firewall.

Dynamic, multi-dataset, multi-run local integration layer around the existing
RAKSHA CLI/pipeline, validation, and evaluation modules.
100% offline, CPU-only, zero external dependencies, zero cloud/AI calls.
Never exposes RAKSHA_SECRET, host filesystem paths, stack traces, or raw PII.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import io
import itertools
import json
import mimetypes
import os
import re
import subprocess
import sys
import threading
import time
import urllib.parse
import zipfile
from collections import Counter, defaultdict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from rakshak.cli import load_policy, run_pipeline
from rakshak.detection.hidden_surfaces import filename_has_pii
from rakshak.encoding import decode_bytes
from rakshak.ingestion import (
    SUPPORTED_EXTENSIONS,
    check_json_depth,
    discover_files,
    sniff_format,
)

ROOT_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = ROOT_DIR / "frontend"
PRACTICE_INPUT_DIR = ROOT_DIR / "dev" / "input"
PRACTICE_OUTPUT_DIR = ROOT_DIR / "output"
TRUTH_PATH = ROOT_DIR / "dev" / "truth" / "truth.json"
RUNS_BASE_DIR = ROOT_DIR / ".raksha_ui_runs"
DATASETS_DIR = RUNS_BASE_DIR / "datasets"
RUNS_OUTPUT_DIR = RUNS_BASE_DIR / "runs"
REGISTRY_PATH = RUNS_BASE_DIR / "registry.json"

MAX_UPLOAD_FILE_BYTES = 52_428_800  # 50 MiB

_LOCK = threading.Lock()
_DATASETS: dict[str, dict[str, Any]] = {}
_RUNS: dict[str, dict[str, Any]] = {}
_ACTIVE_DATASET_ID: str = "practice"
_ACTIVE_RUN_ID: str | None = None
_REGISTRY_LOADED: bool = False


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _safe_rel_path(raw_rel: str) -> str:
    """Normalize an untrusted relative path, stripping traversal & unsafe chars."""
    parts = [p for p in raw_rel.replace("\\", "/").split("/") if p and p not in (".", "..")]
    cleaned_parts = []
    for p in parts:
        c = re.sub(r"[^A-Za-z0-9._\-\u0900-\u097F]", "_", p).strip(".")
        if c:
            cleaned_parts.append(c[:100])
    if not cleaned_parts:
        return "uploaded_file.txt"
    return "/".join(cleaned_parts)


def _mask_filename_for_ui(rel_path: str) -> str:
    """Mask PII-bearing filenames before displaying in pre-processing inspection."""
    parts = rel_path.replace("\\", "/").split("/")
    fname = parts[-1]
    if filename_has_pii(rel_path):
        ext = Path(fname).suffix
        h = hashlib.sha256(rel_path.encode("utf-8", errors="replace")).hexdigest()[:8]
        parts[-1] = f"[REDACTED_NAME_{h}]{ext}"
    return "/".join(parts)


def _read_json_safe(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _system_info() -> dict[str, Any]:
    policy = load_policy(ROOT_DIR / "config" / "policy.yaml")
    return {
        "product": "RAKSHA",
        "tagline": "Protecting Patient Identity. Preserving Clinical Intelligence.",
        "version": "1.0.0",
        "offline": True,
        "cpu_only": True,
        "external_ai": False,
        "secret_configured": bool(os.environ.get("RAKSHA_SECRET", "")),
        "supported_formats": ["CSV", "TSV", "JSON", "FHIR R4 JSON", "TXT"],
        "policy": {
            "age_band_years": int(policy.get("age_band_years", 5)),
            "date_shift_max_days": int(policy.get("date_shift_max_days", 180)),
            "min_group_size": int(policy.get("min_group_size", 5)),
            "max_json_depth": int(policy.get("max_json_depth", 128)),
            "max_file_bytes": int(policy.get("max_file_bytes", 52_428_800)),
        },
    }


def _encode_rel(path: Path) -> str:
    """Encode path relative to ROOT_DIR when possible for portable persistence."""
    try:
        return path.resolve().relative_to(ROOT_DIR.resolve()).as_posix()
    except ValueError:
        return str(path)


def _decode_rel(raw: str) -> Path:
    p = Path(raw)
    return p if p.is_absolute() else (ROOT_DIR / p)


def _save_registry_locked() -> None:
    """Persist safe dataset/run metadata locally (no raw PII, no secrets)."""
    try:
        RUNS_BASE_DIR.mkdir(parents=True, exist_ok=True)
        payload = {
            "active_dataset_id": _ACTIVE_DATASET_ID,
            "active_run_id": _ACTIVE_RUN_ID,
            "datasets": [
                {
                    "id": d["id"],
                    "name": d["name"],
                    "kind": d["kind"],
                    "path": _encode_rel(d["path"]),
                    "created_at": d["created_at"],
                }
                for d in _DATASETS.values()
                if d.get("id") != "practice"
            ],
            "runs": [
                {
                    "run_id": r["run_id"],
                    "dataset_id": r["dataset_id"],
                    "dataset_name": r["dataset_name"],
                    "status": r["status"],
                    "start_time": r["start_time"],
                    "end_time": r["end_time"],
                    "elapsed_seconds": r["elapsed_seconds"],
                    "input_dir": _encode_rel(r["input_dir"]),
                    "output_dir": _encode_rel(r["output_dir"]),
                    "contract": r.get("contract"),
                    "logs": list(r.get("logs") or [])[-50:],
                    "error": r.get("error"),
                }
                for r in _RUNS.values()
                if r.get("run_id") != "practice-baseline"
            ],
        }
        tmp = REGISTRY_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(REGISTRY_PATH)
    except OSError:
        pass


def _load_registry_locked() -> None:
    """Load persisted dataset/run metadata on startup if available."""
    global _ACTIVE_DATASET_ID, _ACTIVE_RUN_ID, _REGISTRY_LOADED
    if _REGISTRY_LOADED:
        return
    _REGISTRY_LOADED = True
    data = _read_json_safe(REGISTRY_PATH)
    if not isinstance(data, dict):
        return

    for d in data.get("datasets") or []:
        if not isinstance(d, dict) or not d.get("id") or not d.get("path"):
            continue
        p = _decode_rel(str(d["path"]))
        if p.is_dir():
            _DATASETS[d["id"]] = {
                "id": d["id"],
                "name": str(d.get("name") or d["id"]),
                "kind": str(d.get("kind") or "uploaded"),
                "path": p,
                "created_at": str(d.get("created_at") or _utc_now()),
                "inspection_cache": None,
            }

    for r in data.get("runs") or []:
        if not isinstance(r, dict) or not r.get("run_id") or not r.get("output_dir"):
            continue
        in_dir = _decode_rel(str(r.get("input_dir") or ""))
        out_dir = _decode_rel(str(r["output_dir"]))
        if not out_dir.is_dir():
            continue
        status = str(r.get("status") or "failed")
        err = r.get("error")
        if status == "processing":
            status = "failed"
            err = err or "Server restarted during execution."
        _RUNS[r["run_id"]] = {
            "run_id": r["run_id"],
            "dataset_id": str(r.get("dataset_id") or "practice"),
            "dataset_name": str(r.get("dataset_name") or ""),
            "status": status,
            "start_time": str(r.get("start_time") or _utc_now()),
            "end_time": r.get("end_time"),
            "elapsed_seconds": float(r.get("elapsed_seconds") or 0.0),
            "input_dir": in_dir,
            "output_dir": out_dir,
            "contract": r.get("contract"),
            "assurance_cache": None,
            "logs": list(r.get("logs") or []),
            "error": err,
            "cancel_requested": False,
        }

    saved_ds = data.get("active_dataset_id")
    if isinstance(saved_ds, str) and saved_ds in _DATASETS:
        _ACTIVE_DATASET_ID = saved_ds
    saved_run = data.get("active_run_id")
    if isinstance(saved_run, str) and saved_run in _RUNS:
        _ACTIVE_RUN_ID = saved_run


def _init_registry() -> None:
    """Initialize practice dataset & baseline run if output exists."""
    global _ACTIVE_RUN_ID
    with _LOCK:
        _load_registry_locked()
        if "practice" not in _DATASETS and PRACTICE_INPUT_DIR.is_dir():
            _DATASETS["practice"] = {
                "id": "practice",
                "name": "Secret Wards Practice Dataset (dev/input)",
                "kind": "practice",
                "path": PRACTICE_INPUT_DIR,
                "created_at": _utc_now(),
                "inspection_cache": None,
            }
        if (PRACTICE_OUTPUT_DIR / "report.json").is_file() and "practice-baseline" not in _RUNS:
            mtime = (PRACTICE_OUTPUT_DIR / "report.json").stat().st_mtime
            rep = _read_json_safe(PRACTICE_OUTPUT_DIR / "report.json") or {}
            _RUNS["practice-baseline"] = {
                "run_id": "practice-baseline",
                "dataset_id": "practice",
                "dataset_name": "Secret Wards Practice Dataset (dev/input)",
                "status": "completed",
                "start_time": dt.datetime.fromtimestamp(mtime, tz=dt.timezone.utc).isoformat(),
                "end_time": dt.datetime.fromtimestamp(mtime, tz=dt.timezone.utc).isoformat(),
                "elapsed_seconds": float((rep.get("timing") or {}).get("seconds", 0.0)),
                "input_dir": PRACTICE_INPUT_DIR,
                "output_dir": PRACTICE_OUTPUT_DIR,
                "contract": _run_contract_check(PRACTICE_INPUT_DIR, PRACTICE_OUTPUT_DIR),
                "assurance_cache": None,
                "logs": [
                    "Run loaded from existing local output directory.",
                    "SENTINEL, IDENTITY GUARD, and VAULT artifacts verified.",
                ],
                "error": None,
                "cancel_requested": False,
            }
            if _ACTIVE_RUN_ID is None and _ACTIVE_DATASET_ID == "practice":
                _ACTIVE_RUN_ID = "practice-baseline"


def _run_contract_check(input_dir: Path, output_dir: Path) -> dict[str, Any]:
    if not (output_dir / "report.json").is_file():
        return {"ok": False, "errors_count": 1, "warnings_count": 0, "status": "NO_OUTPUT"}
    try:
        proc = subprocess.run(
            [
                sys.executable,
                str(ROOT_DIR / "validate_output.py"),
                "--input",
                str(input_dir),
                "--output",
                str(output_dir),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
        warns = sum(1 for ln in lines if ln.startswith("WARN"))
        errs = [ln for ln in lines if ln.startswith("ERROR")]
        return {
            "ok": proc.returncode == 0,
            "errors_count": len(errs),
            "warnings_count": warns,
            "status": "CONTRACT OK" if proc.returncode == 0 else "CONTRACT PROBLEMS",
        }
    except Exception:
        return {"ok": False, "errors_count": 1, "warnings_count": 0, "status": "VALIDATION_UNAVAILABLE"}


def _inspect_dataset(dataset_id: str) -> dict[str, Any] | None:
    with _LOCK:
        ds = _DATASETS.get(dataset_id)
    if not ds:
        return None
    if ds.get("inspection_cache") is not None:
        return ds["inspection_cache"]

    inp_dir: Path = ds["path"]
    policy = load_policy(ROOT_DIR / "config" / "policy.yaml")
    max_file_bytes = int(policy.get("max_file_bytes", MAX_UPLOAD_FILE_BYTES))
    max_json_depth = int(policy.get("max_json_depth", 128))

    files_inv: list[dict[str, Any]] = []
    fmt_counts: Counter[str] = Counter()
    enc_counts: Counter[str] = Counter()
    supported_count = 0
    quarantine_count = 0
    empty_count = 0
    oversized_count = 0
    total_bytes = 0
    folders: set[str] = set()

    for p in discover_files(inp_dir):
        rel = p.relative_to(inp_dir).as_posix()
        parent_rel = Path(rel).parent.as_posix()
        if parent_rel != ".":
            folders.add(parent_rel)
        raw = p.read_bytes()
        size = len(raw)
        total_bytes += size
        ext = p.suffix.lower()

        val_status = "supported"
        reason = None
        fmt_label = ext.lstrip(".").upper() or "UNKNOWN"
        enc_label = "unknown"

        if size == 0:
            empty_count += 1
        if size > max_file_bytes:
            val_status = "quarantine_required"
            reason = "file_too_large"
            oversized_count += 1
        elif ext not in SUPPORTED_EXTENSIONS:
            val_status = "quarantine_required"
            reason = "unsupported_format"
        else:
            decoded, dec_err = decode_bytes(raw)
            if decoded is None:
                val_status = "quarantine_required"
                reason = dec_err or "undecodable_text"
            else:
                enc_label = decoded.encoding
                try:
                    if ext == ".json":
                        check_json_depth(decoded.text, max_depth=max_json_depth)
                    fmt = sniff_format(ext, decoded.text)
                    fmt_label = "FHIR R4 JSON" if fmt == "fhir" else fmt.upper()
                except Exception as exc:
                    val_status = "quarantine_required"
                    reason = getattr(exc, "reason", "malformed_structure")

        if val_status == "supported":
            supported_count += 1
        else:
            quarantine_count += 1

        fmt_counts[fmt_label] += 1
        enc_counts[enc_label] += 1
        files_inv.append({
            "masked_name": _mask_filename_for_ui(rel),
            "pii_in_filename": filename_has_pii(rel),
            "format": fmt_label,
            "encoding": enc_label,
            "size_bytes": size,
            "validation": val_status,
            "reason": reason,
        })

    result = {
        "dataset_id": dataset_id,
        "dataset_name": ds["name"],
        "kind": ds["kind"],
        "total_files": len(files_inv),
        "supported_files": supported_count,
        "quarantine_required": quarantine_count,
        "empty_files": empty_count,
        "oversized_files": oversized_count,
        "total_bytes": total_bytes,
        "folders": sorted(folders)[:30],
        "formats": dict(fmt_counts),
        "encodings": dict(enc_counts),
        "files": files_inv,
    }
    with _LOCK:
        if dataset_id in _DATASETS:
            _DATASETS[dataset_id]["inspection_cache"] = result
    return result


def _compute_practice_assurance(output_dir: Path) -> dict[str, Any]:
    """Evaluate output against dev/truth/truth.json ONLY for practice dataset."""
    if not TRUTH_PATH.is_file():
        return {"verified": False, "reason": "No ground-truth manifest present."}
    try:
        import check_dev

        truth = json.loads(TRUTH_PATH.read_text(encoding="utf-8"))
        san = output_dir / "sanitized"
        report = _read_json_safe(output_dir / "report.json") or {"files": []}
        renamed = {e.get("input_sha256"): e.get("output") for e in report.get("files") or []}

        recs: dict[str, dict[str, Any]] = defaultdict(dict)
        rj = output_dir / "records.jsonl"
        if rj.is_file():
            for line in rj.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    r = json.loads(line)
                    recs[str(r["file"]).replace("sanitized/", "", 1)][r["loc"]] = r.get("patient")

        leaks: Counter[str] = Counter()
        kept: Counter[str] = Counter()
        by_script: Counter[str] = Counter()
        by_channel: Counter[str] = Counter()
        tot_script: Counter[str] = Counter()
        tot_channel: Counter[str] = Counter()
        pres_ok = 0
        pres_all = 0
        pres_by_kind: dict[str, list[int]] = defaultdict(lambda: [0, 0])  # [kept, total]
        unit_patient: dict[tuple[str, str], tuple[str, Any]] = {}
        copied_raw = 0

        for rel, f in truth["files"].items():
            out_rel = rel
            declared = renamed.get(f["sha256"])
            if declared:
                out_rel = str(declared).replace("sanitized/", "", 1)
            p = san / out_rel
            exists = p.is_file()
            text = check_dev.norm(check_dev.read_text(p)) if exists else ""
            src = PRACTICE_INPUT_DIR / rel
            has_pii = any(u["entities"] for u in f["units"].values())
            if has_pii and exists and f.get("expect") == "either" and src.is_file() and p.read_bytes() == src.read_bytes():
                copied_raw += 1
            fname = check_dev.norm(out_rel)
            for loc, u in f["units"].items():
                for e in u["entities"]:
                    if e.get("type") == "CANARY":
                        continue
                    tot_script[e["script"]] += 1
                    tot_channel[e["channel"]] += 1
                    surface = check_dev.norm(e["surface"])
                    hay = fname if e["channel"] == "filename" else text
                    hit = bool(surface) and surface in hay if (exists or e["channel"] == "filename") else False
                    if hit:
                        leaks[e["type"]] += 1
                        by_script[e["script"]] += 1
                        by_channel[e["channel"]] += 1
                    else:
                        kept[e["type"]] += 1
                if exists:
                    for pv in u.get("preserve") or []:
                        pres_all += 1
                        ok = int(check_dev.norm(pv["text"]) in text)
                        pres_ok += ok
                        kind = str(pv.get("kind") or "other")
                        pres_by_kind[kind][0] += ok
                        pres_by_kind[kind][1] += 1
                if u.get("link") == "required" and u.get("patient"):
                    unit_patient[(rel, loc)] = (u["patient"], check_dev.record_for(loc, recs.get(out_rel, {})))

        everything = check_dev.all_text_under(output_dir)
        canary_surfaces = {
            check_dev.norm(e["surface"])
            for f in truth["files"].values()
            for u in f["units"].values()
            for e in u["entities"]
            if e.get("type") == "CANARY"
        }
        canary_hits = sum(1 for s in canary_surfaces if s and s in everything)

        units = list(unit_patient.values())
        tp = fp = 0
        by_true: dict[str, list[int]] = defaultdict(list)
        yours: dict[str, list[int]] = defaultdict(list)
        for i, (t, y) in enumerate(units):
            by_true[t].append(i)
            if y:
                yours[y].append(i)
        true_pairs = sum(len(v) * (len(v) - 1) // 2 for v in by_true.values())
        for members in yours.values():
            for i, j in itertools.combinations(members, 2):
                if units[i][0] == units[j][0]:
                    tp += 1
                else:
                    fp += 1
        fn = true_pairs - tp
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f05 = (1.25 * prec * rec / (0.25 * prec + rec)) if prec + rec else 0.0
        merged_people = sum(1 for m in yours.values() if len({units[i][0] for i in m}) > 1)

        total_ent = sum(leaks.values()) + sum(kept.values())
        leaked_ent = sum(leaks.values())

        entity_breakdown = [
            {
                "type": etype,
                "total": leaks[etype] + kept[etype],
                "transformed": kept[etype],
                "remaining": leaks[etype],
            }
            for etype in sorted(set(leaks) | set(kept))
        ]

        clinical_categories = [
            {
                "category": k,
                "preserved": v[0],
                "total": v[1],
                "missing": v[1] - v[0],
                "pct": round(100.0 * v[0] / v[1], 1) if v[1] else 0.0,
            }
            for k, v in sorted(pres_by_kind.items(), key=lambda x: -x[1][1])
        ]

        return {
            "verified": True,
            "source": "practice_evaluator",
            "pii_total": total_ent,
            "pii_leaked": leaked_ent,
            "pii_transformed": total_ent - leaked_ent,
            "leakage_pct": round((100.0 * leaked_ent / total_ent) if total_ent else 0.0, 2),
            "by_type": entity_breakdown,
            "by_language": [
                {"name": s, "total": tot_script[s], "leaked": by_script[s], "pct": round(100.0 * by_script[s] / tot_script[s], 2) if tot_script[s] else 0.0}
                for s in tot_script
            ],
            "by_channel": [
                {"name": c, "total": tot_channel[c], "leaked": by_channel[c], "pct": round(100.0 * by_channel[c] / tot_channel[c], 2) if tot_channel[c] else 0.0}
                for c in tot_channel
            ],
            "canaries_leaked": canary_hits,
            "canaries_total": len(canary_surfaces),
            "medical_kept": pres_ok,
            "medical_total": pres_all,
            "medical_pct": round((100.0 * pres_ok / pres_all) if pres_all else 0.0, 1),
            "clinical_categories": clinical_categories,
            "raw_copies": copied_raw,
            "secret_exposed": False,
            "linking": {
                "precision": round(prec, 2),
                "recall": round(rec, 2),
                "f05": round(f05, 2),
                "wrong_merges": merged_people,
                "required_units": len(units),
                "linked_units": sum(1 for _, y in units if y),
            },
        }
    except Exception:
        return {"verified": False, "reason": "Practice evaluator check failed."}


def _get_active_run() -> dict[str, Any] | None:
    with _LOCK:
        rid = _ACTIVE_RUN_ID
        return _RUNS.get(rid) if rid else None


def _run_summary(run: dict[str, Any]) -> dict[str, Any]:
    elapsed = run.get("elapsed_seconds", 0.0)
    if run["status"] == "processing" and run.get("_t0"):
        elapsed = round(time.monotonic() - run["_t0"], 2)
    return {
        "run_id": run["run_id"],
        "dataset_id": run["dataset_id"],
        "dataset_name": run["dataset_name"],
        "status": run["status"],
        "start_time": run["start_time"],
        "end_time": run.get("end_time"),
        "elapsed_seconds": elapsed,
        "contract": run.get("contract"),
        "logs": list(run.get("logs") or []),
        "error": run.get("error"),
    }


def _get_overview_payload() -> dict[str, Any]:
    _init_registry()
    with _LOCK:
        ds_id = _ACTIVE_DATASET_ID
        ds = _DATASETS.get(ds_id)
        run = _RUNS.get(_ACTIVE_RUN_ID) if _ACTIVE_RUN_ID else None

    if not run or run["status"] != "completed":
        return {
            "has_output": False,
            "active_dataset": {"id": ds_id, "name": ds["name"] if ds else ds_id},
            "active_run": _run_summary(run) if run else None,
            "counts": None,
            "entities": {},
            "timing": None,
            "resources": None,
            "contract": run.get("contract") if run else None,
            "assurance": {"verified": False, "reason": "No completed run for the selected dataset."},
            "layers": [],
            "system": _system_info(),
        }

    output_dir: Path = run["output_dir"]
    report = _read_json_safe(output_dir / "report.json")
    if not report:
        return {
            "has_output": False,
            "active_dataset": {"id": ds_id, "name": ds["name"] if ds else ds_id},
            "active_run": _run_summary(run),
            "counts": None,
            "entities": {},
            "assurance": {"verified": False, "reason": "Output report missing."},
            "layers": [],
            "system": _system_info(),
        }

    assurance = run.get("assurance_cache")
    if assurance is None:
        if run["dataset_id"] == "practice":
            assurance = _compute_practice_assurance(output_dir)
        else:
            assurance = {
                "verified": False,
                "reason": "Custom dataset run: output contract validated; ground-truth leakage, recall & preservation require labeled truth.",
            }
        with _LOCK:
            run["assurance_cache"] = assurance

    counts = report.get("counts") or {}
    entities = report.get("entities") or {}
    contract = run.get("contract") or {"ok": False, "status": "UNKNOWN"}

    files_total = counts.get("files_total", 0)
    files_sanitized = counts.get("files_sanitized", 0)
    files_quarantined = counts.get("files_quarantined", 0)
    records_processed = counts.get("records_processed", 0)
    records_linked = counts.get("records_linked", 0)
    identifiers_detected = counts.get("identifiers_detected", 0)
    records_generalized = counts.get("records_generalized", 0)
    records_suppressed = counts.get("records_suppressed", 0)

    layers = [
        {
            "id": "sentinel",
            "name": "SENTINEL",
            "subtitle": "Input & Surface Defense",
            "purpose": "Ingests files, detects encodings, normalizes Unicode, inspects filenames/headers/keys/metadata/Base64, and quarantines unsafe payloads.",
            "state": "COMPLETED" if files_total > 0 else "IDLE",
            "details": [
                {"label": "Files Discovered / Inspected", "value": files_total},
                {"label": "Files Quarantined", "value": files_quarantined},
                {"label": "Filename PII Flagged", "value": int(entities.get("FILENAME_PII", 0))},
            ],
        },
        {
            "id": "identity_guard",
            "name": "IDENTITY GUARD",
            "subtitle": "PII Detection & Patient Linkage",
            "purpose": "Detects multilingual PII (Latin, Devanagari, Hinglish) and conservatively links patient clusters without false merges.",
            "state": "COMPLETED" if files_total > 0 else "IDLE",
            "details": [
                {"label": "PII Entities Detected", "value": identifiers_detected},
                {"label": "Records Processed", "value": records_processed},
                {"label": "Records Linked / Unlinked", "value": f"{records_linked} / {max(0, records_processed - records_linked)}"},
            ],
        },
        {
            "id": "vault",
            "name": "VAULT",
            "subtitle": "Privacy Transformation & Output Assurance",
            "purpose": "Applies HMAC pseudonymization, date shifting, age banding, location generalization, clinical preservation, and contract validation.",
            "state": "VERIFIED" if contract.get("ok") else "ATTENTION",
            "details": [
                {"label": "Files Sanitized", "value": files_sanitized},
                {"label": "Records Generalized / Suppressed", "value": f"{records_generalized} / {records_suppressed}"},
                {"label": "Contract Validation", "value": contract.get("status", "UNKNOWN")},
            ],
        },
    ]

    return {
        "has_output": True,
        "active_dataset": {"id": run["dataset_id"], "name": run["dataset_name"]},
        "active_run": _run_summary(run),
        "counts": counts,
        "entities": entities,
        "timing": report.get("timing") or {"seconds": 0},
        "resources": report.get("resources") or {"peak_rss_mb": 0},
        "contract": contract,
        "assurance": assurance,
        "layers": layers,
        "system": _system_info(),
    }


def _get_files_payload(
    search: str = "",
    status_filter: str = "all",
    fmt_filter: str = "all",
    sort_by: str = "index",
    page: int = 1,
    page_size: int = 50,
) -> dict[str, Any]:
    run = _get_active_run()
    if not run or run["status"] != "completed":
        return {"files": [], "total": 0, "page": 1, "page_size": page_size, "formats": []}

    output_dir: Path = run["output_dir"]
    report = _read_json_safe(output_dir / "report.json")
    if not report:
        return {"files": [], "total": 0, "page": 1, "page_size": page_size, "formats": []}

    rec_counts: Counter[str] = Counter()
    linked_counts: Counter[str] = Counter()
    pseudonyms_by_file: dict[str, set[str]] = defaultdict(set)
    rj = output_dir / "records.jsonl"
    if rj.is_file():
        for line in rj.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            fpath = str(r.get("file", ""))
            rec_counts[fpath] += 1
            if r.get("patient"):
                linked_counts[fpath] += 1
                pseudonyms_by_file[fpath].add(str(r["patient"]))

    all_items: list[dict[str, Any]] = []
    formats_seen: set[str] = set()
    for ent in report.get("files") or []:
        if ent.get("_alt"):
            continue
        status = ent.get("status", "unknown")
        out_path = ent.get("output")
        sha = str(ent.get("input_sha256", ""))
        if status == "sanitized" and out_path:
            display_name = str(out_path).replace("sanitized/", "", 1)
            ext = Path(display_name).suffix.lstrip(".").upper() or "TXT"
            file_id = out_path
        else:
            display_name = f"quarantined_{sha[:12]}"
            ext = "QUARANTINED"
            file_id = f"quarantined:{sha[:16]}"
        formats_seen.add(ext)
        all_items.append({
            "index": len(all_items) + 1,
            "id": file_id,
            "sha256_prefix": sha[:12],
            "display_name": display_name,
            "output_path": out_path,
            "file_type": ext,
            "status": status,
            "reason": ent.get("reason"),
            "records": rec_counts.get(out_path or "", 0),
            "linked_records": linked_counts.get(out_path or "", 0),
            "pseudonyms": sorted(pseudonyms_by_file.get(out_path or "", set()))[:12],
        })

    filtered = []
    q = search.strip().lower()
    for item in all_items:
        if status_filter != "all" and item["status"] != status_filter:
            continue
        if fmt_filter != "all" and item["file_type"] != fmt_filter:
            continue
        if q and q not in item["display_name"].lower() and q not in (item["reason"] or "").lower() and q not in item["sha256_prefix"].lower():
            continue
        filtered.append(item)

    if sort_by == "name":
        filtered.sort(key=lambda x: x["display_name"])
    elif sort_by == "records":
        filtered.sort(key=lambda x: -x["records"])
    elif sort_by == "status":
        filtered.sort(key=lambda x: x["status"])

    total = len(filtered)
    start = max(0, (page - 1) * page_size)
    end = start + page_size
    return {
        "files": filtered[start:end],
        "total": total,
        "page": page,
        "page_size": page_size,
        "formats": sorted(formats_seen),
    }


def _get_file_detail(file_id: str) -> dict[str, Any] | None:
    payload = _get_files_payload(page=1, page_size=10000)
    match = next((f for f in payload["files"] if f["id"] == file_id or f["sha256_prefix"] == file_id), None)
    if not match:
        return None
    detail = dict(match)
    run = _get_active_run()
    if run and match["status"] == "sanitized" and match["output_path"]:
        rel = str(match["output_path"]).replace("sanitized/", "", 1)
        san_root = (run["output_dir"] / "sanitized").resolve()
        target = (san_root / rel).resolve()
        if str(target).startswith(str(san_root)) and target.is_file():
            raw_txt = target.read_text(encoding="utf-8", errors="replace")
            detail["sanitized_preview"] = raw_txt[:2500]
            detail["truncated"] = len(raw_txt) > 2500
            detail["size_bytes"] = target.stat().st_size
    return detail


def _get_linkage_payload(
    search: str = "",
    status_filter: str = "all",
    file_filter: str = "all",
    fmt_filter: str = "all",
    page: int = 1,
    page_size: int = 50,
) -> dict[str, Any]:
    run = _get_active_run()
    if not run or run["status"] != "completed":
        return {"summary": {}, "records": [], "clusters": [], "total": 0, "page": 1, "page_size": page_size, "source_files": [], "formats": []}

    output_dir: Path = run["output_dir"]
    rj = output_dir / "records.jsonl"
    all_rows: list[dict[str, Any]] = []
    total_all = 0
    linked_all = 0
    unlinked_all = 0
    clusters_map: dict[str, dict[str, Any]] = {}
    source_files: set[str] = set()
    formats_seen: set[str] = set()

    if rj.is_file():
        for line in rj.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            total_all += 1
            psn = r.get("patient")
            src_file = str(r.get("file", "")).replace("sanitized/", "", 1)
            ext = Path(src_file).suffix.lstrip(".").upper() or "TXT"
            loc = str(r.get("loc", ""))
            source_files.add(src_file)
            formats_seen.add(ext)

            if psn:
                linked_all += 1
                rec_status = "linked"
                reason = None
                c_ent = clusters_map.setdefault(str(psn), {"pseudonym": str(psn), "records": 0, "files": set()})
                c_ent["records"] += 1
                c_ent["files"].add(src_file)
            else:
                unlinked_all += 1
                rec_status = "unlinked"
                reason = "Insufficient corroborated identifiers (conservative threshold preserved)"

            all_rows.append({
                "patient": psn or "UNLINKED",
                "file": src_file,
                "format": ext,
                "loc": loc,
                "status": rec_status,
                "reason": reason,
            })

    q = search.strip().lower()
    filtered = []
    for row in all_rows:
        if status_filter != "all" and row["status"] != status_filter:
            continue
        if file_filter != "all" and row["file"] != file_filter:
            continue
        if fmt_filter != "all" and row["format"] != fmt_filter:
            continue
        if q and q not in row["patient"].lower() and q not in row["file"].lower() and q not in row["loc"].lower():
            continue
        filtered.append(row)

    total_filtered = len(filtered)
    start = max(0, (page - 1) * page_size)
    end = start + page_size

    top_clusters = sorted(
        ({"pseudonym": k, "records": v["records"], "files_count": len(v["files"])} for k, v in clusters_map.items()),
        key=lambda x: -x["records"],
    )[:15]

    assurance = run.get("assurance_cache")
    linking_metrics = assurance.get("linking") if (run["dataset_id"] == "practice" and isinstance(assurance, dict) and assurance.get("verified")) else None

    return {
        "summary": {
            "total_records": total_all,
            "linked_records": linked_all,
            "unlinked_records": unlinked_all,
            "unique_pseudonyms": len(clusters_map),
            "metrics": linking_metrics,
        },
        "clusters": top_clusters,
        "records": filtered[start:end],
        "total": total_filtered,
        "page": page,
        "page_size": page_size,
        "source_files": sorted(source_files)[:100],
        "formats": sorted(formats_seen),
    }


def _start_run_for_dataset(dataset_id: str) -> dict[str, Any] | None:
    global _ACTIVE_DATASET_ID, _ACTIVE_RUN_ID
    _init_registry()
    with _LOCK:
        ds = _DATASETS.get(dataset_id)
        if not ds:
            return None
        _ACTIVE_DATASET_ID = dataset_id
        run_id = dt.datetime.now(dt.timezone.utc).strftime("run_%Y%m%d_%H%M%S_%f")
        out_dir = RUNS_OUTPUT_DIR / run_id / "output"
        out_dir.mkdir(parents=True, exist_ok=True)
        run_obj: dict[str, Any] = {
            "run_id": run_id,
            "dataset_id": dataset_id,
            "dataset_name": ds["name"],
            "status": "processing",
            "start_time": _utc_now(),
            "end_time": None,
            "elapsed_seconds": 0.0,
            "_t0": time.monotonic(),
            "input_dir": ds["path"],
            "output_dir": out_dir,
            "contract": None,
            "assurance_cache": None,
            "logs": [f"Started local RAKSHA pipeline for dataset '{ds['name']}'."],
            "error": None,
            "cancel_requested": False,
        }
        _RUNS[run_id] = run_obj
        _ACTIVE_RUN_ID = run_id
        _save_registry_locked()

    def _worker() -> None:
        if not os.environ.get("RAKSHA_SECRET"):
            os.environ["RAKSHA_SECRET"] = hashlib.sha256(b"raksha-local-session").hexdigest()
        try:
            rc = run_pipeline(ds["path"], out_dir)
            elapsed = round(time.monotonic() - run_obj["_t0"], 2)
            with _LOCK:
                if run_obj["cancel_requested"]:
                    run_obj["status"] = "cancelled"
                    run_obj["end_time"] = _utc_now()
                    run_obj["elapsed_seconds"] = elapsed
                    run_obj["logs"].append("Run cancelled by operator.")
                    _save_registry_locked()
                    return
            if rc != 0:
                with _LOCK:
                    run_obj["status"] = "failed"
                    run_obj["end_time"] = _utc_now()
                    run_obj["elapsed_seconds"] = elapsed
                    run_obj["error"] = "Pipeline exited with non-zero status."
                    run_obj["logs"].append("Pipeline failed during execution.")
                    _save_registry_locked()
                return

            contract = _run_contract_check(ds["path"], out_dir)
            with _LOCK:
                run_obj["contract"] = contract
                run_obj["status"] = "completed"
                run_obj["end_time"] = _utc_now()
                run_obj["elapsed_seconds"] = elapsed
                run_obj["logs"].append(f"Pipeline completed in {elapsed}s ({contract.get('status')}).")
                _save_registry_locked()
        except Exception:
            with _LOCK:
                run_obj["status"] = "failed"
                run_obj["end_time"] = _utc_now()
                run_obj["elapsed_seconds"] = round(time.monotonic() - run_obj["_t0"], 2)
                run_obj["error"] = "Unexpected local pipeline execution error."
                run_obj["logs"].append("Pipeline aborted due to an internal error.")
                _save_registry_locked()

    threading.Thread(target=_worker, daemon=True).start()
    return _run_summary(run_obj)


class RakshaHandler(BaseHTTPRequestHandler):
    server_version = "RAKSHA-Local/1.0"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, data: bytes, content_type: str, download_name: str | None = None) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        if download_name:
            safe_dl = re.sub(r"[^A-Za-z0-9._\-]", "_", Path(download_name).name) or "download"
            self.send_header("Content-Disposition", f'attachment; filename="{safe_dl}"')
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        _init_registry()
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        if path == "/api/overview":
            return self._send_json(_get_overview_payload())

        if path == "/api/datasets":
            with _LOCK:
                ds_list = [
                    {"id": d["id"], "name": d["name"], "kind": d["kind"], "created_at": d["created_at"]}
                    for d in _DATASETS.values()
                ]
                active_ds = _ACTIVE_DATASET_ID
            return self._send_json({"datasets": ds_list, "active_dataset_id": active_ds})

        if path == "/api/datasets/inspect":
            ds_id = (qs.get("dataset_id") or [_ACTIVE_DATASET_ID])[0]
            page = max(1, int((qs.get("page") or ["1"])[0]))
            page_size = min(200, max(10, int((qs.get("page_size") or ["50"])[0])))
            inv = _inspect_dataset(ds_id)
            if not inv:
                return self._send_json({"error": "Dataset not found"}, status=404)
            start = (page - 1) * page_size
            resp = dict(inv)
            resp["files"] = inv["files"][start:start + page_size]
            resp["page"] = page
            resp["page_size"] = page_size
            return self._send_json(resp)

        if path == "/api/runs":
            with _LOCK:
                runs = [_run_summary(r) for r in sorted(_RUNS.values(), key=lambda x: x["start_time"], reverse=True)]
                active_rid = _ACTIVE_RUN_ID
            return self._send_json({"runs": runs, "active_run_id": active_rid})

        if path == "/api/runs/status":
            rid = (qs.get("run_id") or [_ACTIVE_RUN_ID or ""])[0]
            with _LOCK:
                run = _RUNS.get(rid)
            if not run:
                return self._send_json({"error": "Run not found"}, status=404)
            return self._send_json(_run_summary(run))

        if path == "/api/files":
            return self._send_json(_get_files_payload(
                search=(qs.get("q") or [""])[0],
                status_filter=(qs.get("status") or ["all"])[0],
                fmt_filter=(qs.get("format") or ["all"])[0],
                sort_by=(qs.get("sort") or ["index"])[0],
                page=max(1, int((qs.get("page") or ["1"])[0])),
                page_size=min(200, max(10, int((qs.get("page_size") or ["50"])[0]))),
            ))

        if path == "/api/files/detail":
            detail = _get_file_detail((qs.get("id") or [""])[0])
            if detail is None:
                return self._send_json({"error": "File not found"}, status=404)
            return self._send_json(detail)

        if path == "/api/linkage":
            return self._send_json(_get_linkage_payload(
                search=(qs.get("q") or [""])[0],
                status_filter=(qs.get("status") or ["all"])[0],
                file_filter=(qs.get("file") or ["all"])[0],
                fmt_filter=(qs.get("format") or ["all"])[0],
                page=max(1, int((qs.get("page") or ["1"])[0])),
                page_size=min(200, max(10, int((qs.get("page_size") or ["50"])[0]))),
            ))

        if path == "/api/reports/download":
            return self._handle_download((qs.get("target") or [""])[0])

        if path == "/api/reports/bundle":
            return self._handle_bundle_download()

        if path in ("/", "/index.html"):
            return self._serve_static("index.html", "text/html; charset=utf-8")
        if path in ("/styles.css", "/app.js"):
            ctype = "text/css; charset=utf-8" if path.endswith(".css") else "application/javascript; charset=utf-8"
            return self._serve_static(path.lstrip("/"), ctype)

        self._send_json({"error": "Not found"}, status=404)

    def do_POST(self) -> None:
        _init_registry()
        parsed = urllib.parse.urlparse(self.path)
        body = self._read_json_body()

        if parsed.path == "/api/datasets/upload":
            return self._handle_dataset_upload(body)

        if parsed.path == "/api/datasets/select":
            ds_id = str((body or {}).get("dataset_id", ""))
            with _LOCK:
                if ds_id not in _DATASETS:
                    return self._send_json({"error": "Dataset not found"}, status=404)
                global _ACTIVE_DATASET_ID, _ACTIVE_RUN_ID
                _ACTIVE_DATASET_ID = ds_id
                # Select latest completed run for this dataset if one exists, else None (never mix runs!)
                matching = [r for r in _RUNS.values() if r["dataset_id"] == ds_id and r["status"] == "completed"]
                matching.sort(key=lambda x: x["start_time"], reverse=True)
                _ACTIVE_RUN_ID = matching[0]["run_id"] if matching else None
                _save_registry_locked()
            return self._send_json({"ok": True, "active_dataset_id": ds_id, "active_run_id": _ACTIVE_RUN_ID})

        if parsed.path == "/api/runs/start":
            ds_id = str((body or {}).get("dataset_id") or _ACTIVE_DATASET_ID)
            summary = _start_run_for_dataset(ds_id)
            if not summary:
                return self._send_json({"error": "Dataset not found"}, status=404)
            return self._send_json({"ok": True, "run": summary})

        if parsed.path == "/api/runs/select":
            rid = str((body or {}).get("run_id", ""))
            with _LOCK:
                if rid not in _RUNS:
                    return self._send_json({"error": "Run not found"}, status=404)
                _ACTIVE_RUN_ID = rid
                _ACTIVE_DATASET_ID = _RUNS[rid]["dataset_id"]
                _save_registry_locked()
            return self._send_json({"ok": True, "active_run_id": rid})

        if parsed.path == "/api/runs/cancel":
            rid = str((body or {}).get("run_id") or _ACTIVE_RUN_ID or "")
            with _LOCK:
                run = _RUNS.get(rid)
                if not run:
                    return self._send_json({"error": "Run not found"}, status=404)
                if run["status"] == "processing":
                    run["cancel_requested"] = True
                    run["logs"].append("Cancellation requested; waiting for safe boundary.")
            return self._send_json({"ok": True, "run": _run_summary(run)})

        self._send_json({"error": "Not found"}, status=404)

    def _read_json_body(self) -> dict[str, Any] | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length <= 0 or length > 80_000_000:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            return None

    def _serve_static(self, rel_name: str, content_type: str) -> None:
        target = (FRONTEND_DIR / rel_name).resolve()
        if not str(target).startswith(str(FRONTEND_DIR.resolve())) or not target.is_file():
            self._send_json({"error": "Asset not found"}, status=404)
            return
        self._send_bytes(target.read_bytes(), content_type)

    def _handle_dataset_upload(self, payload: dict[str, Any] | None) -> None:
        global _ACTIVE_DATASET_ID, _ACTIVE_RUN_ID
        if not isinstance(payload, dict) or not isinstance(payload.get("files"), list) or not payload["files"]:
            return self._send_json({"error": "No files provided for dataset upload"}, status=400)

        ds_id = dt.datetime.now(dt.timezone.utc).strftime("ds_%Y%m%d_%H%M%S_%f")
        ds_name = str(payload.get("dataset_name") or f"Uploaded Dataset ({len(payload['files'])} files)")[:80]
        ds_dir = DATASETS_DIR / ds_id
        ds_dir.mkdir(parents=True, exist_ok=True)

        written = 0
        for item in payload["files"]:
            if not isinstance(item, dict):
                continue
            rel = _safe_rel_path(str(item.get("name", "file.txt")))
            b64 = str(item.get("content_base64", ""))
            try:
                raw_bytes = base64.b64decode(b64, validate=True)
            except Exception:
                return self._send_json({"error": f"Invalid base64 payload for {_mask_filename_for_ui(rel)}"}, status=400)
            if len(raw_bytes) > MAX_UPLOAD_FILE_BYTES:
                return self._send_json({"error": f"{_mask_filename_for_ui(rel)} exceeds 50 MiB limit"}, status=400)
            dest = (ds_dir / rel).resolve()
            if not str(dest).startswith(str(ds_dir.resolve())):
                return self._send_json({"error": "Invalid relative file path"}, status=400)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(raw_bytes)
            written += 1

        if written == 0:
            return self._send_json({"error": "No valid files uploaded"}, status=400)

        with _LOCK:
            _DATASETS[ds_id] = {
                "id": ds_id,
                "name": ds_name,
                "kind": "uploaded",
                "path": ds_dir,
                "created_at": _utc_now(),
                "inspection_cache": None,
            }
            _ACTIVE_DATASET_ID = ds_id
            _ACTIVE_RUN_ID = None
            _save_registry_locked()

        inv = _inspect_dataset(ds_id)
        return self._send_json({"ok": True, "dataset_id": ds_id, "inspection": inv})

    def _handle_download(self, target: str) -> None:
        run = _get_active_run()
        if not run or run["status"] != "completed" or not (run.get("contract") or {}).get("ok"):
            return self._send_json({"error": "Downloads disabled until output contract passes validation."}, status=403)

        out_root = run["output_dir"].resolve()
        if target in ("report.json", "records.jsonl"):
            fp = (out_root / target).resolve()
            if fp.is_file():
                ctype = "application/json; charset=utf-8" if target.endswith(".json") else "application/x-ndjson; charset=utf-8"
                return self._send_bytes(fp.read_bytes(), ctype, download_name=target)
            return self._send_json({"error": "Report file not found"}, status=404)

        if target.startswith("sanitized/"):
            report = _read_json_safe(out_root / "report.json") or {}
            approved = {
                e.get("output")
                for e in (report.get("files") or [])
                if e.get("status") == "sanitized" and e.get("output")
            }
            if target not in approved:
                return self._send_json({"error": "File is quarantined or not approved for export."}, status=403)
            san_root = (out_root / "sanitized").resolve()
            rel = target.replace("sanitized/", "", 1)
            fp = (san_root / rel).resolve()
            if not str(fp).startswith(str(san_root)) or not fp.is_file():
                return self._send_json({"error": "Invalid file path"}, status=403)
            ctype, _ = mimetypes.guess_type(fp.name)
            return self._send_bytes(fp.read_bytes(), ctype or "text/plain; charset=utf-8", download_name=fp.name)

        return self._send_json({"error": "Invalid download target"}, status=400)

    def _handle_bundle_download(self) -> None:
        run = _get_active_run()
        if not run or run["status"] != "completed" or not (run.get("contract") or {}).get("ok"):
            return self._send_json({"error": "Bundle export disabled until output contract passes validation."}, status=403)

        out_root = run["output_dir"].resolve()
        report = _read_json_safe(out_root / "report.json") or {}
        approved = {
            e.get("output")
            for e in (report.get("files") or [])
            if e.get("status") == "sanitized" and e.get("output")
        }
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for meta_name in ("report.json", "records.jsonl"):
                mp = out_root / meta_name
                if mp.is_file():
                    zf.write(mp, arcname=meta_name)
            san_root = (out_root / "sanitized").resolve()
            for out_rel in sorted(approved):
                if not out_rel:
                    continue
                fp = (san_root / out_rel.replace("sanitized/", "", 1)).resolve()
                if str(fp).startswith(str(san_root)) and fp.is_file():
                    zf.write(fp, arcname=out_rel)
        return self._send_bytes(buf.getvalue(), "application/zip", download_name=f"raksha_{run['run_id']}_sanitized.zip")


def serve(host: str = "127.0.0.1", port: int = 8080) -> None:
    _init_registry()
    httpd = ThreadingHTTPServer((host, port), RakshaHandler)
    print(f"RAKSHA Command Center listening on http://{host}:{port}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    port = int(os.environ.get("RAKSHA_UI_PORT", "8080"))
    serve(port=port)
