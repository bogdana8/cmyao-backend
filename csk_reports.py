# -*- coding: utf-8 -*-
"""
Аналітичні довідки ЦСК — збережені, автономні, з дозаписом нових відповідей.

Що змінилось порівняно зі старою схемою «завантажив файл → чекаєш у запиті → скачав»:
  • Опитування ЗБЕРІГАЄТЬСЯ в базі (таблиці csk_reports*): відповіді, налаштування, готові .docx. Нічого не зникає після закриття вкладки.
  • Нові відповіді ДОДАЮТЬСЯ: файл можна завантажувати повторно (повний експорт або лише новий шматок) — дублікати
    розпізнаються за «ID відправки», старі відповіді не видаляються.
  • Довідки збираються у ФОНІ й в ОКРЕМОМУ процесі (csk_report_worker.py): веб-сервер не рахує pandas/matplotlib і не чекає на AI,
    тому не падає від пам'яті й від таймаутів. Комплект: 1 загальна + по одній на інститут/факультет.
  • Кількість здобувачів береться з бази студентів автоматично (курс, форма, статус — налаштовуються).
  • Збірка перезапускається сама після дозавантаження відповідей; підрозділ, у якому нічого не змінилось, не перебудовується.

Підключення (main.py, поруч зі старими /api/csk/survey-reports/*):
    from csk_reports import register_csk_reports
    register_csk_reports(app, Base, engine, SessionLocal, get_db, require_csk_admin, _practice_student_rows)

Цей модуль НЕ імпортує pandas — у веб-процесі він не потрібен.
"""
import csv
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import zipfile
from datetime import date, datetime
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy import Column, ForeignKey, Integer, JSON, LargeBinary, String, UniqueConstraint
from sqlalchemy.orm import Session

HERE = os.path.dirname(os.path.abspath(__file__))
WORKER = os.path.join(HERE, "csk_report_worker.py")
MAX_MB = int(os.environ.get("SURVEY_REPORT_MAX_MB", "10"))
JOB_TIMEOUT_S = int(os.environ.get("CSK_REPORT_TIMEOUT_S", "1500"))
DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"

INSTITUTES = ["ННІЕБО", "ННТІ", "ННЮІ", "ФІТ"]
INSTITUTE_FULL = {"all": "Загальна довідка — весь університет",
                  "ННІЕБО": "Навчально-науковий інститут економіки та бізнес-освіти", "ННТІ": "Навчально-науковий технологічний інститут",
                  "ННЮІ": "Навчально-науковий юридичний інститут", "ФІТ": "Факультет інформаційних технологій"}

# Ті самі значення, що й у survey_reports_csk.DEFAULTS (дублюємо, щоб не вантажити pandas у веб-процес)
DEFAULTS = {
    "institution": "Державному університеті економіки і технологій",
    "audience": "здобувачів вищої освіти 1-го курсу",
    "topic": "щодо адаптації до навчання",
    "respondents": "здобувачі вищої освіти 1-го курсу денної форми здобуття освіти",
    "instrument": "анонімна анкета адаптації здобувачів освіти 1-го курсу",
    "purpose": ("вивчення рівня адаптації здобувачів вищої освіти першого курсу денної форми здобуття освіти до умов навчання "
                "в Державному університеті економіки і технологій, оцінювання якості освітнього середовища, організації освітнього "
                "процесу, рівня підтримки з боку викладачів та університетських сервісів, а також виявлення проблемних аспектів "
                "і шляхів їх удосконалення."),
    "period_text": "",
    "ai": True, "by_unit": True, "by_spec": True, "open_appendix": False, "auto_rebuild": True,
    "scopes": INSTITUTES, "exclude": [], "titles": {}, "spec_map": {},
    "roster": {"enabled": True, "course": "1", "form": "", "level": "", "exclude_status": "відпуст|відрахов"},
}
TEXT_KEYS = ("institution", "audience", "topic", "respondents", "instrument", "purpose", "period_text")
BOOL_KEYS = ("ai", "by_unit", "by_spec", "open_appendix", "auto_rebuild")
FP_KEYS = TEXT_KEYS + ("ai", "by_unit", "by_spec", "open_appendix", "exclude", "titles", "spec_map")

PERSONAL_RE = re.compile(r"e-?mail|пошт|піб\b|прізвищ|телефон|phone|ім['’ʼ]я", re.I)
KEY_RE = re.compile(r"^\s*(id\s*відправк\w*|submission[\s_-]*id|response[\s_-]*id|id)\s*$", re.I)
TS_RE = re.compile(r"^\s*(час|дата|timestamp|позначка\s*часу|submitted)\b", re.I)
TECH_RE = re.compile(r"^\s*(id(\s*відправк\w*)?|submission[\s_-]*id|response[\s_-]*id)\s*$|мова\s*інтерфейс|час\s*заповнен|тривалість\s*заповн|^\s*(час|дата|timestamp|позначка\s*часу)\b", re.I)
SPEC_RE = re.compile(r"спеціальн|освітн\w*\s+програм|напрям", re.I)


def now_iso():
    return datetime.now().isoformat(timespec="seconds")


# ─────────────────────────────────────────────────────────────────────────────
# Читання завантаженого файлу (без pandas: openpyxl у режимі read_only / csv)
# ─────────────────────────────────────────────────────────────────────────────
def _cell(v):
    if v is None:
        return None
    if isinstance(v, datetime):
        return v.isoformat(sep=" ", timespec="seconds")
    if isinstance(v, date):
        return v.isoformat()
    if isinstance(v, bool):
        return "Так" if v else "Ні"
    if isinstance(v, float):
        if v != v:
            return None
        return int(v) if v == int(v) else v
    if isinstance(v, (int,)):
        return v
    s = str(v).strip()
    return s or None


def _tidy_header(raw):
    seen, out = {}, []
    for h in raw:
        h = re.sub(r"\s+", " ", str(h)).strip() if h is not None else ""
        if h and h in seen:
            seen[h] += 1
            h = f"{h} ({seen[h]})"
        elif h:
            seen[h] = 1
        out.append(h)
    return out


def parse_upload(data: bytes, filename: str):
    """→ (header, rows). Перший непорожній рядок — назви питань."""
    name = (filename or "").lower()
    raw_rows = []
    if name.endswith(".csv"):
        text = None
        for enc in ("utf-8-sig", "cp1251"):
            try:
                text = data.decode(enc)
                break
            except UnicodeDecodeError:
                continue
        if text is None:
            raise HTTPException(400, "Невідоме кодування CSV (потрібне UTF-8 або Windows-1251)")
        try:
            dialect = csv.Sniffer().sniff(text[:4000], delimiters=",;\t")
        except csv.Error:
            dialect = csv.excel
        raw_rows = list(csv.reader(io.StringIO(text), dialect))
    elif name.endswith((".xlsx", ".xlsm")):
        from openpyxl import load_workbook
        try:
            wb = load_workbook(io.BytesIO(data), read_only=True, data_only=True)
        except Exception:
            raise HTTPException(400, "Не вдалося прочитати файл. Потрібна таблиця .xlsx або .csv, де перший рядок — назви питань.")
        for ws in wb.worksheets:
            rows = [list(r) for r in ws.iter_rows(values_only=True)]
            if len([r for r in rows if any(c not in (None, "") for c in r)]) >= 2:
                raw_rows = rows
                break
        wb.close()
    else:
        raise HTTPException(400, "Потрібен файл .xlsx або .csv (старий .xls збережіть як .xlsx)")
    raw_rows = [r for r in raw_rows if any(c not in (None, "") for c in r)]
    if len(raw_rows) < 2:
        raise HTTPException(400, "У файлі немає відповідей")
    header = _tidy_header(raw_rows[0])
    keep = [i for i, h in enumerate(header) if h and not h.lower().startswith("unnamed")]
    header = [header[i] for i in keep]
    rows = []
    for r in raw_rows[1:]:
        vals = [_cell(r[i]) if i < len(r) else None for i in keep]
        if any(v is not None for v in vals):
            rows.append(vals)
    return header, rows


def _detect_cols(header):
    key = next((h for h in header if KEY_RE.match(h)), None)
    ts = next((h for h in header if TS_RE.match(h)), None)
    spec = next((h for h in header if SPEC_RE.search(h) and not PERSONAL_RE.search(h)), None)
    return key, ts, spec


# ─────────────────────────────────────────────────────────────────────────────
# Підключення до FastAPI
# ─────────────────────────────────────────────────────────────────────────────
def register_csk_reports(app, Base, engine, SessionLocal, get_db, require_admin, roster_rows_fn):
    """roster_rows_fn(db) → [{user_id, specialty, institute, course, form, level, status, ...}] — у main.py це _practice_student_rows."""

    class CskReport(Base):
        __tablename__ = "csk_reports"
        id = Column(Integer, primary_key=True, autoincrement=True)
        title = Column(String, nullable=False)
        created_at = Column(String, default=now_iso)
        updated_at = Column(String, default=now_iso)
        created_by = Column(String, nullable=True)
        columns = Column(JSON, default=list)           # впорядковані назви питань (без персональних колонок)
        key_col = Column(String, nullable=True)        # колонка з унікальним ID відправки (для усунення дублікатів)
        ts_col = Column(String, nullable=True)
        spec_col = Column(String, nullable=True)
        settings = Column(JSON, default=dict)          # лише те, що змінив користувач; решта — DEFAULTS
        meta = Column(JSON, default=dict)              # spec_rows, unit_counts, roster — результат останньої збірки
        n_responses = Column(Integer, default=0)

    class CskReportResponse(Base):
        __tablename__ = "csk_report_responses"
        __table_args__ = (UniqueConstraint("report_id", "row_key", name="uq_csk_resp_key"),)
        id = Column(Integer, primary_key=True, autoincrement=True)
        report_id = Column(Integer, ForeignKey("csk_reports.id", ondelete="CASCADE"), index=True, nullable=False)
        row_key = Column(String, nullable=False)
        added_at = Column(String, default=now_iso)
        import_id = Column(Integer, nullable=True)
        data = Column(JSON, nullable=False)

    class CskReportImport(Base):
        __tablename__ = "csk_report_imports"
        id = Column(Integer, primary_key=True, autoincrement=True)
        report_id = Column(Integer, ForeignKey("csk_reports.id", ondelete="CASCADE"), index=True, nullable=False)
        at = Column(String, default=now_iso)
        filename = Column(String, nullable=True)
        by = Column(String, nullable=True)
        rows_in_file = Column(Integer, default=0)
        added = Column(Integer, default=0)
        duplicates = Column(Integer, default=0)

    class CskReportDoc(Base):
        __tablename__ = "csk_report_docs"
        __table_args__ = (UniqueConstraint("report_id", "scope", name="uq_csk_doc_scope"),)
        id = Column(Integer, primary_key=True, autoincrement=True)
        report_id = Column(Integer, ForeignKey("csk_reports.id", ondelete="CASCADE"), index=True, nullable=False)
        scope = Column(String, nullable=False)         # all | ННІЕБО | ННТІ | ННЮІ | ФІТ
        status = Column(String, default="new")        # new | queued | running | ready | error | no_data
        progress = Column(Integer, default=0)
        message = Column(String, nullable=True)
        error = Column(String, nullable=True)
        queued_at = Column(String, nullable=True)
        force_ai = Column(Integer, default=0)
        built_at = Column(String, nullable=True)
        n_built = Column(Integer, default=0)           # скільки відповідей підрозділу в довідці
        n_report_at_build = Column(Integer, default=0)  # скільки відповідей було в усьому опитуванні на момент збірки
        total_students = Column(Integer, nullable=True)
        size = Column(Integer, default=0)
        facts_hash = Column(String, nullable=True)
        settings_fp = Column(String, nullable=True)
        ai = Column(JSON, nullable=True)               # кеш тексту (аналіз/висновки/рекомендації)
        ai_state = Column(String, nullable=True)       # fresh | cached | stale | rule | off
        ai_error = Column(String, nullable=True)

    class CskReportFile(Base):
        __tablename__ = "csk_report_files"
        doc_id = Column(Integer, ForeignKey("csk_report_docs.id", ondelete="CASCADE"), primary_key=True)
        data = Column(LargeBinary, nullable=False)

    R, RR, RI, RD, RF = CskReport, CskReportResponse, CskReportImport, CskReportDoc, CskReportFile
    for m in (R, RR, RI, RD, RF):
        m.__table__.create(bind=engine, checkfirst=True)        # основний create_all у main.py уже відпрацював — створюємо свої таблиці самі

    # ── налаштування ─────────────────────────────────────────────────────────
    def get_settings(rep):
        s = json.loads(json.dumps(DEFAULTS))
        for k, v in (rep.settings or {}).items():
            if k == "roster" and isinstance(v, dict):
                s["roster"].update(v)
            elif k in s:
                s[k] = v
        return s

    def settings_fp(st):
        return hashlib.md5(json.dumps({k: st[k] for k in FP_KEYS}, ensure_ascii=False, sort_keys=True).encode()).hexdigest()

    def clean_settings(patch, cur):
        out = dict(cur or {})
        for k, v in (patch or {}).items():
            if k in TEXT_KEYS:
                out[k] = str(v or "").strip()[:4000]
            elif k in BOOL_KEYS:
                out[k] = bool(v)
            elif k == "scopes":
                out[k] = [s for s in (v or []) if s in INSTITUTES]
            elif k == "exclude":
                out[k] = [str(x) for x in (v or [])][:200]
            elif k in ("titles", "spec_map"):
                out[k] = {str(a): str(b).strip() for a, b in (v or {}).items() if str(b or "").strip()}
            elif k == "roster" and isinstance(v, dict):
                r = dict(out.get("roster") or {})
                for rk in ("course", "form", "level", "exclude_status"):
                    if rk in v:
                        r[rk] = str(v[rk] or "").strip()
                if "enabled" in v:
                    r["enabled"] = bool(v["enabled"])
                out["roster"] = r
        return out

    # ── база студентів → кількість здобувачів по спеціальностях ───────────────
    def roster_snapshot(db, st, with_facets=False):
        cfg = st["roster"]
        if not cfg.get("enabled", True):
            return {"rows": [], "total": 0, "by_institute": {}, "enabled": False}
        try:
            rows = roster_rows_fn(db)
        except Exception as e:                                  # noqa: BLE001
            return {"rows": [], "total": 0, "by_institute": {}, "error": f"{e.__class__.__name__}: {e}"}
        excl = None
        if cfg.get("exclude_status"):
            try:
                excl = re.compile(cfg["exclude_status"], re.I)
            except re.error:
                excl = None
        form = (cfg.get("form") or "").casefold()
        people, facets = {}, {k: {} for k in ("course", "form", "level", "status")}
        for r in rows:
            if with_facets:
                for k in facets:
                    v = str(r.get(k) or "")
                    if v:
                        facets[k][v] = facets[k].get(v, 0) + 1
            if not str(r.get("specialty") or "").strip():
                continue
            if cfg.get("course") and str(r.get("course") or "") != cfg["course"]:
                continue
            if form and form not in str(r.get("form") or "").casefold():
                continue
            if cfg.get("level") and str(r.get("level") or "") != cfg["level"]:
                continue
            if excl and excl.search(str(r.get("status") or "")):
                continue
            people.setdefault((str(r.get("institute") or "").strip(), str(r["specialty"]).strip()), set()).add(r.get("user_id"))
        out = [{"institute": i, "specialty": s, "n": len(u)} for (i, s), u in sorted(people.items())]
        by_inst = {}
        for r in out:
            by_inst[r["institute"] or "—"] = by_inst.get(r["institute"] or "—", 0) + r["n"]
        snap = {"rows": out, "total": sum(r["n"] for r in out), "by_institute": by_inst, "at": now_iso(), "filters": cfg}
        if with_facets:
            snap["facets"] = {k: [{"value": a, "count": b} for a, b in sorted(v.items(), key=lambda t: t[0].zfill(3))] for k, v in facets.items()}
        return snap

    # ── імпорт відповідей (дозапис) ──────────────────────────────────────────
    def ingest(db, rep, header, rows, filename, by):
        keep = [i for i, h in enumerate(header) if not PERSONAL_RE.search(h)]          # персональні колонки не потрапляють у базу
        header = [header[i] for i in keep]
        rows = [[r[i] for i in keep] for r in rows]
        if rep.columns:
            overlap = len(set(header) & set(rep.columns)) / max(len(rep.columns), 1)
            if overlap < 0.6:
                raise HTTPException(400, "Схоже, це файл іншого опитування: назви питань здебільшого не збігаються із збереженими. "
                                         "Додавайте лише відповіді на цю саму анкету.")
        key_col, ts_col, spec_col = _detect_cols(header)
        rep.key_col = rep.key_col if rep.key_col in header else (key_col or rep.key_col)
        rep.ts_col = rep.ts_col if rep.ts_col in header else (ts_col or rep.ts_col)
        rep.spec_col = rep.spec_col if rep.spec_col in header else (spec_col or rep.spec_col)
        if not rep.spec_col:
            raise HTTPException(400, "У файлі немає колонки «Спеціальність» — за нею відповіді розподіляються по інститутах.")
        new_cols = [h for h in header if h not in (rep.columns or [])]
        rep.columns = list(rep.columns or []) + new_cols

        existing = {k for (k,) in db.query(RR.row_key).filter(RR.report_id == rep.id).all()}
        imp = RI(report_id=rep.id, filename=filename, by=by, rows_in_file=len(rows))
        db.add(imp)
        db.flush()
        batch, added, dups = [], 0, 0
        for vals in rows:
            d = dict(zip(header, vals))
            k = str(d.get(rep.key_col) or "").strip() if rep.key_col else ""
            if not k:
                k = "h:" + hashlib.sha1(json.dumps(vals, ensure_ascii=False, default=str).encode()).hexdigest()
            if k in existing:
                dups += 1
                continue
            existing.add(k)
            batch.append({"report_id": rep.id, "row_key": k, "added_at": now_iso(), "import_id": imp.id, "data": d})
            added += 1
            if len(batch) >= 400:
                db.bulk_insert_mappings(RR, batch)
                batch = []
        if batch:
            db.bulk_insert_mappings(RR, batch)
        imp.added, imp.duplicates = added, dups
        rep.n_responses = (rep.n_responses or 0) + added
        rep.updated_at = now_iso()
        db.commit()
        return {"rows_in_file": len(rows), "added": added, "duplicates": dups, "new_columns": new_cols, "import_id": imp.id}

    def read_file(file: UploadFile):
        data = file.file.read()
        if not data:
            raise HTTPException(400, "Файл порожній")
        if len(data) > MAX_MB * 1024 * 1024:
            raise HTTPException(413, f"Файл завеликий (максимум {MAX_MB} МБ)")
        return parse_upload(data, file.filename or "")

    # ── черга й фоновий запуск ───────────────────────────────────────────────
    state = {"thread": None, "retries": {}}
    start_lock = threading.Lock()

    def scopes_of(st):
        return ["all"] + list(st["scopes"])

    def ensure_docs(db, rep, st):
        have = {d.scope: d for d in db.query(RD).filter(RD.report_id == rep.id).all()}
        for sc in scopes_of(st):
            if sc not in have:
                d = RD(report_id=rep.id, scope=sc, status="new")
                db.add(d)
                have[sc] = d
        db.flush()
        return have

    def queue(db, rep, scopes=None, force_ai=False):
        st = get_settings(rep)
        docs = ensure_docs(db, rep, st)
        for sc, d in docs.items():
            if sc not in scopes_of(st) or (scopes and sc not in scopes):
                continue
            if d.status == "running":
                d.queued_at = now_iso()
                d.force_ai = int(force_ai or d.force_ai or 0)
                continue
            d.status, d.progress, d.message, d.error = "queued", 0, "У черзі", None
            d.queued_at, d.force_ai = now_iso(), int(force_ai)
        db.commit()
        ensure_runner()

    def ensure_runner():
        with start_lock:
            t = state["thread"]
            if t is None or not t.is_alive():
                t = threading.Thread(target=runner_loop, name="csk-report-runner", daemon=True)
                state["thread"] = t
                t.start()

    def next_report_id():
        with SessionLocal() as db:
            d = db.query(RD).filter(RD.status == "queued").order_by(RD.queued_at, RD.id).first()
            return d.report_id if d else None

    def runner_loop():
        while True:
            with start_lock:
                rid = next_report_id()
                if rid is None:
                    state["thread"] = None
                    return
            try:
                run_report(rid)
            except Exception as e:                              # noqa: BLE001
                with SessionLocal() as db:
                    for d in db.query(RD).filter(RD.report_id == rid, RD.status.in_(("queued", "running"))).all():
                        d.status, d.error, d.message = "error", f"Збій збірки: {e.__class__.__name__}: {e}", None
                    db.commit()

    def run_report(rid):
        tmp = tempfile.mkdtemp(prefix="csk_rep_")
        try:
            with SessionLocal() as db:
                rep = db.get(R, rid)
                if not rep:
                    return
                st = get_settings(rep)
                docs = ensure_docs(db, rep, st)
                todo = [d for d in docs.values() if d.status == "queued" and d.scope in scopes_of(st)]
                if not todo:
                    for d in docs.values():
                        if d.status == "queued":
                            d.status = "new"
                    db.commit()
                    return
                todo.sort(key=lambda d: scopes_of(st).index(d.scope))
                for d in todo:
                    d.status, d.progress, d.message = "running", 1, "Готую дані"
                db.commit()
                roster = roster_snapshot(db, st)
                fp = settings_fp(st)
                columns = list(rep.columns or [])
                rows = [[(r.data or {}).get(c) for c in columns] for r in db.query(RR).filter(RR.report_id == rid).order_by(RR.id).yield_per(500)]
                n_total = len(rows)
                scopes = [{"scope": d.scope, "force": bool(d.force_ai), "settings_fp": fp,
                           "cache": {"facts_hash": d.facts_hash, "settings_fp": d.settings_fp, "ai": d.ai,
                                     "has_file": db.get(RF, d.id) is not None}} for d in todo]
                job = {"report": {**{k: st[k] for k in FP_KEYS}, "ts_col": rep.ts_col, "spec_col": rep.spec_col},
                       "columns": columns, "rows": rows, "roster": roster["rows"], "scopes": scopes, "out_dir": tmp}
                rep_meta = dict(rep.meta or {})
                rep_meta["roster"] = {k: roster.get(k) for k in ("total", "by_institute", "at", "filters", "error", "enabled")}
                rep.meta = rep_meta
                db.commit()
            del rows
            job_path = os.path.join(tmp, "job.json")
            with open(job_path, "w", encoding="utf-8") as f:
                json.dump(job, f, ensure_ascii=False, default=str)
            del job

            err_path = os.path.join(tmp, "stderr.txt")
            env = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8", OMP_NUM_THREADS="1", OPENBLAS_NUM_THREADS="1", MPLBACKEND="Agg")
            with open(err_path, "wb") as ef:
                proc = subprocess.Popen([sys.executable, WORKER, job_path], stdout=subprocess.PIPE, stderr=ef, cwd=HERE, env=env)
                killer = threading.Timer(JOB_TIMEOUT_S, proc.kill)
                killer.start()
                finished, fatal = set(), None
                try:
                    for raw in proc.stdout:
                        line = raw.decode("utf-8", "replace").strip()
                        if not line.startswith("@@"):
                            continue
                        try:
                            ev = json.loads(line[2:])
                        except ValueError:
                            continue
                        fatal = handle_event(rid, ev, n_total, finished) or fatal
                finally:
                    proc.wait()
                    killer.cancel()
            tail = ""
            try:
                with open(err_path, "rb") as ef:
                    tail = ef.read()[-600:].decode("utf-8", "replace").strip()
            except OSError:
                pass
            with SessionLocal() as db:                           # усе, що не дійшло до «готово» — помилка зі зрозумілим текстом
                for d in db.query(RD).filter(RD.report_id == rid, RD.status == "running").all():
                    killed = proc.returncode in (-9, 137)
                    d.status = "error"
                    d.message = None
                    d.error = (fatal or ("Збірку зупинено: не вистачило пам'яті або часу. Спробуйте ще раз; якщо повторюється — зменште кількість питань."
                                         if killed else "Збірка завершилась без результату." + (f" Деталі: {tail[-300:]}" if tail else "")))
                db.commit()
                rep = db.get(R, rid)                             # відповіді або налаштування змінились, поки йшла збірка — одразу добудовуємо
                if rep:
                    st2 = get_settings(rep)
                    if st2["auto_rebuild"] and ((rep.n_responses or 0) > n_total or settings_fp(st2) != fp):
                        queue(db, rep)
                    bad = db.query(RD).filter(RD.report_id == rid, RD.ai_state.in_(("stale", "rule"))).all()
                    if st2["ai"] and bad and not any("не налаштовано" in (d.ai_error or "") for d in bad):
                        tries = state["retries"].get(rid, 0)           # AI був недоступний — пробуємо ще до 3 разів із паузою
                        if tries < 3:
                            state["retries"][rid] = tries + 1
                            threading.Timer(600, retry_ai, args=(rid,)).start()
                    else:
                        state["retries"].pop(rid, None)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def retry_ai(rid):
        try:
            with SessionLocal() as db:
                rep = db.get(R, rid)
                if rep:
                    queue(db, rep)
        except Exception:                                        # noqa: BLE001
            pass

    def handle_event(rid, ev, n_total, finished):
        kind = ev.get("event")
        with SessionLocal() as db:
            if kind == "fatal":
                for d in db.query(RD).filter(RD.report_id == rid, RD.status == "running").all():
                    d.status, d.error, d.message = "error", ev.get("message") or "Не вдалося обробити дані", None
                db.commit()
                return ev.get("message")
            rep = db.get(R, rid)
            if kind == "meta" and rep:
                m = dict(rep.meta or {})
                m.update(spec_rows=ev.get("spec_rows"), unit_counts=ev.get("unit_counts"), roster_unmatched=ev.get("roster_unmatched"))
                rep.meta = m
                db.commit()
                return None
            d = db.query(RD).filter(RD.report_id == rid, RD.scope == ev.get("scope")).first() if ev.get("scope") else None
            if not d:
                return None
            if kind == "progress":
                d.progress, d.message = int(ev.get("pct") or 0), ev.get("message")
            elif kind == "scope_done":
                st = ev.get("status")
                if st == "ready":
                    d.status, d.progress, d.message, d.error = "ready", 100, None, None
                    d.n_built, d.total_students = ev.get("n"), ev.get("total")
                    d.facts_hash, d.settings_fp = ev.get("facts_hash"), ev.get("settings_fp")
                    d.n_report_at_build = n_total
                    d.force_ai = 0
                    if not ev.get("skipped"):
                        with open(ev["path"], "rb") as f:
                            body = f.read()
                        fr = db.get(RF, d.id)
                        if fr:
                            fr.data = body
                        else:
                            db.add(RF(doc_id=d.id, data=body))
                        d.size, d.built_at = len(body), now_iso()
                        d.ai, d.ai_state, d.ai_error = ev.get("ai"), ev.get("ai_state"), ev.get("ai_error")
                    elif not d.built_at:
                        d.built_at = now_iso()
                elif st == "no_data":
                    d.status, d.progress, d.message, d.error, d.n_built = "no_data", 100, None, None, 0
                else:
                    d.status, d.message, d.error = "error", None, ev.get("error") or "Помилка збірки"
                finished.add(d.scope)
            db.commit()
        return None

    def resume():
        """Після перезапуску сервера недороблені довідки повертаються в чергу."""
        try:
            with SessionLocal() as db:
                n = 0
                for d in db.query(RD).filter(RD.status == "running").all():
                    d.status, d.progress, d.message = "queued", 0, "У черзі"
                    n += 1
                queued = db.query(RD).filter(RD.status == "queued").count()
                db.commit()
            if n or queued:
                ensure_runner()
        except Exception:                                        # noqa: BLE001
            pass

    # ── серіалізація ─────────────────────────────────────────────────────────
    def doc_json(d, rep, unit_counts):
        stale = max(0, (rep.n_responses or 0) - (d.n_report_at_build or 0)) if d.status == "ready" else 0
        n_scope = (rep.n_responses if d.scope == "all" else (unit_counts or {}).get(d.scope))
        total = d.total_students
        return {"scope": d.scope, "name": INSTITUTE_FULL.get(d.scope, d.scope), "status": d.status, "progress": d.progress or 0,
                "message": d.message, "error": d.error, "built_at": d.built_at, "n": d.n_built if d.status == "ready" else n_scope,
                "total": total, "coverage": round(100.0 * d.n_built / total) if total and d.n_built else None, "size": d.size or 0,
                "ai_state": d.ai_state, "ai_error": d.ai_error, "new_responses": stale, "has_file": bool(d.size)}

    def report_json(db, rep, full=False):
        st = get_settings(rep)
        docs = {d.scope: d for d in db.query(RD).filter(RD.report_id == rep.id).all()}
        meta = rep.meta or {}
        uc = meta.get("unit_counts") or {}
        scopes = scopes_of(st)
        out = {"id": rep.id, "title": rep.title, "created_at": rep.created_at, "updated_at": rep.updated_at,
               "n_responses": rep.n_responses or 0,
               "docs": [doc_json(docs[s], rep, uc) if s in docs else
                        {"scope": s, "name": INSTITUTE_FULL.get(s, s), "status": "new", "progress": 0, "n": uc.get(s) if s != "all" else rep.n_responses,
                         "total": None, "coverage": None, "new_responses": 0, "has_file": False} for s in scopes],
               "busy": any(d.status in ("queued", "running") for d in docs.values()),
               "roster_total": (meta.get("roster") or {}).get("total")}
        if full:
            qs = [c for c in (rep.columns or []) if c not in (rep.ts_col, rep.spec_col) and not TECH_RE.search(c) and not PERSONAL_RE.search(c)]
            out.update({"settings": st, "defaults": DEFAULTS, "meta": {k: meta.get(k) for k in ("spec_rows", "unit_counts", "roster", "roster_unmatched")},
                        "questions": [{"col": c, "title": (st["titles"] or {}).get(c, ""), "excluded": c in (st["exclude"] or [])} for c in qs],
                        "imports": [{"id": i.id, "at": i.at, "filename": i.filename, "rows_in_file": i.rows_in_file, "added": i.added, "duplicates": i.duplicates}
                                    for i in db.query(RI).filter(RI.report_id == rep.id).order_by(RI.id.desc()).limit(12).all()],
                        "institutes": INSTITUTES, "institute_full": INSTITUTE_FULL})
        return out

    def get_report(db, rid):
        rep = db.get(R, rid)
        if not rep:
            raise HTTPException(404, "Опитування не знайдено")
        return rep

    # ── маршрути ─────────────────────────────────────────────────────────────
    router = APIRouter(prefix="/api/csk/reports", tags=["csk-reports"])

    @router.get("")
    def list_reports(user: dict = Depends(require_admin), db: Session = Depends(get_db)):
        if db.query(RD.id).filter(RD.status == "queued").first():
            ensure_runner()
        return [report_json(db, r) for r in db.query(R).order_by(R.updated_at.desc()).all()]

    @router.post("")
    def create_report(file: UploadFile = File(...), title: str = Form(""), user: dict = Depends(require_admin), db: Session = Depends(get_db)):
        header, rows = read_file(file)
        name = re.sub(r"\.(xlsx|xlsm|csv)$", "", file.filename or "", flags=re.I).replace("_", " ").strip()
        rep = R(title=(title.strip() or name or "Опитування"), columns=[], settings={}, meta={}, n_responses=0, created_by=str(user.get("id") or user.get("email") or ""))
        db.add(rep)
        db.flush()
        try:
            res = ingest(db, rep, header, rows, file.filename, rep.created_by)
        except HTTPException:
            db.rollback()
            raise
        queue(db, rep)
        return {"report": report_json(db, rep), "import": res}

    @router.get("/{rid}")
    def detail(rid: int, user: dict = Depends(require_admin), db: Session = Depends(get_db)):
        rep = get_report(db, rid)
        if db.query(RD).filter(RD.report_id == rid, RD.status == "queued").count():
            ensure_runner()
        return report_json(db, rep, full=True)

    @router.post("/{rid}/responses")
    def add_responses(rid: int, file: UploadFile = File(...), user: dict = Depends(require_admin), db: Session = Depends(get_db)):
        """Дозапис: нові відповіді додаються, наявні (за ID відправки) пропускаються, нічого не видаляється."""
        rep = get_report(db, rid)
        header, rows = read_file(file)
        res = ingest(db, rep, header, rows, file.filename, str(user.get("id") or user.get("email") or ""))
        if res["added"] and get_settings(rep)["auto_rebuild"]:
            queue(db, rep)
        return {"report": report_json(db, rep, full=True), "import": res}

    @router.put("/{rid}/settings")
    def save_settings(rid: int, body: dict, user: dict = Depends(require_admin), db: Session = Depends(get_db)):
        rep = get_report(db, rid)
        if "title" in body and str(body["title"]).strip():
            rep.title = str(body["title"]).strip()[:200]
        rep.settings = clean_settings(body.get("settings") or {}, rep.settings)
        rep.updated_at = now_iso()
        db.commit()
        if body.get("rebuild"):
            queue(db, rep)
        return report_json(db, rep, full=True)

    @router.post("/{rid}/rebuild")
    def rebuild(rid: int, body: dict = None, user: dict = Depends(require_admin), db: Session = Depends(get_db)):
        """body: {scopes?: [...], refresh_ai?: bool}. refresh_ai — наново попросити AI написати текст навіть якщо цифри не змінились."""
        body = body or {}
        rep = get_report(db, rid)
        queue(db, rep, scopes=body.get("scopes") or None, force_ai=bool(body.get("refresh_ai")))
        return report_json(db, rep, full=True)

    @router.get("/{rid}/roster")
    def roster(rid: int, user: dict = Depends(require_admin), db: Session = Depends(get_db)):
        """Скільки здобувачів зараз у базі за поточними фільтрами + доступні значення фільтрів."""
        rep = get_report(db, rid)
        snap = roster_snapshot(db, get_settings(rep), with_facets=True)
        snap.pop("rows", None)
        return snap

    def _doc_file(db, rid, scope):
        d = db.query(RD).filter(RD.report_id == rid, RD.scope == scope).first()
        f = db.get(RF, d.id) if d else None
        if not f:
            raise HTTPException(404, "Довідка ще не готова")
        return d, f.data

    def _fname(scope):
        return "Аналітична_довідка.docx" if scope == "all" else f"Аналітична_довідка_{scope}.docx"

    @router.get("/{rid}/docs/{scope}/download")
    def download(rid: int, scope: str, user: dict = Depends(require_admin), db: Session = Depends(get_db)):
        _d, body = _doc_file(db, rid, scope)
        return StreamingResponse(io.BytesIO(body), media_type=DOCX_MIME,
                                 headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(_fname(scope))}"})

    @router.get("/{rid}/download-all")
    def download_all(rid: int, user: dict = Depends(require_admin), db: Session = Depends(get_db)):
        rep = get_report(db, rid)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
            for d in db.query(RD).filter(RD.report_id == rid).all():
                f = db.get(RF, d.id)
                if f:
                    z.writestr(_fname(d.scope), f.data)
        if not buf.getbuffer().nbytes:
            raise HTTPException(404, "Жодної довідки ще не готово")
        buf.seek(0)
        return StreamingResponse(buf, media_type="application/zip",
                                 headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote('Аналітичні_довідки.zip')}"})

    @router.delete("/{rid}")
    def delete_report(rid: int, user: dict = Depends(require_admin), db: Session = Depends(get_db)):
        rep = get_report(db, rid)
        ids = [i for (i,) in db.query(RD.id).filter(RD.report_id == rid).all()]
        if ids:
            db.query(RF).filter(RF.doc_id.in_(ids)).delete(synchronize_session=False)
        for m in (RD, RI, RR):
            db.query(m).filter(m.report_id == rid).delete(synchronize_session=False)
        db.delete(rep)
        db.commit()
        return {"ok": True}

    app.include_router(router)
    resume()
    return router
