# -*- coding: utf-8 -*-
"""
Воркер збірки аналітичних довідок ЦСК. Запускається ОКРЕМИМ процесом (див. csk_reports.py), тому:
  • pandas / matplotlib / python-docx живуть лише поки збирається довідка — потім пам'ять повністю повертається системі;
  • якщо процес не вистачить пам'яті, "падає" тільки він, а сайт працює далі.

Вхід:  python csk_report_worker.py job.json
       job.json: {report: {...налаштування...}, columns: [...], rows: [[...]], roster: [{institute, specialty, n}],
                  scopes: [{scope, force, cache: {facts_hash, settings_fp, ai, has_file}}], out_dir: "..."}
Вихід: рядки в stdout виду  @@{"event": "...", ...}  (прогрес, готові файли, підсумки). Файли довідок — у out_dir.
"""
import gc
import hashlib
import io
import json
import os
import re
import sys
import time
import traceback
from datetime import datetime

import pandas as pd

import csk_charts as ch
import survey_reports as sr
import survey_reports_csk as ck

UNIT, SPEC = ck.UNIT_COL, ck.SPEC_COL
SPEC_RAW = "__spec_raw__"
TECH_RE = re.compile(r"^\s*(id(\s*відправк\w*)?|submission[\s_-]*id|response[\s_-]*id)\s*$|мова\s*інтерфейс|час\s*заповнен|тривалість\s*заповн|^\s*(час|дата|timestamp|позначка\s*часу)\b", re.I)

# Як звучить підрозділ у заголовку довідки («здобувачів вищої освіти <…> 1-го курсу»)
SCOPE_PHRASE = {
    "ННІЕБО": "Навчально-наукового інституту економіки та бізнес-освіти",
    "ННТІ": "Навчально-наукового технологічного інституту",
    "ННЮІ": "Навчально-наукового юридичного інституту",
    "ФІТ": "факультету інформаційних технологій",
}


def emit(event, **kw):
    kw["event"] = event
    sys.stdout.write("@@" + json.dumps(kw, ensure_ascii=False) + "\n")
    sys.stdout.flush()


# ── Спеціальності та інститути ────────────────────────────────────────────────
def spec_label(v):
    """«C3 C7 Міжнародні комунікації…» → «Міжнародні комунікації…» (ck.spec_label знімає лише один код)."""
    t = re.sub(r"\s+", " ", str(v)).strip()
    t = re.sub(r"^(?:[A-Za-zА-ЯІЇЄа-яіїє]{0,2}\d+(?:[./]\d+)*\s+)+", "", t)
    return ck.spec_label(t)


def canon_inst(name):
    """Назва підрозділу з бази студентів → канонічна (ННІЕБО/ННТІ/ННЮІ/ФІТ), інакше як є."""
    s = str(name or "").strip()
    if not s:
        return None
    return s if s in ck.INSTITUTE_NAMES else (ck.classify_unit(s) or s)


def resolve_units(df, spec_col, roster, manual):
    """→ (df з колонками UNIT/SPEC, рядки для таблиці перевірки). Порядок: ручне виправлення → база студентів → ключові слова."""
    vals = df[spec_col].fillna("").astype(str).str.strip()
    roster_lab = {}
    for r in roster:
        roster_lab.setdefault(spec_label(r["specialty"]), canon_inst(r["institute"]))
    rows, mp = [], {}
    for v, n in vals[vals != ""].value_counts().items():
        lab, src, unit = spec_label(v), "undefined", None
        if v in manual and manual[v]:
            unit, src = manual[v], "manual"
        else:
            hit = ck._match_name(lab, list(roster_lab)) if roster_lab else None
            if hit and roster_lab.get(hit):
                unit, src = roster_lab[hit], "roster"
            else:
                unit = ck.classify_unit(v)
                src = "keywords" if unit else "undefined"
        mp[v] = (lab, unit or ck.UNDEFINED)
        rows.append({"value": v, "label": lab, "n": int(n), "unit": unit or ck.UNDEFINED, "source": src})
    df[SPEC] = vals.map(lambda x: mp[x][0] if x in mp else None)
    df[UNIT] = vals.map(lambda x: mp[x][1] if x in mp else ck.UNDEFINED)
    return df, rows


def totals_info(df, roster):
    """Кількість здобувачів з бази (по спеціальностях) зіставляється зі спеціальностями з відповідей. Структура — як ck._spec_totals."""
    d = df.dropna(subset=[SPEC])
    lab_unit = {l: str(g[UNIT].mode().iat[0]) for l, g in d.groupby(SPEC)}
    lab_n = d[SPEC].value_counts().to_dict()
    rows = {}
    for r in roster:
        lab = spec_label(r["specialty"])
        key = ck._match_name(lab, list(lab_n)) or lab
        row = rows.setdefault(key, {"label": key, "n": int(lab_n.get(key, 0)), "total": 0,
                                    "unit": lab_unit.get(key) or canon_inst(r["institute"]) or ck.UNDEFINED})
        row["total"] += int(r["n"])
    for lab, n in lab_n.items():
        rows.setdefault(lab, {"label": lab, "n": int(n), "total": None, "unit": lab_unit.get(lab, ck.UNDEFINED)})
    out = sorted(rows.values(), key=lambda r: (ck._unit_key(r["unit"]), -(r["total"] or 0), -r["n"], r["label"].lower()))
    unit_totals = {}
    for r in out:
        if r["total"]:
            unit_totals[r["unit"]] = unit_totals.get(r["unit"], 0) + r["total"]
    has = bool(roster)
    return {"rows": out, "sum": sum(unit_totals.values()), "unit_totals": unit_totals, "has_totals": has}


# ── Підготовка даних ─────────────────────────────────────────────────────────
def prepare(job):
    rep = job["report"]
    df = pd.DataFrame(job["rows"], columns=job["columns"], dtype=object)
    ts = rep.get("ts_col") if rep.get("ts_col") in df.columns else None
    if not ts:
        ts = next((c for c in df.columns if re.match(r"^\s*(час|дата|timestamp|позначка)", c, re.I)), None)
    spec = rep.get("spec_col") if rep.get("spec_col") in df.columns else ck._detect_specialty(df, {ts})
    if not spec:
        raise ValueError("У файлі не знайдено колонку «Спеціальність» — вона потрібна, щоб розподілити відповіді по інститутах.")
    df, spec_rows = resolve_units(df, spec, job.get("roster") or [], rep.get("spec_map") or {})
    if ts:
        df[ts] = pd.to_datetime(df[ts], errors="coerce")
    return df, ts, spec, spec_rows


def choose_questions(df, ts, spec, rep):
    skip = {ts, spec, UNIT, SPEC, SPEC_RAW}
    skip |= {c for c in df.columns if TECH_RE.search(str(c))}
    chosen = ck._questions(df, skip, set(rep.get("exclude") or []), rep.get("titles") or {})
    numbered = [c for c in df.columns if c not in skip and not sr.PERSONAL_RE.search(c) and re.match(r"\s*\d+\s*[.)]", str(c))]
    q_total = len(numbered) or len(chosen)
    return chosen, q_total, skip


def build_stats(dfs, chosen):
    stats = [s for s in (sr.compute_stats(dfs, q) for q in chosen) if s["kind"] != "empty"]
    for st in stats:
        ck._merge_variants(st)
        ck._collapse_free_text(st)
    return stats


# ── AI з кешем ───────────────────────────────────────────────────────────────
SCOPE_NOTE = ("\n\nВАЖЛИВО: довідка стосується лише одного підрозділу — {phrase}. Усі дані вище належать тільки йому. "
              "Не порівнюй з іншими інститутами й не згадуй їх. У «intro» назви спеціальності та охоплення (якщо воно відоме) і застерігай про добровільність участі.")


def ai_text(stats, ctx, scope):
    qids = [f"q{i}" for i in range(1, len(stats) + 1)]
    payload = {"survey": {"audience": ctx["audience"], "topic": ctx["topic"], "institution": ctx["institution"],
                          "respondents": ctx["n"], "total_students": ctx.get("total_students"),
                          "coverage_percent": ctx.get("coverage"), "units": ctx.get("unit_counts")},
               "questions": ck._facts(stats)}
    user = "Дані опитування (JSON):\n" + json.dumps(payload, ensure_ascii=False)
    if scope != "all":
        user += SCOPE_NOTE.format(phrase=SCOPE_PHRASE.get(scope, scope))
    return ck._normalize(ck._parse_json(ck._ai_call(ck.SYSTEM_PROMPT, user)), set(qids))


def report_text(stats, ctx, scope, rep, cache, force):
    """→ (report, ai_state, ai_error, facts_hash). ai_state: fresh | cached | stale | rule | off."""
    fh = hashlib.md5(json.dumps({"f": ck._facts(stats), "n": ctx["n"], "t": ctx.get("total_students"), "s": scope},
                                ensure_ascii=False, sort_keys=True).encode()).hexdigest()
    cached = (cache or {}).get("ai")
    if not rep.get("ai", True):
        return ck.rule_report(stats, ctx), "off", None, fh
    if cached and cache.get("facts_hash") == fh and not force:
        return cached, "cached", None, fh                         # цифри не змінились — текст лишається, AI не потрібен
    try:
        return ai_text(stats, ctx, scope), "fresh", None, fh
    except ck.AIError as e:
        err = str(e)
    except Exception as e:                                         # noqa: BLE001
        err = f"{e.__class__.__name__}: {e}"
    if cached:                                                     # AI недоступний — лишаємо попередній текст, діаграми все одно свіжі
        return cached, "stale", err, fh
    return ck.rule_report(stats, ctx), "rule", err, fh


# ── Збірка .docx ─────────────────────────────────────────────────────────────
def build_docx(dfs, stats, report, ctx, scope, by_unit, by_spec, open_appendix):
    from docx import Document
    if not os.path.exists(ck.TEMPLATE_PATH):
        raise ValueError("Не знайдено шаблон csk_template.docx — покладіть його поруч із csk_report_worker.py.")
    doc = Document(ck.TEMPLATE_PATH)
    doc.core_properties.title = "Аналітична довідка" + ("" if scope == "all" else f" — {scope}")
    inst_doc = scope != "all"
    n = ctx["n"]
    P, L, N, PIC = ck._para, ck._labeled, ck._numbered, ck._picture

    p = P(doc, "АНАЛІТИЧНА ДОВІДКА", style="Heading 1", size=14, center=True)
    for r in p.runs:
        ck._fmt_run(r, 14, auto_color=True)
    sub = P(doc, size=14, center=True)
    lines = [f"за результатами опитування {ctx['audience']}"] + ([ctx["topic"]] if ctx["topic"] else []) + ([f"у {ctx['institution']}"] if ctx["institution"] else [])
    for i, ln in enumerate(lines):
        r = sub.add_run()
        if i:
            r.add_break()
        r.add_text(ln)
        ck._fmt_run(r, 14)
    P(doc, style="Normal")

    P(doc, "1. Загальна інформація", style="Heading 2", size=13)
    ck._fmt_run(P(doc, size=13).add_run("Мета опитування:"), 13, True)
    P(doc, ctx["purpose"], style="Normal (Web)", justify=True)
    P(doc, style="Normal")
    L(doc, "Період проведення опитування:", ctx["period_text"] or "[вкажіть період проведення]")
    P(doc, style="Normal")
    L(doc, "Категорія респондентів:", ctx["respondents"])
    P(doc, style="Normal")
    cnt = (f"загальна кількість здобувачів {ctx['total_students']}, пройшли опитування – {n}." if ctx.get("total_students")
           else f"пройшли опитування – {n}.")
    L(doc, "Кількість респондентів:", cnt)
    P(doc, style="Normal")
    kinds = {s["kind"] for s in stats}
    typ = "закритого та відкритого типу" if "open" in kinds and kinds - {"open"} else "відкритого типу" if kinds == {"open"} else "закритого типу"
    k = ctx["questions_total"]
    L(doc, "Інструмент опитування:", f"{ctx['instrument']}, що містить {k} {sr.plural(k, ('запитання', 'запитання', 'запитань'))} {typ}.")
    P(doc, style="Normal")

    first = 2
    if inst_doc:                                           # як у зразках по інститутах: окремий розділ «2.» про участь
        P(doc, "2. Участь здобувачів в опитуванні", style="Heading 2", size=13, keep_next=True)
        first = 3
    if report["intro"]:
        P(doc, report["intro"], style="Normal", justify=True, first_indent=True)
    for png in ctx["participation_charts"]:
        PIC(doc, png)
    P(doc, style="Normal")

    by_id = {f"q{i}": st for i, st in enumerate(stats, 1)}
    P(doc, f"{first}. Аналіз результатів опитування", style="Heading 2", size=13, keep_next=True)
    for si, sec in enumerate(report["sections"], 1):
        P(doc, f"{first}.{si}. {sec['title']}", style="Heading 3", size=13, keep_next=True)
        for blk in sec["blocks"]:
            for t in blk["paragraphs"]:
                P(doc, t, style="Normal (Web)", justify=True, first_indent=True)
            for qid in blk["question_ids"]:
                st = by_id[qid]
                if st["kind"] == "open":
                    continue
                num = ck._qnum(st, int(qid[1:]))
                png = ch.chart_for(st, num)
                if png:
                    PIC(doc, png)
                if by_unit:
                    m = ck._unit_matrix(dfs, UNIT, st)
                    if m:
                        PIC(doc, ch.chart_by_unit(ch.short_title(st), *m, num))
                if by_spec:
                    m = ck._spec_matrix(dfs, UNIT, st)
                    if m:
                        for img in ch.chart_by_spec(ch.short_title(st), *m, num):
                            PIC(doc, img)

    P(doc, f"{first + 1}. Узагальнені висновки", style="Heading 2", size=13, keep_next=True)
    P(doc, "За результатами опитування встановлено, що:", style="Normal (Web)", keep_next=True)
    for t in (report["conclusions"] or ["[впишіть висновки]"]):
        N(doc, t, 4) if report["conclusions"] else P(doc, t, style="Normal (Web)")
    P(doc, ck.CLOSING_SENTENCE, style="Normal", justify=True, first_indent=True, before=6)

    P(doc, f"{first + 2}. Рекомендації та пропозиції", style="Heading 2", size=13, keep_next=True)
    P(doc, report["recommendations_intro"] or "З метою вдосконалення за результатами опитування рекомендовано:", style="Normal (Web)", keep_next=True)
    for t in (report["recommendations"] or ["[впишіть рекомендації]"]):
        N(doc, t, 5) if report["recommendations"] else P(doc, t, style="Normal (Web)")
    P(doc, style="Normal")
    P(doc, ck._date_phrase(ctx["now"]), style="Normal (Web)")

    if open_appendix:
        cards = [(st, sr.make_open_cards(st)) for st in stats if st["kind"] == "open" and st.get("answers")]
        if cards:
            doc.add_page_break()
            P(doc, "Додаток. Текстові відповіді респондентів", style="Heading 2", size=13, center=True, keep_next=True)
            for _st, pngs in cards:
                for png in pngs:
                    PIC(doc, png)
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


# ── Один підрозділ ───────────────────────────────────────────────────────────
def build_scope(job, df, ts, chosen, q_total, tinfo, spec_total_rows, sc, idx, count):
    rep, scope = job["report"], sc["scope"]
    base, span = 100.0 * idx / count, 100.0 / count
    prog = lambda f, msg: emit("progress", scope=scope, pct=int(base + span * f), message=msg)
    prog(0.05, "Рахую показники")

    dfs = df if scope == "all" else df[df[UNIT] == scope]
    n = int(len(dfs))
    if n == 0:
        emit("scope_done", scope=scope, status="no_data", n=0)
        return
    stats = build_stats(dfs, chosen)
    if not stats:
        raise ValueError("Не залишилось жодного питання для довідки")

    rows = [r for r in tinfo["rows"] if scope == "all" or r["unit"] == scope]
    total = (tinfo["sum"] if scope == "all" else tinfo["unit_totals"].get(scope)) or None
    g = lambda k: (str(rep.get(k) or "").strip() or ck.DEFAULTS[k])
    inst_phrase = SCOPE_PHRASE.get(scope, scope)
    if scope == "all":
        audience, respondents = g("audience"), g("respondents")
    else:
        audience = f"здобувачів вищої освіти {inst_phrase} 1-го курсу"
        respondents = f"{g('respondents').rstrip('.')} {inst_phrase}."
    unit_counts = {str(k): int(v) for k, v in dfs[UNIT].dropna().astype(str).value_counts().items()}
    period = (str(rep.get("period_text") or "").strip()
              or (ck._period_text((df[ts].min().strftime("%d.%m.%Y"), df[ts].max().strftime("%d.%m.%Y"))) if ts and df[ts].notna().any() else ""))

    charts = []
    if scope == "all":
        if len(rows) >= 2:
            charts = ch.chart_participation_specs(ck._spec_groups({"rows": rows}))
        elif len(unit_counts) >= 2:
            names = sorted(unit_counts, key=ck._unit_key)
            charts = [ch.chart_participation([(u, unit_counts[u], tinfo["unit_totals"].get(u)) for u in names[:ck.MAX_UNITS_IN_CHART]])]
    elif rows:
        charts = ch.chart_participation_specs([(scope, [(r["label"], r["n"], r["total"]) for r in rows])])

    ctx = {"institution": g("institution"), "audience": audience, "topic": str(rep.get("topic", ck.DEFAULTS["topic"])).strip(),
           "respondents": respondents, "instrument": g("instrument"), "purpose": g("purpose"), "period_text": period, "n": n,
           "total_students": total, "coverage": round(100.0 * n / total) if total else None,
           "unit_counts": unit_counts if scope == "all" else None, "questions_total": q_total,
           "participation_charts": charts, "now": datetime.now()}

    fp = hashlib.md5(json.dumps({"s": sc.get("settings_fp"), "p": period, "r": [(x["label"], x["total"]) for x in rows]},
                                ensure_ascii=False, sort_keys=True).encode()).hexdigest()
    cache = sc.get("cache") or {}
    facts_hash = hashlib.md5(json.dumps({"f": ck._facts(stats), "n": n, "t": total, "s": scope}, ensure_ascii=False, sort_keys=True).encode()).hexdigest()
    if cache.get("has_file") and cache.get("facts_hash") == facts_hash and cache.get("settings_fp") == fp and not sc.get("force"):
        emit("scope_done", scope=scope, status="ready", skipped=True, n=n, total=total, facts_hash=facts_hash, settings_fp=fp)
        return                                                    # нічого не змінилось у цьому підрозділі — не чіпаємо

    prog(0.25, "AI пише аналіз" if rep.get("ai", True) else "Формую текст")
    report, ai_state, ai_err, facts_hash = report_text(stats, ctx, scope, rep, cache, bool(sc.get("force")))
    prog(0.6, "Будую діаграми й документ")
    body = build_docx(dfs, stats, report, ctx, scope, by_unit=bool(rep.get("by_unit", True)) and scope == "all",
                      by_spec=bool(rep.get("by_spec", True)), open_appendix=bool(rep.get("open_appendix", False)))
    if ai_state in ("stale", "rule"):
        facts_hash = None            # текст не відповідає цифрам — наступна збірка має знову спробувати AI, а не пропустити підрозділ
    path = os.path.join(job["out_dir"], f"{idx}.docx")
    with open(path, "wb") as f:
        f.write(body)
    emit("scope_done", scope=scope, status="ready", path=path, size=len(body), n=n, total=total, facts_hash=facts_hash,
         settings_fp=fp, ai=report if ai_state in ("fresh", "cached", "stale") else None, ai_state=ai_state, ai_error=ai_err)
    del body, stats, charts, ctx, dfs
    gc.collect()


def main(job_path):
    with open(job_path, encoding="utf-8") as f:
        job = json.load(f)
    try:
        df, ts, spec, spec_rows = prepare(job)
        chosen, q_total, _skip = choose_questions(df, ts, spec, job["report"])
        tinfo = totals_info(df, job.get("roster") or [])
        emit("meta", spec_rows=sorted(spec_rows, key=lambda r: -r["n"]), n=int(len(df)),
             unit_counts={str(k): int(v) for k, v in df[UNIT].value_counts().items()},
             roster_unmatched=[r["label"] for r in tinfo["rows"] if r["total"] and not r["n"]][:40])
    except Exception as e:                                         # noqa: BLE001
        emit("fatal", message=str(e) if isinstance(e, ValueError) else f"{e.__class__.__name__}: {e}")
        return 1
    scopes = job["scopes"]
    for i, sc in enumerate(scopes):
        try:
            build_scope(job, df, ts, chosen, q_total, tinfo, None, sc, i, len(scopes))
        except Exception as e:                                     # noqa: BLE001
            traceback.print_exc(file=sys.stderr)
            emit("scope_done", scope=sc["scope"], status="error", error=str(e) if isinstance(e, ValueError) else f"{e.__class__.__name__}: {e}")
        gc.collect()
    emit("finished")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
