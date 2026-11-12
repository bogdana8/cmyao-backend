# -*- coding: utf-8 -*-
"""
Аналітична довідка для ЦСК — структура зі зразка «Аналітична_довідка.docx»:

  АНАЛІТИЧНА ДОВІДКА → 1. Загальна інформація (мета, період, категорія, кількість респондентів, інструмент, діаграми участі)
  → 2. Аналіз результатів опитування (2.1, 2.2 … — тематичні підрозділи: текст аналізу + діаграми питань)
  → 3. Узагальнені висновки → 4. Рекомендації та пропозиції → дата.

Текст аналізу, висновків і рекомендацій пише AI за ТОЧНИМИ числами з файлу (безкоштовний Google Gemini; запасний варіант — Anthropic):
розподіли відповідей, середні бали, відкриті відповіді (без контактів). Діаграми будуються кодом, тож цифри в тексті й на діаграмах збігаються.
Без AI (ai = false) довідка збирається за правилами з цифр, а висновки й рекомендації лишаються для ручного заповнення.

Потрібні: survey_reports.py (поруч), csk_template.docx (поруч), pandas, openpyxl, python-docx, matplotlib, requests.
Змінні середовища (достатньо однієї): GEMINI_API_KEY (безкоштовно, aistudio.google.com) або ANTHROPIC_API_KEY.
Необов'язково: CSK_GEMINI_MODEL (примусово задати модель; інакше підбирається автоматично), CSK_REPORT_AI_MODEL (Anthropic, за замовчуванням claude-sonnet-5-5).
"""
import io
import json
import os
import re
import time
from collections import Counter
from datetime import datetime

import pandas as pd

import survey_reports as sr

TEMPLATE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "csk_template.docx")
# Google часто міняє лінійку моделей, тому код не прив'язаний до однієї: бере CSK_GEMINI_MODEL (якщо задано), інакше
# перебирає ці кандидати (лише ті, що реально доступні ключу) і запам'ятовує першу, що спрацювала.
GEMINI_MODEL = (os.environ.get("CSK_GEMINI_MODEL") or "").strip()
GEMINI_CANDIDATES = ["gemini-3.6-flash", "gemini-3.5-flash-lite", "gemini-3.8-flash", "gemini-3.1-flash-lite",
                     "gemini-3-flash-preview", "gemini-2.5-flash", "gemini-2.5-flash-lite"]
_GEMINI_OK = {"model": None}
ANTHROPIC_MODEL = os.environ.get("CSK_REPORT_AI_MODEL", "claude-sonnet-5-5")
MAX_UNITS_IN_CHART = 12

DEFAULTS = {
    "institution": "Державному університеті економіки і технологій",
    "audience": "здобувачів вищої освіти 1-го курсу",
    "topic": "щодо адаптації до навчання",
    "respondents": "здобувачі вищої освіти 1-го курсу денної форми здобуття освіти",
    "instrument": "анонімна анкета",
    "purpose": ("вивчення рівня адаптації здобувачів вищої освіти першого курсу денної форми здобуття освіти до умов навчання "
                "в Державному університеті економіки і технологій, оцінювання якості освітнього середовища, організації освітнього "
                "процесу, рівня підтримки з боку викладачів та університетських сервісів, а також виявлення проблемних аспектів "
                "і шляхів їх удосконалення."),
}
UNIT_RE = re.compile(r"інститут|факультет|структурн|підрозділ|навчально-науков|\bнні\b", re.I)
CLOSING_SENTENCE = ("Результати опитування використовуються в межах внутрішньої системи забезпечення якості освіти Університету "
                    "для прийняття управлінських рішень та планування заходів з удосконалення освітнього процесу.")


class AIError(ValueError):
    """Помилка виклику AI — показується користувачеві як є."""


# ─────────────────────────────────────────────────────────────────────────────
# Розбір файлу
# ─────────────────────────────────────────────────────────────────────────────
def _detect_unit(df, skip):
    for c in df.columns:
        if c in skip or sr.PERSONAL_RE.search(c):
            continue
        if UNIT_RE.search(c) and 1 < df[c].nunique() <= 30:
            return c
    return None


def _columns(df, overrides):
    ov = overrides or {}
    det = sr.detect_columns(df)
    ts = ov["timestamp"] if "timestamp" in ov else det["timestamp"]
    ts = ts if ts in df.columns else None
    unit = ov["unit"] if "unit" in ov else _detect_unit(df, {ts})
    unit = unit if unit in df.columns else None
    return ts, unit


def _period(df, ts):
    if not ts:
        return None
    s = df[ts]
    if not pd.api.types.is_datetime64_any_dtype(s):
        s = s.map(lambda x: x if hasattr(x, "year") else (str(x).strip() if x is not None else x))
    try:
        d = pd.to_datetime(s, errors="coerce", dayfirst=True, format="mixed").dropna()      # «02.12.2025 10:15» — день перед місяцем
    except Exception:       # noqa: BLE001
        d = pd.to_datetime(s, errors="coerce", dayfirst=True).dropna()
    if d.empty:
        return None
    return d.min().strftime("%d.%m.%Y"), d.max().strftime("%d.%m.%Y")


def _period_text(p):
    if not p:
        return ""
    return f"{p[0]} р." if p[0] == p[1] else f"з {p[0]} р. по {p[1]} р."


def _questions(df, skip, exclude=(), titles=None):
    out = []
    for c in df.columns:
        if c in skip or c in exclude or sr.PERSONAL_RE.search(c):
            continue
        q = sr.classify_question(c, df[c])
        if q["kind"] == "empty":
            continue
        title = sr._clean(str((titles or {}).get(c) or ""))
        if title:
            q["label"], q["label_short"] = title, sr.label_short(title)
        out.append(q)
    return out


def analyze_csk(data: bytes, filename: str = "", overrides: dict = None) -> dict:
    """Для екрана налаштувань: колонки, типи питань, підрозділи, період."""
    df = sr.read_table(data, filename)
    ts, unit = _columns(df, overrides)
    qs = _questions(df, {ts, unit})
    units = []
    if unit:
        units = [{"name": str(k), "n": int(v)} for k, v in df[unit].dropna().astype(str).value_counts().items()]
        units.sort(key=lambda u: u["name"].lower())
    return {"rows": int(len(df)), "columns": {"unit": unit, "timestamp": ts}, "all_columns": list(df.columns),
            "questions": qs, "units": units, "period_text": _period_text(_period(df, ts)), "defaults": DEFAULTS}


# ─────────────────────────────────────────────────────────────────────────────
# Діаграми: участь за підрозділами та розподіл відповідей за підрозділами
# ─────────────────────────────────────────────────────────────────────────────
def chart_participation(rows, title="Участь в опитуванні за підрозділами"):
    """rows: [(підрозділ, пройшли, всього|None)]. Дві смуги, якщо відомо «всього»."""
    has_total = any(t for _, _, t in rows)
    x0, x1 = sr.PAD, sr.CHART_W - sr.PAD
    tl = sr._title_lines(title)
    top = max([max(n, t or 0) for _, n, t in rows] + [1])
    vw = 0.95
    tr_w = x1 - x0 - vw - 0.18
    blocks = []
    for name, n, t in rows:
        ln = sr._wrap(sr._clean(name), 8.8, x1 - x0)
        h = len(ln) * 0.165 + 0.05 + (0.13 + 0.07) * (2 if (has_total and t) else 1) + 0.14
        blocks.append((ln, h))
    legend_h = 0.28 if has_total else 0.0
    y_top = sr.PAD + len(tl) * sr.TITLE_LH + 0.2
    cv = sr._Canvas(y_top + legend_h + sum(h for _, h in blocks) + sr.PAD * 0.6)
    sr._shell(cv)
    sr._draw_title(cv, tl, sr.PAD)
    y = y_top
    if has_total:
        cv.box(x0, y + 0.07, 0.12, 0.12, r=0.06, fc=sr.BLUE, z=2); cv.text(x0 + 0.2, y + 0.13, "Пройшли опитування", 8.5, sr.MUTED)
        cv.box(x0 + 1.75, y + 0.07, 0.12, 0.12, r=0.06, fc=sr.GREEN, z=2); cv.text(x0 + 1.95, y + 0.13, "Всього в Університеті", 8.5, sr.MUTED)
        y += legend_h
    for (name, n, t), (ln, h) in zip(rows, blocks):
        yy = cv.lines(x0, y, ln, 8.8, 0.165, color=sr.INK, weight="bold")
        yb = yy + 0.05 + 0.065
        cv.box(x0, yb - 0.065, tr_w, 0.13, r=0.065, fc=sr.TRACK, z=1)
        cv.box(x0, yb - 0.065, max(tr_w * n / top, 0.13), 0.13, r=0.065, fc=sr.BLUE, z=2)
        lab = f"{n}" + (f" з {t} ({sr.pct(n, t)})" if t else "")
        cv.text(x1, yb, lab, 8.5, sr.INK, "normal", "right")
        if has_total and t:
            yb += 0.2
            cv.box(x0, yb - 0.065, tr_w, 0.13, r=0.065, fc=sr.TRACK, z=1)
            cv.box(x0, yb - 0.065, max(tr_w * t / top, 0.13), 0.13, r=0.065, fc=sr.GREEN, z=2)
            cv.text(x1, yb, str(t), 8.5, sr.MUTED, "normal", "right")
        y += h
    return cv.png()


def _unit_matrix(df, unit, st):
    """→ (категорії [(підпис, колір)], рядки [(підрозділ, [кількості], усього)]) або None."""
    if st["kind"] == "rating":
        lo, hi = st["lo"], st["hi"]
        keys = list(range(lo, hi + 1))
        cats = [(str(k), sr._scale_color((k - lo) / max(hi - lo, 1))) for k in keys]

        def vals(s):
            v = pd.to_numeric(s.astype(str).str.replace(",", ".", regex=False), errors="coerce").dropna().round().astype(int)
            c = Counter(v.tolist())
            return [c.get(k, 0) for k in keys]
    elif st["kind"] == "single":
        top = [o for o, _ in st["opts"][:5]]
        keys = top + (["Інші відповіді"] if len(st["opts"]) > 5 else [])
        cats = [(k, sr.PALETTE[i % len(sr.PALETTE)] if k != "Інші відповіді" else "#B8BECC") for i, k in enumerate(keys)]

        def vals(s):
            c = Counter(s.astype(str).str.strip().tolist())
            row = [c.get(o, 0) for o in top]
            if len(keys) > len(top):
                row.append(sum(v for o, v in c.items() if o not in top))
            return row
    else:
        return None
    rows = []
    for u, g in df.groupby(df[unit].astype(str)):
        s = g[st["col"]].dropna()
        s = s[s.astype(str).str.strip() != ""]
        if len(s):
            v = vals(s)
            rows.append((u, v, sum(v)))
    rows.sort(key=lambda r: -r[2])
    rows = rows[:MAX_UNITS_IN_CHART]
    rows.sort(key=lambda r: r[0].lower())
    return (cats, rows) if len(rows) >= 2 else None


def chart_by_unit(title, cats, rows):
    x0, x1 = sr.PAD, sr.CHART_W - sr.PAD
    lw = 1.85
    bx0, bx1 = x0 + lw, x1 - 0.5
    bw = bx1 - bx0
    tl = sr._title_lines(title + " — за підрозділами")
    # легенда: чипи з переносом
    lg, cx, cy = [], bx0 - lw, 0.0
    for lab, col in cats:
        w = 0.22 + sr._tw(lab, 8.3) + 0.2
        if cx + w > x1 - x0 + (bx0 - lw) and cx > bx0 - lw:
            cx, cy = bx0 - lw, cy + 0.22
        lg.append((cx, cy, lab, col))
        cx += w
    legend_h = cy + 0.26
    rh = []
    for u, _, _ in rows:
        ln = sr._wrap(sr._clean(u), 8.6, lw - 0.12)
        rh.append((ln, max(0.34, len(ln) * 0.16 + 0.12)))
    y_top = sr.PAD + len(tl) * sr.TITLE_LH + 0.2
    cv = sr._Canvas(y_top + legend_h + 0.08 + sum(h for _, h in rh) + sr.PAD * 0.7)
    sr._shell(cv)
    sr._draw_title(cv, tl, sr.PAD)
    for gx, gy, lab, col in lg:
        cv.box(x0 + gx, y_top + gy + 0.07, 0.12, 0.12, r=0.06, fc=col, z=2)
        cv.text(x0 + gx + 0.19, y_top + gy + 0.13, lab, 8.3, sr.MUTED)
    y = y_top + legend_h + 0.08
    for (u, vals, tot), (ln, h) in zip(rows, rh):
        cv.lines(x0, y + (h - len(ln) * 0.16) / 2, ln, 8.6, 0.16, color=sr.INK)
        yc = y + h / 2
        cv.box(bx0, yc - 0.11, bw, 0.22, r=0.05, fc=sr.TRACK, z=1)
        xx = bx0
        for v, (_lab, col) in zip(vals, cats):
            if not v:
                continue
            w = bw * v / tot
            cv.box(xx, yc - 0.11, w, 0.22, r=0.02, fc=col, ec="white", lw=0.8, z=2)
            if w >= 0.36:
                cv.text(xx + w / 2, yc, f"{round(100.0 * v / tot)}%", 7.8, sr._text_on(col), "bold", "center", z=6)
            xx += w
        cv.text(x1, yc, f"n={tot}", 8, sr.MUTED, "normal", "right")
        y += h
    return cv.png()


# ─────────────────────────────────────────────────────────────────────────────
# AI: аналіз діаграм і відповідей → текст довідки
# ─────────────────────────────────────────────────────────────────────────────
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_PHONE_RE = re.compile(r"\+?\d[\d\s()\-]{8,}\d")


def _redact(s, limit=280):
    s = _PHONE_RE.sub("[прибрано]", _EMAIL_RE.sub("[прибрано]", sr._clean(s)))
    return s if len(s) <= limit else s[:limit].rstrip() + "…"


def _facts(stats, open_cap=120):
    out = []
    for i, st in enumerate(stats, 1):
        it = {"id": f"q{i}", "title": st["label"], "type": st["kind"], "answered": st["n"]}
        if st["kind"] == "rating":
            it.update(scale=f"{st['lo']}-{st['hi']}", counts={str(k): v for k, v in sorted(st["counts"].items())}, mean=round(st["mean"], 2))
        elif st["kind"] in ("single", "multi"):
            it["multiple_choice_allowed"] = st["kind"] == "multi"
            it["options"] = [{"text": sr._clean(o), "count": c, "percent": round(100.0 * c / st["n"], 1)} for o, c in st["opts"][:20]]
            if len(st["opts"]) > 20:
                it["other_options_count"] = sum(c for _, c in st["opts"][20:])
        elif st["kind"] == "open":
            it["meaningful_answers"] = st["meaningful"]
            it["answers"] = [_redact(a) for a in st["answers"][:open_cap]]
        out.append(it)
    return out


SYSTEM_PROMPT = """Ти — аналітик Центру студентських комунікацій (ЦСК) українського університету. Складаєш офіційну аналітичну довідку за результатами анонімного опитування здобувачів. Усі діаграми до довідки будуються окремо з тих самих даних, які тобі надано, — твоє завдання написати текст, що їх пояснює.

ПРАВИЛА
1. Пиши українською, офіційно-діловим стилем, від третьої особи («здобувачі зазначили…», «результати свідчать…»). Без «я», «ми», без емоційних оцінок, без markdown, без emoji.
2. Використовуй ЛИШЕ числа з наданих даних. Нічого не вигадуй, не обчислюй нових показників, окрім простих відсотків від наданих кількостей. Кількості респондентів пиши цифрами з правильним узгодженням: 1 здобувач, 2–4 здобувачі, 5+ здобувачів.
3. Для кожної групи питань: опиши найчастішу відповідь (з кількістю), помітні меншості (з кількістю), обережно поясни можливі причини («що може свідчити про…», «може бути пов'язано з…») і заверши абзацом, що починається зі слова «Загалом» і формулює висновок та, за потреби, напрям покращення.
4. Відкриті відповіді: узагальнюй за темами («найчастіше згадували…», «окремі здобувачі пропонують…»). Кількість називай лише якщо вона є в даних (meaningful_answers). Не цитуй дослівно, не називай імен, прізвищ викладачів, груп чи контактів.
5. Показники, що тривожать, не замовчуй; позитивні — не перебільшуй. Якщо респондентів мало (менше 30) — зазнач, що результати орієнтовні.
6. Десяткові дроби пиши через кому (4,25), відсотки — із знаком % (31 %). Тон і обсяг — як у прикладі нижче.

ПРИКЛАД СТИЛЮ (розділ «Загальна оцінка якості освітнього процесу», шкала 1–5):
«Більшість здобувачів оцінили якість освіти на 4 або 5, що свідчить про загальне задоволення процесом навчання та його результатами.»
«13 здобувачів поставили оцінку 3, що може означати певні зауваження або бажання покращити окремі аспекти навчання.»
«Лише 2 здобувачі оцінили якість освіти на 2, а оцінки 1 не було. Це свідчить про мінімальний рівень критики.»
«Загалом здобувачі позитивно оцінюють якість освіти в Університеті, причому велика частина дає максимально високі оцінки. Невелика група здобувачів із середніми оцінками вказує на можливість покращення деяких аспектів освітнього процесу, але критичні проблеми відсутні.»

СТРУКТУРА ВІДПОВІДІ — лише один JSON-об'єкт, без пояснень і без ```:
{
  "intro": "2–3 речення для розділу «Загальна інформація»: хто взяв участь, яку частку охоплено (якщо відомо загальну кількість), застереження про добровільність участі та те, що результати дають узагальнену картину",
  "sections": [
    {"title": "тематична назва підрозділу без нумерації",
     "blocks": [
        {"question_ids": ["q1", "q2"], "paragraphs": ["абзац", "абзац", "абзац", "Загалом …"]}
     ]}
  ],
  "conclusions": ["5–7 узагальнених висновків, кожен — одне-два речення"],
  "recommendations_intro": "одне речення виду «З метою … рекомендовано:»",
  "recommendations": ["5–8 рекомендацій в інфінітиві («Посилити…», «Розглянути можливість…»), кожна випливає з даних"]
}

Вимоги до sections: 3–8 підрозділів за темою питань; кожне питання (id з даних) входить рівно в один блок; порядок питань збережи; в одному блоці 1–3 споріднені питання і 3–5 абзаців. Питання про кількість респондентів чи підрозділи в блоки не включай, якщо їх немає в даних."""


class _Retry(Exception):
    """Тимчасова помилка сервісу AI — можна повторити запит."""


class _ModelUnavailable(Exception):
    """Цієї моделі немає / вона недоступна ключу — пробуємо наступну."""


def _gemini_available(key):
    """Назви моделей, доступних ключу для generateContent (None — не вдалося отримати список)."""
    import requests
    try:
        r = requests.get("https://generativelanguage.googleapis.com/v1beta/models", params={"pageSize": 200},
                         headers={"x-goog-api-key": key}, timeout=30)
        if r.status_code != 200:
            return None
        return {m["name"].split("/", 1)[-1] for m in (r.json().get("models") or [])
                if "generateContent" in (m.get("supportedGenerationMethods") or [])}
    except Exception:       # noqa: BLE001
        return None


def _gemini_once(key, model, system, user, max_tokens, state):
    import requests
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    gen = {"maxOutputTokens": max_tokens + 8000, "responseMimeType": "application/json"}
    if model.startswith("gemini-2."):
        gen["temperature"] = 0.3
        if state.get(model, True):
            gen["thinkingConfig"] = {"thinkingBudget": 0}          # без «роздумів», щоб вони не з'їдали ліміт токенів
    elif state.get(model, True):
        gen["thinkingConfig"] = {"thinkingLevel": "LOW"}            # Gemini 3.x: рівень роздумів замість бюджету
    body = {"systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}], "generationConfig": gen}
    r = requests.post(url, headers={"x-goog-api-key": key, "content-type": "application/json"}, json=body, timeout=240)
    if r.status_code == 200:
        j = r.json() or {}
        cands = j.get("candidates") or []
        if not cands:
            why = (j.get("promptFeedback") or {}).get("blockReason")
            raise AIError("Gemini не повернув відповіді" + (f" (запит заблоковано: {why})" if why else "") + ". Спробуйте ще раз.")
        c = cands[0]
        text = "".join(p.get("text", "") for p in ((c.get("content") or {}).get("parts") or []))
        if c.get("finishReason") == "MAX_TOKENS" and not text.strip().endswith("}"):
            raise AIError("Відповідь AI обрізалась через розмір. Спробуйте ще раз або виключіть частину питань.")
        return text
    msg = ""
    try:
        msg = ((r.json() or {}).get("error") or {}).get("message", "")
    except Exception:       # noqa: BLE001
        pass
    low = msg.lower()
    if r.status_code == 400 and "thinking" in low and state.get(model, True):
        state[model] = False                                        # ця модель не приймає thinkingConfig — повтор без нього
        return _gemini_once(key, model, system, user, max_tokens, state)
    if r.status_code in (400, 401, 403) and ("api key" in low or r.status_code in (401, 403)):
        raise AIError("Gemini відхилив ключ доступу (перевірте GEMINI_API_KEY у змінних середовища Render).")
    if r.status_code == 404 or (r.status_code == 400 and ("not supported" in low or "no longer available" in low)):
        raise _ModelUnavailable(f"{model}: недоступна")
    if r.status_code == 429:
        raise _ModelUnavailable(f"{model}: ліміт вичерпано")      # квоти рахуються по моделях — пробуємо іншу
    if r.status_code in (500, 502, 503, 504):
        raise _ModelUnavailable(f"{model}: перевантажена ({r.status_code})")      # нова модель «лягла» — пробуємо іншу
    raise AIError(f"Gemini відповів {r.status_code}: {msg[:200]}")


def _gemini_call(key, system, user, max_tokens, state):
    if GEMINI_MODEL:
        order = [GEMINI_MODEL]
    else:
        avail = _gemini_available(key)
        order = [m for m in GEMINI_CANDIDATES if avail is None or m in avail]
        if avail:
            # якщо жодного з відомих кандидатів немає — беремо будь-яку доступну flash-модель (без tts/image/live/embedding)
            order += sorted(m for m in avail if "flash" in m and m not in order and not re.search(r"tts|image|live|audio|embed|transcribe|translate|omni|robot", m))
        if _GEMINI_OK["model"] in order:
            order.remove(_GEMINI_OK["model"]); order.insert(0, _GEMINI_OK["model"])
    tried = []
    for model in order:
        try:
            text = _gemini_once(key, model, system, user, max_tokens, state)
            _GEMINI_OK["model"] = model
            return text
        except _ModelUnavailable as e:
            tried.append(str(e))
    if not order:
        raise AIError("Для вашого ключа Gemini немає доступних моделей generateContent. Перевірте ключ на aistudio.google.com.")
    if any(("ліміт" in t or "перевантажена" in t) for t in tried):
        raise _Retry("Gemini зараз перевантажений або вичерпано безкоштовний ліміт (" + "; ".join(tried) + ")")
    raise AIError("Жодна модель Gemini недоступна: " + "; ".join(tried) + ". Задайте чинну модель у CSK_GEMINI_MODEL.")


def _anthropic_call(key, system, user, max_tokens, state):
    import requests
    body = {"model": ANTHROPIC_MODEL, "max_tokens": max_tokens, "temperature": 0.3, "system": system,
            "messages": [{"role": "user", "content": user}]}
    headers = {"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
    r = requests.post("https://api.anthropic.com/v1/messages", headers=headers, json=body, timeout=240)
    if r.status_code == 200:
        return "".join(b.get("text", "") for b in ((r.json() or {}).get("content") or []) if b.get("type") == "text")
    if r.status_code in (401, 403):
        raise AIError("Anthropic відхилив ключ доступу (ANTHROPIC_API_KEY недійсний або без прав).")
    if r.status_code == 404:
        raise AIError(f"Модель «{ANTHROPIC_MODEL}» недоступна. Вкажіть чинну в CSK_REPORT_AI_MODEL.")
    if r.status_code == 400 and "temperature" in r.text and "temperature" in body:
        raise _Retry("повтор без temperature")
    if r.status_code in (429, 500, 502, 503, 529):
        raise _Retry(f"сервіс Anthropic відповів {r.status_code}")
    raise AIError(f"Anthropic відповів {r.status_code}.")


def _ai_call(system, user, max_tokens=7000):
    """Gemini (безкоштовно) — якщо задано GEMINI_API_KEY; інакше Anthropic (ANTHROPIC_API_KEY)."""
    import requests
    gem = (os.environ.get("GEMINI_API_KEY") or "").strip()
    ant = (os.environ.get("ANTHROPIC_API_KEY") or "").strip()
    if gem:
        fn, key = _gemini_call, gem
    elif ant:
        fn, key = _anthropic_call, ant
    else:
        raise AIError("AI не налаштовано: додайте GEMINI_API_KEY (безкоштовний ключ з aistudio.google.com) у змінні середовища "
                      "(на Render: Environment) і перезапустіть сервіс.")
    state, last = {}, ""
    for wait in (0, 8, 25):
        if wait:
            time.sleep(wait)
        try:
            return fn(key, system, user, max_tokens, state)
        except _Retry as e:
            last = str(e)
            if last.startswith("повтор"):
                continue
        except requests.RequestException as e:
            last = f"немає зв'язку з сервісом AI ({e.__class__.__name__})"
    raise AIError(f"Не вдалося отримати текст від AI: {last}. Спробуйте ще раз за хвилину.")


def _parse_json(text):
    t = (text or "").strip()
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", t, flags=re.I)
    a, b = t.find("{"), t.rfind("}")
    if a < 0 or b <= a:
        raise AIError("AI повернув відповідь у невідомому форматі. Спробуйте ще раз.")
    try:
        return json.loads(t[a:b + 1])
    except json.JSONDecodeError:
        raise AIError("AI повернув пошкоджену відповідь. Спробуйте ще раз.")


def _txt(s):
    s = re.sub(r"[*_#`]+", "", str(s or "")).replace("\u00a0", " ")
    return re.sub(r"\s+", " ", s).strip()


def _normalize(raw, qids):
    """Перевіряє структуру відповіді AI: кожне питання рівно в одному блоці, рядки очищено."""
    seen, sections = set(), []
    for sec in (raw.get("sections") or []):
        blocks = []
        for b in (sec.get("blocks") or []):
            ids = [i for i in (b.get("question_ids") or []) if i in qids and i not in seen]
            seen.update(ids)
            paras = [_txt(p) for p in (b.get("paragraphs") or []) if _txt(p)]
            if ids or paras:
                blocks.append({"question_ids": ids, "paragraphs": paras})
        title = re.sub(r"^\s*\d+(?:\.\d+)*[.)]?\s*", "", _txt(sec.get("title")))
        if blocks:
            sections.append({"title": title or "Результати опитування", "blocks": blocks})
    rest = [i for i in qids if i not in seen]            # AI пропустив питання — діаграми все одно мають бути в довідці
    if rest:
        if not sections:
            sections.append({"title": "Результати опитування", "blocks": []})
        sections[-1]["blocks"].append({"question_ids": rest, "paragraphs": []})
    if not sections:
        raise AIError("AI не повернув жодного розділу аналізу. Спробуйте ще раз.")
    return {"intro": _txt(raw.get("intro")), "sections": sections,
            "conclusions": [_txt(x) for x in (raw.get("conclusions") or []) if _txt(x)],
            "recommendations_intro": _txt(raw.get("recommendations_intro")),
            "recommendations": [_txt(x) for x in (raw.get("recommendations") or []) if _txt(x)]}


def ai_report(stats, ctx):
    qids = [f"q{i}" for i in range(1, len(stats) + 1)]
    payload = {"survey": {"audience": ctx["audience"], "topic": ctx["topic"], "institution": ctx["institution"],
                          "respondents": ctx["n"], "total_students": ctx.get("total_students"),
                          "coverage_percent": ctx.get("coverage"), "units": ctx.get("unit_counts")},
               "questions": _facts(stats)}
    text = _ai_call(SYSTEM_PROMPT, "Дані опитування (JSON):\n" + json.dumps(payload, ensure_ascii=False))
    return _normalize(_parse_json(text), set(qids))


def rule_report(stats, ctx):
    """Без AI: речення за правилами з цифр (survey_reports.sentence_*); висновки й рекомендації — вручну."""
    fn = {"rating": sr.sentence_rating, "single": sr.sentence_single, "multi": sr.sentence_multi}
    blocks = []
    for i, st in enumerate(stats, 1):
        p = sr.sentence_open(st, ctx["n"]) if st["kind"] == "open" else fn[st["kind"]](st)
        blocks.append({"question_ids": [f"q{i}"], "paragraphs": [p]})
    intro = f"В опитуванні взяли участь {ctx['n']} респондентів." + (f" Опитування охопило {ctx['coverage']} % від загальної кількості." if ctx.get("coverage") else "")
    return {"intro": intro, "sections": [{"title": "Результати опитування", "blocks": blocks}], "conclusions": [],
            "recommendations_intro": "", "recommendations": []}


# ─────────────────────────────────────────────────────────────────────────────
# Збірка .docx на основі csk_template.docx (стилі, нумерація й поля — як у зразку)
# ─────────────────────────────────────────────────────────────────────────────
def _fmt_run(run, size=13, bold=None, auto_color=False):
    from docx.shared import Pt, RGBColor
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    run.font.name = "Times New Roman"
    run.font.size = Pt(size)
    if bold is not None:
        run.font.bold = bold
    if auto_color:
        run.font.color.rgb = RGBColor(0, 0, 0)
    rpr = run._r.get_or_add_rPr()
    rf = rpr.find(qn("w:rFonts"))
    for a in ("w:eastAsia", "w:cs"):
        rf.set(qn(a), "Times New Roman")
    if rpr.find(qn("w:lang")) is None:
        lang = OxmlElement("w:lang"); lang.set(qn("w:val"), "uk-UA"); rpr.append(lang)


def _para(doc, text="", style="Normal (Web)", size=13, bold=None, center=False, justify=False, first_indent=False, before=0, after=0, keep_next=False):
    from docx.shared import Pt, Cm
    from docx.enum.text import WD_ALIGN_PARAGRAPH as A
    p = doc.add_paragraph(style=style)
    pf = p.paragraph_format
    pf.space_before, pf.space_after = Pt(before), Pt(after)
    if first_indent:
        pf.first_line_indent = Cm(1.25)
    pf.keep_with_next = keep_next
    if center:
        p.alignment = A.CENTER
    elif justify:
        p.alignment = A.JUSTIFY
    if text:
        _fmt_run(p.add_run(text), size, bold)
    return p


def _labeled(doc, label, value):
    """«Період проведення опитування:» (жирним) + перенесення рядка + значення — як у зразку."""
    p = _para(doc, size=13)
    _fmt_run(p.add_run(label), 13, True)
    r = p.add_run(); r.add_break()
    _fmt_run(r, 13)
    _fmt_run(p.add_run(value), 13)
    return p


def _numbered(doc, text, num_id):
    from docx.shared import Pt, Cm
    from docx.enum.text import WD_ALIGN_PARAGRAPH as A
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    p = doc.add_paragraph(style="List Paragraph")
    ppr = p._p.get_or_add_pPr()
    numpr = OxmlElement("w:numPr")
    il = OxmlElement("w:ilvl"); il.set(qn("w:val"), "0")
    ni = OxmlElement("w:numId"); ni.set(qn("w:val"), str(num_id))
    numpr.append(il); numpr.append(ni)
    ps = ppr.find(qn("w:pStyle"))
    (ps.addnext(numpr) if ps is not None else ppr.insert(0, numpr))
    pf = p.paragraph_format
    pf.space_after, pf.line_spacing = Pt(0), 1.0
    pf.left_indent, pf.first_line_indent = Cm(0), Cm(1.25)
    p.alignment = A.JUSTIFY
    _fmt_run(p.add_run(text), 13)
    return p


def _picture(doc, png):
    from docx.shared import Cm, Pt
    from docx.enum.text import WD_ALIGN_PARAGRAPH as A
    p = doc.add_paragraph(style="Normal (Web)")
    p.alignment = A.CENTER
    p.paragraph_format.space_before, p.paragraph_format.space_after = Pt(4), Pt(6)
    p.paragraph_format.keep_together = True
    p.add_run().add_picture(io.BytesIO(png), width=Cm(16.5))
    return p


def _date_phrase(now):
    return f"{now.day} {sr.MONTHS_GEN[now.month - 1]} {now.year} року"


def build_docx(df, stats, report, ctx, unit, by_unit, open_appendix) -> bytes:
    from docx import Document
    if not os.path.exists(TEMPLATE_PATH):
        raise ValueError("Не знайдено шаблон csk_template.docx — покладіть його поруч із survey_reports_csk.py.")
    doc = Document(TEMPLATE_PATH)
    doc.core_properties.title = "Аналітична довідка"
    n = ctx["n"]

    p = _para(doc, "АНАЛІТИЧНА ДОВІДКА", style="Heading 1", size=14, center=True)
    for r in p.runs:
        _fmt_run(r, 14, auto_color=True)
    sub = _para(doc, size=14, center=True)
    lines = [f"за результатами опитування {ctx['audience']}"] + ([ctx["topic"]] if ctx["topic"] else []) + ([f"у {ctx['institution']}"] if ctx["institution"] else [])
    for i, ln in enumerate(lines):
        r = sub.add_run()
        if i:
            r.add_break()
        r.add_text(ln)
        _fmt_run(r, 14)
    _para(doc, style="Normal")

    _para(doc, "1. Загальна інформація", style="Heading 2", size=13)
    p = _para(doc, size=13)                                         # як у зразку: підпис і текст мети — окремими абзацами
    _fmt_run(p.add_run("Мета опитування:"), 13, True)
    _para(doc, ctx["purpose"], style="Normal (Web)", justify=True)
    _para(doc, style="Normal")
    _labeled(doc, "Період проведення опитування:", ctx["period_text"] or "[вкажіть період проведення]")
    _para(doc, style="Normal")
    _labeled(doc, "Категорія респондентів:", ctx["respondents"])
    _para(doc, style="Normal")
    cnt = (f"загальна кількість здобувачів {ctx['total_students']}, пройшли опитування – {n}." if ctx.get("total_students")
           else f"пройшли опитування – {n}.")
    _labeled(doc, "Кількість респондентів:", cnt)
    _para(doc, style="Normal")
    kinds = {s["kind"] for s in stats}
    typ = ("закритого та відкритого типу" if "open" in kinds and kinds - {"open"} else "відкритого типу" if kinds == {"open"} else "закритого типу")
    k = ctx["questions_total"]
    _labeled(doc, "Інструмент опитування:", f"{ctx['instrument']}, що містить {k} {sr.plural(k, ('запитання', 'запитання', 'запитань'))} {typ}.")
    _para(doc, style="Normal")
    if report["intro"]:
        _para(doc, report["intro"], style="Normal", justify=True, first_indent=True)
    for png in ctx["participation_charts"]:
        _picture(doc, png)
    _para(doc, style="Normal")

    by_id = {f"q{i}": st for i, st in enumerate(stats, 1)}
    _para(doc, "2. Аналіз результатів опитування", style="Heading 2", size=13, keep_next=True)
    for si, sec in enumerate(report["sections"], 1):
        _para(doc, f"2.{si}. {sec['title']}", style="Heading 3", size=13, keep_next=True)
        for blk in sec["blocks"]:
            for t in blk["paragraphs"]:
                _para(doc, t, style="Normal (Web)", justify=True, first_indent=True)
            for qid in blk["question_ids"]:
                st = by_id[qid]
                if st["kind"] == "open":
                    continue                                    # відкриті відповіді аналізуються текстом (за потреби — окремий додаток)
                png = sr.make_chart(st)
                if png:
                    _picture(doc, png)
                if by_unit and unit:
                    m = _unit_matrix(df, unit, st)
                    if m:
                        _picture(doc, chart_by_unit(st["label"], *m))

    _para(doc, "3. Узагальнені висновки", style="Heading 2", size=13, keep_next=True)
    _para(doc, "За результатами опитування встановлено, що:", style="Normal (Web)", keep_next=True)
    if report["conclusions"]:
        for t in report["conclusions"]:
            _numbered(doc, t, 4)
    else:
        _para(doc, "[впишіть висновки]", style="Normal (Web)")
    _para(doc, CLOSING_SENTENCE, style="Normal", justify=True, first_indent=True, before=6)

    _para(doc, "4. Рекомендації та пропозиції", style="Heading 2", size=13, keep_next=True)
    _para(doc, report["recommendations_intro"] or "З метою вдосконалення за результатами опитування рекомендовано:", style="Normal (Web)", keep_next=True)
    if report["recommendations"]:
        for t in report["recommendations"]:
            _numbered(doc, t, 5)
    else:
        _para(doc, "[впишіть рекомендації]", style="Normal (Web)")
    _para(doc, style="Normal")
    _para(doc, _date_phrase(ctx["now"]), style="Normal (Web)")

    if open_appendix:
        cards = [(st, sr.make_open_cards(st)) for st in stats if st["kind"] == "open" and st.get("answers")]
        if cards:
            doc.add_page_break()
            _para(doc, "Додаток. Текстові відповіді респондентів", style="Heading 2", size=13, center=True, keep_next=True)
            for _st, pngs in cards:
                for png in pngs:
                    _picture(doc, png)
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


# ─────────────────────────────────────────────────────────────────────────────
# Головна функція
# ─────────────────────────────────────────────────────────────────────────────
def _int(v):
    try:
        v = int(str(v).strip())
        return v if v > 0 else None
    except (TypeError, ValueError):
        return None


def generate_csk(data: bytes, filename: str, opts: dict):
    """opts: unit, timestamp (колонки), exclude, titles, institution, audience, topic, respondents, instrument, purpose, period_text,
    total_students, unit_totals {підрозділ: кількість}, by_unit (bool), ai (bool), open_appendix (bool). → (ім'я_файлу, байти, mime)."""
    df = sr.read_table(data, filename)
    ts, unit = _columns(df, opts)
    all_q = _questions(df, {ts, unit})
    chosen = _questions(df, {ts, unit}, set(opts.get("exclude") or []), opts.get("titles"))
    stats = [s for s in (sr.compute_stats(df, q) for q in chosen) if s["kind"] != "empty"]
    if not stats:
        raise ValueError("Не залишилось жодного питання для довідки")
    g = lambda k: (str(opts.get(k) or "").strip() or DEFAULTS[k])
    n = int(len(df))
    total = _int(opts.get("total_students"))
    period_text = str(opts.get("period_text") or "").strip() or _period_text(_period(df, ts))

    unit_counts = {}
    if unit:
        unit_counts = {str(k): int(v) for k, v in df[unit].dropna().astype(str).value_counts().items()}
    totals = {k: _int(v) for k, v in (opts.get("unit_totals") or {}).items() if _int(v)}
    charts = []
    if unit_counts and len(unit_counts) >= 2:
        names = sorted(unit_counts, key=lambda k: k.lower())
        for i in range(0, len(names), MAX_UNITS_IN_CHART):
            part = names[i:i + MAX_UNITS_IN_CHART]
            charts.append(chart_participation([(u, unit_counts[u], totals.get(u)) for u in part]))

    ctx = {"institution": g("institution"), "audience": g("audience"), "topic": str(opts.get("topic", DEFAULTS["topic"])).strip(),
           "respondents": g("respondents"), "instrument": g("instrument"), "purpose": g("purpose"), "period_text": period_text,
           "n": n, "total_students": total, "coverage": round(100.0 * n / total) if total else None,
           "unit_counts": unit_counts or None, "questions_total": len(all_q), "participation_charts": charts, "now": datetime.now()}

    report = ai_report(stats, ctx) if opts.get("ai", True) else rule_report(stats, ctx)
    body = build_docx(df, stats, report, ctx, unit, bool(opts.get("by_unit", True)), bool(opts.get("open_appendix", False)))
    fname = "Аналітична_довідка_ЦСК_" + ctx["now"].strftime("%Y-%m-%d") + ".docx"
    return fname, body, "application/vnd.openxmlformats-officedocument.wordprocessingml.document"