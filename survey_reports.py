# -*- coding: utf-8 -*-
"""
Аналітичні довідки за результатами опитування (xlsx / csv) — окремо для кожної спеціальності та рівня освіти.

Структура довідки повторює ваші зразки:
  заголовок → вступ (коли/де проведено, мета, скільки респондентів) → діаграми по кожному питанню →
  «За результатами опитування визначено:» + текст висновків → (додаток) текстові відповіді респондентів.

Висновки формуються за правилами з самих цифр (без AI), тому це ЧЕРНЕТКА: текст у .docx можна й потрібно редагувати.
Залежності: pandas, openpyxl, python-docx, matplotlib.
"""
import io
import re
import textwrap
import zipfile
from collections import Counter
from datetime import datetime

import pandas as pd

# ─────────────────────────────────────────────────────────────────────────────
# Довідники
# ─────────────────────────────────────────────────────────────────────────────
CATEGORIES = {
    "graduates": {
        "label": "Випускники", "gen": "випускників", "forms": ("випускник", "випускники", "випускників"),
        "purpose": ("Мета опитування: з'ясувати думку випускників щодо якості підготовки за освітньою програмою, відповідності "
                    "здобутих знань і навичок потребам ринку праці, рівня практичної підготовки та визначити напрями "
                    "вдосконалення програми."),
    },
    "students": {
        "label": "Здобувачі вищої освіти", "gen": "здобувачів вищої освіти",
        "forms": ("здобувач вищої освіти", "здобувачі вищої освіти", "здобувачів вищої освіти"),
        "purpose": ("Мета опитування: виявлення рівня задоволеності здобувачів організацією освітнього процесу, якістю викладання, "
                    "структурою та змістом освітньої програми, а також визначення сильних сторін та аспектів, які потребують "
                    "подальшого вдосконалення."),
    },
    "employers": {
        "label": "Роботодавці", "gen": "роботодавців", "forms": ("роботодавець", "роботодавці", "роботодавців"),
        "purpose": ("Мета опитування: з'ясування думки роботодавців щодо рівня підготовки випускників, відповідності їхніх "
                    "компетентностей потребам ринку праці та пропозицій щодо вдосконалення освітньої програми."),
    },
    "stakeholders": {
        "label": "Стейкголдери", "gen": "стейкголдерів", "forms": ("стейкголдер", "стейкголдери", "стейкголдерів"),
        "purpose": ("Мета опитування: врахування пропозицій стейкголдерів щодо змісту, якості та оновлення освітньої програми."),
    },
    "teachers": {
        "label": "Науково-педагогічні працівники", "gen": "науково-педагогічних працівників",
        "forms": ("науково-педагогічний працівник", "науково-педагогічні працівники", "науково-педагогічних працівників"),
        "purpose": ("Мета опитування: виявлення думки науково-педагогічних працівників щодо організації освітнього процесу, "
                    "умов праці та змісту освітньої програми."),
    },
}
DEFAULT_CATEGORY = "graduates"

# (регулярний вираз, рівень у родовому, коротка назва для файлу, вид програми)
LEVELS = [
    (r"молодш|фахов|короткий", "початкового рівня (короткий цикл)", "короткий_цикл", "освітньо-професійної програми"),
    (r"трет|доктор філософії|phd|освітньо-науков", "третього (освітньо-наукового)", "PhD", "освітньо-наукової програми"),
    (r"друг|магістр", "другого (магістерського)", "магістр", "освітньо-професійної програми"),
    (r"перш|бакалавр", "першого (бакалаврського)", "бакалавр", "освітньо-професійної програми"),
]
LEVEL_ORDER = {"бакалавр": 1, "магістр": 2, "PhD": 3}

MONTHS_NOM_LOC = ["січні", "лютому", "березні", "квітні", "травні", "червні", "липні", "серпні", "вересні", "жовтні", "листопаді", "грудні"]
MONTHS_GEN = ["січня", "лютого", "березня", "квітня", "травня", "червня", "липня", "серпня", "вересня", "жовтня", "листопада", "грудня"]

PLACEHOLDERS = {"-", "—", "–", ".", "..", "...", "…", "н/д", "н/а", "немає", "нема", "нічого", "ні", "відсутні", "відсутнє",
                "не маю", "не знаю", "немає зауважень", "зауважень немає"}
PERSONAL_RE = re.compile(r"e-?mail|пошт|піб\b|прізвищ|телефон|ім['’ʼ]я", re.I)

THEMES = [
    ("практична підготовка та практика", r"практик|практичн|стажув|кейс"),
    ("цифрові технології та програмне забезпечення", r"цифров|програмн|\bit\b|комп['’ʼ]ютер|софт"),
    ("оновлення змісту програми та дисциплін", r"оновл|актуальн|застар|зміст"),
    ("викладачі та якість викладання", r"викладач|викладан|лектор|педагог"),
    ("організація навчання, розклад і навантаження", r"розклад|організац|навантаж|графік"),
    ("матеріально-технічна база", r"аудитор|обладнан|лаборатор|техніч|ремонт"),
    ("дистанційний формат навчання", r"дистанц|онлайн|zoom"),
    ("співпраця з роботодавцями та працевлаштування", r"роботодав|працевлаштув|підприємств|компані"),
    ("іноземні мови", r"англійськ|іноземн|\bмов[аиіуою]"),
    ("комунікація та командна робота", r"команд|комунікац"),
]

BLUE, GREEN, RED, YELLOW, ORANGE, CYAN = "#4285F4", "#34A853", "#EA4335", "#FBBC04", "#FF6D01", "#46BDC6"
PALETTE = [BLUE, RED, YELLOW, GREEN, ORANGE, CYAN, "#7BAAF7", "#F07B72", "#FCD04F", "#57BB8A", "#AB47BC", "#8D6E63"]


# ─────────────────────────────────────────────────────────────────────────────
# Дрібні утиліти
# ─────────────────────────────────────────────────────────────────────────────
def plural(n, forms):
    n = abs(int(n)); a, b = n % 10, n % 100
    if a == 1 and b != 11:
        return forms[0]
    if 2 <= a <= 4 and not 12 <= b <= 14:
        return forms[1]
    return forms[2]

def num(x, digits=1):
    s = f"{x:.{digits}f}"
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    return s.replace(".", ",")

def pct(part, whole):
    return num(100.0 * part / whole) + "%" if whole else "0%"

def lower_first(s):
    return s if (len(s) > 1 and s[1].isupper()) else (s[:1].lower() + s[1:] if s else s)

def safe_name(s):
    s = re.sub(r"[\\/:*?\"<>|]+", "", str(s)).strip()
    return re.sub(r"\s+", "_", s)[:80] or "довідка"

def is_placeholder(v):
    t = re.sub(r"[\s.!,;:]+$", "", str(v).strip().lower())
    return t in PLACEHOLDERS or t == ""

def clean_label(h):
    """«8. Загальна якість підготовки (1-5)» → «Загальна якість підготовки (1-5)»."""
    return re.sub(r"^\s*\d+[\.\)]\s*", "", str(h)).strip()

def label_short(h):
    """Без номера та «(1-5)» — для речень."""
    s = clean_label(h)
    s = re.sub(r"\s*\(\s*\d+\s*[-–]\s*\d+\s*\)\s*$", "", s)
    return s.strip().rstrip("?:").strip()

def level_info(level_raw):
    t = (level_raw or "").lower()
    for rx, gen, short, kind in LEVELS:
        if re.search(rx, t):
            return gen, short, kind
    return None, "", "освітньої програми"

def split_specialty(spec):
    """«053 Психологія» → («053», «Психологія»); «Право» → («», «Право»)."""
    m = re.match(r"^\s*([A-Za-zА-ЯІЇЄҐа-яіїєґ]?\d[\w.]*)\s+(.+)$", spec or "")
    return (m.group(1), m.group(2).strip()) if m else ("", (spec or "").strip())

def spec_phrase(spec):
    code, name = split_specialty(spec)
    return f"{code} «{name}»" if code else f"«{name}»"


# ─────────────────────────────────────────────────────────────────────────────
# Читання таблиці та визначення типів питань
# ─────────────────────────────────────────────────────────────────────────────
def read_table(data: bytes, filename: str = "") -> pd.DataFrame:
    name = (filename or "").lower()
    if name.endswith(".csv"):
        last = None
        for enc in ("utf-8-sig", "cp1251"):
            try:
                df = pd.read_csv(io.BytesIO(data), sep=None, engine="python", dtype=object, encoding=enc)
                break
            except Exception as e:      # noqa: BLE001
                last = e
        else:
            raise ValueError(f"Не вдалося прочитати CSV: {last}")
    else:
        try:
            df = pd.read_excel(io.BytesIO(data), dtype=object)
        except Exception as e:      # noqa: BLE001
            raise ValueError("Не вдалося прочитати файл. Потрібна таблиця .xlsx / .xls / .csv, де перший рядок — назви питань.") from e
    df.columns = [str(c).strip() for c in df.columns]
    df = df.loc[:, [c for c in df.columns if not c.lower().startswith("unnamed")]]
    df = df.dropna(how="all").dropna(axis=1, how="all").reset_index(drop=True)
    for c in df.columns:
        df[c] = df[c].map(lambda x: x.strip() if isinstance(x, str) else x)
        df[c] = df[c].map(lambda x: None if (isinstance(x, str) and x == "") else x)
    if df.empty:
        raise ValueError("У файлі немає відповідей")
    return df

def _parse_dt(series):
    try:
        return pd.to_datetime(series, errors="coerce", format="mixed")
    except Exception:       # noqa: BLE001
        return pd.to_datetime(series, errors="coerce")

def detect_columns(df: pd.DataFrame) -> dict:
    cols = list(df.columns)
    low = {c: c.lower() for c in cols}
    level = next((c for c in cols if "рівен" in low[c] and ("освітн" in low[c] or low[c].strip(" .0123456789") in ("рівень", "рівень освіти"))), None) \
        or next((c for c in cols if "рівен" in low[c] and df[c].nunique() <= 8), None)
    spec = next((c for c in cols if "спеціальн" in low[c]), None) \
        or next((c for c in cols if re.search(r"освітня програма|освітньо-професійна програма|\bопп?\b", low[c]) and df[c].nunique() <= 80), None)
    ts = None
    for c in cols:
        if re.search(r"дата|час\b|timestamp|позначка", low[c]):
            if _parse_dt(df[c]).notna().mean() >= 0.9:
                ts = c
                break
    return {"level": level, "specialty": spec, "timestamp": ts}

def _scale_from_header(h):
    m = re.search(r"(\d+)\s*[-–]\s*(\d+)\s*\)?\s*$", str(h))
    return (int(m.group(1)), int(m.group(2))) if m else None

def classify_question(h, series) -> dict:
    vals = series.dropna().astype(str).str.strip()
    vals = vals[vals != ""]
    info = {"col": h, "label": clean_label(h), "label_short": label_short(h), "answered": int(len(vals)), "kind": "empty"}
    if len(vals) == 0:
        return info
    nums = pd.to_numeric(vals.str.replace(",", ".", regex=False), errors="coerce")
    if nums.notna().mean() >= 0.9:
        nn = nums.dropna()
        if nn.nunique() <= 11 and nn.min() >= 0 and nn.max() <= 10 and ((nn - nn.round()).abs() < 1e-9).all():
            sc = _scale_from_header(h)
            hi = sc[1] if sc and sc[1] >= nn.max() else (5 if nn.max() <= 5 else 10)
            lo = sc[0] if sc and sc[0] <= nn.min() else (1 if nn.min() >= 1 else 0)
            info.update(kind="rating", lo=int(lo), hi=int(hi))
            return info
    semi = vals.str.contains(";", regex=False)
    if semi.sum() >= 3 and semi.mean() >= 0.05:
        toks = [t.strip() for v in vals for t in v.split(";") if t.strip()]
        uniq = len(set(toks))
        if uniq <= 30 and len(toks) / max(uniq, 1) >= 2.5:
            info["kind"] = "multi"
            return info
    if vals.nunique() <= 15:
        info["kind"] = "single"
        return info
    info["kind"] = "open"
    return info

def analyze(data: bytes, filename: str = "", overrides: dict = None) -> dict:
    df = read_table(data, filename)
    det = detect_columns(df)
    ov = overrides or {}
    for k in ("level", "specialty", "timestamp"):
        if k in ov:
            det[k] = ov[k] if ov[k] in df.columns else None
    skip = {c for c in det.values() if c}
    questions = []
    for c in df.columns:
        if c in skip or PERSONAL_RE.search(c):
            continue
        q = classify_question(c, df[c])
        if q["kind"] != "empty":
            questions.append(q)
    groups = []
    for (lv, sp), n in _group_counts(df, det).items():
        _, short, _ = level_info(lv)
        groups.append({"key": f"{lv}||{sp}", "level": lv, "specialty": sp, "n": int(n), "level_short": short})
    groups.sort(key=lambda g: (LEVEL_ORDER.get(g["level_short"], 9), -g["n"], g["specialty"]))
    return {"rows": int(len(df)), "columns": det, "all_columns": list(df.columns), "questions": questions, "groups": groups,
            "period": _period_phrase(df, det["timestamp"]),
            "categories": [{"key": k, "label": v["label"], "purpose": v["purpose"]} for k, v in CATEGORIES.items()],
            "default_category": DEFAULT_CATEGORY}

def _group_counts(df, det):
    lc, sc = det["level"], det["specialty"]
    lv = df[lc].fillna("") if lc else pd.Series([""] * len(df))
    sp = df[sc].fillna("") if sc else pd.Series([""] * len(df))
    return Counter(zip(lv.astype(str), sp.astype(str)))

def _period_phrase(df, ts_col):
    """«у жовтні 2026 року» / «у жовтні–листопаді 2026 року» / «у період з ... по ...»; порожньо, якщо дат немає."""
    if not ts_col:
        return ""
    d = _parse_dt(df[ts_col]).dropna()
    if d.empty:
        return ""
    a, b = d.min(), d.max()
    if (a.year, a.month) == (b.year, b.month):
        return f"у {MONTHS_NOM_LOC[a.month - 1]} {a.year} року"
    if a.year == b.year:
        return f"у {MONTHS_NOM_LOC[a.month - 1]}–{MONTHS_NOM_LOC[b.month - 1]} {a.year} року"
    return f"у період з {MONTHS_GEN[a.month - 1]} {a.year} року по {MONTHS_GEN[b.month - 1]} {b.year} року"


# ─────────────────────────────────────────────────────────────────────────────
# Статистика по групі
# ─────────────────────────────────────────────────────────────────────────────
def compute_stats(gdf: pd.DataFrame, q: dict) -> dict:
    s = gdf[q["col"]].dropna().astype(str).str.strip()
    s = s[s != ""]
    out = dict(q)
    out["n"] = int(len(s))
    if out["n"] == 0:
        out["kind"] = "empty"
        return out
    k = q["kind"]
    if k == "rating":
        v = pd.to_numeric(s.str.replace(",", ".", regex=False), errors="coerce").dropna().round().astype(int)
        cnt = Counter(v.tolist())
        out.update(counts=cnt, n=int(len(v)), mean=float(v.mean()), norm=float(v.mean()) / q["hi"] * 5.0)
    elif k == "single":
        out["opts"] = Counter(s.tolist()).most_common()
    elif k == "multi":
        c = Counter()
        for v in s:
            for t in dict.fromkeys(x.strip() for x in v.split(";") if x.strip()):
                c[t] += 1
        out["opts"] = c.most_common()
    elif k == "open":
        meaningful, seen = [], set()
        for v in s:
            if is_placeholder(v):
                continue
            key = v.lower()
            if key in seen:
                continue
            seen.add(key)
            meaningful.append(v)
        out["answers"] = meaningful
        out["meaningful"] = len(meaningful)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Діаграми (matplotlib → PNG)
# ─────────────────────────────────────────────────────────────────────────────
def _png(fig):
    from matplotlib.backends.backend_agg import FigureCanvasAgg
    FigureCanvasAgg(fig)
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=140, facecolor="white")      # без bbox_inches="tight": усі діаграми однакової ширини
    return buf.getvalue()

CHART_W = 6.6      # дюймів; у документі вставляється шириною 15,2 см

def _heading(fig, title, h):
    """Заголовок діаграми зліва вгорі. Повертає частку висоти, де закінчується поле під заголовок."""
    lines = textwrap.wrap(title, 76) or [""]
    fig.text(0.012, 1 - 0.10 / h, "\n".join(lines), ha="left", va="top", fontsize=10.5, fontweight="bold", color="#202124", linespacing=1.25)
    return 1 - (0.10 + 0.20 * len(lines) + 0.14) / h, len(lines)

def _clean_axes(ax):
    for sp in ("top", "right"):
        ax.spines[sp].set_visible(False)
    ax.spines["left"].set_color("#BDC1C6"); ax.spines["bottom"].set_color("#BDC1C6")
    ax.tick_params(colors="#5F6368", labelsize=8.5)

def _int_ticks(axis):
    from matplotlib.ticker import MaxNLocator
    axis.set_major_locator(MaxNLocator(integer=True))

def chart_rating(st):
    from matplotlib.figure import Figure
    lo, hi = st["lo"], st["hi"]
    xs = list(range(lo, hi + 1)); ys = [st["counts"].get(x, 0) for x in xs]
    nl = len(textwrap.wrap(st["label"], 76) or [""])
    h = 2.75 + 0.20 * nl
    fig = Figure(figsize=(CHART_W, h)); ax = fig.add_subplot(111)
    top_frac, _ = _heading(fig, st["label"], h)
    fig.subplots_adjust(left=0.07, right=0.985, bottom=0.20, top=top_frac)
    bars = ax.bar([str(x) for x in xs], ys, color=BLUE, width=0.62)
    top = max(ys) or 1
    for b, y in zip(bars, ys):
        if y:
            ax.text(b.get_x() + b.get_width() / 2, y + top * 0.02, f"{y} ({pct(y, st['n'])})", ha="center", va="bottom", fontsize=8, color="#3C4043")
    ax.set_ylim(0, top * 1.28); _int_ticks(ax.yaxis)
    ax.set_xlabel(f"Середній бал: {num(st['mean'], 2)} з {hi}  ·  відповідей: {st['n']}", fontsize=8.5, color="#5F6368")
    _clean_axes(ax)
    return _png(fig)

def chart_pie(st):
    from matplotlib.figure import Figure
    import math
    opts = st["opts"]; total = sum(c for _, c in opts)
    nl = len(textwrap.wrap(st["label"], 76) or [""])
    h = 2.9 + 0.20 * nl
    fig = Figure(figsize=(CHART_W, h))
    top_frac, _ = _heading(fig, st["label"], h)
    side = 2.35 / h
    ax = fig.add_axes([0.03, max(0.08, top_frac - side - 0.02), 2.35 / CHART_W, side])
    wedges, _t = ax.pie([c for _, c in opts], colors=PALETTE[:len(opts)], startangle=90, counterclock=False,
                        wedgeprops=dict(edgecolor="white", linewidth=1.2))
    for w, (_, c) in zip(wedges, opts):
        if c / total >= 0.07:
            ang = math.radians((w.theta1 + w.theta2) / 2)
            ax.text(0.68 * math.cos(ang), 0.68 * math.sin(ang), pct(c, total), ha="center", va="center", color="white", fontsize=9, fontweight="bold")
    fig.legend(wedges, [f"{textwrap.fill(o, 40)} — {c} ({pct(c, total)})" for o, c in opts], loc="center left",
               bbox_to_anchor=(2.55 / CHART_W, max(0.08, top_frac - side - 0.02) + side / 2), fontsize=8.5, frameon=False, labelcolor="#3C4043")
    fig.text(0.012, 0.03, f"відповідей: {st['n']}", fontsize=8.5, color="#5F6368")
    return _png(fig)

def chart_hbar(st):
    from matplotlib.figure import Figure
    opts = st["opts"][:15]
    rest = sum(c for _, c in st["opts"][15:])
    if rest:
        opts = opts + [(f"Інші відповіді ({len(st['opts']) - 15})", rest)]
    k = len(opts)
    nl = len(textwrap.wrap(st["label"], 76) or [""])
    h = max(2.0, 0.40 * k + 0.95) + 0.20 * nl
    fig = Figure(figsize=(CHART_W, h)); ax = fig.add_subplot(111)
    top_frac, _ = _heading(fig, st["label"], h)
    fig.subplots_adjust(left=0.47, right=0.97, bottom=0.62 / h + 0.02, top=top_frac)
    vals = [c for _, c in opts][::-1]
    labels = [textwrap.fill(o, 44) for o, _ in opts][::-1]
    ax.barh(range(k), vals, color=BLUE, height=0.62)
    top = max(vals) or 1
    for i, v in enumerate(vals):
        ax.text(v + top * 0.015, i, f"{v} ({pct(v, st['n'])})", va="center", fontsize=8, color="#3C4043")
    ax.set_yticks(range(k)); ax.set_yticklabels(labels, fontsize=8.5, color="#3C4043")
    ax.set_xlim(0, top * 1.3); _int_ticks(ax.xaxis)
    ax.set_xlabel(f"відповідей: {st['n']}" + ("  ·  можна було обрати кілька варіантів" if st["kind"] == "multi" else ""), fontsize=8.5, color="#5F6368")
    _clean_axes(ax)
    return _png(fig)

def make_chart(st):
    k = st["kind"]
    if k == "rating":
        return chart_rating(st)
    if k == "single" and len(st["opts"]) <= 6 and max(len(o) for o, _ in st["opts"]) <= 60:
        return chart_pie(st)
    if k in ("single", "multi"):
        return chart_hbar(st)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Текст висновків (за правилами з цифр)
# ─────────────────────────────────────────────────────────────────────────────
def _level_word(norm):
    return "дуже високий" if norm >= 4.5 else "високий" if norm >= 4.0 else "достатній" if norm >= 3.5 else "середній" if norm >= 3.0 else "низький"

_POS, _NEG = {"так", "скоріше так"}, {"ні", "скоріше ні"}
_NONE_RE = re.compile(r"^нічого|не бракувал|не зацікавлен|не потрібн|не потребу", re.I)

def sentence_rating(st):
    n, hi = st["n"], st["hi"]
    top = st["counts"].get(hi, 0)
    low_thr = max(st["lo"], int(round(hi * 0.4)))
    low = sum(c for v, c in st["counts"].items() if v <= low_thr)
    s = (f"За показником «{lower_first(st['label_short'])}» середній бал становить {num(st['mean'])} з {hi} "
         f"({_level_word(st['norm'])} рівень оцінки): найвищу оцінку ({hi}) поставили {top} з {n} респондентів ({pct(top, n)})")
    if low:
        s += f", а оцінки {low_thr} і нижче дали {low} ({pct(low, n)})"
    return s + "."

def sentence_single(st):
    n, opts = st["n"], st["opts"]
    top, c = opts[0]
    s = f"За питанням «{lower_first(st['label_short'])}» найчастіше обирали відповідь «{top}» — {c} з {n} респондентів ({pct(c, n)})"
    if len(opts) > 1:
        s += f"; на другому місці — «{opts[1][0]}» ({pct(opts[1][1], n)})"
    s += "."
    pos = [(o, k) for o, k in opts if o.lower() in _POS]
    neg = [(o, k) for o, k in opts if o.lower() in _NEG]
    if len(pos) + len(neg) >= 2 or (pos and neg):
        pp, pn = sum(k for _, k in pos), sum(k for _, k in neg)
        s += f" Позитивні відповіді («{'» та «'.join(o for o, _ in pos)}») надали {pct(pp, n)} респондентів"
        if neg:
            s += f", негативні («{'» та «'.join(o for o, _ in neg)}») — {pct(pn, n)}"
        s += "."
    return s

def sentence_multi(st):
    n, opts = st["n"], st["opts"]
    none = [(o, c) for o, c in opts if _NONE_RE.search(o)]
    real = [(o, c) for o, c in opts if not _NONE_RE.search(o)]
    gap = bool(re.search(r"не вистачил|бракува|не вистачає", st["label"].lower()))
    if not real:
        return f"За питанням «{lower_first(st['label_short'])}» респонденти здебільшого обирали варіант «{none[0][0]}» ({pct(none[0][1], n)})."
    top = real[:3]
    listing = ", ".join(f"«{o}» ({pct(c, n)})" for o, c in top)
    if gap:
        s = f"Серед знань і навичок, яких, на думку респондентів, не вистачило під час навчання, найчастіше називали: {listing}."
    else:
        s = f"За питанням «{lower_first(st['label_short'])}» респонденти найчастіше обирали: {listing}."
    if none:
        s += f" Варіант «{none[0][0]}» обрали {pct(none[0][1], n)} респондентів."
    return s

def sentence_open(st, total):
    k = st["meaningful"]
    if k == 0:
        return f"У відкритому питанні «{lower_first(st['label_short'])}» змістовних зауважень чи пропозицій не надійшло."
    s = f"У відкритому питанні «{lower_first(st['label_short'])}» змістовні відповіді надали {k} з {st['n']} респондентів ({pct(k, st['n'])})."
    counts = []
    for name, rx in THEMES:
        c = sum(1 for a in st["answers"] if re.search(rx, a.lower()))
        if c >= 2:
            counts.append((c, name))
    counts.sort(reverse=True)
    if counts:
        s += " Серед тем, до яких респонденти звертались найчастіше: " + ", ".join(f"{name} ({c})" for c, name in counts[:3]) + "."
    return s

def conclusions(stats, n_group):
    """Повертає список абзаців «За результатами опитування визначено»."""
    paras = []
    singles = [s for s in stats if s["kind"] == "single"]
    ratings = [s for s in stats if s["kind"] == "rating"]
    multis = [s for s in stats if s["kind"] == "multi"]
    opens = [s for s in stats if s["kind"] == "open"]

    def chunks(items, fn, size):
        for i in range(0, len(items), size):
            paras.append(" ".join(fn(x) for x in items[i:i + size]))
    chunks(singles, sentence_single, 2)
    chunks(ratings, sentence_rating, 2)
    chunks(multis, sentence_multi, 1)
    chunks(opens, lambda x: sentence_open(x, n_group), 1)
    summary = []
    if ratings:
        avg = sum(s["norm"] for s in ratings) / len(ratings)
        summary.append(f"Загальний рівень оцінки програми респондентами — {_level_word(avg)} (середній бал за шкальними питаннями — {num(avg, 2)} з 5).")
        if len(ratings) > 1:
            best, worst = max(ratings, key=lambda s: s["norm"]), min(ratings, key=lambda s: s["norm"])
            if best is not worst:
                summary.append(f"Найвище оцінено «{lower_first(best['label_short'])}» ({num(best['mean'])} з {best['hi']}), "
                               f"найнижче — «{lower_first(worst['label_short'])}» ({num(worst['mean'])} з {worst['hi']}).")
        weak = [s for s in ratings if s["norm"] < 4.0]
        if weak:
            summary.append("Уваги потребують показники із середнім балом нижче 4,0: " + "; ".join(f"«{lower_first(s['label_short'])}»" for s in weak) + ".")
    if n_group < 5:
        summary.append(f"Через невелику кількість респондентів ({n_group}) отримані результати мають орієнтовний характер.")
    summary.append("Результати опитування доцільно врахувати під час перегляду та вдосконалення освітньої програми.")
    paras.append(" ".join(summary))
    return paras


# ─────────────────────────────────────────────────────────────────────────────
# Збірка .docx
# ─────────────────────────────────────────────────────────────────────────────
def _new_document():
    from docx import Document
    from docx.shared import Pt, Cm
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    doc = Document()
    for z in doc.settings.element.findall(qn("w:zoom")):       # у шаблоні python-docx немає обов'язкового атрибута
        z.set(qn("w:percent"), "100")
    sec = doc.sections[0]
    sec.page_width, sec.page_height = Cm(21.0), Cm(29.7)
    sec.left_margin, sec.right_margin, sec.top_margin, sec.bottom_margin = Cm(2.7), Cm(1.7), Cm(2.0), Cm(1.7)
    for name in ("Normal", "List Bullet"):
        st = doc.styles[name]
        st.font.name, st.font.size = "Times New Roman", Pt(12)
        rpr = st.element.get_or_add_rPr()
        rf = rpr.find(qn("w:rFonts"))
        if rf is None:
            rf = OxmlElement("w:rFonts"); rpr.append(rf)
        for a in ("w:ascii", "w:hAnsi", "w:eastAsia", "w:cs"):
            rf.set(qn(a), "Times New Roman")
        if name == "Normal":
            lang = OxmlElement("w:lang"); lang.set(qn("w:val"), "uk-UA"); lang.set(qn("w:eastAsia"), "uk-UA"); rpr.append(lang)
    return doc

def _p(doc, text="", bold=False, center=False, indent=True, after=6, keep_next=False, style=None):
    from docx.shared import Pt, Cm
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    p = doc.add_paragraph(style=style)
    pf = p.paragraph_format
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER if center else WD_ALIGN_PARAGRAPH.JUSTIFY
    pf.space_after, pf.space_before, pf.line_spacing = Pt(after), Pt(0), 1.15
    if indent and not center and not style:
        pf.first_line_indent = Cm(1.25)
    pf.keep_with_next = keep_next
    if text:
        r = p.add_run(text); r.bold = bold
    return p

def build_docx(gdf, questions, ctx) -> bytes:
    """gdf — відповіді однієї групи; questions — перелік питань (з типами); ctx — контекст довідки."""
    from docx.shared import Cm, Pt
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    cat = CATEGORIES.get(ctx.get("category"), CATEGORIES[DEFAULT_CATEGORY])
    n = len(gdf)
    gen_lvl, _, prog_kind = level_info(ctx.get("level", ""))
    spec = spec_phrase(ctx.get("specialty", ""))
    level_txt = f"{gen_lvl} рівня вищої освіти" if gen_lvl else ((ctx.get("level") or "").strip().lower())
    object_txt = f"{prog_kind} {spec}" + (f" {level_txt}" if level_txt else "")

    doc = _new_document()
    doc.core_properties.title = "Аналітична довідка"
    doc.core_properties.author = ctx.get("institution_short") or ""
    _p(doc, "Аналітична довідка", bold=True, center=True, after=4)
    _p(doc, f"за результатами опитування {cat['gen']} {object_txt}.", bold=True, center=True, after=12)

    period = ctx.get("period") or ""
    inst = (ctx.get("institution") or "").strip()
    head = (period[:1].upper() + period[1:] + " ") if period else ""
    where = f"в {inst} " if inst else ""
    verb = "проведено" if head else "Проведено"
    _p(doc, f"{head}{where}{verb} опитування {cat['gen']} {object_txt}.".replace("  ", " "))
    _p(doc, (ctx.get("purpose") or cat["purpose"]).strip())
    took = "взяв участь" if (n % 10 == 1 and n % 100 != 11) else "взяли участь"
    _p(doc, f"В опитуванні {took} {n} {plural(n, cat['forms'])}.")
    _p(doc, "Узагальнені результати опитування відображені у діаграмах та текстових відповідях респондентів, наведених нижче.", after=10)

    stats = [compute_stats(gdf, q) for q in questions]
    stats = [s for s in stats if s["kind"] != "empty"]
    for st in stats:
        png = make_chart(st)
        if png:
            p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_after = 8
            p.paragraph_format.keep_together = True
            p.add_run().add_picture(io.BytesIO(png), width=Cm(15.2))

    p = _p(doc, "За результатами опитування визначено:", indent=False, after=6, keep_next=True)
    p.paragraph_format.space_before = Pt(10)
    for text in conclusions(stats, n):
        _p(doc, text)

    if ctx.get("include_open", True):
        opens = [s for s in stats if s["kind"] == "open" and s["answers"]]
        if opens:
            doc.add_page_break()
            _p(doc, "Додаток. Текстові відповіді респондентів", bold=True, center=True, indent=False, after=6, keep_next=True)
            for st in opens:
                _p(doc, st["label"], bold=True, indent=False, after=3, keep_next=True)
                for a in st["answers"]:
                    _p(doc, a, indent=False, after=2, style="List Bullet")
    buf = io.BytesIO(); doc.save(buf)
    return buf.getvalue()


# ─────────────────────────────────────────────────────────────────────────────
# Головна функція: файл + налаштування → .docx (одна група) або .zip (кілька)
# ─────────────────────────────────────────────────────────────────────────────
def generate(data: bytes, filename: str, opts: dict):
    """opts: level, specialty, timestamp (назви колонок), groups (список ключів «рівень||спеціальність»),
    exclude (колонки-питання, які не включати), category, institution, purpose, include_open.
    Повертає (ім'я_файлу, байти, mime)."""
    df = read_table(data, filename)
    det = detect_columns(df)
    for k in ("level", "specialty", "timestamp"):
        if k in opts:
            det[k] = opts[k] if opts[k] in df.columns else None
    skip = {c for c in det.values() if c}
    exclude = set(opts.get("exclude") or [])
    questions = []
    for c in df.columns:
        if c in skip or c in exclude or PERSONAL_RE.search(c):
            continue
        q = classify_question(c, df[c])
        if q["kind"] != "empty":
            questions.append(q)

    lc, sc = det["level"], det["specialty"]
    lv = (df[lc].fillna("") if lc else pd.Series([""] * len(df))).astype(str)
    sp = (df[sc].fillna("") if sc else pd.Series([""] * len(df))).astype(str)
    keys = opts.get("groups") or []
    if not keys:
        raise ValueError("Оберіть хоча б одну групу")
    period = _period_phrase(df, det["timestamp"])
    results = []
    for key in keys:
        level, spec = (key.split("||", 1) + [""])[:2]
        mask = (lv == level) & (sp == spec)
        if not mask.any():
            continue
        ctx = {"category": opts.get("category") or DEFAULT_CATEGORY, "institution": opts.get("institution") or "",
               "purpose": opts.get("purpose") or "", "include_open": opts.get("include_open", True),
               "level": level, "specialty": spec, "period": period}
        body = build_docx(df[mask].reset_index(drop=True), questions, ctx)
        code, name = split_specialty(spec)
        _, short, _ = level_info(level)
        fname = "Аналітична_довідка_" + safe_name("_".join(x for x in (code, name, short) if x)) + ".docx"
        results.append((fname, body))
    if not results:
        raise ValueError("Для обраних груп не знайдено відповідей")
    docx_mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    if len(results) == 1:
        return results[0][0], results[0][1], docx_mime
    buf = io.BytesIO(); used = Counter()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for fname, body in results:
            used[fname] += 1
            if used[fname] > 1:
                fname = fname.replace(".docx", f"_{used[fname]}.docx")
            z.writestr(fname, body)
    return "Аналітичні_довідки.zip", buf.getvalue(), "application/zip"
