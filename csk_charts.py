# -*- coding: utf-8 -*-
"""
Діаграми для аналітичної довідки ЦСК — спокійний «звітний» стиль: світла картка, підпис «ПИТАННЯ N», тонка лінія під заголовком,
стримана палітра, акцент на головній відповіді. Базується на полотні з survey_reports.py (звідти ж шрифти й вимірювання тексту),
саму survey_reports.py (довідки ЦМЯО) не змінює.

  chart_for(st, num)           – діаграма питання: шкала → стовпчики + середній бал; 2–6 варіантів → кільце; решта → смуги
  chart_by_unit(...)           – розподіл відповідей за інститутами (100 % смуги)
  chart_participation(rows)    – участь за інститутами: «пройшли» на тлі «всього»
"""
import math

import survey_reports as sr

INK, MUTED, FAINT, TRACK, LINE, SOFT = "#1B2333", "#667085", "#98A2B3", "#EEF1F6", "#E4E8F0", "#F6F8FC"
PAL = ["#3B6FE0", "#1FB5A0", "#F4A93B", "#EF6A6A", "#8A6BE8", "#2BB3D9", "#F58A4B", "#E0679B", "#7DBE4A", "#9AA5B8"]
OTHER = "#C4CBD8"
SENTIMENT = ["#E5484D", "#F1823B", "#F5C04A", "#8CCB7A", "#2FA36B"]          # від «погано» до «добре»

PAD = sr.PAD
LH = sr.TITLE_LH
W = sr.CHART_W


def scale_color(t):
    t = min(1.0, max(0.0, t))
    pos = t * (len(SENTIMENT) - 1)
    i = min(int(pos), len(SENTIMENT) - 2)
    return sr._mix(SENTIMENT[i], SENTIMENT[i + 1], pos - i)


def _fmt(x):
    return f"{x:.2f}".rstrip("0").rstrip(".").replace(".", ",")


# ── спільне оформлення ───────────────────────────────────────────────────────────────────────
def _title_lines(title):
    return sr._wrap(sr._clean(title), 11.5, W - 2 * PAD - 0.1, "bold")


def _head_h(tl):
    return 0.2 + len(tl) * LH + 0.2


def _head(cv, caption, tl):
    """Картка + підпис + заголовок + тонка лінія. Повертає y, з якого починається вміст."""
    cv.box(0.03, 0.03, cv.w - 0.06, cv.h - 0.06, r=0.12, fc="white", ec=LINE, lw=1.0, z=0)
    cv.text(PAD, PAD + 0.07, caption.upper(), 7.4, FAINT, "bold")
    cv.lines(PAD, PAD + 0.16, tl, 11.5, LH, color=INK, weight="bold")
    y = PAD + 0.16 + len(tl) * LH + 0.1
    cv.hline(PAD, W - PAD, y, color=LINE, lw=0.9)
    return y + 0.2


def _canvas(tl, body_h):
    return sr._Canvas(PAD + _head_h(tl) + body_h + PAD * 0.8)


# ── шкала → стовпчики ────────────────────────────────────────────────────────────────────────
def chart_rating(st, num):
    lo, hi = st["lo"], st["hi"]
    xs = list(range(lo, hi + 1))
    cnt, n = st["counts"], st["n"]
    top = max(cnt.get(x, 0) for x in xs) or 1
    tl = _title_lines(st["label"])
    H, label_h, below = 1.5, 0.42, 0.32
    cv = _canvas(tl, label_h + H + below)
    y0 = _head(cv, f"Питання {num} · відповідей: {n}", tl)

    badge_w = 1.45
    ax0, ax1 = PAD + 0.05, W - PAD - badge_w - 0.3
    slot = (ax1 - ax0) / len(xs)
    bw = min(0.62, slot * 0.62)
    base = y0 + label_h + H - 0.2
    cv.hline(ax0 - 0.02, ax1 + 0.02, base, color=LINE, lw=1.0)
    for i, x in enumerate(xs):
        c = cnt.get(x, 0)
        col = scale_color((x - lo) / max(hi - lo, 1))
        cx = ax0 + (i + 0.5) * slot
        h = max(H * c / top, 0.035) if c else 0.035
        cv.box(cx - bw / 2, base - h, bw, h, r=min(0.07, bw / 2), fc=(col if c else TRACK), z=2)
        cv.text(cx, base - h - 0.2, str(c), 10, INK if c else FAINT, "bold", "center")
        if c:
            cv.text(cx, base - h - 0.06, sr.pct(c, n), 7.4, MUTED, "normal", "center")
        cv.text(cx, base + 0.17, str(x), 10, INK, "bold", "center")

    bx, by, bh = W - PAD - badge_w, y0 - 0.02, label_h + H + below - 0.1
    cv.box(bx, by, badge_w, bh, r=0.12, fc=SOFT, z=1)
    mean = st["mean"]
    cv.text(bx + badge_w / 2, by + bh * 0.36, _fmt(mean), 26, scale_color((mean - lo) / max(hi - lo, 1)), "bold", "center")
    cv.text(bx + badge_w / 2, by + bh * 0.36 + 0.34, f"з {hi}", 9.5, MUTED, "normal", "center")
    cv.text(bx + badge_w / 2, by + bh * 0.36 + 0.55, "середній бал", 8.5, MUTED, "normal", "center")
    return cv.png()


# ── один варіант (2–6 відповідей) → кільце з легендою ─────────────────────────────────────────
def chart_donut(st, num):
    opts = st["opts"]
    total = sum(c for _, c in opts)
    tl = _title_lines(st["label"])
    D = 2.05
    x1 = W - PAD
    lx0 = PAD + D + 0.4
    cw, pw = 0.45, 0.62
    txt_w = x1 - lx0 - 0.22 - cw - pw - 0.08
    rows = []
    for o, c in opts:
        ln = sr._wrap(sr._clean(o), 9.2, txt_w)
        rows.append((ln, len(ln) * 0.17 + 0.2))
    leg_h = sum(r[1] for r in rows) - 0.2
    area = max(D, leg_h)
    cv = _canvas(tl, area)
    y0 = _head(cv, f"Питання {num} · відповідей: {total}", tl)
    h = cv.h

    ax = cv.fig.add_axes([PAD / W, 1 - (y0 + (area - D) / 2 + D) / h, D / W, D / h])
    ax.set_facecolor("none")
    colors = [PAL[i % len(PAL)] for i in range(len(opts))]
    wedges, _t = ax.pie([c for _, c in opts], colors=colors, startangle=90, counterclock=False,
                        wedgeprops=dict(width=0.36, edgecolor="white", linewidth=2.6))
    for w_, (_o, c), col in zip(wedges, opts, colors):
        if c / total >= 0.09:
            ang = math.radians((w_.theta1 + w_.theta2) / 2)
            ax.text(0.82 * math.cos(ang), 0.82 * math.sin(ang), f"{round(100.0 * c / total)}%", ha="center", va="center",
                    color=sr._text_on(col), fontsize=8, fontweight="bold", family=sr._font())
    ax.text(0, 0.07, str(total), ha="center", va="center", fontsize=20, fontweight="bold", color=INK, family=sr._font())
    ax.text(0, -0.22, "відповідей", ha="center", va="center", fontsize=8, color=MUTED, family=sr._font())

    y = y0 + (area - leg_h) / 2
    for i, ((ln, rh), (o, c), col) in enumerate(zip(rows, opts, colors)):
        mid = y + (len(ln) * 0.17) / 2
        cv.box(lx0, mid - 0.065, 0.13, 0.13, r=0.04, fc=col, z=2)
        cv.lines(lx0 + 0.22, y, ln, 9.2, 0.17, color=INK, weight=("bold" if i == 0 else "normal"))
        cv.text(x1 - pw, mid, str(c), 9.2, INK, "bold", "right")
        cv.text(x1, mid, sr.pct(c, total), 8.6, MUTED, "normal", "right")
        if i < len(rows) - 1:
            cv.hline(lx0, x1, y + rh - 0.1, color=TRACK, lw=0.9)
        y += rh
    return cv.png()


# ── багато варіантів / множинний вибір → горизонтальні смуги ──────────────────────────────────
def chart_bars(st, num):
    opts = list(st["opts"][:15])
    rest = sum(c for _, c in st["opts"][15:])
    if rest:
        opts.append((f"Інші відповіді ({len(st['opts']) - 15})", rest))
    x0, x1 = PAD, W - PAD
    vals = [f"{c}  ·  {sr.pct(c, st['n'])}" for _, c in opts]
    vw = max(sr._tw(v, 8.8, "bold") for v in vals) + 0.05
    tr_w = x1 - x0 - vw - 0.2
    top = max(c for _, c in opts) or 1
    tl = _title_lines(st["label"])
    rows = []
    for o, c in opts:
        ln = sr._wrap(sr._clean(o), 9, x1 - x0)
        rows.append((ln, len(ln) * 0.17 + 0.05 + 0.15 + 0.17))
    foot = "можна було обрати кілька варіантів" if st["kind"] == "multi" else ""
    cv = _canvas(tl, sum(r[1] for r in rows) + (0.22 if foot else 0))
    y0 = _head(cv, f"Питання {num} · відповідей: {st['n']}", tl)
    soft = sr._mix(PAL[0], "#FFFFFF", 0.5)
    y = y0 - 0.05
    for i, ((ln, rh), (o, c), v) in enumerate(zip(rows, opts, vals)):
        yy = cv.lines(x0, y, ln, 9, 0.17, color=INK, weight=("bold" if i == 0 else "normal"))
        yb = yy + 0.05 + 0.075
        grey = o.startswith("Інші відповіді")
        cv.box(x0, yb - 0.075, tr_w, 0.15, r=0.075, fc=TRACK, z=1)
        cv.box(x0, yb - 0.075, max(tr_w * c / top, 0.15), 0.15, r=0.075, fc=(OTHER if grey else PAL[0] if i == 0 else soft), z=2)
        cv.text(x1, yb, v, 8.8, INK, "bold", "right")
        y += rh
    if foot:
        cv.text(x0, y + 0.06, foot, 8, MUTED)
    return cv.png()


def chart_for(st, num):
    k = st["kind"]
    if k == "rating":
        return chart_rating(st, num)
    if k == "single" and len(st["opts"]) <= 6 and max(len(o) for o, _ in st["opts"]) <= 60:
        return chart_donut(st, num)
    if k in ("single", "multi"):
        return chart_bars(st, num)
    return None


# ── розподіл відповідей за інститутами ────────────────────────────────────────────────────────
def chart_by_unit(title, cats, rows, num):
    """cats: [(підпис, колір)]; rows: [(інститут, [кількості], усього)]."""
    x0, x1 = PAD, W - PAD
    lw = 1.85
    bx0, bx1 = x0 + lw, x1 - 0.5
    bw = bx1 - bx0
    tl = _title_lines(title)
    lg, cx, cy = [], 0.0, 0.0                                       # легенда: чипи з переносом
    for lab, col in cats:
        w = 0.2 + sr._tw(lab, 8.3) + 0.22
        if cx + w > x1 - x0 and cx > 0:
            cx, cy = 0.0, cy + 0.23
        lg.append((cx, cy, lab, col))
        cx += w
    legend_h = cy + 0.3
    rh = []
    for u, _, _ in rows:
        ln = sr._wrap(sr._clean(u), 8.8, lw - 0.15)
        rh.append((ln, max(0.38, len(ln) * 0.165 + 0.14)))
    cv = _canvas(tl, legend_h + sum(h for _, h in rh))
    y0 = _head(cv, f"Питання {num} · за інститутами", tl)
    for gx, gy, lab, col in lg:
        cv.box(x0 + gx, y0 + gy - 0.065, 0.13, 0.13, r=0.04, fc=col, z=2)
        cv.text(x0 + gx + 0.2, y0 + gy, lab, 8.3, MUTED)
    y = y0 + legend_h
    for (u, vals, tot), (ln, h) in zip(rows, rh):
        cv.lines(x0, y + (h - len(ln) * 0.165) / 2, ln, 8.8, 0.165, color=INK)
        yc = y + h / 2
        cv.box(bx0, yc - 0.12, bw, 0.24, r=0.06, fc=TRACK, z=1)
        xx = bx0
        for v, (_lab, col) in zip(vals, cats):
            if not v:
                continue
            w = bw * v / tot
            cv.box(xx, yc - 0.12, w, 0.24, r=0.03, fc=col, ec="white", lw=1.2, z=2)
            if w >= 0.38:
                cv.text(xx + w / 2, yc, f"{round(100.0 * v / tot)}%", 7.8, sr._text_on(col), "bold", "center", z=6)
            xx += w
        cv.text(x1, yc, f"n={tot}", 8, MUTED, "normal", "right")
        y += h
    return cv.png()


# ── участь за інститутами ─────────────────────────────────────────────────────────────────────
def chart_participation(rows, title="Участь в опитуванні за інститутами та факультетами"):
    """rows: [(інститут, пройшли, всього|None)]. Темна смуга — пройшли, світла — всього (в одному масштабі)."""
    x0, x1 = PAD, W - PAD
    tl = _title_lines(title)
    has_total = any(t for _, _, t in rows)
    scale = max([max(n, t or 0) for _, n, t in rows] + [1])
    blocks = []
    for name, n, t in rows:
        lab = f"{n} з {t}  ·  {sr.pct(n, t)}" if t else str(n)
        vw = sr._tw(lab, 8.8, "bold") + 0.05
        ln = sr._wrap(sr._clean(name), 9.2, x1 - x0 - vw - 0.15, "bold")
        blocks.append((ln, lab, len(ln) * 0.17 + 0.07 + 0.17 + 0.15))
    legend_h = 0.3 if has_total else 0.0
    cv = _canvas(tl, legend_h + sum(b[2] for b in blocks))
    y0 = _head(cv, f"Опитування · респондентів: {sum(n for _, n, _ in rows)}", tl)
    if has_total:
        cv.box(x0, y0 - 0.065, 0.13, 0.13, r=0.04, fc=PAL[0], z=2); cv.text(x0 + 0.2, y0, "Пройшли опитування", 8.5, MUTED)
        cv.box(x0 + 1.75, y0 - 0.065, 0.13, 0.13, r=0.04, fc="#D5DCEC", z=2); cv.text(x0 + 1.95, y0, "Всього в Університеті", 8.5, MUTED)
    y = y0 + legend_h
    full = x1 - x0
    for (name, n, t), (ln, lab, h) in zip(rows, blocks):
        yy = cv.lines(x0, y, ln, 9.2, 0.17, color=INK, weight="bold")
        cv.text(x1, y + 0.085, lab, 8.8, INK, "bold", "right")
        yb = yy + 0.07 + 0.075
        track = full * (t or scale) / scale if has_total else full
        cv.box(x0, yb - 0.075, track, 0.15, r=0.075, fc=("#D5DCEC" if t else TRACK), z=1)
        cv.box(x0, yb - 0.075, max(full * n / scale, 0.15), 0.15, r=0.075, fc=PAL[0], z=2)
        y += h
    return cv.png()
