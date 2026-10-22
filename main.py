from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import List, Optional, Generator
import uuid
import requests
from sqlalchemy import create_engine, Column, String, Integer, Float, LargeBinary, JSON, ForeignKey, Boolean, text, func, UniqueConstraint
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt, JWTError
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import json
import pandas as pd
import io
import re
import os
import time
import shutil
import hashlib
import zipfile
import difflib
import asyncio
from starlette.concurrency import run_in_threadpool
from collections import defaultdict
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from shevchenko import in_genitive, GrammaticalGender, DeclensionInput
from docxtpl import DocxTemplate
from num2words import num2words
from fastapi.responses import StreamingResponse
from urllib.parse import quote


# =========================================================
# ⚙️ КОНФІГУРАЦІЯ
# =========================================================
from dotenv import load_dotenv
load_dotenv()

SECRET_KEY = os.environ.get("SECRET_KEY")
DATABASE_URL = os.environ.get("DATABASE_URL")
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY не задано!")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL не задано!")
if not GOOGLE_CLIENT_ID:
    raise RuntimeError("GOOGLE_CLIENT_ID не задано!")

# =========================================================
# 🚀 ІНІЦІАЛІЗАЦІЯ ДОДАТКУ
# =========================================================
app = FastAPI()

os.makedirs("static/uploads", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

# CORS: домени фронтенду через змінну середовища ALLOWED_ORIGINS
# (через кому, напр. "https://my-site.vercel.app,http://localhost:5173").
# Якщо змінну не задано — лишається "*" (як було), щоб нічого не зламати до налаштування.
_origins_env = os.environ.get("ALLOWED_ORIGINS", "").strip()
ALLOWED_ORIGINS = [o.strip().rstrip("/") for o in _origins_env.split(",") if o.strip()] or ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================================================
# 🛡️ RATE LIMITER
# =========================================================
LOGIN_RATE_LIMIT = 10
LOGIN_RATE_WINDOW = 60 * 15

def get_client_ip(request: Request) -> str:
    """IP клієнта. За проксі (Render) request.client.host — адреса проксі, тому
    спершу беремо перший елемент X-Forwarded-For, інакше — адресу з'єднання."""
    xff = request.headers.get("x-forwarded-for", "")
    first = xff.split(",")[0].strip() if xff else ""
    if first:
        return first[:64]
    return request.client.host if request.client else "unknown"

def _rate_keys(request: Request, email: Optional[str] = None) -> list:
    keys = [f"ip:{get_client_ip(request)}"]
    if email:
        # окремий ліміт на конкретний акаунт — працює, навіть якщо атакуючий міняє IP
        keys.append(f"email:{email.strip().lower()[:200]}")
    return keys

def check_login_rate_limit(request: Request, db: Session, email: Optional[str] = None):
    """Перевіряє ліміт, але НЕ рахує спробу — рахуються лише невдалі спроби
    (див. register_failed_login), щоб успішні логіни в різні акаунти не
    вважалися 'спробами зламу' і не блокували легітимну роботу.
    Лічильник зберігається в БД, тож переживає перезапуск сервера."""
    since = time.time() - LOGIN_RATE_WINDOW
    for key in _rate_keys(request, email):
        attempts = db.query(func.count(DBLoginAttempt.id)).filter(
            DBLoginAttempt.key == key, DBLoginAttempt.ts > since
        ).scalar() or 0
        if attempts >= LOGIN_RATE_LIMIT:
            raise HTTPException(
                status_code=429,
                detail="Забагато спроб входу. Спробуйте через 15 хвилин."
            )

def register_failed_login(request: Request, db: Session, email: Optional[str] = None):
    """Реєструє невдалу спробу входу (неправильний пароль / пошта не в базі)"""
    now = time.time()
    for key in _rate_keys(request, email):
        db.add(DBLoginAttempt(key=key, ts=now))
    db.query(DBLoginAttempt).filter(DBLoginAttempt.ts < now - LOGIN_RATE_WINDOW)\
        .delete(synchronize_session=False)
    db.commit()   # інакше запис загубиться через HTTPException нижче

def clear_failed_logins(db: Session, email: str):
    """Після успішного входу скидаємо лічильник невдач для цього акаунта"""
    db.query(DBLoginAttempt).filter(DBLoginAttempt.key == f"email:{email.strip().lower()[:200]}")\
        .delete(synchronize_session=False)
    db.commit()

# =========================================================
# 🗄️ БАЗА ДАНИХ
# =========================================================
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# =========================================================
# 🔐 КРИПТОГРАФІЯ ТА ТОКЕНИ
# =========================================================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
ALGORITHM = "HS256"
security = HTTPBearer()

# =========================================================
# 🏗️ МОДЕЛІ БАЗИ ДАНИХ
# =========================================================
class DBCertificateRequest(Base):
    __tablename__ = "certificate_requests"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    student_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    doc_type = Column(String, nullable=False)
    details = Column(JSON, nullable=True)
    status = Column(String, default="pending")
    admin_comment = Column(String, nullable=True)
    created_at = Column(String, default=lambda: datetime.now().strftime("%d.%m.%Y %H:%M"))
    completed_at = Column(String, nullable=True)

class DBUser(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String)
    full_name = Column(String, nullable=True)
    student_data = Column(JSON, nullable=True)

class DBTemplate(Base):
    __tablename__ = "templates"
    id = Column(String, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(String, nullable=True)
    questions = Column(JSON)
    target_audience = Column(JSON, nullable=True)
    is_anonymous = Column(Boolean, default=True)
    feathers_reward = Column(Integer, default=0)
    hashtags = Column(JSON, default=list)      # 🏷 список slug-ів хештегів
    deadline = Column(String, nullable=True)   # 🗓 дедлайн "DD.MM.YYYY HH:MM"

class DBResponse(Base):
    __tablename__ = "responses"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    survey_id = Column(String, index=True)
    answers = Column(JSON)
    respondent_id = Column(String, nullable=True)
    respondent_name = Column(String, nullable=True)
    opp_context = Column(String, nullable=True)   # 🎓 назва ОПП для #По_ОПП опитувань

class DBCompletedSurvey(Base):
    __tablename__ = "completed_surveys"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(String, index=True)
    survey_id = Column(String, index=True)

class DBGrade(Base):
    __tablename__ = "grades"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    student_id = Column(String, ForeignKey("users.id"))
    group_name = Column(String, nullable=False)
    subject = Column(String, nullable=False)
    semester = Column(Integer)
    score = Column(String)
    control_form = Column(String)
    teacher = Column(String)
    # 🔗 Канонічні зв'язки (Крок 3 реформи бази): якщо вдалось зіставити текст із
    # довідниками Структури — тут зберігається справжній id. Текстові поля вище
    # лишаються як резервне відображення для записів, які ще не вдалось зіставити.
    group_id = Column(String, ForeignKey("academic_groups.id", ondelete="SET NULL"), nullable=True)
    subject_id = Column(Integer, ForeignKey("subjects.id", ondelete="SET NULL"), nullable=True)
    teacher_id = Column(String, ForeignKey("teachers.id", ondelete="SET NULL"), nullable=True)

class DBAnnouncement(Base):
    __tablename__ = "announcements"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    title = Column(String, nullable=False)
    content = Column(String, nullable=True)
    date = Column(String)
    sender = Column(String)
    is_important = Column(Boolean, default=False)
    is_edited = Column(Boolean, default=False)
    target_groups = Column(JSON, nullable=True)   # null = для всіх; список назв груп = лише студентам цих груп

class DBDictionary(Base):
    __tablename__ = "dictionaries"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    data = Column(JSON, nullable=False)

class DBBoardState(Base):
    __tablename__ = "board_state"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    state = Column(JSON, nullable=False)

class DBAuditLog(Base):
    __tablename__ = "audit_logs"
    id           = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp    = Column(String, default=lambda: datetime.now().strftime("%d.%m.%Y %H:%M:%S"))
    user_id      = Column(String, nullable=True)
    user_email   = Column(String, nullable=True)
    ip_address   = Column(String, nullable=True)
    user_agent   = Column(String, nullable=True)
    path         = Column(String, nullable=True)
    method       = Column(String, nullable=True)
    action       = Column(String, nullable=True)
    content_type = Column(String, nullable=True)
    object_id    = Column(String, nullable=True)
    object_repr  = Column(String, nullable=True)
    details      = Column(JSON, nullable=True)

# =========================================================
# 🪶 МОДЕЛІ СИСТЕМИ ПЕР'ЯТА
# =========================================================
class DBFeathersWallet(Base):
    """Гаманець студента — загальний баланс пер'їв"""
    __tablename__ = "feathers_wallet"
    id         = Column(Integer, primary_key=True, index=True, autoincrement=True)
    student_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False)
    balance    = Column(Integer, default=0)

class DBFeathersTransaction(Base):
    """Журнал транзакцій пер'їв"""
    __tablename__ = "feathers_transactions"
    id          = Column(Integer, primary_key=True, index=True, autoincrement=True)
    student_id  = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    amount      = Column(Integer, nullable=False)   # + нарахування, - списання
    reason      = Column(String, nullable=True)     # "Опитування: Назва" / "Куплена тема: ..."
    survey_id   = Column(String, nullable=True)
    created_at  = Column(String, default=lambda: datetime.now().strftime("%d.%m.%Y %H:%M"))

class DBOwnedTheme(Base):
    """Придбані студентом теми"""
    __tablename__ = "owned_themes"
    id         = Column(Integer, primary_key=True, index=True, autoincrement=True)
    student_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    theme_id   = Column(String, nullable=False)
    purchased_at = Column(String, default=lambda: datetime.now().strftime("%d.%m.%Y %H:%M"))

class DBActiveTheme(Base):
    """Активна тема студента"""
    __tablename__ = "active_themes"
    id         = Column(Integer, primary_key=True, index=True, autoincrement=True)
    student_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False)
    theme_id   = Column(String, nullable=False)

class DBHashtagCatalog(Base):
    """Глобальний каталог хештегів — керується SuperAdmin"""
    __tablename__ = "hashtag_catalog"
    id          = Column(Integer, primary_key=True, index=True, autoincrement=True)
    slug        = Column(String, unique=True, nullable=False)
    label       = Column(String, nullable=False)
    # audience | visibility | deadline | tag
    type        = Column(String, nullable=False, default="tag")
    description = Column(String, nullable=True)
    color       = Column(String, default="#a78bfa")
    icon        = Column(String, default="🏷")
    is_system   = Column(Boolean, default=False)
    created_at  = Column(String, default=lambda: datetime.now().strftime("%d.%m.%Y"))

# =========================================================
# 🏛️ АКАДЕМІЧНА СТРУКТУРА (Інститут → Кафедра → ОПП → План → Група → Предмети)
# =========================================================
class DBInstitute(Base):
    """ННІ / Факультет"""
    __tablename__ = "institutes"
    id   = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False, unique=True)   # напр. "ФІТ", "ННІЕБО"
    full_name = Column(String, nullable=True)             # повна назва

class DBDepartment(Base):
    """Кафедра"""
    __tablename__ = "departments_struct"
    id           = Column(String, primary_key=True, index=True)
    institute_id = Column(String, ForeignKey("institutes.id", ondelete="CASCADE"), nullable=False)
    name         = Column(String, nullable=False)          # напр. "ІППЗ", "МВ"
    full_name    = Column(String, nullable=True)

class DBOpp(Base):
    """Освітньо-професійна програма"""
    __tablename__ = "opps"
    id            = Column(String, primary_key=True, index=True)
    department_id = Column(String, ForeignKey("departments_struct.id", ondelete="CASCADE"), nullable=False)
    name          = Column(String, nullable=False)          # напр. "ІПЗ-23-Б"
    level         = Column(String, nullable=False, default="bachelor")  # bachelor | master | phd
    full_name     = Column(String, nullable=True)

class DBStudyPlan(Base):
    """Навчальний план"""
    __tablename__ = "study_plans"
    id     = Column(String, primary_key=True, index=True)
    opp_id = Column(String, ForeignKey("opps.id", ondelete="CASCADE"), nullable=False)
    name   = Column(String, nullable=False)                 # напр. "ІПЗ-23-Б-Д"

class DBAcademicGroup(Base):
    """Академічна група (статичний довідник груп)"""
    __tablename__ = "academic_groups"
    id            = Column(String, primary_key=True, index=True)
    study_plan_id = Column(String, ForeignKey("study_plans.id", ondelete="CASCADE"), nullable=False)
    name          = Column(String, nullable=False, unique=True)   # напр. "ІПЗ-23-2"
    # рівень визначається з назви групи (цифра/ск=бакалавр, м=магістр, дф=доктор філософії),
    # але зберігаємо явно для надійності/можливості ручного перевизначення
    level         = Column(String, nullable=True)  # bachelor | master | phd

class DBTeacher(Base):
    """Викладач — єдиний довідник (замінює вільний текст teachers/викладач у Subject і Grade)"""
    __tablename__ = "teachers"
    id            = Column(String, primary_key=True, index=True)
    full_name     = Column(String, nullable=False, index=True)
    department_id = Column(String, ForeignKey("departments_struct.id", ondelete="SET NULL"), nullable=True)
    email         = Column(String, nullable=True)
    position      = Column(String, nullable=True)   # посада, напр. "доцент"

CONTROL_FORMS = ("Екзамен", "Залік", "Диф. залік")

class DBSubject(Base):
    """Предмет (дисципліна) ОПП — семестр і форма контролю живуть тут,
    бо це властивості освітньої програми, а не конкретного навчального плану.
    Години для предмета — в DBPlanSubjectHours (там вони різні для різних форм навчання).
    name_norm — нормалізована назва для надійного пошуку/унікальності
    (регістр, пробіли, різні апострофи), бо lower() у Postgres залежить від локалі БД."""
    __tablename__ = "subjects"
    id            = Column(Integer, primary_key=True, index=True, autoincrement=True)
    opp_id        = Column(String, ForeignKey("opps.id", ondelete="CASCADE"), nullable=True)
    # DEPRECATED: старе поле, залишене лише для міграції існуючих даних на opp_id.
    # Новий код завжди повинен використовувати opp_id.
    study_plan_id = Column(String, ForeignKey("study_plans.id", ondelete="CASCADE"), nullable=True)
    name          = Column(String, nullable=False)          # напр. "Французька мова", "Бази даних"
    name_norm     = Column(String, index=True)
    semester      = Column(Integer, nullable=True)
    # control_form: форма контролю — "Екзамен" | "Залік" | "Диф. залік"
    control_form  = Column(String, nullable=True)
    # elective_slot: null = обов'язковий предмет; "ВК1", "ВК2" і т.д. = слот вибіркового блоку
    elective_slot = Column(String, nullable=True)
    # DEPRECATED: замінено таблицею subject_teachers. Читається лише одноразовою міграцією.
    teachers      = Column(JSON, default=list)
    # False = чернетка, автоматично створена імпортом оцінок; чекає підтвердження/злиття
    is_verified   = Column(Boolean, nullable=False, default=True, server_default=text("true"))

    teacher_links = relationship("DBSubjectTeacher", cascade="all, delete-orphan",
                                 passive_deletes=True, lazy="selectin")
    aliases       = relationship("DBSubjectAlias", cascade="all, delete-orphan",
                                 passive_deletes=True, lazy="selectin")

class DBSubjectTeacher(Base):
    """Зв'язок предмет ↔ викладач (many-to-many). Видалили викладача — зв'язок зник сам."""
    __tablename__ = "subject_teachers"
    subject_id = Column(Integer, ForeignKey("subjects.id", ondelete="CASCADE"), primary_key=True)
    teacher_id = Column(String, ForeignKey("teachers.id", ondelete="CASCADE"), primary_key=True)

class DBSubjectAlias(Base):
    """Інші написання назви предмета (з Excel-відомостей). Наступний імпорт зіставляється сам."""
    __tablename__ = "subject_aliases"
    id         = Column(Integer, primary_key=True, autoincrement=True)
    subject_id = Column(Integer, ForeignKey("subjects.id", ondelete="CASCADE"), nullable=False, index=True)
    alias_text = Column(String, nullable=False)
    alias_norm = Column(String, nullable=False, index=True)
    __table_args__ = (UniqueConstraint("subject_id", "alias_norm", name="uq_subject_alias"),)

class DBPlanSubjectHours(Base):
    """Години предмета в межах конкретного навчального плану.
    Один предмет ОПП може мати різні години у денного/заочного/іншого плану —
    тому години прив'язані до пари (план, предмет), а не до предмета напряму."""
    __tablename__ = "plan_subject_hours"
    id               = Column(Integer, primary_key=True, index=True, autoincrement=True)
    study_plan_id    = Column(String, ForeignKey("study_plans.id", ondelete="CASCADE"), nullable=False)
    subject_id       = Column(Integer, ForeignKey("subjects.id", ondelete="CASCADE"), nullable=False)
    hours            = Column(Integer, nullable=True)
    lecture_hours    = Column(Integer, nullable=True)
    practice_hours   = Column(Integer, nullable=True)
    self_study_hours = Column(Integer, nullable=True)

class DBStudentSubjectChoice(Base):
    """Фіксація вибору студента в межах вибіркового слоту (ВК1, ВК2...).
    Гнучка модель: прив'язка по (student_id, study_plan_id, elective_slot) -> subject_id,
    легко змінити механізм вибору пізніше без зміни схеми."""
    __tablename__ = "student_subject_choices"
    id            = Column(Integer, primary_key=True, index=True, autoincrement=True)
    student_id    = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    study_plan_id = Column(String, ForeignKey("study_plans.id", ondelete="CASCADE"), nullable=False)
    elective_slot = Column(String, nullable=False)          # "ВК1" і т.д.
    subject_id    = Column(Integer, ForeignKey("subjects.id", ondelete="CASCADE"), nullable=False)
    chosen_at     = Column(String, default=lambda: datetime.now().strftime("%d.%m.%Y %H:%M"))

# =========================================================
# 🔏 ЗГОДА НА ОБРОБКУ ПЕРСОНАЛЬНИХ ДАНИХ (студенти, викладачі)
# =========================================================
CONSENT_ROLES = ("student", "teacher")
CONSENT_VERSION = 1   # збільшіть число — і всі побачать повідомлення знову
CONSENT_LOCATIONS = {"city": "У місті", "ukraine": "В Україні", "abroad": "За кордоном"}

class DBUserConsent(Base):
    """Підтвердження ознайомлення з повідомленням про персональні дані + місце перебування"""
    __tablename__ = "user_consents"
    id             = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id        = Column(String, ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False)
    version        = Column(Integer, default=0)
    accepted_at    = Column(String, nullable=True)
    location       = Column(String, nullable=True)      # city | ukraine | abroad
    reset_required = Column(Boolean, default=False)     # суперадмін вимагає показати знову

# =========================================================
# 📨 СЛУЖБОВІ ЗАПИСКИ (СЗ) ПРО ВІДСУТНІСТЬ ВИКЛАДАЧІВ
# =========================================================
SERVICE_NOTE_REASONS = ["Відпустка", "Лікарняний", "Сімейні обставини", "Відрядження", "Інше"]
SERVICE_NOTE_MAX_FILE = 5 * 1024 * 1024
SERVICE_NOTE_EXT = (".pdf", ".doc", ".docx")

class DBServiceNote(Base):
    """Рядок таблиці службових записок. Файл зберігається в БД (диск Render не постійний)."""
    __tablename__ = "service_notes"
    id               = Column(Integer, primary_key=True, index=True, autoincrement=True)
    teacher_id       = Column(String, ForeignKey("teachers.id", ondelete="SET NULL"), nullable=True)
    teacher_name     = Column(String, nullable=False)            # ПІБ (з довідника або вписаний вручну)
    date_from        = Column(String, nullable=False)            # YYYY-MM-DD
    date_to          = Column(String, nullable=True)             # YYYY-MM-DD
    note_number      = Column(String, nullable=True)
    note_date        = Column(String, nullable=True)             # дата написання СЗ, YYYY-MM-DD
    note_written     = Column(Boolean, default=False)            # «є в наявності»
    reason           = Column(String, nullable=True)
    schedule_changed = Column(Boolean, default=False)
    group_names      = Column(JSON, default=list)                # назви змінених груп
    notes            = Column(String, nullable=True)
    file_url         = Column(String, nullable=True)             # посилання на файл (Google Drive тощо)
    file_name        = Column(String, nullable=True)
    file_mime        = Column(String, nullable=True)
    file_data        = Column(LargeBinary, nullable=True)
    notified_at      = Column(String, nullable=True)
    announcement_id  = Column(Integer, nullable=True)
    created_by       = Column(String, nullable=True)
    created_at       = Column(String, default=lambda: datetime.now().strftime("%d.%m.%Y %H:%M"))
    updated_at       = Column(String, nullable=True)

class DBLoginAttempt(Base):
    """Невдалі спроби входу для ліміту (ключ: ip:<адреса> або email:<пошта>)"""
    __tablename__ = "login_attempts"
    id  = Column(Integer, primary_key=True, index=True, autoincrement=True)
    key = Column(String, index=True, nullable=False)
    ts  = Column(Float, index=True, nullable=False)

# =========================================================
# 🧾 ПЕРЕВІРКА ПАР (ЦМЯО) — ОКРЕМІ ТАБЛИЦІ, з іншими базами не пов'язані
# =========================================================
LESSON_PAIR_MINUTES = 40                       # одна пара = 40 хв
LESSON_MAX_PAIR_NO = 10
LESSON_ALARM_OPTIONS = ("Так", "Ні", "Не відомо")

class DBLessonSubject(Base):
    """Власний список предметів для перевірки пар (наповнюється поступово)"""
    __tablename__ = "lesson_subjects"
    id        = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name      = Column(String, nullable=False)
    name_norm = Column(String, nullable=False, unique=True, index=True)

class DBLessonGroup(Base):
    """Власний список груп/потоків для перевірки пар (наповнюється поступово)"""
    __tablename__ = "lesson_groups"
    id        = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name      = Column(String, nullable=False)
    name_norm = Column(String, nullable=False, unique=True, index=True)

class DBLessonTeacher(Base):
    """Власний список викладачів для перевірки пар (окремо від довідника Структури)"""
    __tablename__ = "lesson_teachers"
    id        = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name      = Column(String, nullable=False)
    name_norm = Column(String, nullable=False, unique=True, index=True)
    note      = Column(String, nullable=True)     # примітка про викладача (Zoom, вичитка пар тощо); порожньо = немає
    note_at   = Column(String, nullable=True)     # коли примітку востаннє змінено (ISO, київський час)

class DBLessonCheck(Base):
    """Рядок таблиці перевірки пар. Усі довідники — власні (lesson_*), без FK на інші таблиці."""
    __tablename__ = "lesson_checks"
    id           = Column(Integer, primary_key=True, index=True, autoincrement=True)
    subject_id   = Column(Integer, nullable=True, index=True)     # lesson_subjects.id
    teacher_id   = Column(String, nullable=True)                  # застаріле (id з довідника Структури), більше не використовується
    lesson_teacher_id = Column(Integer, nullable=True, index=True)  # lesson_teachers.id
    teacher_name = Column(String, nullable=False)                 # ПІБ на момент запису
    group_ids    = Column(JSON, default=list)                     # [lesson_groups.id, ...]
    lesson_date  = Column(String, nullable=False, index=True)     # YYYY-MM-DD
    pairs        = Column(JSON, default=list)                     # номери пар, напр. [1, 2]
    pairs_count  = Column(Integer, nullable=False, default=0)
    minutes      = Column(Integer, nullable=False, default=0)     # pairs_count * 40
    alarm        = Column(String, nullable=False, default="Не відомо")
    notes        = Column(String, nullable=True)
    created_by   = Column(String, nullable=True)
    created_at   = Column(String, default=lambda: datetime.now().strftime("%d.%m.%Y %H:%M"))
    updated_at   = Column(String, nullable=True)

# =========================================================
# 📅 РОЗКЛАД ↔ ZOOM (ЦМЯО) — ТАБЛИЦІ
# Розклад із архіву прив'язується ТІЛЬКИ до викладачів зі списку lesson_teachers
# (за id), нових викладачів завантаження не створює.
# =========================================================
SCHED_SLOT_MINUTES = 80                                   # тривалість одного слота розкладу (пари), хв
SCHED_SLOT_STARTS = ["09:00", "10:30", "12:30", "14:00", "15:30", "17:00", "18:30"]   # початки слотів 1..7
SCHED_OK_RATIO = 0.6                                      # «проведено»: у Zoom ≥ 60% слота
SCHED_MIN_PARTIAL_MIN = 10                                # менше 10 хв у слоті — не враховуємо (тест зв'язку)

class DBLessonSchedBatch(Base):
    """Журнал завантажень: що, коли й ким завантажено (розклад або звіт Zoom)"""
    __tablename__ = "lesson_sched_batches"
    id          = Column(Integer, primary_key=True, index=True, autoincrement=True)
    kind        = Column(String, nullable=False, index=True)          # 'schedule' | 'zoom'
    filename    = Column(String, nullable=True)
    period_from = Column(String, nullable=True)                       # розклад: YYYY-MM-DD; zoom: YYYY-MM-DDTHH:MM:SS
    period_to   = Column(String, nullable=True)
    data_until  = Column(String, nullable=True)                       # zoom: до якого моменту дані вважаються повними
    stats       = Column(JSON, default=dict)
    created_by  = Column(String, nullable=True)
    created_at  = Column(String, nullable=False)                      # ISO, час Києва

class DBLessonSchedItem(Base):
    """Пара за розкладом: ця пара ПОВИННА відбутися у цього викладача в цей час"""
    __tablename__ = "lesson_sched_items"
    id                = Column(Integer, primary_key=True, index=True, autoincrement=True)
    fingerprint       = Column(String, nullable=False, unique=True, index=True)   # захист від дублів при повторному завантаженні
    lesson_teacher_id = Column(Integer, nullable=False, index=True)               # lesson_teachers.id
    lesson_date       = Column(String, nullable=False, index=True)                # YYYY-MM-DD
    start_time        = Column(String, nullable=False)                            # HH:MM
    slot_no           = Column(Integer, nullable=True)
    subject_name      = Column(String, nullable=False)
    lesson_type       = Column(String, nullable=True)                             # ЛК / ПР / ЛБ
    groups_text       = Column(String, nullable=True)
    place             = Column(String, nullable=True)
    is_online         = Column(Boolean, nullable=False, default=True)
    zoom_meeting_id   = Column(String, nullable=True)                             # якщо в розкладі є пряме посилання Zoom
    note              = Column(String, nullable=True)
    source_owner      = Column(String, nullable=True)                             # чий файл (може відрізнятися від викладача при заміні)
    batch_id          = Column(Integer, nullable=True, index=True)
    created_at        = Column(String, nullable=True)
    updated_at        = Column(String, nullable=True)

class DBLessonZoomAccount(Base):
    """Акаунт Zoom (організатор). Зіставляється з викладачем зі списку; зіставлення запам'ятовується."""
    __tablename__ = "lesson_zoom_accounts"
    id                = Column(Integer, primary_key=True, index=True, autoincrement=True)
    email_key         = Column(String, nullable=False, unique=True, index=True)   # e-mail (нижній регістр) або name:<ім'я>
    display_name      = Column(String, nullable=True)
    lesson_teacher_id = Column(Integer, nullable=True, index=True)                # lesson_teachers.id
    link_status       = Column(String, nullable=False, default="none")           # auto | manual | none | ignored
    created_at        = Column(String, nullable=True)

class DBLessonZoomMeeting(Base):
    """Зустріч Zoom зі звіту (хто, коли, скільки)"""
    __tablename__ = "lesson_zoom_meetings"
    id              = Column(Integer, primary_key=True, index=True, autoincrement=True)
    fingerprint     = Column(String, nullable=False, unique=True, index=True)     # id зустрічі + початок + e-mail
    meeting_id      = Column(String, nullable=True, index=True)                   # лише цифри
    topic           = Column(String, nullable=True)
    organizer_name  = Column(String, nullable=True)
    account_id      = Column(Integer, nullable=True, index=True)                  # lesson_zoom_accounts.id
    start_dt        = Column(String, nullable=False, index=True)                  # YYYY-MM-DDTHH:MM:SS
    end_dt          = Column(String, nullable=False)
    duration_sec    = Column(Integer, nullable=False, default=0)
    participants    = Column(Integer, nullable=True)
    batch_id        = Column(Integer, nullable=True, index=True)

# =========================================================
# 🚨 ТРИВОГИ (ukrainealarm.com) — ТАБЛИЦІ
# Офіційна повітряна тривога — поважна причина не проводити пару. Історію беремо з API і кешуємо тут.
# =========================================================
class DBLessonAlertConfig(Base):
    """Налаштування: за якими регіонами враховувати тривоги (один рядок)"""
    __tablename__ = "lesson_alert_config"
    id         = Column(Integer, primary_key=True, autoincrement=True)
    source     = Column(String, nullable=True)       # ukrainealarm | alertsinua (порожньо = ukrainealarm)
    regions    = Column(JSON, default=list)          # [{"id", "name", "type", "scan_uid"?}] — для активного джерела
    history_from   = Column(String, nullable=True)   # з якої дати зберігати історію (YYYY-MM-DD), за замовчуванням 2026-09-01
    lease_until    = Column(String, nullable=True)   # «слот» запиту до API: до цього часу новий запит не робимо (спільне для всіх процесів)
    cooldown_until = Column(String, nullable=True)   # після HTTP 429: до цього часу запитів немає
    updated_at = Column(String, nullable=True)
    updated_by = Column(String, nullable=True)

class DBLessonAlertDay(Base):
    """Облік того, за які дні історію вже завантажено (і коли, з якими налаштуваннями)"""
    __tablename__ = "lesson_alert_days"
    day        = Column(String, primary_key=True)    # YYYY-MM-DD
    fetched_at = Column(String, nullable=False)      # ISO, київський час
    cfg_hash   = Column(String, nullable=True)       # відбиток налаштувань (регіони + типи) на момент завантаження
    status     = Column(String, nullable=False, default="ok")   # ok | error
    error      = Column(String, nullable=True)
    count      = Column(Integer, nullable=False, default=0)

class DBLessonAlert(Base):
    """Тривога обраного регіону (час київський)"""
    __tablename__ = "lesson_alerts"
    id          = Column(Integer, primary_key=True, index=True, autoincrement=True)
    day         = Column(String, nullable=False, index=True)       # дата, за яку запитано історію
    region_id   = Column(String, nullable=False)
    region_name = Column(String, nullable=True)
    alert_type  = Column(String, nullable=True)                    # AIR | ARTILLERY | ...
    start_dt    = Column(String, nullable=False)
    end_dt      = Column(String, nullable=False)
    is_continue = Column(Boolean, nullable=False, default=False)   # тривога ще триває
    scan_uid    = Column(String, nullable=True, index=True)        # alerts.in.ua: за яким запитом (uid області/району) отримано

Base.metadata.create_all(bind=engine)

# =========================================================
# 🔧 МІГРАЦІЇ
# =========================================================

DEFAULT_HASHTAGS = [
    # --- audience ---
    {"slug": "Студентам",       "label": "Студентам",       "type": "audience",    "color": "#38bdf8", "icon": "🎓", "is_system": True,  "description": "Опитування бачать лише студенти"},
    {"slug": "Викладачам",      "label": "Викладачам",      "type": "audience",    "color": "#f472b6", "icon": "👨‍🏫", "is_system": True,  "description": "Опитування бачать лише викладачі"},
    {"slug": "Стейкголдерам",   "label": "Стейкголдерам",   "type": "audience",    "color": "#fb923c", "icon": "💼", "is_system": True,  "description": "Опитування бачать лише стейкголдери"},
    {"slug": "Всім",            "label": "Всім",            "type": "audience",    "color": "#4ade80", "icon": "🌐", "is_system": True,  "description": "Опитування бачать усі ролі"},
    # --- visibility ---
    {"slug": "Анонімне",        "label": "Анонімне",        "type": "visibility",  "color": "#86efac", "icon": "🔒", "is_system": True,  "description": "Відповіді зберігаються без імені"},
    {"slug": "Не_анонімне",     "label": "Не анонімне",     "type": "visibility",  "color": "#fdba74", "icon": "👁",  "is_system": True,  "description": "Відповіді підписуються іменем"},
    # --- tag ---
    {"slug": "По_кафедрам",     "label": "По кафедрам",     "type": "tag",         "color": "#c084fc", "icon": "🏛", "is_system": False, "description": "Опитування стосується кафедр"},
    {"slug": "По_ОПП",          "label": "По ОПП",          "type": "tag",         "color": "#a78bfa", "icon": "📋", "is_system": False, "description": "Пов'язане з освітньо-професійною програмою"},
    {"slug": "Акредитація",     "label": "Акредитація",     "type": "tag",         "color": "#fbbf24", "icon": "🏅", "is_system": False, "description": "Акредитаційне опитування"},
    {"slug": "Невизначене",     "label": "Невизначене",     "type": "tag",         "color": "#94a3b8", "icon": "❓", "is_system": False, "description": "Без чіткої категорії"},
]

def _seed_hashtags(db_session):
    for h in DEFAULT_HASHTAGS:
        exists = db_session.query(DBHashtagCatalog).filter(DBHashtagCatalog.slug == h["slug"]).first()
        if not exists:
            db_session.add(DBHashtagCatalog(**h))
    db_session.commit()

def _run_migrations():
    migrations = [
        "ALTER TABLE templates ADD COLUMN IF NOT EXISTS is_anonymous BOOLEAN DEFAULT TRUE",
        "ALTER TABLE templates ADD COLUMN IF NOT EXISTS description VARCHAR",
        "ALTER TABLE responses ADD COLUMN IF NOT EXISTS respondent_id VARCHAR",
        "ALTER TABLE responses ADD COLUMN IF NOT EXISTS respondent_name VARCHAR",
        "ALTER TABLE responses ADD COLUMN IF NOT EXISTS opp_context VARCHAR",
        "ALTER TABLE announcements ADD COLUMN IF NOT EXISTS target_groups JSON",
        "ALTER TABLE templates ADD COLUMN IF NOT EXISTS feathers_reward INTEGER DEFAULT 0",
        "ALTER TABLE templates ADD COLUMN IF NOT EXISTS hashtags JSON DEFAULT '[]'",
        "ALTER TABLE templates ADD COLUMN IF NOT EXISTS deadline VARCHAR",
        # Нові таблиці академічної структури — Base.metadata.create_all їх вже створює,
        # але на випадок якщо БД старіша — страхуємо ALTER-ами де потрібно
        "ALTER TABLE academic_groups ADD COLUMN IF NOT EXISTS level VARCHAR",
        "ALTER TABLE subjects ADD COLUMN IF NOT EXISTS elective_slot VARCHAR",
        "ALTER TABLE subjects ADD COLUMN IF NOT EXISTS teachers JSON DEFAULT '[]'",
        # 🏗 Реформа: Subject переїжджає на рівень ОПП, години — окремо по планах,
        # з'являється довідник викладачів
        "ALTER TABLE subjects ADD COLUMN IF NOT EXISTS opp_id VARCHAR",
        "ALTER TABLE subjects ADD COLUMN IF NOT EXISTS control_form VARCHAR",
        "ALTER TABLE subjects ALTER COLUMN study_plan_id DROP NOT NULL",
        "ALTER TABLE teachers ADD COLUMN IF NOT EXISTS email VARCHAR",
        "ALTER TABLE teachers ADD COLUMN IF NOT EXISTS position VARCHAR",
        # 🔗 Grade: канонічні зв'язки замість вільного тексту
        "ALTER TABLE grades ADD COLUMN IF NOT EXISTS group_id VARCHAR",
        "ALTER TABLE grades ADD COLUMN IF NOT EXISTS subject_id INTEGER",
        "ALTER TABLE grades ADD COLUMN IF NOT EXISTS teacher_id VARCHAR",
        # 🧱 Реформа предметів: нормалізована назва + прапорець чернетки
        "ALTER TABLE subjects ADD COLUMN IF NOT EXISTS name_norm VARCHAR",
        "ALTER TABLE subjects ADD COLUMN IF NOT EXISTS is_verified BOOLEAN NOT NULL DEFAULT TRUE",
        # 🧾 Перевірка пар: власний список викладачів
        "ALTER TABLE lesson_checks ADD COLUMN IF NOT EXISTS lesson_teacher_id INTEGER",
        "CREATE INDEX IF NOT EXISTS ix_lesson_checks_lesson_teacher_id ON lesson_checks (lesson_teacher_id)",
        # 📝 Примітки до викладачів
        "ALTER TABLE lesson_teachers ADD COLUMN IF NOT EXISTS note VARCHAR",
        "ALTER TABLE lesson_teachers ADD COLUMN IF NOT EXISTS note_at VARCHAR",
        # 🚨 Тривоги: друге джерело, історія від дати, спільний «слот» запитів
        "ALTER TABLE lesson_alert_config ADD COLUMN IF NOT EXISTS source VARCHAR",
        "ALTER TABLE lesson_alert_config ADD COLUMN IF NOT EXISTS history_from VARCHAR",
        "ALTER TABLE lesson_alert_config ADD COLUMN IF NOT EXISTS lease_until VARCHAR",
        "ALTER TABLE lesson_alert_config ADD COLUMN IF NOT EXISTS cooldown_until VARCHAR",
        "ALTER TABLE lesson_alerts ADD COLUMN IF NOT EXISTS scan_uid VARCHAR",
    ]
    with engine.connect() as conn:
        for sql in migrations:
            try:
                conn.execute(text(sql))
                conn.commit()
            except Exception:
                conn.rollback()  # інакше у Postgres усі наступні міграції мовчки не виконуються

def _migrate_subjects_to_opp_level(db_session):
    """Одноразова міграція: для предметів, які ще мають лише study_plan_id (стара схема),
    підставляємо opp_id з їхнього навчального плану, і переносимо прив'язку в plan_subject_hours,
    щоб нічого не загубилось при переході на нову структуру."""
    legacy_subjects = db_session.query(DBSubject).filter(
        DBSubject.opp_id.is_(None), DBSubject.study_plan_id.isnot(None)
    ).all()
    for subj in legacy_subjects:
        plan = db_session.query(DBStudyPlan).filter(DBStudyPlan.id == subj.study_plan_id).first()
        if not plan:
            continue
        subj.opp_id = plan.opp_id
        exists = db_session.query(DBPlanSubjectHours).filter(
            DBPlanSubjectHours.study_plan_id == subj.study_plan_id,
            DBPlanSubjectHours.subject_id == subj.id,
        ).first()
        if not exists:
            db_session.add(DBPlanSubjectHours(study_plan_id=subj.study_plan_id, subject_id=subj.id))
    if legacy_subjects:
        db_session.commit()

def resolve_group_id(db_session, group_name: str):
    """Зіставляє вільний текст назви групи з канонічним записом Структури.
    Спершу точний збіг, потім без урахування регістру/пробілів."""
    if not group_name:
        return None
    gname = group_name.strip()
    grp = db_session.query(DBAcademicGroup).filter(DBAcademicGroup.name == gname).first()
    if grp:
        return grp.id
    grp = db_session.query(DBAcademicGroup).filter(func.lower(DBAcademicGroup.name) == gname.lower()).first()
    return grp.id if grp else None

def _norm(s) -> str:
    """Нормалізація для порівняння назв: різні апострофи → ', зайві пробіли, регістр."""
    s = (s or "")
    for ch in ("’", "ʼ", "`", "´"):
        s = s.replace(ch, "'")
    return re.sub(r"\s+", " ", s).strip().lower()

def _clean(s) -> str:
    return re.sub(r"\s+", " ", (s or "")).strip()

def _normalize_slot(slot):
    """'вк 1' / 'Вк1' → 'ВК1'; порожнє → None."""
    s = re.sub(r"\s+", "", (slot or "")).upper()
    return s or None

def _validate_control_form(cf):
    if not cf:
        return None
    for allowed in CONTROL_FORMS:
        if cf.strip().lower() == allowed.lower():
            return allowed
    raise HTTPException(status_code=400, detail=f"Форма контролю має бути однією з: {', '.join(CONTROL_FORMS)}")

def _validate_semester(sem):
    if sem is not None and not (1 <= sem <= 12):
        raise HTTPException(status_code=400, detail="Семестр має бути від 1 до 12")

def _sync_subject_teachers(db_session, subject, teacher_ids):
    """Приводить зв'язки викладачів предмета до заданого списку (з перевіркою існування)."""
    ids = list(dict.fromkeys(teacher_ids or []))
    if ids:
        found = {r[0] for r in db_session.query(DBTeacher.id).filter(DBTeacher.id.in_(ids)).all()}
        missing = [i for i in ids if i not in found]
        if missing:
            raise HTTPException(status_code=400, detail=f"Викладачів не знайдено: {', '.join(missing)}")
    current = {l.teacher_id: l for l in subject.teacher_links}
    for tid, link in current.items():
        if tid not in ids:
            subject.teacher_links.remove(link)
    for tid in ids:
        if tid not in current:
            subject.teacher_links.append(DBSubjectTeacher(teacher_id=tid))

def _find_duplicate_subject(db_session, opp_id, name, semester, exclude_id=None):
    q = db_session.query(DBSubject).filter(
        DBSubject.opp_id == opp_id,
        DBSubject.name_norm == _norm(name),
        func.coalesce(DBSubject.semester, 0) == (semester or 0),
    )
    if exclude_id is not None:
        q = q.filter(DBSubject.id != exclude_id)
    return q.first()

def _opp_id_of_group(db_session, group_id):
    if not group_id:
        return None
    grp = db_session.query(DBAcademicGroup).filter(DBAcademicGroup.id == group_id).first()
    if not grp:
        return None
    plan = db_session.query(DBStudyPlan).filter(DBStudyPlan.id == grp.study_plan_id).first()
    return plan.opp_id if plan else None

def resolve_subject_id(db_session, subject_name: str, group_id: str = None):
    """Точний збіг за name_norm → збіг за аліасом. Якщо відома група — тільки в межах її ОПП."""
    n = _norm(subject_name)
    if not n:
        return None
    opp_id = _opp_id_of_group(db_session, group_id)

    q = db_session.query(DBSubject).filter(DBSubject.name_norm == n)
    if opp_id:
        q = q.filter(DBSubject.opp_id == opp_id)
    subj = q.order_by(DBSubject.is_verified.desc(), DBSubject.id).first()
    if subj:
        return subj.id

    aq = db_session.query(DBSubjectAlias).join(DBSubject, DBSubject.id == DBSubjectAlias.subject_id)\
        .filter(DBSubjectAlias.alias_norm == n)
    if opp_id:
        aq = aq.filter(DBSubject.opp_id == opp_id)
    alias = aq.first()
    return alias.subject_id if alias else None

def resolve_or_create_subject(db_session, subject_name, group_id, semester=None, control_form=None):
    """Як resolve_subject_id, але якщо збігу нема і ОПП групи відома — створює
    ЧЕРНЕТКУ (is_verified=False), щоб оцінка не лишалась без канонічного предмета."""
    sid = resolve_subject_id(db_session, subject_name, group_id)
    if sid:
        return sid
    opp_id = _opp_id_of_group(db_session, group_id)
    name = _clean(subject_name)
    if not opp_id or not name:
        return None
    cf = next((c for c in CONTROL_FORMS if (control_form or "").strip().lower() == c.lower()), None)
    draft = DBSubject(opp_id=opp_id, name=name, name_norm=_norm(name),
                      semester=semester if semester and 1 <= semester <= 12 else None,
                      control_form=cf, is_verified=False)
    db_session.add(draft)
    db_session.flush()
    return draft.id

def merge_subjects(db_session, source_id: int, target_id: int):
    """Зливає source у target: оцінки, вибори, години, викладачі, аліаси переїжджають;
    назва source стає аліасом target (щоб наступний імпорт зіставився автоматично)."""
    if source_id == target_id:
        raise HTTPException(status_code=400, detail="Не можна злити предмет сам із собою")
    db_session.flush()  # autoflush вимкнено — синхронізуємо стан перед запитами
    src = db_session.query(DBSubject).filter(DBSubject.id == source_id).first()
    tgt = db_session.query(DBSubject).filter(DBSubject.id == target_id).first()
    if not src or not tgt:
        raise HTTPException(status_code=404, detail="Предмет не знайдено")
    if src.opp_id != tgt.opp_id:
        raise HTTPException(status_code=400, detail="Злиття можливе лише в межах однієї ОПП")

    db_session.query(DBGrade).filter(DBGrade.subject_id == src.id)\
        .update({DBGrade.subject_id: tgt.id}, synchronize_session=False)
    db_session.query(DBStudentSubjectChoice).filter(DBStudentSubjectChoice.subject_id == src.id)\
        .update({DBStudentSubjectChoice.subject_id: tgt.id}, synchronize_session=False)

    tgt_plans = {h.study_plan_id for h in
                 db_session.query(DBPlanSubjectHours).filter(DBPlanSubjectHours.subject_id == tgt.id)}
    for h in db_session.query(DBPlanSubjectHours).filter(DBPlanSubjectHours.subject_id == src.id).all():
        if h.study_plan_id in tgt_plans:
            db_session.delete(h)          # у target уже є години для цього плану — лишаємо їх
        else:
            h.subject_id = tgt.id
            tgt_plans.add(h.study_plan_id)

    have_t = {l.teacher_id for l in tgt.teacher_links}
    for l in src.teacher_links:
        if l.teacher_id not in have_t:
            tgt.teacher_links.append(DBSubjectTeacher(teacher_id=l.teacher_id))
            have_t.add(l.teacher_id)

    have_a = {a.alias_norm for a in tgt.aliases} | {tgt.name_norm}
    for a in list(src.aliases):
        if a.alias_norm not in have_a:
            tgt.aliases.append(DBSubjectAlias(alias_text=a.alias_text, alias_norm=a.alias_norm))
            have_a.add(a.alias_norm)
    if src.name_norm not in have_a:
        tgt.aliases.append(DBSubjectAlias(alias_text=src.name, alias_norm=src.name_norm))

    db_session.flush()
    db_session.delete(src)
    db_session.flush()
    return tgt

def resolve_teacher_id(db_session, teacher_name: str):
    """Зіставляє вільний текст ПІБ викладача з довідником Teacher (точний, потім без регістру)."""
    if not teacher_name:
        return None
    tname = teacher_name.strip()
    if not tname:
        return None
    t = db_session.query(DBTeacher).filter(DBTeacher.full_name == tname).first()
    if t:
        return t.id
    t = db_session.query(DBTeacher).filter(func.lower(DBTeacher.full_name) == tname.lower()).first()
    return t.id if t else None

def _migrate_grades_to_canonical_links(db_session):
    """Одноразова міграція: для оцінок, які ще не мають group_id/subject_id/teacher_id,
    пробує зіставити текстові поля з довідниками Структури. Те, що не зіставилось,
    залишається з порожнім id — текстове поле й далі відображається як є (нічого не губиться)."""
    legacy_grades = db_session.query(DBGrade).filter(DBGrade.group_id.is_(None)).all()
    if not legacy_grades:
        return
    changed = 0
    for g in legacy_grades:
        gid = resolve_group_id(db_session, g.group_name)
        if gid:
            g.group_id = gid
            changed += 1
        sid = resolve_subject_id(db_session, g.subject, gid)
        if sid:
            g.subject_id = sid
        tid = resolve_teacher_id(db_session, g.teacher)
        if tid:
            g.teacher_id = tid
    if changed:
        db_session.commit()
    else:
        db_session.rollback()

def _backfill_subject_norms(db_session):
    changed = False
    for sj in db_session.query(DBSubject).all():
        n = _norm(sj.name)
        if sj.name_norm != n:
            sj.name_norm = n; changed = True
        slot = _normalize_slot(sj.elective_slot)
        if slot != sj.elective_slot:
            sj.elective_slot = slot; changed = True
        if sj.control_form:
            canon = next((c for c in CONTROL_FORMS if sj.control_form.strip().lower() == c.lower()), None)
            if canon and canon != sj.control_form:
                sj.control_form = canon; changed = True
    if changed:
        db_session.commit()

def _migrate_subject_teachers_json_to_links(db_session):
    """Одноразово: subjects.teachers (JSON) → subject_teachers. JSON очищається,
    інакше при кожному старті видалені зв'язки «воскресали» б."""
    valid = {r[0] for r in db_session.query(DBTeacher.id).all()}
    changed = False
    for sj in db_session.query(DBSubject).all():
        legacy = sj.teachers or []
        if not legacy:
            continue
        have = {l.teacher_id for l in sj.teacher_links}
        for tid in legacy:
            if tid in valid and tid not in have:
                sj.teacher_links.append(DBSubjectTeacher(teacher_id=tid))
                have.add(tid)
        sj.teachers = []
        changed = True
    if changed:
        db_session.commit()

def _dedupe_subjects(db_session):
    groups = defaultdict(list)
    for sj in db_session.query(DBSubject).filter(DBSubject.opp_id.isnot(None)).order_by(DBSubject.id):
        groups[(sj.opp_id, sj.name_norm, sj.semester or 0)].append(sj)
    merged = 0
    for items in groups.values():
        if len(items) < 2:
            continue
        keep = next((x for x in items if x.is_verified), items[0])
        for dup in items:
            if dup.id != keep.id:
                merge_subjects(db_session, dup.id, keep.id)
                merged += 1
    if merged:
        db_session.commit()
        print(f"[migration] злито дублікатів предметів: {merged}")

def _dedupe_plan_hours(db_session):
    seen, removed = set(), 0
    for h in db_session.query(DBPlanSubjectHours).order_by(DBPlanSubjectHours.id).all():
        key = (h.study_plan_id, h.subject_id)
        if key in seen:
            db_session.delete(h); removed += 1
        else:
            seen.add(key)
    if removed:
        db_session.commit()
        print(f"[migration] видалено дублікатів годин: {removed}")

def _apply_subject_constraints():
    """Застосовується ПІСЛЯ дедуплікації. Якщо в даних лишились порушення — констрейнт
    не створиться, причина буде в логах (сервер при цьому не падає)."""
    stmts = [
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_subject_opp_name_sem ON subjects (opp_id, name_norm, (COALESCE(semester, 0)))",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_plan_subject ON plan_subject_hours (study_plan_id, subject_id)",
        "ALTER TABLE subjects ADD CONSTRAINT ck_subject_semester CHECK (semester IS NULL OR semester BETWEEN 1 AND 12)",
        "ALTER TABLE subjects ADD CONSTRAINT ck_subject_control_form CHECK (control_form IS NULL OR control_form IN ('Екзамен','Залік','Диф. залік'))",
        "ALTER TABLE plan_subject_hours ADD CONSTRAINT ck_hours_nonneg CHECK (COALESCE(hours,0) >= 0 AND COALESCE(lecture_hours,0) >= 0 AND COALESCE(practice_hours,0) >= 0 AND COALESCE(self_study_hours,0) >= 0)",
    ]
    with engine.connect() as conn:
        for sql in stmts:
            try:
                conn.execute(text(sql))
                conn.commit()
            except Exception as e:
                conn.rollback()
                if "already exists" not in str(e):
                    print(f"[migration] не застосовано: {sql[:70]}… → {str(e)[:160]}")

_run_migrations()
_seed_db = SessionLocal()
try:
    _seed_hashtags(_seed_db)
    _migrate_subjects_to_opp_level(_seed_db)
    _backfill_subject_norms(_seed_db)
    _migrate_subject_teachers_json_to_links(_seed_db)
    _dedupe_subjects(_seed_db)
    _dedupe_plan_hours(_seed_db)
    _migrate_grades_to_canonical_links(_seed_db)
finally:
    _seed_db.close()
_apply_subject_constraints()

# =========================================================
# 📋 СХЕМИ (Pydantic)
# =========================================================
class CertRequestCreateSchema(BaseModel):
    doc_type: str
    details: dict = {}

class CertStatusUpdateSchema(BaseModel):
    status: str
    admin_comment: Optional[str] = None

class UserLoginSchema(BaseModel):
    email: str
    password: str

class GoogleLoginSchema(BaseModel):
    credential: str

class UserCreateSchema(BaseModel):
    email: str
    password: Optional[str] = None
    role: str
    full_name: Optional[str] = None
    student_data: Optional[dict] = None

class QuestionSchema(BaseModel):
    id: str
    text: str
    type: str
    options: List[dict]
    logic_parent: Optional[str] = None
    logic_value: Optional[str] = None

class SurveyTemplateSchema(BaseModel):
    id: Optional[str] = None
    title: str
    description: Optional[str] = None
    questions: List[QuestionSchema]
    target_audience: Optional[dict] = None
    is_anonymous: bool = True
    feathers_reward: int = 0
    hashtags: List[str] = []       # 🏷 slug-и хештегів
    deadline: Optional[str] = None # 🗓 "DD.MM.YYYY HH:MM"

class StudentResponseSchema(BaseModel):
    survey_id: str
    answers: list

class GradeUpdateSchema(BaseModel):
    score: str
    subject: str
    semester: int
    control_form: str
    teacher: str

class AnnouncementCreateSchema(BaseModel):
    title: str
    content: str = ""
    is_important: bool = False
    is_edited: bool = False

class ThemePurchaseSchema(BaseModel):
    theme_id: str

class ActiveThemeSchema(BaseModel):
    theme_id: str

class HashtagCreateSchema(BaseModel):
    slug: str
    label: str
    type: str = "tag"
    description: Optional[str] = None
    color: str = "#a78bfa"
    icon: str = "🏷"

class HashtagUpdateSchema(BaseModel):
    label: Optional[str] = None
    type: Optional[str] = None
    description: Optional[str] = None
    color: Optional[str] = None
    icon: Optional[str] = None

# --- Академічна структура ---
class InstituteSchema(BaseModel):
    id: Optional[str] = None
    name: str
    full_name: Optional[str] = None

class DepartmentSchema(BaseModel):
    id: Optional[str] = None
    institute_id: str
    name: str
    full_name: Optional[str] = None

class OppSchema(BaseModel):
    id: Optional[str] = None
    department_id: str
    name: str
    level: str = "bachelor"
    full_name: Optional[str] = None

class StudyPlanSchema(BaseModel):
    id: Optional[str] = None
    opp_id: str
    name: str

class AcademicGroupSchema(BaseModel):
    id: Optional[str] = None
    study_plan_id: str
    name: str
    level: Optional[str] = None

class SubjectSchema(BaseModel):
    id: Optional[int] = None
    opp_id: str
    name: str
    semester: Optional[int] = None
    control_form: Optional[str] = None
    elective_slot: Optional[str] = None
    teachers: List[str] = []   # список id викладачів (DBTeacher.id)

class PlanSubjectHoursSchema(BaseModel):
    id: Optional[int] = None
    study_plan_id: str
    subject_id: int
    hours: Optional[int] = None
    lecture_hours: Optional[int] = None
    practice_hours: Optional[int] = None
    self_study_hours: Optional[int] = None

class TeacherSchema(BaseModel):
    id: Optional[str] = None
    full_name: str
    department_id: Optional[str] = None
    email: Optional[str] = None
    position: Optional[str] = None

class StudentSubjectChoiceSchema(BaseModel):
    student_id: str
    study_plan_id: str
    elective_slot: str
    subject_id: int

# =========================================================
# 🔑 ФУНКЦІЇ АВТОРИЗАЦІЇ
# =========================================================
def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=1)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("sub") is None:
            raise HTTPException(status_code=401, detail="Недійсний токен")
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Недійсний токен")

def require_superadmin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "superadmin":
        raise HTTPException(status_code=403, detail="Доступ заборонено")
    return user

def require_csk_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") not in ["superadmin", "admin_csk"]:
        raise HTTPException(status_code=403, detail="Тільки для ЦСК")
    return user

def require_cmyo_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") not in ["superadmin", "admin_cmyo"]:
        raise HTTPException(status_code=403, detail="Тільки для ЦМЯО")
    return user

def require_announcement_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") not in ["superadmin", "admin_csk", "admin_cmyo"]:
        raise HTTPException(status_code=403, detail="Тільки для адміністраторів")
    return user

def write_audit(
    db, request, action, user=None, content_type=None,
    object_id=None, object_repr=None, details=None,
):
    try:
        db.add(DBAuditLog(
            user_id      = user.get("user_id") if user else None,
            user_email   = user.get("sub")     if user else None,
            ip_address   = get_client_ip(request),
            user_agent   = request.headers.get("user-agent", "")[:300],
            path         = str(request.url.path),
            method       = request.method,
            action       = action,
            content_type = content_type,
            object_id    = str(object_id) if object_id is not None else None,
            object_repr  = object_repr,
            details      = details,
        ))
    except Exception:
        pass

# =========================================================
# 🪶 ДОПОМІЖНІ ФУНКЦІЇ ДЛЯ ПЕР'ЯТА
# =========================================================

# Каталог тем (статичний, розширюйте за потребою)
THEMES_CATALOG = [
    {
        "id": "theme_sakura",
        "name": "Сакура",
        "description": "Рожево-ніжний градієнт з пелюстками сакури",
        "price": 50,
        "preview_gradient": "linear-gradient(135deg, #fbc2eb 0%, #a18cd1 100%)",
        "css_vars": {
            "--bg-gradient": "linear-gradient(135deg, #2d1b2e 0%, #3d1f3f 50%, #1a0f2e 100%)",
            "--accent": "#e879f9",
            "--accent-bg": "rgba(232,121,249,0.15)",
            "--accent-border": "rgba(232,121,249,0.3)",
            "--accent-text": "#f5d0fe",
        }
    },
    {
        "id": "theme_ocean",
        "name": "Океан",
        "description": "Глибокі відтінки моря та бірюзові хвилі",
        "price": 60,
        "preview_gradient": "linear-gradient(135deg, #0f3460 0%, #16213e 50%, #0d7377 100%)",
        "css_vars": {
            "--bg-gradient": "linear-gradient(135deg, #0d1b2a 0%, #0f3460 50%, #0d4f6e 100%)",
            "--accent": "#06b6d4",
            "--accent-bg": "rgba(6,182,212,0.15)",
            "--accent-border": "rgba(6,182,212,0.3)",
            "--accent-text": "#a5f3fc",
        }
    },
    {
        "id": "theme_forest",
        "name": "Ліс",
        "description": "Темно-зелений з нотками смарагду та моху",
        "price": 55,
        "preview_gradient": "linear-gradient(135deg, #134e5e 0%, #1a3a2a 50%, #2d5a27 100%)",
        "css_vars": {
            "--bg-gradient": "linear-gradient(135deg, #0d2818 0%, #1a3a2a 50%, #0f3d24 100%)",
            "--accent": "#4ade80",
            "--accent-bg": "rgba(74,222,128,0.15)",
            "--accent-border": "rgba(74,222,128,0.3)",
            "--accent-text": "#bbf7d0",
        }
    },
    {
        "id": "theme_sunset",
        "name": "Захід сонця",
        "description": "Теплі відтінки помаранчевого та золотого",
        "price": 65,
        "preview_gradient": "linear-gradient(135deg, #f83600 0%, #f9d423 100%)",
        "css_vars": {
            "--bg-gradient": "linear-gradient(135deg, #2d1200 0%, #4a1a00 50%, #3d2000 100%)",
            "--accent": "#fb923c",
            "--accent-bg": "rgba(251,146,60,0.15)",
            "--accent-border": "rgba(251,146,60,0.3)",
            "--accent-text": "#fed7aa",
        }
    },
    {
        "id": "theme_midnight",
        "name": "Північ",
        "description": "Чорний космос із сріблястими акцентами",
        "price": 80,
        "preview_gradient": "linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%)",
        "css_vars": {
            "--bg-gradient": "linear-gradient(135deg, #050507 0%, #0f0c29 50%, #1a1040 100%)",
            "--accent": "#e2e8f0",
            "--accent-bg": "rgba(226,232,240,0.1)",
            "--accent-border": "rgba(226,232,240,0.25)",
            "--accent-text": "#f8fafc",
        }
    },
    {
        "id": "theme_rose_gold",
        "name": "Рожеве золото",
        "description": "Елегантний рожево-золотий градієнт",
        "price": 90,
        "preview_gradient": "linear-gradient(135deg, #b76e79 0%, #c9956c 50%, #f2c27a 100%)",
        "css_vars": {
            "--bg-gradient": "linear-gradient(135deg, #2d1018 0%, #3d1a10 50%, #2a1500 100%)",
            "--accent": "#f9a8d4",
            "--accent-bg": "rgba(249,168,212,0.15)",
            "--accent-border": "rgba(249,168,212,0.3)",
            "--accent-text": "#fce7f3",
        }
    },
]

# =========================================================
# 🏛️ ДОПОМІЖНІ ФУНКЦІЇ АКАДЕМІЧНОЇ СТРУКТУРИ
# =========================================================
def detect_level_from_group_name(group_name: str) -> str:
    """Визначає рівень освіти за закінченням назви групи.
    Бакалавр: закінчується на цифру або 'ск'
    Магістр: закінчується на 'м'
    Доктор філософії: закінчується на 'дф'
    """
    if not group_name:
        return "bachelor"
    g = group_name.strip().lower()
    if g.endswith("дф"):
        return "phd"
    if g.endswith("м"):
        return "master"
    if g.endswith("ск") or (g and g[-1].isdigit()):
        return "bachelor"
    return "bachelor"

def _struct_to_dict(obj, fields):
    return {f: getattr(obj, f) for f in fields}

def _subject_to_dict(s: "DBSubject") -> dict:
    return {
        "id": s.id, "opp_id": s.opp_id, "name": s.name, "semester": s.semester,
        "control_form": s.control_form, "elective_slot": s.elective_slot,
        "teachers": [l.teacher_id for l in s.teacher_links],
        "is_verified": s.is_verified,
    }

def _plan_subject_hours_to_dict(h: "DBPlanSubjectHours") -> dict:
    return {
        "id": h.id, "study_plan_id": h.study_plan_id, "subject_id": h.subject_id,
        "hours": h.hours, "lecture_hours": h.lecture_hours,
        "practice_hours": h.practice_hours, "self_study_hours": h.self_study_hours,
    }

def _teacher_to_dict(t: "DBTeacher") -> dict:
    return {
        "id": t.id, "full_name": t.full_name, "department_id": t.department_id,
        "email": t.email, "position": t.position,
    }

def get_or_create_wallet(db: Session, student_id: str) -> "DBFeathersWallet":
    """Повертає гаманець студента, створюючи його при першому зверненні"""
    wallet = db.query(DBFeathersWallet).filter(DBFeathersWallet.student_id == student_id).first()
    if not wallet:
        wallet = DBFeathersWallet(student_id=student_id, balance=0)
        db.add(wallet)
        db.flush()
    return wallet

def award_feathers(db: Session, student_id: str, amount: int, reason: str, survey_id: str = None):
    """Нараховує пер'я студенту та записує транзакцію"""
    if amount <= 0:
        return
    wallet = get_or_create_wallet(db, student_id)
    wallet.balance += amount
    db.add(DBFeathersTransaction(
        student_id=student_id,
        amount=amount,
        reason=reason,
        survey_id=survey_id
    ))

# =========================================================
# 🔐 АВТОРИЗАЦІЯ
# =========================================================
@app.post("/api/login")
async def login(
    user: UserLoginSchema,
    request: Request,
    db: Session = Depends(get_db)
):
    check_login_rate_limit(request, db, user.email)
    db_user = db.query(DBUser).filter(DBUser.email == user.email).first()
    dummy_hash = "$2b$12$KIX6s9S8sS8sS8sS8sS8sOKIX6s9S8sS8sS8sS8sS8sS8sS8sS8s"
    hash_to_check = db_user.hashed_password if db_user else dummy_hash
    password_valid = pwd_context.verify(user.password, hash_to_check)
    if not db_user or not password_valid:
        register_failed_login(request, db, user.email)
        raise HTTPException(status_code=401, detail="Неправильна пошта або пароль")
    clear_failed_logins(db, user.email)
    access_token = create_access_token(
        data={"sub": db_user.email, "role": db_user.role, "user_id": db_user.id}
    )
    write_audit(db, request,
        action="login", user={"user_id": db_user.id, "sub": db_user.email},
        content_type="Users | Користувач", object_id=db_user.id, object_repr=db_user.email,
    )
    db.commit()
    return {"access_token": access_token, "role": db_user.role}

@app.post("/api/google-login")
async def google_login(
    auth_data: GoogleLoginSchema,
    request: Request,
    db: Session = Depends(get_db)
):
    check_login_rate_limit(request, db)

    # Технічні подробиці — лише в серверний лог; користувачу віддаємо загальні повідомлення
    try:
        response = requests.get(
            "https://oauth2.googleapis.com/tokeninfo",
            params={"id_token": auth_data.credential},
            timeout=10,
        )
    except requests.exceptions.RequestException as e:
        print(f"[google-login] помилка зв'язку з Google: {type(e).__name__}")
        raise HTTPException(status_code=503, detail="Не вдалося зв'язатися з Google. Спробуйте пізніше.")

    if response.status_code != 200:
        register_failed_login(request, db)
        raise HTTPException(status_code=401, detail="Не вдалося підтвердити вхід через Google")

    idinfo = response.json()

    # aud (для якого додатка виданий токен) — рядок або список
    aud = idinfo.get("aud", "")
    aud_ok = GOOGLE_CLIENT_ID in aud if isinstance(aud, list) else aud == GOOGLE_CLIENT_ID
    if not aud_ok or idinfo.get("iss") not in ("accounts.google.com", "https://accounts.google.com"):
        register_failed_login(request, db)
        raise HTTPException(status_code=401, detail="Не вдалося підтвердити вхід через Google")

    # пошта має бути підтверджена Google
    if str(idinfo.get("email_verified", "")).lower() != "true":
        register_failed_login(request, db)
        raise HTTPException(status_code=401, detail="Пошта Google не підтверджена")

    email = (idinfo.get("email") or "").strip()
    if not email:
        raise HTTPException(status_code=401, detail="Не вдалося отримати пошту з Google")

    db_user = db.query(DBUser).filter(func.lower(DBUser.email) == email.lower()).first()
    if not db_user:
        register_failed_login(request, db, email)
        raise HTTPException(
            status_code=403,
            detail="Вашої пошти немає в системі. Зверніться до підтримки: moodle@duet.edu.ua"
        )

    access_token = create_access_token(
        data={"sub": db_user.email, "role": db_user.role, "user_id": db_user.id}
    )
    write_audit(db, request,
        action="login", user={"user_id": db_user.id, "sub": db_user.email},
        content_type="Users | Користувач", object_id=db_user.id,
        object_repr=db_user.email, details={"method": "google"},
    )
    db.commit()
    return {"access_token": access_token, "role": db_user.role}

# =========================================================
# 👑 СУПЕРАДМІН — КЕРУВАННЯ КОРИСТУВАЧАМИ
# =========================================================
@app.get("/api/superadmin/users")
async def get_all_users(admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)):
    users = db.query(DBUser).all()
    return [{
        "id": u.id, "email": u.email, "full_name": u.full_name,
        "role": u.role, "student_data": u.student_data
    } for u in users]

def _normalize_student_data_groups(db_session, student_data):
    """Нормалізує 'Група' в student_data['навчання'][] за канонічним довідником AcademicGroup —
    щоб та сама група завжди писалась однаково, незалежно від того, звідки її внесли
    (ручна форма SuperAdmin, масовий імпорт, тощо). Групи, яких ще немає в Структурі,
    залишаються як є — це не блокує створення користувача."""
    if not isinstance(student_data, dict):
        return student_data
    studies = student_data.get("навчання")
    if not isinstance(studies, list):
        return student_data
    for s in studies:
        if not isinstance(s, dict):
            continue
        raw_group = s.get("Група")
        if not raw_group:
            continue
        gid = resolve_group_id(db_session, str(raw_group))
        if gid:
            grp = db_session.query(DBAcademicGroup).filter(DBAcademicGroup.id == gid).first()
            if grp:
                s["Група"] = grp.name
                s["_group_id"] = grp.id
    return student_data

@app.post("/api/superadmin/users")
async def create_or_update_user(
    user: UserCreateSchema, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    db_user = db.query(DBUser).filter(DBUser.email == user.email).first()
    normalized_data = _normalize_student_data_groups(db, user.student_data)
    if db_user:
        if user.password:
            db_user.hashed_password = pwd_context.hash(user.password)
        db_user.role = user.role
        db_user.full_name = user.full_name
        db_user.student_data = normalized_data
        msg = f"Профіль {user.email} успішно оновлено!"
    else:
        if not user.password:
            raise HTTPException(status_code=400, detail="Для нового користувача пароль обов'язковий!")
        new_user = DBUser(
            id=str(uuid.uuid4())[:8], email=user.email,
            hashed_password=pwd_context.hash(user.password),
            role=user.role, full_name=user.full_name, student_data=normalized_data
        )
        db.add(new_user)
        msg = f"Нового користувача {user.email} створено!"
    write_audit(db, request,
        action="update" if db_user else "create", user=admin,
        content_type="Users | Користувач", object_id=user.email,
        object_repr=user.full_name or user.email, details={"role": user.role},
    )
    db.commit()
    return {"message": msg}

@app.post("/api/superadmin/users/bulk")
async def bulk_import_users(
    payload: dict, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    users_data = payload.get("users", [])
    added, updated = 0, 0
    skipped = []
    for u in users_data:
        existing = db.query(DBUser).filter(DBUser.email == u.get("email")).first()
        normalized_data = _normalize_student_data_groups(db, u.get("student_data"))
        if existing:
            existing.role = u.get("role", existing.role)
            existing.full_name = u.get("full_name", existing.full_name)
            existing.student_data = normalized_data if normalized_data is not None else existing.student_data
            if u.get("password"):
                existing.hashed_password = pwd_context.hash(u["password"])
            updated += 1
        else:
            # Новий користувач без пароля не створюється (раніше отримував «changeme»)
            if not u.get("password"):
                skipped.append(u.get("email") or "—")
                continue
            new_user = DBUser(
                id=str(uuid.uuid4())[:8], email=u.get("email"),
                hashed_password=pwd_context.hash(u["password"]),
                role=u.get("role", "student"), full_name=u.get("full_name"),
                student_data=normalized_data
            )
            db.add(new_user)
            added += 1
    write_audit(db, request,
        action="bulk_import", user=admin, content_type="Users | Користувач",
        details={"added": added, "updated": updated, "skipped_no_password": skipped},
    )
    db.commit()
    msg = f"Імпорт завершено: додано {added}, оновлено {updated}."
    if skipped:
        msg += f" Пропущено {len(skipped)} нових без пароля: {', '.join(skipped[:10])}" + ("…" if len(skipped) > 10 else "")
    return {"message": msg, "added": added, "updated": updated, "skipped": skipped}

# =========================================================
# 📊 ЦСК — ЗАВАНТАЖЕННЯ ТА РЕДАГУВАННЯ ОЦІНОК
# =========================================================
@app.post("/api/csk/upload-grades")
async def upload_grades(
    request: Request, file: UploadFile = File(...),
    admin: dict = Depends(require_csk_admin), db: Session = Depends(get_db)
):
    content = await file.read()
    try:
        xls = pd.read_excel(io.BytesIO(content), sheet_name=None, header=None)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Помилка читання Excel: {str(e)}")
    added_count = 0
    resolved_groups = 0
    for sheet_name, df in xls.items():
        group_name = str(sheet_name).strip()
        if df.empty:
            continue
        resolved_group_id = resolve_group_id(db, group_name)
        if resolved_group_id:
            resolved_groups += 1
        subjects = df.iloc[0, 1:].fillna("").astype(str).tolist()
        semester_row, teacher_row, control_row = None, [], []
        for index, row in df.iterrows():
            val0 = str(row[0]).strip().lower()
            if "семестр" in val0 or any("семестр" in str(cell).lower() for cell in row):
                semester_row = row.fillna("").astype(str).tolist()
            elif val0 == "викладач":
                teacher_row = row.fillna("").astype(str).tolist()
            elif val0 == "вид контролю":
                control_row = row.fillna("").astype(str).tolist()
        semesters = []
        current_sem = 1
        if semester_row is not None:
            for cell in semester_row[1:]:
                val = str(cell).strip().lower()
                if "семестр" in val:
                    match = re.search(r"\d+", val)
                    if match:
                        current_sem = int(match.group())
                semesters.append(current_sem)
        else:
            semesters = [1] * len(subjects)
        # Кешуємо резолв предмет/викладач по (текст → id) в межах листа, щоб не бити базу на кожному студенті
        subject_id_cache, teacher_id_cache = {}, {}
        for index, row in df.iterrows():
            student_name = str(row[0]).strip()
            if not student_name or student_name.lower() == "nan":
                continue
            student_in_db = db.query(DBUser).filter(DBUser.full_name == student_name).first()
            if student_in_db:
                student_id = student_in_db.id
                db.query(DBGrade).filter(
                    DBGrade.student_id == student_id,
                    DBGrade.group_name == group_name
                ).delete()
                for i in range(1, len(row)):
                    score = str(row[i]).strip()
                    if score and score.lower() != "nan":
                        if i - 1 < len(subjects) and subjects[i - 1].strip():
                            subject_text = subjects[i - 1].strip()
                            teacher_text = teacher_row[i].strip() if i < len(teacher_row) else ""
                            control_text = control_row[i].strip() if i < len(control_row) else ""

                            if subject_text not in subject_id_cache:
                                subject_id_cache[subject_text] = resolve_or_create_subject(
                                    db, subject_text, resolved_group_id,
                                    semester=semesters[i - 1] if i - 1 < len(semesters) else None,
                                    control_form=control_text,
                                )
                            if teacher_text and teacher_text not in teacher_id_cache:
                                teacher_id_cache[teacher_text] = resolve_teacher_id(db, teacher_text)

                            new_grade = DBGrade(
                                student_id=student_id, group_name=group_name,
                                subject=subject_text,
                                semester=semesters[i - 1] if i - 1 < len(semesters) else 1,
                                score=score,
                                control_form=control_text,
                                teacher=teacher_text,
                                group_id=resolved_group_id,
                                subject_id=subject_id_cache.get(subject_text),
                                teacher_id=teacher_id_cache.get(teacher_text) if teacher_text else None,
                            )
                            db.add(new_grade)
                            added_count += 1
    write_audit(db, request,
        action="create", user=admin, content_type="Grades | Оцінки",
        object_repr=file.filename, details={"added_count": added_count, "resolved_groups": resolved_groups},
    )
    db.commit()
    drafts = db.query(DBSubject).filter(DBSubject.is_verified == False).count()
    return {
        "message": f"Успіх! Оброблено та додано/оновлено {added_count} оцінок."
                   + (f" Непідтверджених предметів (чернеток): {drafts}." if drafts else ""),
        "resolved_groups": resolved_groups, "unverified_subjects": drafts,
    }

def _student_data_dict(raw):
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:
            raw = {}
    return raw if isinstance(raw, dict) else {}

def _student_study_values(sd: dict, key: str) -> list:
    return [str(x.get(key)).strip() for x in (sd.get("навчання") or []) if isinstance(x, dict) and x.get(key) not in (None, "")]

@app.get("/api/csk/students")
async def get_students_for_csk(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    q: str = Query(default=None),
    group: str = Query(default=None),
    course: str = Query(default=None),
    status: str = Query(default="all"),
    admin: dict = Depends(require_csk_admin), db: Session = Depends(get_db)
):
    """Список студентів зі серверною пагінацією, пошуком і фільтрами.
    Оцінки в список НЕ входять (вони завантажуються окремо: GET /api/csk/students/{id}) —
    тільки кількість оцінок і групи. Два легкі запити замість N+1."""
    users = db.query(DBUser.id, DBUser.full_name, DBUser.email, DBUser.student_data)\
        .filter(DBUser.role == "student").order_by(DBUser.full_name).all()

    grade_groups = defaultdict(set)
    grade_counts = defaultdict(int)
    for sid, gname, cnt in db.query(DBGrade.student_id, DBGrade.group_name, func.count(DBGrade.id))\
            .group_by(DBGrade.student_id, DBGrade.group_name).all():
        if gname:
            grade_groups[sid].add(gname)
        grade_counts[sid] += cnt

    ql = (q or "").strip().lower()
    facet_groups, facet_courses = set(), set()
    rows = []
    for u in users:
        sd = _student_data_dict(u.student_data)
        groups = sorted(set(_student_study_values(sd, "Група")) | grade_groups.get(u.id, set()))
        courses = sorted(set(_student_study_values(sd, "Курс")))
        facet_groups.update(groups); facet_courses.update(courses)
        if group and group != "all" and group not in groups:
            continue
        if course and course != "all" and course not in courses:
            continue
        cnt = grade_counts.get(u.id, 0)
        if status == "has_grades" and cnt == 0:
            continue
        if status == "no_grades" and cnt > 0:
            continue
        if ql and not ((u.full_name or "").lower().find(ql) >= 0 or (u.email or "").lower().find(ql) >= 0
                       or any(ql in g.lower() for g in groups)):
            continue
        rows.append({"id": u.id, "full_name": u.full_name or "Без імені", "email": u.email,
                     "groups": groups, "courses": courses, "grades_count": cnt})

    return {
        "total": len(rows), "limit": limit, "offset": offset,
        "items": rows[offset: offset + limit],
        "facets": {"groups": sorted(facet_groups), "courses": sorted(facet_courses)},
    }

@app.get("/api/csk/students/{student_id}")
async def get_student_for_csk(
    student_id: str, admin: dict = Depends(require_csk_admin), db: Session = Depends(get_db)
):
    s = db.query(DBUser).filter(DBUser.id == student_id, DBUser.role == "student").first()
    if not s:
        raise HTTPException(status_code=404, detail="Студента не знайдено")
    grades = db.query(DBGrade).filter(DBGrade.student_id == s.id).all()
    return {
        "id": s.id, "full_name": s.full_name or "Без імені", "email": s.email,
        "student_data": s.student_data,
        "grades": [{
            "id": g.id, "subject": g.subject, "score": g.score,
            "semester": g.semester, "control_form": g.control_form,
            "teacher": g.teacher, "group_name": g.group_name,
            "group_id": g.group_id, "subject_id": g.subject_id, "teacher_id": g.teacher_id,
        } for g in grades],
    }

@app.put("/api/csk/grades/{grade_id}")
async def update_single_grade(
    grade_id: int, grade_data: GradeUpdateSchema, request: Request,
    admin: dict = Depends(require_csk_admin), db: Session = Depends(get_db)
):
    grade = db.query(DBGrade).filter(DBGrade.id == grade_id).first()
    if not grade:
        raise HTTPException(status_code=404, detail="Оцінку не знайдено")
    grade.score = grade_data.score
    grade.subject = grade_data.subject
    grade.semester = grade_data.semester
    grade.control_form = grade_data.control_form
    grade.teacher = grade_data.teacher
    # Пробуємо повторно зіставити з довідниками Структури (текст могли виправити вручну)
    grade.subject_id = resolve_subject_id(db, grade_data.subject, grade.group_id)
    grade.teacher_id = resolve_teacher_id(db, grade_data.teacher)
    write_audit(db, request,
        action="update", user=admin, content_type="Grades | Оцінки",
        object_id=grade_id, object_repr=grade_data.subject,
        details={"score": grade_data.score, "control_form": grade_data.control_form},
    )
    db.commit()
    return {"message": "Оцінку успішно оновлено!"}

# =========================================================
# 🎓 СТУДЕНТ — ПРОФІЛЬ ТА ОПИТУВАННЯ
# =========================================================
@app.get("/api/student/me")
async def get_student_profile(
    user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    db_user = db.query(DBUser).filter(DBUser.id == user["user_id"]).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="Користувача не знайдено")
    s_data = db_user.student_data or {}
    if isinstance(s_data, str):
        try:
            s_data = json.loads(s_data)
        except Exception:
            s_data = {}
    grades = db.query(DBGrade).filter(DBGrade.student_id == db_user.id).all()
    grades_list = [{
        "subject": g.subject, "score": g.score, "semester": g.semester,
        "teacher": g.teacher, "group_name": g.group_name, "control_form": g.control_form
    } for g in grades]
    return {
        "full_name": db_user.full_name, "email": db_user.email,
        "student_data": s_data, "grades": grades_list
    }

@app.get("/api/student/surveys")
async def get_student_surveys(
    user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    db_user = db.query(DBUser).filter(DBUser.id == user["user_id"]).first()
    s_data = (db_user.student_data or {}) if db_user else {}
    if isinstance(s_data, str):
        try:
            s_data = json.loads(s_data)
        except Exception:
            s_data = {}
    student_studies = s_data.get("навчання", []) if isinstance(s_data, dict) else []
    user_role = user.get("role", "student")

    # Словник аудієнц-хештегів → ролі
    AUDIENCE_ROLES = {
        "Студентам":     ["student"],
        "Викладачам":    ["teacher"],
        "Стейкголдерам": ["stakeholder"],
        "Всім":          ["student", "teacher", "stakeholder"],
    }

    all_templates = db.query(DBTemplate).all()
    completed_records = db.query(DBCompletedSurvey).filter(
        DBCompletedSurvey.user_id == user["user_id"]
    ).all()
    completed_ids = {record.survey_id for record in completed_records}
    now_str = datetime.now().strftime("%d.%m.%Y %H:%M")

    result = []
    for t in all_templates:
        hashtags = t.hashtags or []

        # 1. Перевіряємо дедлайн
        if t.deadline:
            try:
                dl = datetime.strptime(t.deadline, "%d.%m.%Y %H:%M")
                if datetime.now() > dl:
                    continue
            except Exception:
                pass

        # 2. Перевіряємо аудієнцію через хештеги
        audience_tags = [h for h in hashtags if h in AUDIENCE_ROLES]
        if audience_tags:
            allowed_roles = set()
            for tag in audience_tags:
                allowed_roles.update(AUDIENCE_ROLES.get(tag, []))
            if user_role not in allowed_roles:
                continue
        else:
            # Fallback: старий механізм target_audience (для сумісності)
            t_audience = t.target_audience or {}
            if isinstance(t_audience, str):
                try:
                    t_audience = json.loads(t_audience)
                except Exception:
                    t_audience = {}
            if t_audience:
                is_allowed = any(
                    all(study.get(k) == v for k, v in t_audience.items())
                    for study in student_studies
                )
                if not is_allowed:
                    continue

        # 3. Хештег #По_ОПП — дублюємо опитування для кожної ОПП студента
        if "По_ОПП" in hashtags and user_role == "student":
            # Збираємо ОПП студента через структуру груп
            student_opps = []
            for study in student_studies:
                group_name = study.get("Група", "")
                grp = db.query(DBAcademicGroup).filter(DBAcademicGroup.name == group_name).first()
                if grp:
                    plan = db.query(DBStudyPlan).filter(DBStudyPlan.id == grp.study_plan_id).first()
                    if plan:
                        opp = db.query(DBOpp).filter(DBOpp.id == plan.opp_id).first()
                        if opp and not any(o["id"] == opp.id for o in student_opps):
                            student_opps.append({"id": opp.id, "name": opp.name})
                else:
                    # Fallback якщо група ще не прив'язана до структури
                    opp_name = study.get("ОПП", study.get("Спеціальність", ""))
                    if opp_name and not any(o["name"] == opp_name for o in student_opps):
                        student_opps.append({"id": None, "name": opp_name})

            if len(student_opps) <= 1:
                # Одна ОПП — звичайна картка без приписки
                opp_label = student_opps[0]["name"] if student_opps else None
                result.append({
                    "id": t.id,
                    "title": f"{t.title} [{opp_label}]" if opp_label else t.title,
                    "is_completed": t.id in completed_ids,
                    "feathers_reward": t.feathers_reward or 0,
                    "hashtags": hashtags,
                    "deadline": t.deadline,
                    "opp_context": opp_label,
                })
            else:
                # Кілька ОПП — дублюємо з приміткою для кожної
                for opp in student_opps:
                    virtual_id = f"{t.id}__opp__{opp['id'] or opp['name']}"
                    is_done = virtual_id in completed_ids or t.id in completed_ids
                    result.append({
                        "id": virtual_id,
                        "base_id": t.id,
                        "title": f"{t.title} [{opp['name']}]",
                        "is_completed": is_done,
                        "feathers_reward": t.feathers_reward or 0,
                        "hashtags": hashtags,
                        "deadline": t.deadline,
                        "opp_context": opp["name"],
                    })
            continue

        result.append({
            "id": t.id, "title": t.title, "is_completed": t.id in completed_ids,
            "feathers_reward": t.feathers_reward or 0,
            "hashtags": hashtags,
            "deadline": t.deadline,
            "opp_context": None,
        })
    return result

# =========================================================
# 📝 ЦМЯО — УПРАВЛІННЯ ОПИТУВАННЯМИ
# =========================================================
@app.get("/api/templates")
async def get_templates(
    user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)
):
    templates = db.query(DBTemplate).all()
    return [{
        "id": t.id, "title": t.title, "description": t.description or "",
        "questions": t.questions,
        "target_audience": t.target_audience,
        "is_anonymous": t.is_anonymous if t.is_anonymous is not None else True,
        "feathers_reward": t.feathers_reward or 0,
        "hashtags": t.hashtags or [],
        "deadline": t.deadline,
    } for t in templates]

@app.post("/api/templates")
async def save_template(
    survey: SurveyTemplateSchema,
    user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)
):
    if not survey.id:
        survey.id = str(uuid.uuid4())[:8]
    db_template = db.query(DBTemplate).filter(DBTemplate.id == survey.id).first()
    questions_data = [q.model_dump() for q in survey.questions]

    # Деривуємо is_anonymous з хештегів якщо є
    hashtags = survey.hashtags or []
    is_anon = survey.is_anonymous
    if "Анонімне" in hashtags:
        is_anon = True
    elif "Не_анонімне" in hashtags:
        is_anon = False

    if db_template:
        db_template.title = survey.title
        db_template.description = survey.description or ""
        db_template.questions = questions_data
        db_template.target_audience = survey.target_audience
        db_template.is_anonymous = is_anon
        db_template.feathers_reward = survey.feathers_reward
        db_template.hashtags = hashtags
        db_template.deadline = survey.deadline
    else:
        db.add(DBTemplate(
            id=survey.id, title=survey.title, description=survey.description or "",
            questions=questions_data,
            target_audience=survey.target_audience, is_anonymous=is_anon,
            feathers_reward=survey.feathers_reward,
            hashtags=hashtags,
            deadline=survey.deadline,
        ))
    db.commit()
    return {"message": "Шаблон збережено!", "id": survey.id}

@app.delete("/api/templates/{template_id}")
async def delete_template(
    template_id: str,
    user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)
):
    template = db.query(DBTemplate).filter(DBTemplate.id == template_id).first()
    if template:
        db.delete(template)
        db.commit()
    return {"message": "Видалено"}

# 🔐 Перевірка доступу до опитування на сервері (аудиторія + дедлайн)
SURVEY_AUDIENCE_ROLES = {
    "Студентам":     ["student"],
    "Викладачам":    ["teacher"],
    "Стейкголдерам": ["stakeholder"],
    "Всім":          ["student", "teacher", "stakeholder"],
}
SURVEY_ADMIN_ROLES = ("superadmin", "admin_cmyo", "admin_csk")

def _survey_access_error(db_session, template, user: dict):
    """Повертає текст помилки, якщо користувач НЕ має права відкривати/заповнювати опитування,
    або None, якщо доступ дозволено. Адміністратори (перегляд/тест) не обмежуються."""
    role = user.get("role")
    if role in SURVEY_ADMIN_ROLES:
        return None

    # 1. Дедлайн
    if template.deadline:
        try:
            if datetime.now() > datetime.strptime(template.deadline, "%d.%m.%Y %H:%M"):
                return "Термін проходження цього опитування минув"
        except Exception:
            pass

    # 2. Аудиторія за хештегами
    hashtags = template.hashtags or []
    audience_tags = [h for h in hashtags if h in SURVEY_AUDIENCE_ROLES]
    if audience_tags:
        allowed = set()
        for tag in audience_tags:
            allowed.update(SURVEY_AUDIENCE_ROLES[tag])
        if role not in allowed:
            return "Це опитування недоступне для вашої ролі"
        return None

    # 3. Старий механізм target_audience (збіг із полями «навчання»)
    t_audience = template.target_audience or {}
    if isinstance(t_audience, str):
        try:
            t_audience = json.loads(t_audience)
        except Exception:
            t_audience = {}
    if t_audience:
        db_user = db_session.query(DBUser).filter(DBUser.id == user.get("user_id")).first()
        s_data = (db_user.student_data or {}) if db_user else {}
        if isinstance(s_data, str):
            try:
                s_data = json.loads(s_data)
            except Exception:
                s_data = {}
        studies = s_data.get("навчання", []) if isinstance(s_data, dict) else []
        if not any(all(st.get(k) == v for k, v in t_audience.items()) for st in studies):
            return "Це опитування недоступне для вашої групи"
    return None

@app.get("/api/templates/{template_id}")
async def get_single_template(
    template_id: str,
    user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    template = db.query(DBTemplate).filter(DBTemplate.id == template_id).first()
    if not template:
        raise HTTPException(status_code=404, detail="Опитування не знайдено")
    access_error = _survey_access_error(db, template, user)
    if access_error:
        raise HTTPException(status_code=403, detail=access_error)
    return {
        "id": template.id, "title": template.title, "questions": template.questions,
        "is_anonymous": template.is_anonymous if template.is_anonymous is not None else True,
        "feathers_reward": template.feathers_reward or 0,
        "hashtags": template.hashtags or [],
        "deadline": template.deadline,
    }

# =========================================================
# 🏷️ КАТАЛОГ ХЕШТЕГІВ
# =========================================================
def _hashtag_to_dict(h: DBHashtagCatalog) -> dict:
    return {
        "id": h.id, "slug": h.slug, "label": h.label, "type": h.type,
        "description": h.description, "color": h.color, "icon": h.icon,
        "is_system": h.is_system, "created_at": h.created_at,
    }

@app.get("/api/hashtags")
async def get_hashtags(
    user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    """Повертає весь каталог хештегів (доступно всім авторизованим)"""
    tags = db.query(DBHashtagCatalog).order_by(DBHashtagCatalog.type, DBHashtagCatalog.slug).all()
    return [_hashtag_to_dict(t) for t in tags]

@app.post("/api/superadmin/hashtags")
async def create_hashtag(
    data: HashtagCreateSchema, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    # Нормалізуємо slug
    slug = data.slug.strip().replace(" ", "_")
    exists = db.query(DBHashtagCatalog).filter(DBHashtagCatalog.slug == slug).first()
    if exists:
        raise HTTPException(status_code=409, detail=f"Хештег #{slug} вже існує")
    tag = DBHashtagCatalog(
        slug=slug, label=data.label, type=data.type,
        description=data.description, color=data.color, icon=data.icon, is_system=False,
    )
    db.add(tag)
    write_audit(db, request, action="create", user=admin,
        content_type="Hashtag | Хештег", object_repr=f"#{slug}")
    db.commit()
    db.refresh(tag)
    return _hashtag_to_dict(tag)

@app.put("/api/superadmin/hashtags/{tag_id}")
async def update_hashtag(
    tag_id: int, data: HashtagUpdateSchema, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    tag = db.query(DBHashtagCatalog).filter(DBHashtagCatalog.id == tag_id).first()
    if not tag:
        raise HTTPException(status_code=404, detail="Хештег не знайдено")
    if data.label is not None:  tag.label       = data.label
    if data.type is not None:   tag.type        = data.type
    if data.description is not None: tag.description = data.description
    if data.color is not None:  tag.color       = data.color
    if data.icon is not None:   tag.icon        = data.icon
    write_audit(db, request, action="update", user=admin,
        content_type="Hashtag | Хештег", object_id=tag_id, object_repr=f"#{tag.slug}")
    db.commit()
    return _hashtag_to_dict(tag)

@app.delete("/api/superadmin/hashtags/{tag_id}")
async def delete_hashtag(
    tag_id: int, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    tag = db.query(DBHashtagCatalog).filter(DBHashtagCatalog.id == tag_id).first()
    if not tag:
        raise HTTPException(status_code=404, detail="Хештег не знайдено")
    if tag.is_system:
        raise HTTPException(status_code=403, detail="Системний хештег не можна видалити")
    write_audit(db, request, action="delete", user=admin,
        content_type="Hashtag | Хештег", object_id=tag_id, object_repr=f"#{tag.slug}")
    db.delete(tag)
    db.commit()
    return {"message": "Видалено"}

# =========================================================
# 🏛️ АКАДЕМІЧНА СТРУКТУРА — CRUD ЕНДПОІНТИ
# Інститут → Кафедра → ОПП → Навчальний план → Група → Предмети
# =========================================================

# ── ІНСТИТУТИ / ФАКУЛЬТЕТИ ──────────────────────────────
@app.get("/api/structure/institutes")
async def get_institutes(user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    items = db.query(DBInstitute).order_by(DBInstitute.name).all()
    return [{"id": i.id, "name": i.name, "full_name": i.full_name} for i in items]

@app.post("/api/superadmin/structure/institutes")
async def create_institute(
    data: InstituteSchema, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    new_id = data.id or str(uuid.uuid4())[:8]
    if db.query(DBInstitute).filter(DBInstitute.id == new_id).first():
        raise HTTPException(status_code=409, detail="Інститут з таким ID вже існує")
    obj = DBInstitute(id=new_id, name=data.name, full_name=data.full_name)
    db.add(obj)
    write_audit(db, request, action="create", user=admin, content_type="Structure | Інститут", object_repr=data.name)
    db.commit()
    return {"id": new_id, "name": obj.name, "full_name": obj.full_name}

@app.put("/api/superadmin/structure/institutes/{item_id}")
async def update_institute(
    item_id: str, data: InstituteSchema, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    obj = db.query(DBInstitute).filter(DBInstitute.id == item_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Не знайдено")
    obj.name = data.name
    obj.full_name = data.full_name
    write_audit(db, request, action="update", user=admin, content_type="Structure | Інститут", object_id=item_id, object_repr=data.name)
    db.commit()
    return {"id": obj.id, "name": obj.name, "full_name": obj.full_name}

@app.delete("/api/superadmin/structure/institutes/{item_id}")
async def delete_institute(
    item_id: str, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    obj = db.query(DBInstitute).filter(DBInstitute.id == item_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Не знайдено")
    write_audit(db, request, action="delete", user=admin, content_type="Structure | Інститут", object_id=item_id, object_repr=obj.name)
    db.delete(obj)
    db.commit()
    return {"message": "Видалено"}

# ── КАФЕДРИ ──────────────────────────────────────────────
@app.get("/api/structure/departments")
async def get_departments(
    institute_id: str = Query(default=None),
    user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    q = db.query(DBDepartment)
    if institute_id:
        q = q.filter(DBDepartment.institute_id == institute_id)
    items = q.order_by(DBDepartment.name).all()
    return [{"id": d.id, "institute_id": d.institute_id, "name": d.name, "full_name": d.full_name} for d in items]

@app.post("/api/superadmin/structure/departments")
async def create_department(
    data: DepartmentSchema, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    if not db.query(DBInstitute).filter(DBInstitute.id == data.institute_id).first():
        raise HTTPException(status_code=404, detail="Інститут не знайдено")
    new_id = data.id or str(uuid.uuid4())[:8]
    if db.query(DBDepartment).filter(DBDepartment.id == new_id).first():
        raise HTTPException(status_code=409, detail="Кафедра з таким ID вже існує")
    obj = DBDepartment(id=new_id, institute_id=data.institute_id, name=data.name, full_name=data.full_name)
    db.add(obj)
    write_audit(db, request, action="create", user=admin, content_type="Structure | Кафедра", object_repr=data.name)
    db.commit()
    return {"id": new_id, "institute_id": obj.institute_id, "name": obj.name, "full_name": obj.full_name}

@app.put("/api/superadmin/structure/departments/{item_id}")
async def update_department(
    item_id: str, data: DepartmentSchema, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    obj = db.query(DBDepartment).filter(DBDepartment.id == item_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Не знайдено")
    obj.institute_id = data.institute_id
    obj.name = data.name
    obj.full_name = data.full_name
    write_audit(db, request, action="update", user=admin, content_type="Structure | Кафедра", object_id=item_id, object_repr=data.name)
    db.commit()
    return {"id": obj.id, "institute_id": obj.institute_id, "name": obj.name, "full_name": obj.full_name}

@app.delete("/api/superadmin/structure/departments/{item_id}")
async def delete_department(
    item_id: str, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    obj = db.query(DBDepartment).filter(DBDepartment.id == item_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Не знайдено")
    write_audit(db, request, action="delete", user=admin, content_type="Structure | Кафедра", object_id=item_id, object_repr=obj.name)
    db.delete(obj)
    db.commit()
    return {"message": "Видалено"}

# ── ОПП ──────────────────────────────────────────────────
@app.get("/api/structure/opps")
async def get_opps(
    department_id: str = Query(default=None),
    user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    q = db.query(DBOpp)
    if department_id:
        q = q.filter(DBOpp.department_id == department_id)
    items = q.order_by(DBOpp.name).all()
    return [{"id": o.id, "department_id": o.department_id, "name": o.name, "level": o.level, "full_name": o.full_name} for o in items]

@app.post("/api/superadmin/structure/opps")
async def create_opp(
    data: OppSchema, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    if not db.query(DBDepartment).filter(DBDepartment.id == data.department_id).first():
        raise HTTPException(status_code=404, detail="Кафедру не знайдено")
    new_id = data.id or str(uuid.uuid4())[:8]
    if db.query(DBOpp).filter(DBOpp.id == new_id).first():
        raise HTTPException(status_code=409, detail="ОПП з таким ID вже існує")
    obj = DBOpp(id=new_id, department_id=data.department_id, name=data.name, level=data.level, full_name=data.full_name)
    db.add(obj)
    write_audit(db, request, action="create", user=admin, content_type="Structure | ОПП", object_repr=data.name)
    db.commit()
    return {"id": new_id, "department_id": obj.department_id, "name": obj.name, "level": obj.level, "full_name": obj.full_name}

@app.put("/api/superadmin/structure/opps/{item_id}")
async def update_opp(
    item_id: str, data: OppSchema, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    obj = db.query(DBOpp).filter(DBOpp.id == item_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Не знайдено")
    obj.department_id = data.department_id
    obj.name = data.name
    obj.level = data.level
    obj.full_name = data.full_name
    write_audit(db, request, action="update", user=admin, content_type="Structure | ОПП", object_id=item_id, object_repr=data.name)
    db.commit()
    return {"id": obj.id, "department_id": obj.department_id, "name": obj.name, "level": obj.level, "full_name": obj.full_name}

@app.delete("/api/superadmin/structure/opps/{item_id}")
async def delete_opp(
    item_id: str, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    obj = db.query(DBOpp).filter(DBOpp.id == item_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Не знайдено")
    write_audit(db, request, action="delete", user=admin, content_type="Structure | ОПП", object_id=item_id, object_repr=obj.name)
    db.delete(obj)
    db.commit()
    return {"message": "Видалено"}

# ── НАВЧАЛЬНІ ПЛАНИ ─────────────────────────────────────
@app.get("/api/structure/study-plans")
async def get_study_plans(
    opp_id: str = Query(default=None),
    user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    q = db.query(DBStudyPlan)
    if opp_id:
        q = q.filter(DBStudyPlan.opp_id == opp_id)
    items = q.order_by(DBStudyPlan.name).all()
    return [{"id": p.id, "opp_id": p.opp_id, "name": p.name} for p in items]

@app.post("/api/superadmin/structure/study-plans")
async def create_study_plan(
    data: StudyPlanSchema, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    if not db.query(DBOpp).filter(DBOpp.id == data.opp_id).first():
        raise HTTPException(status_code=404, detail="ОПП не знайдено")
    new_id = data.id or str(uuid.uuid4())[:8]
    if db.query(DBStudyPlan).filter(DBStudyPlan.id == new_id).first():
        raise HTTPException(status_code=409, detail="План з таким ID вже існує")
    obj = DBStudyPlan(id=new_id, opp_id=data.opp_id, name=data.name)
    db.add(obj)
    write_audit(db, request, action="create", user=admin, content_type="Structure | План", object_repr=data.name)
    db.commit()
    return {"id": new_id, "opp_id": obj.opp_id, "name": obj.name}

@app.put("/api/superadmin/structure/study-plans/{item_id}")
async def update_study_plan(
    item_id: str, data: StudyPlanSchema, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    obj = db.query(DBStudyPlan).filter(DBStudyPlan.id == item_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Не знайдено")
    obj.opp_id = data.opp_id
    obj.name = data.name
    write_audit(db, request, action="update", user=admin, content_type="Structure | План", object_id=item_id, object_repr=data.name)
    db.commit()
    return {"id": obj.id, "opp_id": obj.opp_id, "name": obj.name}

@app.delete("/api/superadmin/structure/study-plans/{item_id}")
async def delete_study_plan(
    item_id: str, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    obj = db.query(DBStudyPlan).filter(DBStudyPlan.id == item_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Не знайдено")
    write_audit(db, request, action="delete", user=admin, content_type="Structure | План", object_id=item_id, object_repr=obj.name)
    db.delete(obj)
    db.commit()
    return {"message": "Видалено"}

# ── ГРУПИ ────────────────────────────────────────────────
@app.get("/api/structure/groups")
async def get_academic_groups(
    study_plan_id: str = Query(default=None),
    user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    q = db.query(DBAcademicGroup)
    if study_plan_id:
        q = q.filter(DBAcademicGroup.study_plan_id == study_plan_id)
    items = q.order_by(DBAcademicGroup.name).all()
    return [{"id": g.id, "study_plan_id": g.study_plan_id, "name": g.name, "level": g.level} for g in items]

@app.post("/api/superadmin/structure/groups")
async def create_academic_group(
    data: AcademicGroupSchema, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    if not db.query(DBStudyPlan).filter(DBStudyPlan.id == data.study_plan_id).first():
        raise HTTPException(status_code=404, detail="Навчальний план не знайдено")
    if db.query(DBAcademicGroup).filter(DBAcademicGroup.name == data.name).first():
        raise HTTPException(status_code=409, detail=f"Група {data.name} вже існує")
    new_id = data.id or str(uuid.uuid4())[:8]
    level = data.level or detect_level_from_group_name(data.name)
    obj = DBAcademicGroup(id=new_id, study_plan_id=data.study_plan_id, name=data.name, level=level)
    db.add(obj)
    write_audit(db, request, action="create", user=admin, content_type="Structure | Група", object_repr=data.name)
    db.commit()
    return {"id": new_id, "study_plan_id": obj.study_plan_id, "name": obj.name, "level": obj.level}

@app.put("/api/superadmin/structure/groups/{item_id}")
async def update_academic_group(
    item_id: str, data: AcademicGroupSchema, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    obj = db.query(DBAcademicGroup).filter(DBAcademicGroup.id == item_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Не знайдено")
    obj.study_plan_id = data.study_plan_id
    obj.name = data.name
    obj.level = data.level or detect_level_from_group_name(data.name)
    write_audit(db, request, action="update", user=admin, content_type="Structure | Група", object_id=item_id, object_repr=data.name)
    db.commit()
    return {"id": obj.id, "study_plan_id": obj.study_plan_id, "name": obj.name, "level": obj.level}

@app.delete("/api/superadmin/structure/groups/{item_id}")
async def delete_academic_group(
    item_id: str, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    obj = db.query(DBAcademicGroup).filter(DBAcademicGroup.id == item_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Не знайдено")
    write_audit(db, request, action="delete", user=admin, content_type="Structure | Група", object_id=item_id, object_repr=obj.name)
    db.delete(obj)
    db.commit()
    return {"message": "Видалено"}

# ── ІМПОРТ ГРУП/ОПП З EXCEL (формат Groups_Query) ───────
GROUP_IMPORT_LEVEL_MAP = {
    "бакалавр": "bachelor",
    "магістр": "master", "магістратура": "master",
    "доктор філософії": "phd", "аспірантура": "phd", "phd": "phd",
}
UNASSIGNED_DEPT_SUFFIX = "__unassigned"
UNASSIGNED_DEPT_NAME = "🗂 Без кафедри"

@app.post("/api/superadmin/structure/import-groups")
async def import_groups(
    request: Request, file: UploadFile = File(...),
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    """Імпортує Інститути/ОПП/Навчальні плани/Групи з файлу типу Groups_Query.xlsx.
    Очікувані колонки: NameShort, Name, Speciality, isFullTime, Groups_Name,
    EducationalLevel_Name, study_program.
    Кафедра у файлі відсутня — нові ОПП тимчасово потрапляють у службову
    кафедру "Без кафедри" цього інституту, звідки ви самі перенесете їх у потрібну
    (просто відредагуйте ОПП і оберіть кафедру — так само, як завжди)."""
    content = await file.read()
    try:
        df = pd.read_excel(io.BytesIO(content))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Помилка читання Excel: {str(e)}")

    required_cols = {"NameShort", "Name", "isFullTime", "Groups_Name", "EducationalLevel_Name", "study_program"}
    missing = required_cols - set(df.columns)
    if missing:
        raise HTTPException(status_code=400, detail=f"У файлі бракує колонок: {', '.join(sorted(missing))}")

    stats = {
        "institutes_created": 0, "opps_created": 0, "plans_created": 0,
        "groups_created": 0, "groups_updated": 0, "rows_skipped": 0, "errors": [],
    }

    for idx, row in df.iterrows():
        try:
            inst_short = str(row.get("NameShort") or "").strip()
            inst_full = str(row.get("Name") or "").strip()
            opp_name = str(row.get("study_program") or "").strip()
            group_name = str(row.get("Groups_Name") or "").strip()
            raw_ft = row.get("isFullTime")
            is_denna = str(raw_ft).strip() in ("1", "1.0", "True", "true")
            level_raw = str(row.get("EducationalLevel_Name") or "").strip().lower()

            if not inst_short or not opp_name or not group_name or inst_short.lower() == "nan":
                stats["rows_skipped"] += 1
                stats["errors"].append(f"Рядок {idx + 2}: пропущено — немає інституту/ОПП/групи")
                continue

            level = GROUP_IMPORT_LEVEL_MAP.get(level_raw) or detect_level_from_group_name(group_name)

            # 1) Інститут
            inst = db.query(DBInstitute).filter(DBInstitute.name == inst_short).first()
            if not inst:
                inst = DBInstitute(id=str(uuid.uuid4())[:8], name=inst_short, full_name=inst_full or None)
                db.add(inst)
                db.flush()
                stats["institutes_created"] += 1

            # 2) Службова кафедра "Без кафедри" для цього інституту (щоб не порушувати
            #    обов'язковий зв'язок ОПП→кафедра, доки ви самі не призначите справжню)
            placeholder_id = f"{inst.id}{UNASSIGNED_DEPT_SUFFIX}"
            placeholder_dept = db.query(DBDepartment).filter(DBDepartment.id == placeholder_id).first()
            if not placeholder_dept:
                placeholder_dept = DBDepartment(
                    id=placeholder_id, institute_id=inst.id, name=UNASSIGNED_DEPT_NAME,
                    full_name="Створено автоматично імпортом — розподіліть ОПП по кафедрах вручну",
                )
                db.add(placeholder_dept)
                db.flush()

            # 3) ОПП — шукаємо серед УСІХ кафедр цього інституту (щоб не плодити дублі
            #    після того, як ви вручну перенесли ОПП у справжню кафедру)
            opp = db.query(DBOpp).join(DBDepartment, DBOpp.department_id == DBDepartment.id).filter(
                DBDepartment.institute_id == inst.id, DBOpp.name == opp_name
            ).first()
            if not opp:
                opp = DBOpp(id=str(uuid.uuid4())[:8], department_id=placeholder_dept.id, name=opp_name, level=level)
                db.add(opp)
                db.flush()
                stats["opps_created"] += 1

            # 4) Навчальний план — окремо для денної/заочної форми цієї ОПП
            form_label = "Денна" if is_denna else "Заочна"
            plan_name = f"{opp_name} — {form_label}"
            plan = db.query(DBStudyPlan).filter(DBStudyPlan.opp_id == opp.id, DBStudyPlan.name == plan_name).first()
            if not plan:
                plan = DBStudyPlan(id=str(uuid.uuid4())[:8], opp_id=opp.id, name=plan_name)
                db.add(plan)
                db.flush()
                stats["plans_created"] += 1

            # 5) Група — назва унікальна в усій системі (щоб ЦСК/ЦМЯО завжди бачили ту саму групу)
            existing_group = db.query(DBAcademicGroup).filter(DBAcademicGroup.name == group_name).first()
            if existing_group:
                if existing_group.study_plan_id != plan.id or existing_group.level != level:
                    existing_group.study_plan_id = plan.id
                    existing_group.level = level
                    stats["groups_updated"] += 1
            else:
                db.add(DBAcademicGroup(id=str(uuid.uuid4())[:8], study_plan_id=plan.id, name=group_name, level=level))
                stats["groups_created"] += 1

        except Exception as e:
            stats["rows_skipped"] += 1
            stats["errors"].append(f"Рядок {idx + 2}: {str(e)}")

    write_audit(db, request, action="bulk_import", user=admin,
        content_type="Structure | Імпорт груп", object_repr=file.filename, details=stats)
    db.commit()
    return {"message": "Імпорт завершено", **stats}

# ── ПРЕДМЕТИ ─────────────────────────────────────────────
@app.get("/api/structure/subjects")
async def get_subjects(
    opp_id: str = Query(default=None),
    user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    """Предмети живуть на рівні ОПП: семестр і форма контролю тут спільні
    для всіх навчальних планів цієї програми. Години — окремо, дивись /api/structure/plan-subject-hours."""
    q = db.query(DBSubject)
    if opp_id:
        q = q.filter(DBSubject.opp_id == opp_id)
    items = q.order_by(DBSubject.semester, DBSubject.name).all()
    return [_subject_to_dict(s) for s in items]

@app.post("/api/superadmin/structure/subjects")
async def create_subject(
    data: SubjectSchema, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    if not db.query(DBOpp).filter(DBOpp.id == data.opp_id).first():
        raise HTTPException(status_code=404, detail="ОПП не знайдено")
    name = _clean(data.name)
    if not name:
        raise HTTPException(status_code=400, detail="Назва предмета порожня")
    _validate_semester(data.semester)
    control_form = _validate_control_form(data.control_form)
    if _find_duplicate_subject(db, data.opp_id, name, data.semester):
        raise HTTPException(status_code=409, detail="Такий предмет (назва + семестр) у цій ОПП вже існує")
    obj = DBSubject(
        opp_id=data.opp_id, name=name, name_norm=_norm(name), semester=data.semester,
        control_form=control_form, elective_slot=_normalize_slot(data.elective_slot),
        is_verified=True,
    )
    db.add(obj)
    _sync_subject_teachers(db, obj, data.teachers)
    write_audit(db, request, action="create", user=admin, content_type="Structure | Предмет", object_repr=name)
    db.commit()
    db.refresh(obj)
    return _subject_to_dict(obj)

@app.put("/api/superadmin/structure/subjects/{item_id}")
async def update_subject(
    item_id: int, data: SubjectSchema, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    obj = db.query(DBSubject).filter(DBSubject.id == item_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Не знайдено")
    name = _clean(data.name)
    if not name:
        raise HTTPException(status_code=400, detail="Назва предмета порожня")
    _validate_semester(data.semester)
    control_form = _validate_control_form(data.control_form)
    if data.opp_id != obj.opp_id:
        if not db.query(DBOpp).filter(DBOpp.id == data.opp_id).first():
            raise HTTPException(status_code=404, detail="ОПП не знайдено")
        if db.query(DBPlanSubjectHours).filter(DBPlanSubjectHours.subject_id == obj.id).first():
            raise HTTPException(status_code=400,
                detail="Спершу видаліть прив'язки годин: предмет прив'язаний до планів іншої ОПП")
    if _find_duplicate_subject(db, data.opp_id, name, data.semester, exclude_id=obj.id):
        raise HTTPException(status_code=409, detail="Такий предмет (назва + семестр) у цій ОПП вже існує")

    obj.opp_id = data.opp_id
    obj.name = name
    obj.name_norm = _norm(name)
    obj.semester = data.semester
    obj.control_form = control_form
    obj.elective_slot = _normalize_slot(data.elective_slot)
    obj.is_verified = True                      # ручне редагування = підтвердження
    _sync_subject_teachers(db, obj, data.teachers)
    write_audit(db, request, action="update", user=admin, content_type="Structure | Предмет", object_id=item_id, object_repr=name)
    db.commit()
    db.refresh(obj)
    return _subject_to_dict(obj)

@app.delete("/api/superadmin/structure/subjects/{item_id}")
async def delete_subject(
    item_id: int, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    obj = db.query(DBSubject).filter(DBSubject.id == item_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Не знайдено")
    write_audit(db, request, action="delete", user=admin, content_type="Structure | Предмет", object_id=item_id, object_repr=obj.name)
    db.delete(obj)
    db.commit()
    return {"message": "Видалено"}

# ── ЧЕРНЕТКИ ПРЕДМЕТІВ (створені імпортом оцінок) ───────
@app.get("/api/superadmin/structure/subjects/unverified")
async def get_unverified_subjects(admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)):
    subs = db.query(DBSubject).filter(DBSubject.is_verified == False).order_by(DBSubject.name).all()
    ids = [x.id for x in subs]
    counts = {}
    if ids:
        counts = dict(db.query(DBGrade.subject_id, func.count(DBGrade.id))
                        .filter(DBGrade.subject_id.in_(ids)).group_by(DBGrade.subject_id).all())
    opp_names = {}
    if subs:
        opp_names = {o.id: o.name for o in db.query(DBOpp).filter(DBOpp.id.in_({x.opp_id for x in subs})).all()}
    return [{**_subject_to_dict(x), "opp_name": opp_names.get(x.opp_id), "grades_count": counts.get(x.id, 0)} for x in subs]

@app.post("/api/superadmin/structure/subjects/{item_id}/verify")
async def verify_subject(
    item_id: int, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    obj = db.query(DBSubject).filter(DBSubject.id == item_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Не знайдено")
    obj.is_verified = True
    write_audit(db, request, action="update", user=admin, content_type="Structure | Предмет",
                object_id=item_id, object_repr=obj.name, details={"verified": True})
    db.commit()
    db.refresh(obj)
    return _subject_to_dict(obj)

class SubjectMergeSchema(BaseModel):
    target_id: int

@app.post("/api/superadmin/structure/subjects/{item_id}/merge")
async def merge_subject_endpoint(
    item_id: int, data: SubjectMergeSchema, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    src = db.query(DBSubject).filter(DBSubject.id == item_id).first()
    src_name = src.name if src else None
    tgt = merge_subjects(db, item_id, data.target_id)
    write_audit(db, request, action="update", user=admin, content_type="Structure | Злиття предметів",
                object_id=item_id, object_repr=f"{src_name} → {tgt.name}")
    db.commit()
    db.refresh(tgt)
    return _subject_to_dict(tgt)

# ── ГОДИНИ ПРЕДМЕТА В МЕЖАХ НАВЧАЛЬНОГО ПЛАНУ ───────────
@app.get("/api/structure/plan-subject-hours")
async def get_plan_subject_hours(
    study_plan_id: str = Query(default=None),
    user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    q = db.query(DBPlanSubjectHours)
    if study_plan_id:
        q = q.filter(DBPlanSubjectHours.study_plan_id == study_plan_id)
    items = q.all()
    return [_plan_subject_hours_to_dict(h) for h in items]

@app.put("/api/superadmin/structure/plan-subject-hours")
async def upsert_plan_subject_hours(
    data: PlanSubjectHoursSchema, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    """Upsert: якщо для пари (план, предмет) вже є запис годин — оновлює його, інакше створює.
    Так предмет ОПП 'підключається' до конкретного навчального плану зі своїми годинами."""
    plan = db.query(DBStudyPlan).filter(DBStudyPlan.id == data.study_plan_id).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Навчальний план не знайдено")
    subject = db.query(DBSubject).filter(DBSubject.id == data.subject_id).first()
    if not subject:
        raise HTTPException(status_code=404, detail="Предмет не знайдено")
    if subject.opp_id != plan.opp_id:
        raise HTTPException(status_code=400, detail="Предмет належить іншій ОПП, ніж навчальний план")
    parts = [data.hours, data.lecture_hours, data.practice_hours, data.self_study_hours]
    if any(p is not None and p < 0 for p in parts):
        raise HTTPException(status_code=400, detail="Години не можуть бути від'ємними")
    if data.hours is not None and sum(p or 0 for p in parts[1:]) > data.hours:
        raise HTTPException(status_code=400, detail="Лекції + практичні + самостійна перевищують загальні години")
    obj = db.query(DBPlanSubjectHours).filter(
        DBPlanSubjectHours.study_plan_id == data.study_plan_id,
        DBPlanSubjectHours.subject_id == data.subject_id,
    ).first()
    if not obj:
        obj = DBPlanSubjectHours(study_plan_id=data.study_plan_id, subject_id=data.subject_id)
        db.add(obj)
    obj.hours = data.hours
    obj.lecture_hours = data.lecture_hours
    obj.practice_hours = data.practice_hours
    obj.self_study_hours = data.self_study_hours
    write_audit(db, request, action="update", user=admin, content_type="Structure | Години предмета", object_repr=subject.name)
    db.commit()
    db.refresh(obj)
    return _plan_subject_hours_to_dict(obj)

@app.delete("/api/superadmin/structure/plan-subject-hours/{item_id}")
async def delete_plan_subject_hours(
    item_id: int, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    """Видаляє прив'язку предмета до плану (сам предмет в ОПП залишається)"""
    obj = db.query(DBPlanSubjectHours).filter(DBPlanSubjectHours.id == item_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Не знайдено")
    write_audit(db, request, action="delete", user=admin, content_type="Structure | Години предмета", object_id=item_id)
    db.delete(obj)
    db.commit()
    return {"message": "Видалено"}

# ── ВИКЛАДАЧІ ────────────────────────────────────────────
@app.get("/api/structure/teachers")
async def get_teachers(
    department_id: str = Query(default=None),
    q: str = Query(default=None),
    user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    query = db.query(DBTeacher)
    if department_id:
        query = query.filter(DBTeacher.department_id == department_id)
    if q:
        query = query.filter(DBTeacher.full_name.ilike(f"%{q}%"))
    items = query.order_by(DBTeacher.full_name).all()
    return [_teacher_to_dict(t) for t in items]

@app.post("/api/superadmin/structure/teachers")
async def create_teacher(
    data: TeacherSchema, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    if data.department_id and not db.query(DBDepartment).filter(DBDepartment.id == data.department_id).first():
        raise HTTPException(status_code=404, detail="Кафедру не знайдено")
    obj = DBTeacher(
        id=str(uuid.uuid4())[:8], full_name=data.full_name,
        department_id=data.department_id, email=data.email, position=data.position,
    )
    db.add(obj)
    write_audit(db, request, action="create", user=admin, content_type="Structure | Викладач", object_repr=data.full_name)
    db.commit()
    return _teacher_to_dict(obj)

@app.put("/api/superadmin/structure/teachers/{item_id}")
async def update_teacher(
    item_id: str, data: TeacherSchema, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    obj = db.query(DBTeacher).filter(DBTeacher.id == item_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Не знайдено")
    obj.full_name = data.full_name
    obj.department_id = data.department_id
    obj.email = data.email
    obj.position = data.position
    write_audit(db, request, action="update", user=admin, content_type="Structure | Викладач", object_id=item_id, object_repr=data.full_name)
    db.commit()
    return _teacher_to_dict(obj)

@app.delete("/api/superadmin/structure/teachers/{item_id}")
async def delete_teacher(
    item_id: str, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    obj = db.query(DBTeacher).filter(DBTeacher.id == item_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Не знайдено")
    write_audit(db, request, action="delete", user=admin, content_type="Structure | Викладач", object_id=item_id, object_repr=obj.full_name)
    db.delete(obj)
    db.commit()
    return {"message": "Видалено"}

# ── ІМПОРТ ВИКЛАДАЧІВ (формат Список_викладачів_ДУЕТ.xlsx) ─
def _norm_dept_name(name: str) -> str:
    n = (name or "").strip()
    if n.lower().startswith("кафедра"):
        n = n[len("кафедра"):].strip()
    return n.lower()

@app.post("/api/superadmin/structure/import-teachers")
async def import_teachers(
    request: Request, file: UploadFile = File(...),
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    """Імпортує довідник викладачів з файлу типу Список_викладачів_ДУЕТ.xlsx.
    Очікує два листи:
    - "Список": колонки Кафедра, Прізвище, Ім'я, По батькові, Навантаження, Навантаження (дпд)
      (рядки з ПІБ що починається на "." — вакансії, пропускаються)
    - "Аркуш1": колонки Ім'я викладача, Прізвище викладача, Електронна пошта (для email)
    Один викладач може мати навантаження на кількох кафедрах одразу (сумісництво) —
    основною кафедрою обирається та, де сумарне навантаження найбільше.
    Кафедра з файлу зіставляється з вашою Структурою за повною назвою; якщо збігу
    немає — викладач імпортується без кафедри, а назва потрапляє у список
    'незіставлених кафедр', щоб ви або перейменували, або створили потрібну."""
    content = await file.read()
    try:
        xls = pd.ExcelFile(io.BytesIO(content))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Помилка читання Excel: {str(e)}")
    if "Список" not in xls.sheet_names:
        raise HTTPException(status_code=400, detail="У файлі немає листа 'Список'")

    df = pd.read_excel(xls, sheet_name="Список")
    required_cols = {"Кафедра", "ПІБ", "Прізвище", "Ім'я", "По батькові"}
    missing = required_cols - set(df.columns)
    if missing:
        raise HTTPException(status_code=400, detail=f"У листі 'Список' бракує колонок: {', '.join(sorted(missing))}")

    # email за (прізвище, ім'я) з другого листа, якщо він є
    email_map = {}
    if "Аркуш1" in xls.sheet_names:
        df_email = pd.read_excel(xls, sheet_name="Аркуш1")
        if {"Прізвище викладача", "Ім'я викладача", "Електронна пошта"}.issubset(df_email.columns):
            for _, r in df_email.iterrows():
                last = str(r.get("Прізвище викладача") or "").strip().lower()
                first = str(r.get("Ім'я викладача") or "").strip().lower()
                email = str(r.get("Електронна пошта") or "").strip()
                if last and first and email and email.lower() != "nan":
                    email_map.setdefault((last, first), email)

    # довідник кафедр Структури: нормалізована назва -> id
    dept_lookup = {}
    for d in db.query(DBDepartment).all():
        if d.full_name:
            dept_lookup.setdefault(_norm_dept_name(d.full_name), d.id)
        dept_lookup.setdefault(_norm_dept_name(d.name), d.id)

    # накопичуємо навантаження по (ПІБ, кафедра) щоб визначити основну кафедру
    teacher_loads = {}      # full_name -> { dept_name_from_file: total_hours }
    teacher_names_parts = {}  # full_name -> (last, first)
    for _, row in df.iterrows():
        pib = str(row.get("ПІБ") or "").strip()
        if not pib or pib.startswith("."):
            continue  # вакансія
        last = str(row.get("Прізвище") or "").strip()
        first = str(row.get("Ім'я") or "").strip()
        patronymic = str(row.get("По батькові") or "").strip()
        if patronymic.lower() == "nan":
            patronymic = ""
        full_name = " ".join(p for p in [last, first, patronymic] if p and p.lower() != "nan")
        if not full_name:
            continue
        dept_name_file = str(row.get("Кафедра") or "").strip()
        hours = 0
        for col in ("Навантаження", "Навантаження (дпд)"):
            val = row.get(col)
            try:
                hours += float(val) if val is not None and str(val).lower() != "nan" else 0
            except (TypeError, ValueError):
                pass
        teacher_loads.setdefault(full_name, {})
        teacher_loads[full_name][dept_name_file] = teacher_loads[full_name].get(dept_name_file, 0) + hours
        teacher_names_parts[full_name] = (last.lower(), first.lower())

    stats = {"teachers_created": 0, "teachers_updated": 0, "emails_matched": 0, "unmatched_departments": []}
    unmatched_dept_names = set()

    for full_name, loads in teacher_loads.items():
        primary_dept_file_name = max(loads, key=loads.get) if loads else None
        dept_id = dept_lookup.get(_norm_dept_name(primary_dept_file_name)) if primary_dept_file_name else None
        if primary_dept_file_name and not dept_id:
            unmatched_dept_names.add(primary_dept_file_name)

        last, first = teacher_names_parts.get(full_name, ("", ""))
        email = email_map.get((last, first))

        existing = db.query(DBTeacher).filter(DBTeacher.full_name == full_name).first()
        if existing:
            changed = False
            if dept_id and existing.department_id != dept_id:
                existing.department_id = dept_id; changed = True
            if email and not existing.email:
                existing.email = email; changed = True
            if changed:
                stats["teachers_updated"] += 1
        else:
            db.add(DBTeacher(id=str(uuid.uuid4())[:8], full_name=full_name, department_id=dept_id, email=email))
            stats["teachers_created"] += 1
        if email:
            stats["emails_matched"] += 1

    stats["unmatched_departments"] = sorted(unmatched_dept_names)
    write_audit(db, request, action="bulk_import", user=admin,
        content_type="Structure | Імпорт викладачів", object_repr=file.filename, details=stats)
    db.commit()
    return {"message": "Імпорт завершено", **stats}

# ── ВИБІР СТУДЕНТОМ ВИБІРКОВОГО ПРЕДМЕТУ ────────────────
@app.get("/api/student/elective-choices")
async def get_my_elective_choices(
    user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    """Повертає поточні вибори студента по всіх його навчальних планах"""
    choices = db.query(DBStudentSubjectChoice).filter(
        DBStudentSubjectChoice.student_id == user["user_id"]
    ).all()
    return [{
        "study_plan_id": c.study_plan_id, "elective_slot": c.elective_slot,
        "subject_id": c.subject_id, "chosen_at": c.chosen_at
    } for c in choices]

@app.get("/api/student/elective-options/{study_plan_id}")
async def get_elective_options(
    study_plan_id: str,
    user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    """Повертає всі вибіркові слоти і варіанти предметів для конкретного плану.
    Вибіркові предмети визначені на рівні ОПП цього плану."""
    plan = db.query(DBStudyPlan).filter(DBStudyPlan.id == study_plan_id).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Навчальний план не знайдено")
    subjects = db.query(DBSubject).filter(
        DBSubject.opp_id == plan.opp_id,
        DBSubject.elective_slot.isnot(None)
    ).all()
    slots = {}
    for s in subjects:
        slots.setdefault(s.elective_slot, []).append({
            "id": s.id, "name": s.name, "semester": s.semester, "teachers": [l.teacher_id for l in s.teacher_links]
        })
    return slots

@app.post("/api/student/elective-choices")
async def set_elective_choice(
    data: StudentSubjectChoiceSchema,
    user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    subject = db.query(DBSubject).filter(DBSubject.id == data.subject_id).first()
    if not subject:
        raise HTTPException(status_code=404, detail="Предмет не знайдено")
    plan = db.query(DBStudyPlan).filter(DBStudyPlan.id == data.study_plan_id).first()
    if not plan or subject.elective_slot != data.elective_slot or subject.opp_id != plan.opp_id:
        raise HTTPException(status_code=400, detail="Предмет не належить вказаному слоту/плану")
    existing = db.query(DBStudentSubjectChoice).filter(
        DBStudentSubjectChoice.student_id == user["user_id"],
        DBStudentSubjectChoice.study_plan_id == data.study_plan_id,
        DBStudentSubjectChoice.elective_slot == data.elective_slot,
    ).first()
    if existing:
        existing.subject_id = data.subject_id
        existing.chosen_at = datetime.now().strftime("%d.%m.%Y %H:%M")
    else:
        db.add(DBStudentSubjectChoice(
            student_id=user["user_id"], study_plan_id=data.study_plan_id,
            elective_slot=data.elective_slot, subject_id=data.subject_id,
        ))
    db.commit()
    return {"message": "Вибір збережено"}

# =========================================================
# 📊 АНАЛІТИКА ЦМЯО
# =========================================================
@app.get("/api/cmyo/responses/{survey_id}")
async def get_survey_responses(
    survey_id: str,
    user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)
):
    template = db.query(DBTemplate).filter(DBTemplate.id == survey_id).first()
    is_anonymous = (template.is_anonymous if template and template.is_anonymous is not None else True)
    responses = db.query(DBResponse).filter(DBResponse.survey_id == survey_id).all()
    result = []
    for r in responses:
        entry = {"id": r.id, "answers": r.answers, "opp_context": r.opp_context}
        if not is_anonymous:
            if r.respondent_id:
                resp_user = db.query(DBUser).filter(DBUser.id == r.respondent_id).first()
                entry["respondent"] = {
                    "name": resp_user.full_name if resp_user else r.respondent_name,
                    "email": resp_user.email if resp_user else "—",
                    "role": resp_user.role if resp_user else "—"
                }
            else:
                entry["respondent"] = {"name": r.respondent_name or "Анонімно", "email": "—", "role": "—"}
        result.append(entry)
    return result

def _resolve_response_opp(db_session, template, user: dict, opp_ctx_raw):
    """Визначає назву ОПП для відповіді на #По_ОПП опитування.
    1) якщо в virtual_id є контекст — це id ОПП або (fallback) її назва;
    2) якщо опитування #По_ОПП, а студент має рівно одну ОПП — беремо її;
    3) інакше None."""
    if opp_ctx_raw:
        opp = db_session.query(DBOpp).filter(DBOpp.id == opp_ctx_raw).first()
        return opp.name if opp else opp_ctx_raw
    if "По_ОПП" not in (template.hashtags or []) or user.get("role") != "student":
        return None
    db_user = db_session.query(DBUser).filter(DBUser.id == user["user_id"]).first()
    s_data = (db_user.student_data or {}) if db_user else {}
    if isinstance(s_data, str):
        try:
            s_data = json.loads(s_data)
        except Exception:
            s_data = {}
    names = []
    for study in (s_data.get("навчання", []) if isinstance(s_data, dict) else []):
        grp = db_session.query(DBAcademicGroup).filter(DBAcademicGroup.name == study.get("Група", "")).first()
        plan = db_session.query(DBStudyPlan).filter(DBStudyPlan.id == grp.study_plan_id).first() if grp else None
        opp = db_session.query(DBOpp).filter(DBOpp.id == plan.opp_id).first() if plan else None
        name = opp.name if opp else (study.get("ОПП") or study.get("Спеціальність") or "")
        if name and name not in names:
            names.append(name)
    return names[0] if len(names) == 1 else None

@app.post("/api/responses")
async def save_student_response(
    response: StudentResponseSchema,
    user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    # Розпаковуємо virtual_id для По_ОПП опитувань (формат: "baseId__opp__oppIdOrName")
    raw_survey_id = response.survey_id
    base_survey_id = raw_survey_id.split("__opp__")[0] if "__opp__" in raw_survey_id else raw_survey_id
    opp_context = raw_survey_id.split("__opp__")[1] if "__opp__" in raw_survey_id else None

    template = db.query(DBTemplate).filter(DBTemplate.id == base_survey_id).first()
    if not template:
        raise HTTPException(status_code=404, detail="Опитування не знайдено")

    access_error = _survey_access_error(db, template, user)
    if access_error:
        raise HTTPException(status_code=403, detail=access_error)

    if user.get("role") != "stakeholder":
        # Перевіряємо за virtual_id (щоб одна і та ж база-опитування могла пройтися двічі по різних ОПП)
        already_completed = db.query(DBCompletedSurvey).filter(
            DBCompletedSurvey.user_id == user["user_id"],
            DBCompletedSurvey.survey_id == raw_survey_id
        ).first()
        if already_completed:
            raise HTTPException(status_code=409, detail="Ви вже проходили це опитування")

    is_anon = template.is_anonymous if template.is_anonymous is not None else True
    respondent_id = None
    respondent_name = None
    if not is_anon:
        respondent_id = user["user_id"]
        db_user_obj = db.query(DBUser).filter(DBUser.id == user["user_id"]).first()
        respondent_name = db_user_obj.full_name if db_user_obj else None

    resolved_opp = _resolve_response_opp(db, template, user, opp_context)
    db.add(DBResponse(
        survey_id=base_survey_id,
        answers=response.answers,
        respondent_id=respondent_id,
        respondent_name=respondent_name,
        opp_context=resolved_opp,
    ))

    if user.get("role") != "stakeholder":
        # Зберігаємо virtual_id щоб кожна ОПП-копія вважалась окремо пройденою
        db.add(DBCompletedSurvey(user_id=user["user_id"], survey_id=raw_survey_id))

    # 🪶 Нараховуємо пер'я лише студентам
    if user.get("role") == "student" and template.feathers_reward and template.feathers_reward > 0:
        award_feathers(
            db=db,
            student_id=user["user_id"],
            amount=template.feathers_reward,
            reason=f"Опитування: {template.title}" + (f" [{resolved_opp}]" if resolved_opp else ""),
            survey_id=base_survey_id
        )

    db.commit()
    return {"message": "Збережено.", "feathers_earned": template.feathers_reward or 0}


# =========================================================
# 🪶 ЕНДПОІНТИ СИСТЕМИ ПЕР'ЯТА
# =========================================================

@app.get("/api/student/feathers")
async def get_feathers_info(
    user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    """Повертає баланс, транзакції та активну тему студента"""
    if user.get("role") != "student":
        raise HTTPException(status_code=403, detail="Тільки для студентів")

    wallet = get_or_create_wallet(db, user["user_id"])
    db.commit()

    transactions = db.query(DBFeathersTransaction).filter(
        DBFeathersTransaction.student_id == user["user_id"]
    ).order_by(DBFeathersTransaction.id.desc()).limit(20).all()

    owned = db.query(DBOwnedTheme).filter(
        DBOwnedTheme.student_id == user["user_id"]
    ).all()
    owned_ids = [o.theme_id for o in owned]

    active = db.query(DBActiveTheme).filter(
        DBActiveTheme.student_id == user["user_id"]
    ).first()
    active_theme_id = active.theme_id if active else None

    return {
        "balance": wallet.balance,
        "owned_theme_ids": owned_ids,
        "active_theme_id": active_theme_id,
        "transactions": [{
            "amount": t.amount,
            "reason": t.reason,
            "created_at": t.created_at
        } for t in transactions]
    }

@app.get("/api/themes/catalog")
async def get_themes_catalog(user: dict = Depends(get_current_user)):
    """Каталог доступних тем"""
    if user.get("role") != "student":
        raise HTTPException(status_code=403, detail="Тільки для студентів")
    return THEMES_CATALOG

@app.post("/api/student/feathers/buy-theme")
async def buy_theme(
    purchase: ThemePurchaseSchema,
    user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    """Купівля теми за пер'я"""
    if user.get("role") != "student":
        raise HTTPException(status_code=403, detail="Тільки для студентів")

    theme = next((t for t in THEMES_CATALOG if t["id"] == purchase.theme_id), None)
    if not theme:
        raise HTTPException(status_code=404, detail="Тему не знайдено")

    # Перевіряємо — можливо вже куплено
    already_owned = db.query(DBOwnedTheme).filter(
        DBOwnedTheme.student_id == user["user_id"],
        DBOwnedTheme.theme_id == purchase.theme_id
    ).first()
    if already_owned:
        raise HTTPException(status_code=409, detail="Ця тема вже придбана")

    wallet = get_or_create_wallet(db, user["user_id"])
    if wallet.balance < theme["price"]:
        raise HTTPException(
            status_code=402,
            detail=f"Недостатньо пер'їв. Потрібно {theme['price']}, у вас {wallet.balance}"
        )

    wallet.balance -= theme["price"]
    db.add(DBFeathersTransaction(
        student_id=user["user_id"],
        amount=-theme["price"],
        reason=f"Куплена тема: {theme['name']}",
    ))
    db.add(DBOwnedTheme(student_id=user["user_id"], theme_id=purchase.theme_id))
    db.commit()
    return {"message": f"Тему «{theme['name']}» успішно придбано! 🎉", "new_balance": wallet.balance}

@app.post("/api/student/feathers/set-theme")
async def set_active_theme(
    data: ActiveThemeSchema,
    user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    """Встановлення активної теми"""
    if user.get("role") != "student":
        raise HTTPException(status_code=403, detail="Тільки для студентів")

    # Перевіряємо власність (або дефолтна тема)
    if data.theme_id != "default":
        owned = db.query(DBOwnedTheme).filter(
            DBOwnedTheme.student_id == user["user_id"],
            DBOwnedTheme.theme_id == data.theme_id
        ).first()
        if not owned:
            raise HTTPException(status_code=403, detail="Ця тема не придбана")

    active = db.query(DBActiveTheme).filter(
        DBActiveTheme.student_id == user["user_id"]
    ).first()
    if active:
        active.theme_id = data.theme_id
    else:
        db.add(DBActiveTheme(student_id=user["user_id"], theme_id=data.theme_id))
    db.commit()
    return {"message": "Тему активовано!"}

# =========================================================
# 🔏 ЗГОДА НА ОБРОБКУ ПЕРСОНАЛЬНИХ ДАНИХ — ЕНДПОІНТИ
# =========================================================
class ConsentAcceptSchema(BaseModel):
    location: str

class ConsentResetSchema(BaseModel):
    user_ids: Optional[List[str]] = None
    role: Optional[str] = None

def _consent_status(rec) -> str:
    """confirmed | pending (ще не підтверджував) | reset (потрібно підтвердити знову)"""
    if rec is None or not rec.accepted_at:
        return "pending"
    if rec.reset_required or (rec.version or 0) < CONSENT_VERSION:
        return "reset"
    return "confirmed"

@app.get("/api/me/consent")
async def get_my_consent(user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    applicable = user.get("role") in CONSENT_ROLES
    rec = db.query(DBUserConsent).filter(DBUserConsent.user_id == user["user_id"]).first()
    status = _consent_status(rec)
    return {
        "applicable": applicable,
        "required": applicable and status != "confirmed",
        "status": status,
        "location": rec.location if rec else None,
        "accepted_at": rec.accepted_at if rec else None,
        "version": CONSENT_VERSION,
    }

@app.post("/api/me/consent")
async def accept_my_consent(
    data: ConsentAcceptSchema, request: Request,
    user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    if user.get("role") not in CONSENT_ROLES:
        raise HTTPException(status_code=403, detail="Для вашої ролі підтвердження не потрібне")
    if data.location not in CONSENT_LOCATIONS:
        raise HTTPException(status_code=400, detail="Оберіть, де ви перебуваєте")
    rec = db.query(DBUserConsent).filter(DBUserConsent.user_id == user["user_id"]).first()
    if not rec:
        rec = DBUserConsent(user_id=user["user_id"])
        db.add(rec)
    rec.version = CONSENT_VERSION
    rec.accepted_at = datetime.now().strftime("%d.%m.%Y %H:%M")
    rec.location = data.location
    rec.reset_required = False
    write_audit(db, request, action="update", user=user, content_type="Consent | Згода",
        object_id=user["user_id"], object_repr=user.get("sub"),
        details={"location": data.location, "version": CONSENT_VERSION})
    db.commit()
    return {"message": "Дякуємо!"}

@app.get("/api/superadmin/consents")
async def list_consents(admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)):
    users = db.query(DBUser).filter(DBUser.role.in_(CONSENT_ROLES)).order_by(DBUser.full_name).all()
    recs = {r.user_id: r for r in db.query(DBUserConsent).all()}
    items = []
    for u in users:
        r = recs.get(u.id)
        items.append({
            "user_id": u.id, "full_name": u.full_name, "email": u.email, "role": u.role,
            "status": _consent_status(r),
            "accepted_at": r.accepted_at if r else None,
            "location": r.location if r else None,
        })
    return {"version": CONSENT_VERSION, "items": items}

@app.post("/api/superadmin/consents/reset")
async def reset_consents(
    data: ConsentResetSchema, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    """Показати повідомлення знову: конкретним користувачам (user_ids) або всій ролі (role)."""
    if data.user_ids:
        q = db.query(DBUser).filter(DBUser.id.in_(data.user_ids), DBUser.role.in_(CONSENT_ROLES))
    elif data.role in CONSENT_ROLES:
        q = db.query(DBUser).filter(DBUser.role == data.role)
    else:
        raise HTTPException(status_code=400, detail="Вкажіть користувачів або роль (student / teacher)")
    users = q.all()
    existing = {r.user_id: r for r in db.query(DBUserConsent).filter(
        DBUserConsent.user_id.in_([u.id for u in users])).all()} if users else {}
    for u in users:
        rec = existing.get(u.id)
        if not rec:
            rec = DBUserConsent(user_id=u.id)
            db.add(rec)
        rec.reset_required = True
    write_audit(db, request, action="update", user=admin, content_type="Consent | Згода",
        object_repr=f"reset: {len(users)}", details={"role": data.role, "user_ids": data.user_ids, "count": len(users)})
    db.commit()
    return {"message": f"Повідомлення буде показано знову: {len(users)} користувачів", "count": len(users)}

# =========================================================
# 📨 СЛУЖБОВІ ЗАПИСКИ — ЕНДПОІНТИ
# Редагують: ЦМЯО і суперадмін. Переглядає також ЦСК.
# =========================================================
class ServiceNoteSchema(BaseModel):
    teacher_id: Optional[str] = None
    teacher_name: Optional[str] = None
    date_from: str
    date_to: Optional[str] = None
    note_number: Optional[str] = None
    note_date: Optional[str] = None
    note_written: bool = False
    reason: Optional[str] = None
    schedule_changed: bool = False
    group_names: List[str] = []
    notes: Optional[str] = None
    file_url: Optional[str] = None

class ServiceNoteNotifySchema(BaseModel):
    title: str
    content: str = ""
    is_important: bool = False
    force: bool = False

def require_notes_reader(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") not in ["superadmin", "admin_cmyo", "admin_csk"]:
        raise HTTPException(status_code=403, detail="Доступ заборонено")
    return user

def require_notes_editor(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") not in ["superadmin", "admin_cmyo"]:
        raise HTTPException(status_code=403, detail="Службові записки вносить лише ЦМЯО")
    return user

def _note_to_dict(n: "DBServiceNote") -> dict:
    return {
        "id": n.id, "teacher_id": n.teacher_id, "teacher_name": n.teacher_name,
        "date_from": n.date_from, "date_to": n.date_to,
        "note_number": n.note_number, "note_date": n.note_date, "note_written": bool(n.note_written),
        "reason": n.reason, "schedule_changed": bool(n.schedule_changed),
        "group_names": n.group_names or [], "notes": n.notes, "file_url": n.file_url,
        "has_file": bool(n.file_data), "file_name": n.file_name,
        "notified_at": n.notified_at, "created_by": n.created_by,
        "created_at": n.created_at, "updated_at": n.updated_at,
    }

def _parse_iso_date(value, field):
    if not value:
        return None
    try:
        datetime.strptime(value, "%Y-%m-%d")
        return value
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Невірна дата в полі «{field}»")

def _apply_service_note(db_session, obj, data: "ServiceNoteSchema"):
    date_from = _parse_iso_date(data.date_from, "Початок")
    date_to = _parse_iso_date(data.date_to, "Кінець")
    note_date = _parse_iso_date(data.note_date, "Дата СЗ")
    if not date_from:
        raise HTTPException(status_code=400, detail="Вкажіть дату початку")
    if date_to and date_to < date_from:
        raise HTTPException(status_code=400, detail="Кінець періоду раніше за початок")
    teacher_name = _clean(data.teacher_name)
    teacher_id = None
    if data.teacher_id:
        t = db_session.query(DBTeacher).filter(DBTeacher.id == data.teacher_id).first()
        if not t:
            raise HTTPException(status_code=404, detail="Викладача не знайдено")
        teacher_id, teacher_name = t.id, t.full_name
    if not teacher_name:
        raise HTTPException(status_code=400, detail="Вкажіть викладача")
    groups = list(dict.fromkeys(_clean(g) for g in (data.group_names or []) if _clean(g)))
    if groups:
        found = {r[0] for r in db_session.query(DBAcademicGroup.name).filter(DBAcademicGroup.name.in_(groups)).all()}
        missing = [g for g in groups if g not in found]
        if missing:
            raise HTTPException(status_code=400, detail=f"Груп немає в Структурі: {', '.join(missing)}")
    url = (data.file_url or "").strip() or None
    if url and not url.lower().startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Посилання має починатися з http:// або https://")
    obj.teacher_id = teacher_id
    obj.teacher_name = teacher_name
    obj.date_from, obj.date_to, obj.note_date = date_from, date_to, note_date
    obj.note_number = _clean(data.note_number) or None
    obj.note_written = data.note_written
    obj.reason = _clean(data.reason)[:100] or None
    obj.schedule_changed = data.schedule_changed
    obj.group_names = groups
    obj.notes = (data.notes or "").strip() or None
    obj.file_url = url
    obj.updated_at = datetime.now().strftime("%d.%m.%Y %H:%M")

@app.get("/api/service-notes")
async def list_service_notes(user: dict = Depends(require_notes_reader), db: Session = Depends(get_db)):
    items = db.query(DBServiceNote).order_by(DBServiceNote.date_from.desc(), DBServiceNote.id.desc()).all()
    return {"reasons": SERVICE_NOTE_REASONS, "items": [_note_to_dict(n) for n in items]}

@app.post("/api/service-notes")
async def create_service_note(
    data: ServiceNoteSchema, request: Request,
    user: dict = Depends(require_notes_editor), db: Session = Depends(get_db)
):
    obj = DBServiceNote(created_by=user.get("sub"))
    _apply_service_note(db, obj, data)
    db.add(obj)
    write_audit(db, request, action="create", user=user, content_type="ServiceNote | СЗ",
        object_repr=obj.teacher_name, details={"date_from": obj.date_from, "date_to": obj.date_to, "reason": obj.reason})
    db.commit()
    db.refresh(obj)
    return _note_to_dict(obj)

@app.put("/api/service-notes/{note_id}")
async def update_service_note(
    note_id: int, data: ServiceNoteSchema, request: Request,
    user: dict = Depends(require_notes_editor), db: Session = Depends(get_db)
):
    obj = db.query(DBServiceNote).filter(DBServiceNote.id == note_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Запис не знайдено")
    _apply_service_note(db, obj, data)
    write_audit(db, request, action="update", user=user, content_type="ServiceNote | СЗ",
        object_id=note_id, object_repr=obj.teacher_name)
    db.commit()
    db.refresh(obj)
    return _note_to_dict(obj)

@app.delete("/api/service-notes/{note_id}")
async def delete_service_note(
    note_id: int, request: Request,
    user: dict = Depends(require_notes_editor), db: Session = Depends(get_db)
):
    obj = db.query(DBServiceNote).filter(DBServiceNote.id == note_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Запис не знайдено")
    write_audit(db, request, action="delete", user=user, content_type="ServiceNote | СЗ",
        object_id=note_id, object_repr=obj.teacher_name)
    db.delete(obj)
    db.commit()
    return {"message": "Видалено"}

@app.post("/api/service-notes/{note_id}/file")
async def upload_service_note_file(
    note_id: int, request: Request, file: UploadFile = File(...),
    user: dict = Depends(require_notes_editor), db: Session = Depends(get_db)
):
    obj = db.query(DBServiceNote).filter(DBServiceNote.id == note_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Запис не знайдено")
    name = os.path.basename(file.filename or "")
    if not name.lower().endswith(SERVICE_NOTE_EXT):
        raise HTTPException(status_code=400, detail="Дозволені файли: PDF, DOC, DOCX")
    content = await file.read()
    if len(content) > SERVICE_NOTE_MAX_FILE:
        raise HTTPException(status_code=413, detail="Файл завеликий (максимум 5 МБ)")
    if not content:
        raise HTTPException(status_code=400, detail="Файл порожній")
    obj.file_name = name[:200]
    obj.file_mime = file.content_type or "application/octet-stream"
    obj.file_data = content
    obj.updated_at = datetime.now().strftime("%d.%m.%Y %H:%M")
    write_audit(db, request, action="update", user=user, content_type="ServiceNote | СЗ (файл)",
        object_id=note_id, object_repr=name, details={"size": len(content)})
    db.commit()
    return _note_to_dict(obj)

@app.get("/api/service-notes/{note_id}/file")
async def download_service_note_file(
    note_id: int, user: dict = Depends(require_notes_reader), db: Session = Depends(get_db)
):
    obj = db.query(DBServiceNote).filter(DBServiceNote.id == note_id).first()
    if not obj or not obj.file_data:
        raise HTTPException(status_code=404, detail="Файл не знайдено")
    return StreamingResponse(
        io.BytesIO(obj.file_data),
        media_type=obj.file_mime or "application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(obj.file_name or 'file')}"},
    )

@app.delete("/api/service-notes/{note_id}/file")
async def delete_service_note_file(
    note_id: int, request: Request,
    user: dict = Depends(require_notes_editor), db: Session = Depends(get_db)
):
    obj = db.query(DBServiceNote).filter(DBServiceNote.id == note_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Запис не знайдено")
    obj.file_name = obj.file_mime = obj.file_data = None
    write_audit(db, request, action="delete", user=user, content_type="ServiceNote | СЗ (файл)", object_id=note_id)
    db.commit()
    return _note_to_dict(obj)

# ── ІМПОРТ СЗ З EXCEL/CSV (формат чинної таблиці) ───────
_DATE_RE = re.compile(r"(\d{1,2})\.(\d{1,2})\.(\d{4})")

def _to_iso(d, mth, y):
    try:
        return datetime(int(y), int(mth), int(d)).strftime("%Y-%m-%d")
    except ValueError:
        return None

def _parse_period_cell(val):
    """'15.09.2026-21.09.2026' / '29.09.2026' / datetime → (date_from, date_to) у ISO."""
    if val is None or (isinstance(val, float) and pd.isna(val)):
        return None, None
    if hasattr(val, "strftime"):
        iso = val.strftime("%Y-%m-%d")
        return iso, None
    dates = [_to_iso(*g) for g in _DATE_RE.findall(str(val))]
    dates = [d for d in dates if d]
    if not dates:
        return None, None
    return dates[0], (dates[-1] if len(dates) > 1 and dates[-1] != dates[0] else None)

def _name_initials(text):
    """('Нестеренко К.О.' | 'Нестеренко Катерина Олексіївна') → (прізвище_norm, [ініціали])"""
    parts = (text or "").replace(",", " ").split()
    if not parts:
        return "", []
    surname = _norm(parts[0])
    rest = " ".join(parts[1:])
    if "." in rest:
        initials = re.findall(r"[A-Za-zА-ЯІЇЄҐа-яіїєґ]", rest.replace(".", " . ").replace(" . ", ""))
    else:
        initials = [p[0] for p in parts[1:] if p]
    return surname, [i.lower() for i in initials]

def _match_teacher(teachers, text):
    """Повертає DBTeacher, якщо збіг однозначний (прізвище + ініціали), інакше None."""
    surname, ini = _name_initials(text)
    if not surname:
        return None
    cands = []
    for t in teachers:
        t_sur, t_ini = _name_initials(t.full_name)
        if t_sur != surname:
            continue
        if ini and t_ini[:len(ini)] != ini[:len(t_ini)] and t_ini[:len(ini)] != ini:
            continue
        cands.append(t)
    return cands[0] if len(cands) == 1 else None

def _norm_reason(text):
    t = _clean(text)
    if not t:
        return None
    for r in SERVICE_NOTE_REASONS:
        if t.lower() == r.lower():
            return r
    return t[:100]

@app.post("/api/service-notes/import")
async def import_service_notes(
    request: Request, file: UploadFile = File(...), dry_run: bool = Query(default=True),
    user: dict = Depends(require_notes_editor), db: Session = Depends(get_db)
):
    """Імпорт рядків зі старої таблиці (xlsx/xls/csv). dry_run=true — лише перевірка без запису.
    Очікувані колонки (за заголовком): НПП/ПП, Дата…, Службові записки, Причина, Змінено в розкладі?,
    Примітки, Посилання на файл. Рядки-заголовки років («2027 н.р.») пропускаються."""
    name = (file.filename or "").lower()
    content = await file.read()
    try:
        if name.endswith(".csv"):
            df = pd.read_csv(io.BytesIO(content), header=None, dtype=object)
        else:
            df = pd.read_excel(io.BytesIO(content), header=None, dtype=object)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Помилка читання файлу: {str(e)}")

    # знаходимо рядок заголовків
    header_idx, cols = None, {}
    for idx in range(min(len(df), 15)):
        cells = [str(c).strip().lower() if not pd.isna(c) else "" for c in df.iloc[idx].tolist()]
        if any("нпп" in c for c in cells) and any("причин" in c for c in cells):
            header_idx = idx
            for ci, c in enumerate(cells):
                if "нпп" in c: cols["teacher"] = ci
                elif c.startswith("дата") or "термін" in c: cols["period"] = ci
                elif "службов" in c: cols["note"] = ci
                elif "причин" in c: cols["reason"] = ci
                elif "змінено" in c: cols["schedule"] = ci
                elif "примітк" in c: cols["notes"] = ci
                elif "посилан" in c: cols["url"] = ci
            break
    if header_idx is None or "teacher" not in cols or "period" not in cols:
        raise HTTPException(status_code=400, detail="Не знайдено рядок заголовків (потрібні колонки «НПП/ПП» і «Дата…»)")

    def cell(row, key):
        ci = cols.get(key)
        if ci is None or ci >= len(row):
            return ""
        v = row[ci]
        return "" if pd.isna(v) else v

    teachers = db.query(DBTeacher).all()
    existing = {(n.teacher_name, n.date_from, n.date_to or "") for n in db.query(DBServiceNote).all()}
    stats = {"rows": 0, "created": 0, "duplicates": 0, "matched_teachers": 0, "unmatched_teachers": [], "errors": []}
    preview = []
    seen_unmatched = set()

    for idx in range(header_idx + 1, len(df)):
        row = df.iloc[idx].tolist()
        teacher_raw = _clean(str(cell(row, "teacher")))
        others = [c for i, c in enumerate(row) if i != cols["teacher"] and not pd.isna(c) and str(c).strip()]
        if not teacher_raw or not others or re.search(r"\d{4}.*н\.?\s?р", teacher_raw.lower()):
            continue   # порожній рядок або заголовок року
        date_from, date_to = _parse_period_cell(cell(row, "period"))
        if not date_from:
            stats["errors"].append(f"Рядок {idx + 1}: «{teacher_raw}» — немає коректної дати")
            continue
        stats["rows"] += 1
        t = _match_teacher(teachers, teacher_raw)
        teacher_name = t.full_name if t else teacher_raw
        if t:
            stats["matched_teachers"] += 1
        elif teacher_raw not in seen_unmatched:
            seen_unmatched.add(teacher_raw)
            stats["unmatched_teachers"].append(teacher_raw)
        key = (teacher_name, date_from, date_to or "")
        if key in existing:
            stats["duplicates"] += 1
            continue
        existing.add(key)
        note_txt = str(cell(row, "note")).lower()
        url = str(cell(row, "url")).strip()
        rec = dict(
            teacher_id=t.id if t else None, teacher_name=teacher_name,
            date_from=date_from, date_to=date_to,
            note_written=("є" in note_txt.split() or "наявн" in note_txt),
            reason=_norm_reason(str(cell(row, "reason"))),
            schedule_changed=str(cell(row, "schedule")).strip().lower() in ("так", "yes", "true", "1", "+"),
            notes=(str(cell(row, "notes")).strip() or None),
            file_url=url if url.lower().startswith(("http://", "https://")) else None,
        )
        stats["created"] += 1
        if len(preview) < 15:
            preview.append({**rec, "teacher_matched": bool(t)})
        if not dry_run:
            db.add(DBServiceNote(created_by=user.get("sub"),
                updated_at=datetime.now().strftime("%d.%m.%Y %H:%M"), group_names=[], **rec))

    if not dry_run:
        write_audit(db, request, action="bulk_import", user=user, content_type="ServiceNote | Імпорт СЗ",
            object_repr=file.filename, details={k: v for k, v in stats.items() if k != "errors"})
        db.commit()
    return {"dry_run": dry_run, "preview": preview, **stats}

@app.post("/api/service-notes/{note_id}/notify")
async def notify_service_note(
    note_id: int, data: ServiceNoteNotifySchema, request: Request,
    user: dict = Depends(require_notes_editor), db: Session = Depends(get_db)
):
    """Публікує оголошення, яке бачать лише студенти вказаних груп."""
    obj = db.query(DBServiceNote).filter(DBServiceNote.id == note_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Запис не знайдено")
    if not obj.schedule_changed:
        raise HTTPException(status_code=400, detail="Спершу позначте, що зміни внесено в розклад")
    if not obj.group_names:
        raise HTTPException(status_code=400, detail="Не вказано групи, яким потрібно надіслати повідомлення")
    if not data.title.strip():
        raise HTTPException(status_code=400, detail="Заголовок обов'язковий")
    if obj.notified_at and not data.force:
        raise HTTPException(status_code=409, detail=f"Повідомлення вже надсилалося {obj.notified_at}")
    sender = {"admin_cmyo": "ЦМЯО", "superadmin": "Адміністрація"}.get(user.get("role"), "Деканат")
    now = datetime.now().strftime("%d.%m.%Y %H:%M")
    ann = DBAnnouncement(
        title=data.title.strip(), content=data.content, date=now, sender=sender,
        is_important=data.is_important, target_groups=list(obj.group_names),
    )
    db.add(ann)
    db.flush()
    obj.notified_at = now
    obj.announcement_id = ann.id
    write_audit(db, request, action="create", user=user, content_type="Announcements | Оголошення",
        object_id=ann.id, object_repr=ann.title, details={"service_note_id": note_id, "groups": obj.group_names})
    db.commit()
    return _note_to_dict(obj)

# =========================================================
# 📢 ОГОЛОШЕННЯ
# =========================================================
@app.post("/api/announcements")
async def create_announcement(
    ann: AnnouncementCreateSchema, request: Request,
    user: dict = Depends(require_announcement_admin), db: Session = Depends(get_db)
):
    sender_map = {"admin_csk": "ЦСК", "admin_cmyo": "ЦМЯО", "superadmin": "Адміністрація"}
    sender = sender_map.get(user["role"], "Деканат")
    db.add(DBAnnouncement(
        title=ann.title, content=ann.content,
        date=datetime.now().strftime("%d.%m.%Y %H:%M"),
        sender=sender, is_important=ann.is_important
    ))
    write_audit(db, request,
        action="create", user=user, content_type="Announcements | Оголошення",
        object_repr=ann.title, details={"is_important": ann.is_important, "sender": sender},
    )
    db.commit()
    return {"message": "Оголошення опубліковано!"}

@app.get("/api/announcements")
async def get_announcements(
    user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    anns = db.query(DBAnnouncement).order_by(DBAnnouncement.id.desc()).all()
    role = user.get("role")
    if role in ("superadmin", "admin_csk", "admin_cmyo"):
        return anns
    # Оголошення з target_groups бачать лише студенти цих груп
    my_groups = set()
    if role == "student":
        db_user = db.query(DBUser).filter(DBUser.id == user["user_id"]).first()
        s_data = (db_user.student_data or {}) if db_user else {}
        if isinstance(s_data, str):
            try:
                s_data = json.loads(s_data)
            except Exception:
                s_data = {}
        for study in (s_data.get("навчання", []) if isinstance(s_data, dict) else []):
            if study.get("Група"):
                my_groups.add(study["Група"])
    return [a for a in anns if not a.target_groups or (set(a.target_groups) & my_groups)]

@app.put("/api/announcements/{ann_id}")
async def update_announcement(
    ann_id: int, ann: AnnouncementCreateSchema, request: Request,
    user: dict = Depends(require_announcement_admin), db: Session = Depends(get_db)
):
    db_ann = db.query(DBAnnouncement).filter(DBAnnouncement.id == ann_id).first()
    if not db_ann:
        raise HTTPException(status_code=404, detail="Оголошення не знайдено")
    if user.get("role") == "admin_csk" and db_ann.sender != "ЦСК":
        raise HTTPException(status_code=403, detail="Ви можете змінювати лише оголошення ЦСК")
    if user.get("role") == "admin_cmyo" and db_ann.sender != "ЦМЯО":
        raise HTTPException(status_code=403, detail="Ви можете змінювати лише оголошення ЦМЯО")
    db_ann.title = ann.title
    db_ann.content = ann.content
    db_ann.is_important = ann.is_important
    db_ann.is_edited = True
    write_audit(db, request,
        action="update", user=user, content_type="Announcements | Оголошення",
        object_id=ann_id, object_repr=ann.title, details={"is_important": ann.is_important},
    )
    db.commit()
    return {"message": "Оголошення оновлено"}

@app.delete("/api/announcements/{ann_id}")
async def delete_announcement(
    ann_id: int, request: Request,
    user: dict = Depends(require_announcement_admin), db: Session = Depends(get_db)
):
    ann = db.query(DBAnnouncement).filter(DBAnnouncement.id == ann_id).first()
    if not ann:
        raise HTTPException(status_code=404, detail="Оголошення не знайдено")
    if user.get("role") == "admin_csk" and ann.sender != "ЦСК":
        raise HTTPException(status_code=403, detail="Ви можете видаляти лише оголошення ЦСК")
    if user.get("role") == "admin_cmyo" and ann.sender != "ЦМЯО":
        raise HTTPException(status_code=403, detail="Ви можете видаляти лише оголошення ЦМЯО")
    write_audit(db, request,
        action="delete", user=user, content_type="Announcements | Оголошення",
        object_id=ann_id, object_repr=ann.title,
    )
    db.delete(ann)
    db.commit()
    return {"message": "Видалено"}

# =========================================================
# 📄 ФАЙЛИ (ОПП)
# =========================================================
@app.post("/api/upload-opp")
async def upload_opp(file: UploadFile = File(...), user: dict = Depends(get_current_user)):
    if user.get("role") not in ["superadmin", "admin_cmyo"]:
        raise HTTPException(status_code=403, detail="Доступ заборонено")
    os.makedirs("static/uploads", exist_ok=True)
    with open("static/uploads/current_opp.pdf", "wb+") as f:
        shutil.copyfileobj(file.file, f)
    return {"message": "ОПП успішно завантажено!"}

@app.get("/api/opp/download")
async def download_opp(user: dict = Depends(get_current_user)):
    file_path = "static/uploads/current_opp.pdf"
    if os.path.exists(file_path):
        return FileResponse(file_path, media_type="application/pdf", filename="OPP.pdf")
    raise HTTPException(status_code=404, detail="Файл не знайдено")

@app.get("/api/opp")
async def get_opp(user: dict = Depends(get_current_user)):
    if os.path.exists("static/uploads/current_opp.pdf"):
        return {"url": f"/api/opp/download?t={int(time.time())}"}
    return {"url": None}

# =========================================================
# 📚 ДОВІДНИКИ
# =========================================================
DEFAULT_DICTS = {
    "groups": [], "specialties": [], "courses": [], "semester": [],
    "floor": [], "finances": [], "study_forms": [], "faculties": [],
    "curriculum": [], "program": [], "departments": [],
    "teacher_positions": [], "degrees": [], "companies": [],
    "industries": [], "admin_departments": []
}

@app.get("/api/dictionaries")
async def get_dictionaries(
    user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    dict_record = db.query(DBDictionary).first()
    if not dict_record:
        dict_record = DBDictionary(data=DEFAULT_DICTS)
        db.add(dict_record)
        db.commit()
        db.refresh(dict_record)
    return dict_record.data

@app.put("/api/dictionaries")
async def update_dictionaries(
    new_data: dict,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    dict_record = db.query(DBDictionary).first()
    if dict_record:
        dict_record.data = new_data
    else:
        db.add(DBDictionary(data=new_data))
    db.commit()
    return {"message": "Довідники успішно оновлено!"}

# =========================================================
# 🗂️ ДОШКА ЦМЯО
# =========================================================
DEFAULT_BOARD_STATE = {"folders": [], "survey_folders": {}}

@app.get("/api/cmyo/board")
async def get_board_state(
    user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)
):
    record = db.query(DBBoardState).first()
    if not record:
        return DEFAULT_BOARD_STATE
    return record.state

@app.put("/api/cmyo/board")
async def save_board_state(
    state: dict,
    user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)
):
    record = db.query(DBBoardState).first()
    if record:
        record.state = state
    else:
        db.add(DBBoardState(state=state))
    db.commit()
    return {"message": "Збережено"}

# =========================================================
# 🧾 ПЕРЕВІРКА ПАР (ЦМЯО) — API
# Усе під /api/cmyo/lessons, доступ: ЦМЯО + суперадмін.
# Предмети, групи й викладачі — власні списки (lesson_subjects / lesson_groups / lesson_teachers).
# =========================================================
class LessonNameSchema(BaseModel):
    name: str

class LessonCheckSchema(BaseModel):
    subject_id: Optional[int] = None
    teacher_id: Optional[int] = None
    teacher_name: Optional[str] = None
    group_ids: List[int] = []
    lesson_date: str
    pairs: List[int] = []
    alarm: str = "Не відомо"
    notes: Optional[str] = None
    minutes: Optional[int] = None      # фактично вичитано, хв (якщо не вказано — пари × 40)

def _lesson_check_to_dict(c: "DBLessonCheck", subj_map: dict, grp_map: dict) -> dict:
    gids = c.group_ids or []
    return {
        "id": c.id, "subject_id": c.subject_id, "subject_name": subj_map.get(c.subject_id),
        "teacher_id": c.lesson_teacher_id, "teacher_name": c.teacher_name,
        "group_ids": gids, "group_names": [grp_map[g] for g in gids if g in grp_map],
        "lesson_date": c.lesson_date, "pairs": c.pairs or [],
        "pairs_count": c.pairs_count, "minutes": c.minutes,
        "alarm": c.alarm, "notes": c.notes,
        "created_by": c.created_by, "created_at": c.created_at, "updated_at": c.updated_at,
    }

def _lesson_backfill_teacher_links(db, teachers):
    """Старі рядки, збережені лише з текстовим ПІБ, підв'язуємо до списку викладачів за збігом імені."""
    rows = db.query(DBLessonCheck).filter(DBLessonCheck.lesson_teacher_id.is_(None)).all()
    if not rows or not teachers:
        return
    tmap = {t.name_norm: t.id for t in teachers}
    changed = False
    for r in rows:
        tid = tmap.get(_norm(r.teacher_name))
        if tid:
            r.lesson_teacher_id = tid
            changed = True
    if changed:
        db.commit()

@app.get("/api/cmyo/lessons")
async def list_lesson_checks(user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)):
    subjects = db.query(DBLessonSubject).order_by(DBLessonSubject.name).all()
    groups = db.query(DBLessonGroup).order_by(DBLessonGroup.name).all()
    teachers = db.query(DBLessonTeacher).order_by(DBLessonTeacher.name).all()
    _lesson_backfill_teacher_links(db, teachers)
    subj_map = {s.id: s.name for s in subjects}
    grp_map = {g.id: g.name for g in groups}
    items = db.query(DBLessonCheck).order_by(DBLessonCheck.lesson_date.desc(), DBLessonCheck.id.desc()).all()
    return {
        "pair_minutes": LESSON_PAIR_MINUTES,
        "max_pair_no": LESSON_MAX_PAIR_NO,
        "alarm_options": list(LESSON_ALARM_OPTIONS),
        "subjects": [{"id": s.id, "name": s.name} for s in subjects],
        "groups": [{"id": g.id, "name": g.name} for g in groups],
        "teachers": [{"id": t.id, "name": t.name} for t in teachers],
        "items": [_lesson_check_to_dict(c, subj_map, grp_map) for c in items],
    }

def _lesson_catalog_create(db, model, name: str, label: str):
    name = _clean(name)
    if not name:
        raise HTTPException(status_code=400, detail=f"Вкажіть {label}")
    if len(name) > 300:
        raise HTTPException(status_code=400, detail="Занадто довга назва")
    existing = db.query(model).filter(model.name_norm == _norm(name)).first()
    if existing:
        return existing                       # вже є — просто повертаємо (без дублів)
    obj = model(name=name, name_norm=_norm(name))
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj

def _lesson_catalog_rename(db, model, item_id: int, name: str, label: str):
    obj = db.query(model).filter(model.id == item_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Не знайдено")
    name = _clean(name)
    if not name:
        raise HTTPException(status_code=400, detail=f"Вкажіть {label}")
    n = _norm(name)
    dup = db.query(model).filter(model.name_norm == n, model.id != item_id).first()
    if dup:
        raise HTTPException(status_code=409, detail="Такий елемент уже є в списку")
    obj.name, obj.name_norm = name, n
    db.commit()
    return obj

@app.post("/api/cmyo/lessons/subjects")
async def create_lesson_subject(data: LessonNameSchema, user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)):
    o = _lesson_catalog_create(db, DBLessonSubject, data.name, "назву предмета")
    return {"id": o.id, "name": o.name}

@app.put("/api/cmyo/lessons/subjects/{item_id}")
async def rename_lesson_subject(item_id: int, data: LessonNameSchema, user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)):
    o = _lesson_catalog_rename(db, DBLessonSubject, item_id, data.name, "назву предмета")
    return {"id": o.id, "name": o.name}

@app.delete("/api/cmyo/lessons/subjects/{item_id}")
async def delete_lesson_subject(item_id: int, user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)):
    obj = db.query(DBLessonSubject).filter(DBLessonSubject.id == item_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Не знайдено")
    used = db.query(func.count(DBLessonCheck.id)).filter(DBLessonCheck.subject_id == item_id).scalar() or 0
    if used:
        raise HTTPException(status_code=409, detail=f"Предмет використовується в записах ({used}). Спочатку змініть їх.")
    db.delete(obj)
    db.commit()
    return {"message": "Видалено"}

@app.post("/api/cmyo/lessons/groups")
async def create_lesson_group(data: LessonNameSchema, user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)):
    o = _lesson_catalog_create(db, DBLessonGroup, data.name, "назву групи")
    return {"id": o.id, "name": o.name}

@app.put("/api/cmyo/lessons/groups/{item_id}")
async def rename_lesson_group(item_id: int, data: LessonNameSchema, user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)):
    o = _lesson_catalog_rename(db, DBLessonGroup, item_id, data.name, "назву групи")
    return {"id": o.id, "name": o.name}

@app.delete("/api/cmyo/lessons/groups/{item_id}")
async def delete_lesson_group(item_id: int, user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)):
    obj = db.query(DBLessonGroup).filter(DBLessonGroup.id == item_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Не знайдено")
    used = sum(1 for c in db.query(DBLessonCheck.group_ids).all() if item_id in (c[0] or []))
    if used:
        raise HTTPException(status_code=409, detail=f"Група використовується в записах ({used}). Спочатку змініть їх.")
    db.delete(obj)
    db.commit()
    return {"message": "Видалено"}

# ── Викладачі ────────────────────────────────────────────
@app.post("/api/cmyo/lessons/teachers")
async def create_lesson_teacher(data: LessonNameSchema, user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)):
    o = _lesson_catalog_create(db, DBLessonTeacher, data.name, "ПІБ викладача")
    return {"id": o.id, "name": o.name}

@app.put("/api/cmyo/lessons/teachers/{item_id}")
async def rename_lesson_teacher(item_id: int, data: LessonNameSchema, user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)):
    o = _lesson_catalog_rename(db, DBLessonTeacher, item_id, data.name, "ПІБ викладача")
    # у вже збережених рядках оновлюємо ПІБ, щоб назви не розходились
    db.query(DBLessonCheck).filter(DBLessonCheck.lesson_teacher_id == item_id).update({"teacher_name": o.name})
    db.commit()
    return {"id": o.id, "name": o.name}

@app.delete("/api/cmyo/lessons/teachers/{item_id}")
async def delete_lesson_teacher(item_id: int, user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)):
    obj = db.query(DBLessonTeacher).filter(DBLessonTeacher.id == item_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Не знайдено")
    used = db.query(func.count(DBLessonCheck.id)).filter(DBLessonCheck.lesson_teacher_id == item_id).scalar() or 0
    if used:
        raise HTTPException(status_code=409, detail=f"Викладач використовується в записах ({used}). Спочатку змініть їх.")
    # похідні дані розкладу: пари цього викладача видаляємо, акаунти Zoom відв'язуємо
    db.query(DBLessonSchedItem).filter(DBLessonSchedItem.lesson_teacher_id == item_id).delete(synchronize_session=False)
    db.query(DBLessonZoomAccount).filter(DBLessonZoomAccount.lesson_teacher_id == item_id).update({"lesson_teacher_id": None, "link_status": "none"})
    db.delete(obj)
    db.commit()
    return {"message": "Видалено"}

# ── Примітки до викладачів (хто не використовує корпоративний Zoom, не вичитує пари тощо) ──
LESSON_NOTE_MAX = 2000

class LessonTeacherNoteSchema(BaseModel):
    note: Optional[str] = None

@app.put("/api/cmyo/lessons/teachers/{item_id}/note")
async def set_lesson_teacher_note(item_id: int, data: LessonTeacherNoteSchema, user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)):
    obj = db.query(DBLessonTeacher).filter(DBLessonTeacher.id == item_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Не знайдено")
    note = re.sub(r"\n{3,}", "\n\n", (data.note or "").replace("\r\n", "\n").strip())
    if len(note) > LESSON_NOTE_MAX:
        raise HTTPException(status_code=400, detail=f"Примітка задовга (максимум {LESSON_NOTE_MAX} символів)")
    obj.note = note or None                      # порожня примітка = її немає
    obj.note_at = _sched_iso(_sched_now()) if note else None
    db.commit()
    return {"id": obj.id, "note": obj.note, "note_at": obj.note_at}

@app.get("/api/cmyo/lessons/teachers/export")
async def export_lesson_teacher_notes(contains: Optional[str] = Query(default=None), only_notes: bool = Query(default=True),
                                      user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)):
    """Таблиця Excel: викладачі, у яких щось написано в примітці (опційно — лише ті, де примітка містить фрагмент тексту)."""
    import openpyxl
    from openpyxl.styles import Font, Alignment, PatternFill, Border, Side
    from openpyxl.utils import get_column_letter
    from openpyxl.worksheet.properties import PageSetupProperties
    needle = _norm(contains or "")
    rows = [t for t in db.query(DBLessonTeacher).all()
            if (not only_notes or (t.note or "").strip()) and (not needle or needle in _norm(t.note or ""))]
    if not rows:
        raise HTTPException(status_code=404, detail="Немає викладачів із примітками за цим фільтром")
    rows.sort(key=lambda t: t.name.lower())
    today = _sched_now()
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Примітки"
    ws["A1"] = "Викладачі з примітками"
    ws["A1"].font = Font(bold=True, size=14)
    ws["A2"] = f"Станом на {today.strftime('%d.%m.%Y')} · записів: {len(rows)}" + (f" · фільтр: «{contains.strip()}»" if needle else "")
    ws["A2"].font = Font(color="666666", size=10)
    head = ["№", "Викладач", "Примітка", "Змінено"]
    thin = Side(style="thin", color="BBBBBB")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    for j, h in enumerate(head, 1):
        c = ws.cell(row=4, column=j, value=h)
        c.font = Font(bold=True, color="FFFFFF")
        c.fill = PatternFill("solid", fgColor="1F3A5F")
        c.alignment = Alignment(horizontal="center", vertical="center")
        c.border = border
    for i, t in enumerate(rows, 1):
        vals = [i, t.name, t.note or "", _sched_fmt_label(t.note_at) or ""]
        for j, v in enumerate(vals, 1):
            c = ws.cell(row=4 + i, column=j, value=v)
            c.border = border
            c.alignment = Alignment(vertical="top", wrap_text=True, horizontal="center" if j in (1, 4) else "left")
    for j, w in enumerate([6, 30, 90, 18], 1):
        ws.column_dimensions[get_column_letter(j)].width = w
    ws.freeze_panes = "A5"
    ws.auto_filter.ref = f"A4:D{4 + len(rows)}"
    ws.page_setup.orientation = "landscape"
    ws.page_setup.fitToWidth = 1
    ws.page_setup.fitToHeight = 0
    ws.sheet_properties.pageSetUpPr = PageSetupProperties(fitToPage=True)
    out = io.BytesIO()
    wb.save(out)
    out.seek(0)
    fname = f"vykladachi_prymitky_{today.strftime('%Y-%m-%d')}.xlsx"
    return StreamingResponse(out, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                             headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(fname)}"})

# ── Масове додавання / імпорт зі списку чи файлу (для предметів, груп, викладачів) ──
LESSON_CATALOGS = {"subjects": DBLessonSubject, "groups": DBLessonGroup, "teachers": DBLessonTeacher}
_LESSON_HEADER_WORDS = {"працівник", "піб", "викладач", "викладачі", "прізвище", "назва", "предмет", "предмети", "група", "групи", "потік", "потоки"}

class LessonBulkSchema(BaseModel):
    names: List[str] = []

def _lesson_catalog_bulk(db, model, names):
    if len(names) > 5000:
        raise HTTPException(status_code=400, detail="Забагато рядків за раз (максимум 5000)")
    existing = {n for (n,) in db.query(model.name_norm).all()}
    seen, added, already, dups, too_long = set(), [], 0, [], 0
    for raw in names:
        name = _clean(raw)
        if not name or name.lower() == "nan":
            continue
        if len(name) > 300:
            too_long += 1
            continue
        n = _norm(name)
        if n in seen:
            dups.append(name)
            continue
        seen.add(n)
        if n in existing:
            already += 1
            continue
        db.add(model(name=name, name_norm=n))
        added.append(name)
    db.commit()
    return {"added_count": len(added), "already_count": already, "duplicates_in_input": dups, "too_long": too_long}

def _lesson_names_from_file(content: bytes, filename: str):
    fn = (filename or "").lower()
    rows = []
    try:
        if fn.endswith((".csv", ".txt")):
            text_ = None
            for enc in ("utf-8-sig", "cp1251"):
                try:
                    text_ = content.decode(enc)
                    break
                except UnicodeDecodeError:
                    continue
            if text_ is None:
                raise ValueError("невідоме кодування")
            rows = [re.split(r"[;\t]", line) for line in text_.splitlines()]
        else:
            df = pd.read_excel(io.BytesIO(content), header=None, dtype=str)
            rows = df.fillna("").values.tolist()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Не вдалося прочитати файл: {e}")
    if not rows:
        raise HTTPException(status_code=400, detail="Файл порожній")
    col, start = 0, 0
    for i, cell in enumerate(rows[0]):
        if _norm(str(cell)) in _LESSON_HEADER_WORDS:
            col, start = i, 1
            break
    return [str(r[col]) for r in rows[start:] if len(r) > col]

@app.post("/api/cmyo/lessons/{kind}/bulk")
async def bulk_lesson_catalog(kind: str, data: LessonBulkSchema, user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)):
    model = LESSON_CATALOGS.get(kind)
    if not model:
        raise HTTPException(status_code=404, detail="Невідомий список")
    return _lesson_catalog_bulk(db, model, data.names)

@app.post("/api/cmyo/lessons/{kind}/import")
async def import_lesson_catalog(kind: str, file: UploadFile = File(...), user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)):
    model = LESSON_CATALOGS.get(kind)
    if not model:
        raise HTTPException(status_code=404, detail="Невідомий список")
    content = await file.read()
    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Файл завеликий (максимум 5 МБ)")
    return _lesson_catalog_bulk(db, model, _lesson_names_from_file(content, file.filename))

@app.get("/api/cmyo/lessons/{kind}")
async def list_lesson_catalog(kind: str, user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)):
    model = LESSON_CATALOGS.get(kind)
    if not model:
        raise HTTPException(status_code=404, detail="Невідомий список")
    rows = db.query(model).order_by(model.name).all()
    if kind == "teachers":
        return [{"id": r.id, "name": r.name, "note": r.note, "note_at": r.note_at} for r in rows]
    return [{"id": r.id, "name": r.name} for r in rows]

def _apply_lesson_check(db, obj, data: "LessonCheckSchema"):
    lesson_date = _parse_iso_date(data.lesson_date, "Дата")
    if not lesson_date:
        raise HTTPException(status_code=400, detail="Вкажіть дату")
    # предмет
    if data.subject_id is not None:
        if not db.query(DBLessonSubject.id).filter(DBLessonSubject.id == data.subject_id).first():
            raise HTTPException(status_code=400, detail="Предмет не знайдено в списку")
    # викладач — зі свого списку (lesson_teachers)
    teacher_id, teacher_name = None, _clean(data.teacher_name)
    if data.teacher_id:
        t = db.query(DBLessonTeacher).filter(DBLessonTeacher.id == data.teacher_id).first()
        if not t:
            raise HTTPException(status_code=404, detail="Викладача не знайдено в списку")
        teacher_id, teacher_name = t.id, t.name
    if not teacher_name:
        raise HTTPException(status_code=400, detail="Вкажіть викладача")
    # групи
    gids = list(dict.fromkeys(data.group_ids or []))
    if gids:
        found = {r[0] for r in db.query(DBLessonGroup.id).filter(DBLessonGroup.id.in_(gids)).all()}
        if set(gids) - found:
            raise HTTPException(status_code=400, detail="Групу не знайдено в списку")
    # пари
    pairs = sorted(set(data.pairs or []))
    if any((p < 1 or p > LESSON_MAX_PAIR_NO) for p in pairs):
        raise HTTPException(status_code=400, detail=f"Номер пари має бути від 1 до {LESSON_MAX_PAIR_NO}")
    # тривога
    if data.alarm not in LESSON_ALARM_OPTIONS:
        raise HTTPException(status_code=400, detail="Невірне значення «Чи є тривога?»")
    obj.subject_id, obj.lesson_teacher_id, obj.teacher_name = data.subject_id, teacher_id, teacher_name
    obj.teacher_id = None
    obj.group_ids, obj.lesson_date = gids, lesson_date
    obj.pairs, obj.pairs_count = pairs, len(pairs)
    if data.minutes is not None:
        if data.minutes < 0 or data.minutes > 1000:
            raise HTTPException(status_code=400, detail="Хвилини мають бути від 0 до 1000")
        obj.minutes = data.minutes
    else:
        obj.minutes = len(pairs) * LESSON_PAIR_MINUTES
    obj.alarm = data.alarm
    obj.notes = (data.notes or "").strip() or None
    obj.updated_at = datetime.now().strftime("%d.%m.%Y %H:%M")

def _lesson_check_response(db, obj):
    subj_map = {s.id: s.name for s in db.query(DBLessonSubject).all()}
    grp_map = {g.id: g.name for g in db.query(DBLessonGroup).all()}
    return _lesson_check_to_dict(obj, subj_map, grp_map)

@app.post("/api/cmyo/lessons")
async def create_lesson_check(data: LessonCheckSchema, user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)):
    obj = DBLessonCheck(created_by=user.get("sub"))
    _apply_lesson_check(db, obj, data)
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return _lesson_check_response(db, obj)

@app.put("/api/cmyo/lessons/{check_id}")
async def update_lesson_check(check_id: int, data: LessonCheckSchema, user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)):
    obj = db.query(DBLessonCheck).filter(DBLessonCheck.id == check_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Запис не знайдено")
    _apply_lesson_check(db, obj, data)
    db.commit()
    db.refresh(obj)
    return _lesson_check_response(db, obj)

@app.delete("/api/cmyo/lessons/{check_id}")
async def delete_lesson_check(check_id: int, user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)):
    obj = db.query(DBLessonCheck).filter(DBLessonCheck.id == check_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Запис не знайдено")
    db.delete(obj)
    db.commit()
    return {"message": "Видалено"}

# =========================================================
# 📅 РОЗКЛАД ↔ ZOOM (ЦМЯО) — API
# 1) Завантаження архіву розкладу (.7z/.zip/.xlsx): це пари, які викладачі ПОВИННІ провести.
#    Повторне завантаження дублів не створює (відбиток пари), зміни в розкладі підтягуються.
# 2) Завантаження звіту Zoom (.csv/.xlsx): хто, коли й скільки проводив.
# 3) Зіставлення: пара за розкладом ↔ зустрічі Zoom цього викладача в цей день і час.
# Усе доступно ЦМЯО + суперадміну; викладачі — лише зі списку lesson_teachers.
# =========================================================
SCHED_MAX_FILES = 600
SCHED_MAX_MEMBER_BYTES = 5 * 1024 * 1024
SCHED_MAX_TOTAL_BYTES = 150 * 1024 * 1024
SCHED_MAX_UPLOAD_BYTES = 60 * 1024 * 1024
ZOOM_MAX_UPLOAD_BYTES = 30 * 1024 * 1024

def _sched_now() -> datetime:
    """Поточний київський час (без tzinfo) — звіти Zoom і розклад у місцевому часі."""
    try:
        from zoneinfo import ZoneInfo
        return datetime.now(ZoneInfo(os.environ.get("APP_TIMEZONE", "Europe/Kyiv"))).replace(tzinfo=None)
    except Exception:
        return datetime.now()

def _sched_iso(dt_: datetime) -> str:
    return dt_.strftime("%Y-%m-%dT%H:%M:%S")

def _sched_dt(s: str) -> datetime:
    return datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")

def _sched_fmt_label(iso: Optional[str]) -> Optional[str]:
    if not iso:
        return None
    try:
        return _sched_dt(iso).strftime("%d.%m.%Y %H:%M")
    except Exception:
        return iso

# ── Розбір розкладу ─────────────────────────────────────────────
_SCHED_HEADERS = {
    "date": ("дата",), "time": ("час",), "subject": ("назва",), "type": ("тип",),
    "groups": ("групи", "група"), "teachers": ("викладачі", "викладач"),
    "place": ("місце проведення", "місце"), "status": ("статус",), "desc": ("опис",), "note": ("примітка",),
}

def _sched_cell_date(v) -> Optional[str]:
    if v is None or v == "":
        return None
    try:
        if isinstance(v, datetime):
            return v.strftime("%Y-%m-%d")
        if hasattr(v, "strftime") and not hasattr(v, "hour"):
            return v.strftime("%Y-%m-%d")
        s = str(v).strip()
        m = re.match(r"^(\d{4})-(\d{2})-(\d{2})", s)
        if m:
            datetime.strptime(m.group(0), "%Y-%m-%d")
            return m.group(0)
        m = re.match(r"^(\d{1,2})[./](\d{1,2})[./](\d{4})", s)
        if m:
            iso = f"{int(m.group(3)):04d}-{int(m.group(2)):02d}-{int(m.group(1)):02d}"
            datetime.strptime(iso, "%Y-%m-%d")
            return iso
    except ValueError:
        return None
    return None

def _sched_cell_time(v) -> Optional[str]:
    if v is None or v == "":
        return None
    if isinstance(v, datetime):
        return v.strftime("%H:%M")
    if hasattr(v, "hour") and hasattr(v, "minute"):
        return f"{v.hour:02d}:{v.minute:02d}"
    if isinstance(v, (int, float)) and 0 <= float(v) < 1:
        mins = round(float(v) * 24 * 60)
        return f"{mins // 60:02d}:{mins % 60:02d}"
    m = re.match(r"^(\d{1,2})[:.](\d{2})", str(v).strip())
    if m and int(m.group(1)) < 24 and int(m.group(2)) < 60:
        return f"{int(m.group(1)):02d}:{m.group(2)}"
    return None

def _sched_short_from_filename(fname: str) -> str:
    """'Андрущенко_Ганна_Іванівна.xlsx' → 'Андрущенко Г. І.' (запасний варіант, якщо немає заголовка)"""
    stem = re.sub(r"\.xlsx$", "", (fname or "").replace("\\", "/").split("/")[-1], flags=re.I)
    parts = [p for p in stem.replace("_", " ").split() if p]
    if not parts:
        return ""
    return " ".join([parts[0]] + [p[0].upper() + "." for p in parts[1:3]])

def _sched_parse_workbook(content: bytes, fname: str) -> dict:
    import openpyxl
    wb = openpyxl.load_workbook(io.BytesIO(content), read_only=True, data_only=True)
    try:
        ws = wb["Розклад"] if "Розклад" in wb.sheetnames else wb.worksheets[0]
        rows = [list(r) for r in ws.iter_rows(values_only=True)]
    finally:
        wb.close()
    hdr_i, cols = None, {}
    for i, r in enumerate(rows[:15]):
        names = [_norm(str(c)) if c is not None else "" for c in r]
        if "дата" in names and "час" in names:
            hdr_i = i
            for key, variants in _SCHED_HEADERS.items():
                for j, nm in enumerate(names):
                    if nm in variants:
                        cols[key] = j
                        break
            break
    if hdr_i is None or not {"date", "time", "subject"} <= set(cols):
        raise ValueError("не знайдено таблицю розкладу (колонки «Дата», «Час», «Назва»)")
    title = str(rows[0][0]).strip() if rows and rows[0] and rows[0][0] else ""
    owner = re.sub(r"^розклад\s*:\s*", "", title, flags=re.I).strip() or _sched_short_from_filename(fname)
    period_from = period_to = None
    for r in rows[:hdr_i]:
        txt = " ".join(str(c) for c in r if c)
        m = re.search(r"(\d{2})\.(\d{2})\.(\d{4}).*?(\d{2})\.(\d{2})\.(\d{4})", txt)
        if m:
            period_from, period_to = f"{m.group(3)}-{m.group(2)}-{m.group(1)}", f"{m.group(6)}-{m.group(5)}-{m.group(4)}"
            break
    get = lambda r, k: (r[cols[k]] if k in cols and cols[k] < len(r) else None)
    lessons, skipped_cancelled = [], 0
    for r in rows[hdr_i + 1:]:
        d, t = _sched_cell_date(get(r, "date")), _sched_cell_time(get(r, "time"))
        subj = _clean(str(get(r, "subject") or ""))
        if not d or not t or not subj:
            continue
        status = _norm(str(get(r, "status") or ""))
        if "скас" in status or "відмін" in status:
            skipped_cancelled += 1
            continue
        lessons.append({
            "date": d, "time": t, "subject": subj,
            "type": _clean(str(get(r, "type") or "")) or None,
            "groups": _clean(str(get(r, "groups") or "")) or None,
            "teachers": _clean(str(get(r, "teachers") or "")),
            "place": _clean(str(get(r, "place") or "")) or None,
            "note": _clean(" ".join(str(x) for x in (get(r, "desc"), get(r, "note")) if x)) or None,
        })
    if not period_from and lessons:
        period_from, period_to = min(l["date"] for l in lessons), max(l["date"] for l in lessons)
    return {"owner": owner, "period_from": period_from, "period_to": period_to,
            "lessons": lessons, "skipped_cancelled": skipped_cancelled}

def _sched_read_7z(content: bytes, accept, check):
    """Розпаковка .7z. Основний шлях — ПОВНІСТЮ В ПАМ'ЯТІ (не залежить від прав файлової системи сервера);
    старіші версії py7zr та запис у тимчасову папку — лише запасні варіанти."""
    import py7zr
    with py7zr.SevenZipFile(io.BytesIO(content)) as z:
        infos = [i for i in z.list() if not i.is_directory and accept(i.filename)]
        check([i.uncompressed for i in infos])
    names = [i.filename for i in infos]
    if not names:
        return []
    errors = []
    # 1) у пам'яті (py7zr ≥ 0.21 / 1.x)
    try:
        from py7zr.io import BytesIOFactory
        with py7zr.SevenZipFile(io.BytesIO(content)) as z:
            factory = BytesIOFactory(SCHED_MAX_MEMBER_BYTES + 1)
            z.extract(targets=names, factory=factory)
        out = []
        for name, bio in factory.products.items():
            bio.seek(0)
            out.append((name, bio.read()))
        if out:
            return out
    except Exception as e:
        errors.append(f"memory: {e}")
    # 2) старіший API py7zr (read / readall)
    try:
        with py7zr.SevenZipFile(io.BytesIO(content)) as z:
            data = z.read(targets=names) if hasattr(z, "read") else z.readall()
        out = [(n, b.read()) for n, b in data.items() if n in names]
        if out:
            return out
    except Exception as e:
        errors.append(f"read: {e}")
    # 3) тимчасова папка: заздалегідь створюємо підпапки з правами на запис
    import tempfile
    try:
        with tempfile.TemporaryDirectory() as tmp:
            for n in names:
                os.makedirs(os.path.join(tmp, os.path.dirname(n)), mode=0o777, exist_ok=True)
            with py7zr.SevenZipFile(io.BytesIO(content)) as z:
                z.extract(path=tmp, targets=names)
            base, out = os.path.realpath(tmp), []
            for n in names:
                p = os.path.realpath(os.path.join(tmp, n))
                if p.startswith(base + os.sep) and os.path.isfile(p):
                    with open(p, "rb") as fh:
                        out.append((n, fh.read()))
            if out:
                return out
    except Exception as e:
        errors.append(f"disk: {e}")
    raise HTTPException(status_code=400, detail="Не вдалося розпакувати .7z (" + "; ".join(errors) + "). Спробуйте завантажити .zip")

def _sched_extract_members(content: bytes, filename: str):
    """Список (ім'я, байти) xlsx-файлів з архіву. Нічого не пишемо на диск; обмеження від zip-бомб."""
    fn = (filename or "").lower()
    accept = lambda n: (n.replace("\\", "/").split("/")[-1].lower().endswith(".xlsx")
                        and not n.replace("\\", "/").split("/")[-1].startswith("~$") and "__macosx" not in n.lower())
    def check(sizes):
        if len(sizes) > SCHED_MAX_FILES:
            raise HTTPException(status_code=400, detail=f"В архіві забагато файлів (максимум {SCHED_MAX_FILES})")
        if any(s > SCHED_MAX_MEMBER_BYTES for s in sizes) or sum(sizes) > SCHED_MAX_TOTAL_BYTES:
            raise HTTPException(status_code=400, detail="Файли в архіві завеликі")
    try:
        if fn.endswith(".xlsx"):
            return [(filename, content)]
        if fn.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(content)) as z:
                infos = [i for i in z.infolist() if not i.is_dir() and accept(i.filename)]
                check([i.file_size for i in infos])
                return [(i.filename, z.read(i)) for i in infos]
        if fn.endswith(".7z"):
            try:
                import py7zr
            except ImportError:
                raise HTTPException(status_code=500, detail="На сервері не встановлено py7zr (pip install py7zr). Можна завантажити .zip.")
            return _sched_read_7z(content, accept, check)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Не вдалося розпакувати архів: {e}")
    raise HTTPException(status_code=400, detail="Підтримуються архіви .7z, .zip або окремі файли .xlsx")

def _sched_fingerprint(teacher_id: int, date_: str, time_: str, subject: str, ltype, groups) -> str:
    g = sorted({_norm(x) for x in re.split(r"[;,]", groups or "") if _norm(x)})
    raw = "|".join([str(teacher_id), date_, time_, _norm(subject), _norm(ltype or ""), ",".join(g)])
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()

def _sched_is_online(place: Optional[str]) -> bool:
    p = _norm(place or "")
    return (not p) or p.startswith("онлайн") or "zoom" in p or "визначено" in p

def _sched_zoom_id(place: Optional[str]) -> Optional[str]:
    m = re.search(r"zoom\.us/(?:j|wc/join|s)/(\d{9,11})", place or "", flags=re.I)
    return m.group(1) if m else None

def _sched_split_teachers(raw: str):
    return [p.strip() for p in re.split(r"\s*[;,]\s*", raw or "") if p.strip()]

def _sched_process_archive(db, content: bytes, filename: str, user_sub, dry_run: bool) -> dict:
    members = _sched_extract_members(content, filename)
    if not members:
        raise HTTPException(status_code=400, detail="В архіві немає файлів .xlsx")
    teachers = db.query(DBLessonTeacher).all()
    tmap = {t.name_norm: t for t in teachers}

    failed, found, total_rows, dups = [], {}, 0, 0
    unknown = defaultdict(int)
    covered = {}                                   # teacher_id → (період від, до) — для видалення зниклих пар
    skipped_cancelled = 0
    for name, data in members:
        try:
            p = _sched_parse_workbook(data, name)
        except Exception as e:
            failed.append({"file": name.replace("\\", "/").split("/")[-1], "error": str(e)})
            continue
        skipped_cancelled += p["skipped_cancelled"]
        owner_t = tmap.get(_norm(p["owner"]))
        if owner_t and p["period_from"] and p["period_to"]:
            old = covered.get(owner_t.id)
            covered[owner_t.id] = (min(old[0], p["period_from"]), max(old[1], p["period_to"])) if old else (p["period_from"], p["period_to"])
        for l in p["lessons"]:
            total_rows += 1
            names = _sched_split_teachers(l["teachers"]) or [p["owner"]]
            for tn in names:
                t = tmap.get(_norm(tn))
                if not t:
                    unknown[tn] += 1                 # ТІЛЬКИ викладачі зі списку — інших не створюємо
                    continue
                fp = _sched_fingerprint(t.id, l["date"], l["time"], l["subject"], l["type"], l["groups"])
                if fp in found:
                    dups += 1                         # той самий урок у файлах двох викладачів (заміна)
                    # «чий файл» — не залежить від порядку файлів: віддаємо перевагу власнику, відмінному від викладача
                    if _norm(found[fp]["owner"]) == t.name_norm and _norm(p["owner"]) != t.name_norm:
                        found[fp]["owner"] = p["owner"]
                    continue
                found[fp] = {**l, "teacher_id": t.id, "fingerprint": fp, "owner": p["owner"]}

    dates = [v["date"] for v in found.values()] + [c[0] for c in covered.values()] + [c[1] for c in covered.values()]
    d_min, d_max = (min(dates), max(dates)) if dates else (None, None)
    existing = {}
    if d_min:
        for it in db.query(DBLessonSchedItem).filter(DBLessonSchedItem.lesson_date >= d_min, DBLessonSchedItem.lesson_date <= d_max).all():
            existing[it.fingerprint] = it

    added, updated, unchanged, removed = [], [], 0, []
    for fp, v in found.items():
        slot = SCHED_SLOT_STARTS.index(v["time"]) + 1 if v["time"] in SCHED_SLOT_STARTS else None
        fields = dict(slot_no=slot, subject_name=v["subject"], lesson_type=v["type"], groups_text=v["groups"], place=v["place"],
                      is_online=_sched_is_online(v["place"]), zoom_meeting_id=_sched_zoom_id(v["place"]), note=v["note"], source_owner=v["owner"])
        cur = existing.get(fp)
        if cur is None:
            added.append((v, fields))
        elif any(getattr(cur, k) != val for k, val in fields.items()):
            updated.append((cur, fields))
        else:
            unchanged += 1
    for fp, it in existing.items():
        cov = covered.get(it.lesson_teacher_id)
        if fp not in found and cov and cov[0] <= it.lesson_date <= cov[1]:
            removed.append(it)

    period_from = min((c[0] for c in covered.values()), default=d_min)
    period_to = max((c[1] for c in covered.values()), default=d_max)
    stats = {
        "dry_run": dry_run, "files": len(members), "files_failed": failed,
        "teachers_in_archive": len(covered), "rows_in_files": total_rows, "unique_lessons": len(found),
        "duplicates_in_files": dups, "added": len(added), "updated": len(updated), "unchanged": unchanged,
        "removed": len(removed), "skipped_cancelled": skipped_cancelled,
        "unknown_teachers": sorted(({"name": k, "lessons": v} for k, v in unknown.items()), key=lambda x: -x["lessons"]),
        "period_from": period_from, "period_to": period_to,
    }
    if dry_run:
        return stats
    if not found and not covered:
        raise HTTPException(status_code=400, detail="У файлах немає жодної пари зі списку викладачів")
    now_iso = _sched_iso(_sched_now())
    batch = DBLessonSchedBatch(kind="schedule", filename=filename, period_from=period_from, period_to=period_to,
                               stats={k: v for k, v in stats.items() if k != "unknown_teachers"} | {"unknown_count": len(unknown)},
                               created_by=user_sub, created_at=now_iso)
    db.add(batch)
    db.flush()
    for v, f in added:
        db.add(DBLessonSchedItem(fingerprint=v["fingerprint"], lesson_teacher_id=v["teacher_id"], lesson_date=v["date"],
                                 start_time=v["time"], batch_id=batch.id, created_at=now_iso, **f))
    for cur, f in updated:
        for k, val in f.items():
            setattr(cur, k, val)
        cur.updated_at, cur.batch_id = now_iso, batch.id
    for it in removed:
        db.delete(it)
    db.commit()
    stats["batch_id"] = batch.id
    return stats

# ── Розбір звіту Zoom ───────────────────────────────────────────
_ZM_COLS = {
    "meeting_id": ("идентификатор конференции", "идентификатор встречи", "meeting id", "id конференції", "ідентифікатор конференції", "id совещания"),
    "topic": ("тема", "topic"),
    "organizer": ("организатор", "організатор", "host", "host name"),
    "email": ("эл. почта", "ел. пошта", "електронна пошта", "email", "user email", "host email"),
    "start": ("время начала", "час початку", "start time"),
    "end": ("время завершения", "час завершення", "end time"),
    "duration": ("продолжительность", "тривалість", "duration"),
    "participants": ("участники", "учасники", "participants"),
}
_ZM_POS = {"meeting_id": 0, "topic": 1, "organizer": 2, "email": 3, "start": 10, "end": 11, "duration": 12, "participants": 13}
_ZM_MONTHS = {"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
              "січ": 1, "лют": 2, "бер": 3, "кві": 4, "тра": 5, "чер": 6, "лип": 7, "сер": 8, "вер": 9, "жов": 10, "лис": 11, "гру": 12,
              "янв": 1, "фев": 2, "мар": 3, "апр": 4, "мая": 5, "июн": 6, "июл": 7, "авг": 8, "сен": 9, "окт": 10, "ноя": 11, "дек": 12}

def _zm_parse_dt(v) -> Optional[datetime]:
    if v is None or v == "":
        return None
    if isinstance(v, datetime):
        return v.replace(microsecond=0)
    s = str(v).strip()
    m = re.match(r"^(\d{1,2})\s+([A-Za-zА-Яа-яІіЇїЄє]{3})[A-Za-zА-Яа-яІіЇїЄє]*\.?\s+(\d{4})[ ,]+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([AaPp][Mm])?", s)
    if m:
        mon = _ZM_MONTHS.get(m.group(2).lower())
        if mon:
            return _zm_build(int(m.group(3)), mon, int(m.group(1)), m.group(4), m.group(5), m.group(6), m.group(7))
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})[ T](\d{1,2}):(\d{2})(?::(\d{2}))?\s*([AaPp][Mm])?", s)
    if m:
        return _zm_build(int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4), m.group(5), m.group(6), m.group(7))
    m = re.match(r"^(\d{1,2})[./](\d{1,2})[./](\d{4})[ ,]+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([AaPp][Mm])?", s)
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        day, mon = (a, b) if "." in s[:6] or a > 12 else (b, a) if b > 12 else (a, b)
        return _zm_build(int(m.group(3)), mon, day, m.group(4), m.group(5), m.group(6), m.group(7))
    return None

def _zm_build(y, mo, d, h, mi, s, ap) -> Optional[datetime]:
    try:
        h = int(h)
        if ap:
            h = h % 12 + (12 if ap.lower() == "pm" else 0)
        return datetime(y, mo, d, h, int(mi), int(s or 0))
    except ValueError:
        return None

def _zm_parse_duration(v, minutes_unit: bool) -> Optional[int]:
    if v is None or v == "":
        return None
    if hasattr(v, "hour") and hasattr(v, "minute"):
        return v.hour * 3600 + v.minute * 60 + getattr(v, "second", 0)
    s = str(v).strip()
    m = re.match(r"^(\d+):(\d{2}):(\d{2})$", s)
    if m:
        return int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3))
    m = re.match(r"^(\d+):(\d{2})$", s)
    if m:
        return int(m.group(1)) * 60 + int(m.group(2))
    try:
        n = float(s.replace(",", "."))
        return int(round(n * 60)) if minutes_unit else int(round(n))
    except ValueError:
        return None

def _zm_read_rows(content: bytes, filename: str):
    fn = (filename or "").lower()
    if fn.endswith((".xlsx", ".xls")):
        import openpyxl
        wb = openpyxl.load_workbook(io.BytesIO(content), read_only=True, data_only=True)
        try:
            return [list(r) for r in wb.worksheets[0].iter_rows(values_only=True)]
        finally:
            wb.close()
    text_ = None
    for enc in ("utf-8-sig", "utf-16", "cp1251"):
        try:
            text_ = content.decode(enc)
            break
        except UnicodeError:
            continue
    if text_ is None:
        raise HTTPException(status_code=400, detail="Невідоме кодування файлу")
    first = text_.split("\n", 1)[0]
    delim = max((",", ";", "\t"), key=lambda d: first.count(d))
    import csv as _csv
    return [r for r in _csv.reader(io.StringIO(text_), delimiter=delim)]

def _zm_email_key(email: str, organizer: str) -> str:
    e = (email or "").strip().strip("'\"` ").lower()
    if "@" in e:
        return e
    return "name:" + _norm(organizer)[:120]

# ── Зіставлення акаунтів Zoom з викладачами ─────────────────────
_ZM_CYR = {'а':'a','б':'b','в':'v','г':'h','ґ':'g','д':'d','е':'e','є':'e','ж':'zh','з':'z','и':'y','і':'i','ї':'i','й':'i',
           'к':'k','л':'l','м':'m','н':'n','о':'o','п':'p','р':'r','с':'s','т':'t','у':'u','ф':'f','х':'kh','ц':'ts','ч':'ch',
           'ш':'sh','щ':'sch','ю':'iu','я':'ia','ь':'','ъ':'','ы':'y','э':'e','ё':'io'}

def _zm_fold(s: str) -> str:
    """Фонетичний ключ: укр/рос/лат написання одного прізвища дають однаковий (або дуже схожий) рядок."""
    s = (s or "").lower()
    for ch in ("’", "ʼ", "`", "´", "'", "-"):
        s = s.replace(ch, "")
    t = "".join(_ZM_CYR.get(ch, ch) for ch in s)
    t = t.replace("sch", "sh").replace("tch", "ch").replace("tsy", "tsi")
    t = re.sub(r"ii|iy|yi|yy", "i", t)
    t = t.replace("y", "i").replace("j", "i").replace("w", "v").replace("x", "ks").replace("q", "k")
    t = t.replace("kh", "h").replace("ck", "k").replace("c", "k").replace("g", "h")
    t = t.replace("ia", "a").replace("iu", "u").replace("ie", "e").replace("io", "o")
    t = re.sub(r"(.)\1+", r"\1", t)
    return re.sub(r"[^a-z]", "", t)

def _zm_sim(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    if min(len(a), len(b)) < 5:
        return 1.0 if a == b else 0.0          # короткі прізвища — лише точний збіг
    return difflib.SequenceMatcher(None, a, b).ratio()

def _zm_clean_display(n: str) -> str:
    n = re.sub(r"\(.*?\)", " ", n or "")
    n = re.sub(r"\s[-–—]\s.*$", "", n)
    n = re.sub(r"[-–—](suet|duet)\b", "", n, flags=re.I)
    return re.sub(r"\s+", " ", n).strip()

def _zm_teacher_index(teachers):
    out = []
    for t in teachers:
        parts = t.name.replace(".", " ").split()
        if parts:
            out.append((t, _zm_fold(parts[0]), [_zm_fold(p[0])[:1] for p in parts[1:3]]))
    return out

def _zm_guess(email: str, display: str, index) -> dict:
    """Повертає {'level': 'auto'|'review'|'none', 'teacher_id', 'suggestions': [ids]}.
    auto  — прізвище збігається і підтверджено ініціал (e-mail виду prizvysche_ab@ або ім'я); одна явна відповідь.
    review — лише прізвище (без підтвердження ініціалу) — потрібне підтвердження людиною."""
    local = (email or "").split("@")[0].lower() if "@" in (email or "") else ""
    em = re.match(r"^([a-z'\-]{3,}?)(?:[_.]([a-z]{1,3}))?\d*$", local)
    email_sur, email_ini = (em.group(1), em.group(2) or "") if em else ("", "")
    tokens = [t for t in _zm_clean_display(display).split(" ") if t]
    tfold = [_zm_fold(t) for t in tokens]
    cands = []
    for t, sk, inits in index:
        best_sim, best_i = 0.0, -1
        if email_sur:
            best_sim = _zm_sim(_zm_fold(email_sur), sk)
        for i, tf in enumerate(tfold):
            s_ = _zm_sim(tf, sk)
            if s_ > best_sim:
                best_sim, best_i = s_, i
        if best_sim < 0.85:
            continue
        given = [tfold[i] for i in range(len(tfold)) if i != best_i]
        i1 = bool(inits) and (any(g[:1] == inits[0] for g in given[:1]) or (email_ini and _zm_fold(email_ini[0])[:1] == inits[0]))
        if inits and not i1 and len(given) > 1:
            i1 = any(g[:1] == inits[0] for g in given)
        i2 = len(inits) > 1 and ((len(email_ini) > 1 and _zm_fold(email_ini[1])[:1] == inits[1]) or (len(given) > 1 and given[1][:1] == inits[1]))
        cands.append((best_sim + 0.6 * bool(i1) + 0.4 * bool(i2), best_sim, bool(i1), t))
    cands.sort(key=lambda c: -c[0])
    sugg = [c[3].id for c in cands[:3]]
    if not cands:
        return {"level": "none", "teacher_id": None, "suggestions": []}
    top = cands[0]
    margin_ok = len(cands) == 1 or top[0] - cands[1][0] >= 0.25
    if margin_ok and top[2]:
        return {"level": "auto", "teacher_id": top[3].id, "suggestions": sugg}
    return {"level": "review", "teacher_id": None, "suggestions": sugg}

def _zm_autolink(db, accounts, teachers) -> int:
    """Пробує прив'язати ще не прив'язані акаунти (ручні та ігноровані не чіпає). Повертає кількість нових прив'язок."""
    index = _zm_teacher_index(teachers)
    n = 0
    for a in accounts:
        if a.link_status in ("manual", "ignored") or a.lesson_teacher_id:
            continue
        g = _zm_guess(a.email_key if "@" in a.email_key else "", a.display_name or "", index)
        if g["level"] == "auto":
            a.lesson_teacher_id, a.link_status = g["teacher_id"], "auto"
            n += 1
    return n

def _zm_process_report(db, content: bytes, filename: str, user_sub, dry_run: bool, data_until_override: Optional[str] = None) -> dict:
    rows = _zm_read_rows(content, filename)
    if len(rows) < 2:
        raise HTTPException(status_code=400, detail="Файл порожній")
    hdr = [_norm(str(c)) for c in rows[0]]
    cols = {}
    for key, variants in _ZM_COLS.items():
        for j, h in enumerate(hdr):
            if any(h == v or h.startswith(v) for v in variants):
                cols[key] = j
                break
    if not {"start", "organizer"} <= set(cols):
        if len(rows[0]) >= 14:
            cols = dict(_ZM_POS)           # типовий експорт «Звіт про конференції» без впізнаваних заголовків
        else:
            raise HTTPException(status_code=400, detail="Не вдалося розпізнати колонки звіту Zoom (потрібні: організатор, час початку, тривалість)")
    dur_hdr = hdr[cols["duration"]] if "duration" in cols and cols["duration"] < len(hdr) else ""
    minutes_unit = any(w in dur_hdr for w in ("minute", "хвилин", "минут"))
    get = lambda r, k: (r[cols[k]] if k in cols and cols[k] < len(r) else None)

    meetings, bad_rows, dups = {}, 0, 0
    acct_names = {}
    for r in rows[1:]:
        if not any(str(c).strip() for c in r if c is not None):
            continue
        start = _zm_parse_dt(get(r, "start"))
        if not start:
            bad_rows += 1
            continue
        dur = _zm_parse_duration(get(r, "duration"), minutes_unit)
        if dur is None:
            end_t = _zm_parse_dt(f"{start:%Y-%m-%d} {get(r, 'end')}") if get(r, "end") else None
            dur = int((end_t - start).total_seconds()) % 86400 if end_t else 0
        organizer = _clean(str(get(r, "organizer") or ""))
        email = str(get(r, "email") or "")
        ek = _zm_email_key(email, organizer)
        mid = re.sub(r"\D", "", str(get(r, "meeting_id") or "")) or None
        fp = hashlib.sha1(f"{mid}|{_sched_iso(start)}|{ek}".encode("utf-8")).hexdigest()
        if fp in meetings:
            dups += 1
            continue
        try:
            part = int(float(str(get(r, "participants") or 0)))
        except ValueError:
            part = None
        meetings[fp] = {"fp": fp, "mid": mid, "topic": _clean(str(get(r, "topic") or ""))[:500] or None, "organizer": organizer or None,
                        "ek": ek, "start": start, "end": start + timedelta(seconds=dur), "dur": dur, "part": part}
        acct_names.setdefault(ek, organizer)
    if not meetings:
        raise HTTPException(status_code=400, detail="У файлі не знайдено жодної зустрічі")

    starts, ends = [m["start"] for m in meetings.values()], [m["end"] for m in meetings.values()]
    existing_fp = {fp for (fp,) in db.query(DBLessonZoomMeeting.fingerprint).filter(
        DBLessonZoomMeeting.start_dt >= _sched_iso(min(starts) - timedelta(days=1)),
        DBLessonZoomMeeting.start_dt <= _sched_iso(max(starts) + timedelta(days=1))).all()}
    new_meetings = [m for fp, m in meetings.items() if fp not in existing_fp]
    accounts = {a.email_key: a for a in db.query(DBLessonZoomAccount).all()}
    new_keys = [k for k in acct_names if k not in accounts]
    teachers = db.query(DBLessonTeacher).all()
    index = _zm_teacher_index(teachers)

    # період звіту: з назви файлу (meetings2026_10_11_00_00_00_2026_10_15_23_59_00.csv) або за самими даними
    pf, pt = min(starts).replace(hour=0, minute=0, second=0), max(ends)
    fm = re.search(r"(\d{4})_(\d{2})_(\d{2})_(\d{2})_(\d{2})_(\d{2})_(\d{4})_(\d{2})_(\d{2})_(\d{2})_(\d{2})_(\d{2})", filename or "")
    if fm:
        try:
            g = [int(x) for x in fm.groups()]
            pf, pt = datetime(*g[0:6]), datetime(*g[6:12])
        except ValueError:
            pass
    now = _sched_now()
    # звіт, зроблений «наживо» (період ще не закінчився), має дані лише до останньої зустрічі
    data_until = pt if pt <= now else min(pt, max(ends))
    if data_until_override:                      # користувач вказав, до якого часу звіт справді повний
        try:
            data_until = datetime.strptime(data_until_override[:16].replace(" ", "T"), "%Y-%m-%dT%H:%M")
        except ValueError:
            raise HTTPException(status_code=400, detail="Невірний формат «Дані повні до» (потрібно РРРР-ММ-ДДTГГ:ХХ)")
        data_until = max(data_until, pf)

    auto_new, review_new = 0, 0
    for k in new_keys:
        g = _zm_guess(k if "@" in k else "", acct_names[k], index)
        auto_new += g["level"] == "auto"
        review_new += g["level"] == "review"
    stats = {
        "dry_run": dry_run, "rows": len(rows) - 1, "bad_rows": bad_rows, "duplicates_in_file": dups,
        "meetings_new": len(new_meetings), "meetings_existing": len(meetings) - len(new_meetings),
        "accounts_total": len(acct_names), "accounts_new": len(new_keys),
        "accounts_auto_linked": auto_new, "accounts_need_review": review_new,
        "date_from": min(starts).strftime("%Y-%m-%d"), "date_to": max(starts).strftime("%Y-%m-%d"),
        "data_until": _sched_iso(data_until),
    }
    if dry_run:
        return stats
    batch = DBLessonSchedBatch(kind="zoom", filename=filename, period_from=_sched_iso(pf), period_to=_sched_iso(pt),
                               data_until=_sched_iso(data_until), stats={k: v for k, v in stats.items()},
                               created_by=user_sub, created_at=_sched_iso(now))
    db.add(batch)
    db.flush()
    for k in new_keys:
        a = DBLessonZoomAccount(email_key=k, display_name=acct_names[k] or None, link_status="none", created_at=_sched_iso(now))
        db.add(a)
        accounts[k] = a
    db.flush()
    _zm_autolink(db, list(accounts.values()), teachers)
    for m in new_meetings:
        db.add(DBLessonZoomMeeting(fingerprint=m["fp"], meeting_id=m["mid"], topic=m["topic"], organizer_name=m["organizer"],
                                   account_id=accounts[m["ek"]].id, start_dt=_sched_iso(m["start"]), end_dt=_sched_iso(m["end"]),
                                   duration_sec=m["dur"], participants=m["part"], batch_id=batch.id))
    db.commit()
    stats["batch_id"] = batch.id
    return stats

# ── Ендпоїнти завантаження ──────────────────────────────────────
@app.post("/api/cmyo/schedule/upload")
async def upload_schedule_archive(file: UploadFile = File(...), dry_run: bool = Query(default=True),
                                  user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)):
    content = await file.read()
    if len(content) > SCHED_MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=400, detail="Файл завеликий")
    return _sched_process_archive(db, content, file.filename or "", user.get("sub"), dry_run)

@app.post("/api/cmyo/schedule/zoom/upload")
async def upload_zoom_report(file: UploadFile = File(...), dry_run: bool = Query(default=True),
                             data_until: Optional[str] = Query(default=None),
                             user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)):
    content = await file.read()
    if len(content) > ZOOM_MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=400, detail="Файл завеликий")
    return _zm_process_report(db, content, file.filename or "", user.get("sub"), dry_run, data_until)

@app.get("/api/cmyo/schedule/batches")
async def list_schedule_batches(user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)):
    rows = db.query(DBLessonSchedBatch).order_by(DBLessonSchedBatch.id.desc()).limit(20).all()
    return [{"id": b.id, "kind": b.kind, "filename": b.filename, "created_at": _sched_fmt_label(b.created_at),
             "created_by": b.created_by, "stats": b.stats or {}} for b in rows]

# ── Зіставлення розкладу з Zoom ─────────────────────────────────
def _sched_overlap_minutes(win_s: datetime, win_e: datetime, intervals) -> float:
    clipped = sorted((max(s, win_s), min(e, win_e)) for s, e in intervals if min(e, win_e) > max(s, win_s))
    total, cur_s, cur_e = 0.0, None, None
    for s, e in clipped:
        if cur_e is None or s > cur_e:
            if cur_e is not None:
                total += (cur_e - cur_s).total_seconds()
            cur_s, cur_e = s, e
        else:
            cur_e = max(cur_e, e)
    if cur_e is not None:
        total += (cur_e - cur_s).total_seconds()
    return total / 60.0

def _sched_zoom_coverage(db):
    """Інтервали, за які є звіт Zoom: [(від, до)]. Повертає (інтервали, найпізніше 'до')."""
    out = []
    for b in db.query(DBLessonSchedBatch).filter(DBLessonSchedBatch.kind == "zoom").all():
        if b.period_from and b.data_until:
            out.append((_sched_dt(b.period_from), _sched_dt(b.data_until)))
    return out, (max((c[1] for c in out), default=None))

def _sched_lesson_status(it, slot_s, slot_e, overlap_min, has_account, covered, global_until):
    if not it.is_online:
        return "offline"
    ok_thr = SCHED_SLOT_MINUTES * SCHED_OK_RATIO
    if overlap_min >= ok_thr:
        return "ok"
    if not has_account and not it.zoom_meeting_id:
        return "no_account"
    if not covered:
        # дані Zoom ще неповні (пара йде або попереду) → «очікується»; прогалина між звітами / немає звіту → «немає даних»
        return "pending" if (global_until is not None and slot_e > global_until) else "no_data"
    return "partial" if overlap_min >= SCHED_MIN_PARTIAL_MIN else "missed"

# =========================================================
# 🚨 ТРИВОГИ — офіційна підстава не проводити пару
# Два джерела (обирається у вікні «Тривоги»):
#   • ukrainealarm  — api.ukrainealarm.com, ключ у UKRAINE_ALARM_API_KEY; історія за днями (/api/v3/alerts/dateHistory);
#   • alertsinua    — api.alerts.in.ua,     токен у ALERTS_IN_UA_TOKEN;   історія за місяць одним запитом (ліміт 2 запити/хв).
# Запити до API робляться ОБЕРЕЖНО: по одному, з паузою, лише за дні з парами, з урахуванням Retry-After;
# після ліміту (HTTP 429) — пауза без жодних запитів, решта днів дозавантажується поступово.
# Правило поважної причини: якщо Zoom і тривога РАЗОМ покривають ≥ 60% пари, а самого Zoom замало — статус «Тривога».
# =========================================================
ALERT_EXCUSE_MIN = 10            # тривога коротша за 10 хв у межах пари не береться до уваги як причина
ALERT_CACHE_TTL_SEC = 180        # поточний день (ukrainealarm) перезавантажуємо не частіше, ніж раз на 3 хв
ALERT_INUA_TTL_SEC = 300         # місячну історію alerts.in.ua — не частіше, ніж раз на 5 хв
ALERT_RETRY_SEC = 60             # після помилки (не ліміт) наступна спроба не раніше ніж за хвилину
ALERT_HTTP_TIMEOUT = 12
ALERT_MAX_PER_CALL = 2           # скільки днів докачуємо за один запит розкладу (решта — пізніше)
ALERT_MAX_SLEEP = 3.0            # довше за це в запиті не чекаємо — позначаємо «пізніше»
ALERT_REGIONS_TTL_SEC = 6 * 3600
ALERT_PROVIDERS = {
    "ukrainealarm": {"label": "ukrainealarm.com", "key_env": "UKRAINE_ALARM_API_KEY", "base_env": "UKRAINE_ALARM_BASE_URL",
                     "base": "https://api.ukrainealarm.com", "gap": 1.5, "retry": 65, "max_gap": 30.0},
    "alertsinua":   {"label": "alerts.in.ua", "key_env": "ALERTS_IN_UA_TOKEN", "base_env": "ALERTS_IN_UA_BASE_URL",
                     "base": "https://api.alerts.in.ua", "gap": 31.0, "retry": 40, "max_gap": 120.0},
}
ALERT_TYPE_LABELS = {"AIR": "Повітряна тривога", "ARTILLERY": "Артилерійський обстріл", "URBAN_FIGHTS": "Вуличні бої",
                     "CHEMICAL": "Хімічна загроза", "NUCLEAR": "Радіаційна загроза", "INFO": "Інформація", "UNKNOWN": "Невідомо"}
_INUA_TYPES = {"AIR_RAID": "AIR", "ARTILLERY_SHELLING": "ARTILLERY", "URBAN_FIGHTS": "URBAN_FIGHTS", "CHEMICAL": "CHEMICAL", "NUCLEAR": "NUCLEAR"}
_alert_regions_cache = {"at": 0.0, "items": []}
_alert_scan_cache = {}           # alerts.in.ua: uid → (час, відповідь сканування)
_alert_rt = {p: {"until": 0.0, "gap": v["gap"], "last": 0.0, "ok": 0} for p, v in ALERT_PROVIDERS.items()}

class AlertsApiError(Exception):
    def __init__(self, msg, retry_after=None, kind="limit"):
        super().__init__(msg)
        self.retry_after = retry_after            # секунди до наступної спроби, інакше None
        self.kind = kind                          # limit — API сказало «забагато запитів»; wait — наша власна пауза між запитами

def _alerts_key(provider: str = "ukrainealarm") -> str:
    return os.environ.get(ALERT_PROVIDERS[provider]["key_env"], "").strip()

def _alerts_types() -> set:
    return {x.strip().upper() for x in os.environ.get("UKRAINE_ALARM_TYPES", "AIR").split(",") if x.strip()}

def _alerts_get(provider: str, path: str, params: Optional[dict] = None):
    """Блокуючий GET (викликається в потоці). Ключ у повідомлення про помилку не потрапляє."""
    pv = ALERT_PROVIDERS[provider]
    key = _alerts_key(provider)
    if not key:
        raise AlertsApiError(f"Не задано змінну {pv['key_env']}")
    base = os.environ.get(pv["base_env"], pv["base"]).rstrip("/")
    headers = {"Accept": "application/json", "Authorization": (f"Bearer {key}" if provider == "alertsinua" else key)}
    try:
        r = requests.get(base + path, params=params, headers=headers, timeout=ALERT_HTTP_TIMEOUT)
    except requests.RequestException as e:
        raise AlertsApiError(f"Немає зв'язку з {pv['label']} ({e.__class__.__name__})")
    if r.status_code in (401, 403):
        raise AlertsApiError(f"{pv['label']} не прийняло ключ (HTTP {r.status_code}). Перевірте {pv['key_env']}")
    if r.status_code == 429:
        try:
            ra = float(r.headers.get("Retry-After", ""))
        except ValueError:
            ra = pv["retry"]
        raise AlertsApiError(f"Ліміт запитів до {pv['label']} (HTTP 429)", retry_after=max(5.0, min(ra, 600.0)))
    if r.status_code >= 400:
        raise AlertsApiError(f"{pv['label']} повернуло помилку HTTP {r.status_code}")
    try:
        return r.json()
    except ValueError:
        raise AlertsApiError(f"{pv['label']} повернуло відповідь не у форматі JSON")

async def _alerts_call(provider: str, path: str, params: Optional[dict] = None):
    """Один запит з дотриманням паузи між запитами і режиму очікування після 429."""
    rt, pv = _alert_rt[provider], ALERT_PROVIDERS[provider]
    now = time.time()
    if now < rt["until"]:
        raise AlertsApiError(f"Ліміт запитів до {pv['label']}: чекаємо", retry_after=rt["until"] - now)
    wait = rt["last"] + rt["gap"] - now
    if wait > ALERT_MAX_SLEEP:
        raise AlertsApiError(f"Пауза між запитами до {pv['label']}", retry_after=wait, kind="wait")
    if wait > 0:
        await asyncio.sleep(wait)
    rt["last"] = time.time()
    try:
        data = await run_in_threadpool(_alerts_get, provider, path, params)
        rt["ok"] += 1
        if rt["ok"] >= 5:                                          # довго без проблем — повертаємо звичайну паузу
            rt["gap"], rt["ok"] = max(pv["gap"], rt["gap"] / 2), 0
        return data
    except AlertsApiError as e:
        if e.retry_after is not None:                              # ліміт: чекаємо і збільшуємо паузу між запитами
            rt["until"] = time.time() + e.retry_after
            rt["gap"], rt["ok"] = min(rt["gap"] * 2, pv["max_gap"]), 0
        raise

def _eu_dst_range_utc(year: int):
    def last_sunday(month):
        d = datetime(year, month, 31, 1, 0)
        while d.weekday() != 6:
            d -= timedelta(days=1)
        return d
    return last_sunday(3), last_sunday(10)          # перехід о 01:00 UTC

def _utc_to_kyiv(utc: datetime) -> datetime:
    try:
        from zoneinfo import ZoneInfo
        from datetime import timezone
        return utc.replace(tzinfo=timezone.utc).astimezone(ZoneInfo(os.environ.get("APP_TIMEZONE", "Europe/Kyiv"))).replace(tzinfo=None)
    except Exception:                                # немає бази часових поясів (напр. Windows без tzdata)
        a, b = _eu_dst_range_utc(utc.year)
        return utc + timedelta(hours=3 if a <= utc < b else 2)

def _alerts_to_kyiv(s) -> Optional[datetime]:
    """'2026-10-20T10:57:01.133Z' (UTC) → київський час без tzinfo. Некоректні/порожні дати → None."""
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?\s*(Z|[+-]\d{2}:?\d{2})?$", str(s or "").strip())
    if not m or int(m.group(1)) < 2000:
        return None
    try:
        dt = datetime(*[int(x) for x in m.groups()[:6]])
    except ValueError:
        return None
    tz = m.group(7)
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        dt -= sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
    return _utc_to_kyiv(dt)

def _alerts_flatten_regions(payload) -> list:
    """Дерево /api/v3/regions → плаский список {id, name, type, path, ancestors}."""
    out = []
    def walk(node, path, anc):
        if not isinstance(node, dict):
            return
        rid, name = node.get("regionId"), node.get("regionName")
        if rid is not None and name:
            out.append({"id": str(rid), "name": str(name), "type": str(node.get("regionType") or ""), "path": " › ".join(path + [str(name)]), "ancestors": list(anc)})
            path, anc = path + [str(name)], anc + [str(rid)]
        for k in ("regionChildIds", "children", "states"):
            for ch in node.get(k) or []:
                walk(ch, path, anc)
    for n in (payload if isinstance(payload, list) else [payload]):
        walk(n, [], [])
    return out

def _alerts_regions_cached(force: bool = False) -> list:
    if not force and _alert_regions_cache["items"] and time.time() - _alert_regions_cache["at"] < ALERT_REGIONS_TTL_SEC:
        return _alert_regions_cache["items"]
    items = _alerts_flatten_regions(_alerts_get("ukrainealarm", "/api/v3/regions"))
    if not items:
        raise AlertsApiError("ukrainealarm.com повернуло порожній список регіонів")
    _alert_regions_cache.update(at=time.time(), items=items)
    return items

def _alerts_suggest(items: list) -> list:
    """Початковий вибір для Дніпропетровщини: область + Криворізький/Дніпровський район. Користувач підтверджує вручну."""
    return [{"id": r["id"], "name": r["name"], "type": r["type"]} for r in items
            if r["type"].lower() == "state" and "дніпропетров" in r["name"].lower()]

def _alerts_parse_day(payload, region_ids: set, types: set, now: datetime) -> list:
    """ukrainealarm: відповідь dateHistory → тривоги обраних регіонів"""
    items = payload if isinstance(payload, list) else ((payload.get("alerts") or payload.get("items") or []) if isinstance(payload, dict) else [])
    rows, seen = [], set()
    for a in items:
        if not isinstance(a, dict):
            continue
        rid = str(a.get("regionId") or "")
        typ = str(a.get("alertType") or "UNKNOWN").upper()
        if rid not in region_ids or (types and typ not in types):
            continue
        st, en = _alerts_to_kyiv(a.get("startDate")), _alerts_to_kyiv(a.get("endDate"))
        if not st:
            continue
        cont = bool(a.get("isContinue"))
        if cont:
            en = max(en or st, now)                # тривога ще триває
        elif not en or en <= st:
            continue
        if (rid, typ, st) in seen:
            continue
        seen.add((rid, typ, st))
        rows.append({"region_id": rid, "region_name": str(a.get("regionName") or ""), "alert_type": typ, "start": st, "end": en, "cont": cont})
    return rows

def _alerts_parse_inua(payload, location_ids: set, types: set, now: datetime) -> list:
    """alerts.in.ua: відповідь month_ago → тривоги обраних локацій (за location_uid)"""
    items = payload if isinstance(payload, list) else ((payload.get("alerts") or []) if isinstance(payload, dict) else [])
    rows, seen = [], set()
    for a in items:
        if not isinstance(a, dict):
            continue
        uid = str(a.get("location_uid") or "")
        typ = _INUA_TYPES.get(str(a.get("alert_type") or "").upper(), "UNKNOWN")
        if uid not in location_ids or (types and typ not in types):
            continue
        st, en = _alerts_to_kyiv(a.get("started_at")), _alerts_to_kyiv(a.get("finished_at"))
        if not st:
            continue
        cont = en is None                          # finished_at = null — тривога триває
        if cont:
            en = max(st, now)
        elif en <= st:
            continue
        if (uid, typ, st) in seen:
            continue
        seen.add((uid, typ, st))
        rows.append({"region_id": uid, "region_name": str(a.get("location_title") or ""), "alert_type": typ, "start": st, "end": en, "cont": cont})
    return rows

def _alerts_cfg_hash(source, ids, types) -> str:
    return hashlib.sha1((source + "|" + ",".join(sorted(ids)) + "|" + ",".join(sorted(types))).encode("utf-8")).hexdigest()[:16]

def _alerts_merge(intervals: list) -> list:
    """Об'єднує тривоги, що перетинаються (різні регіони/типи), для показу: [{start, end, types, regions}]"""
    out = []
    for s, e, typ, reg in sorted(intervals, key=lambda x: (x[0], x[1])):
        if out and s <= out[-1]["end"]:
            out[-1]["end"] = max(out[-1]["end"], e)
            out[-1]["types"].add(typ)
            out[-1]["regions"].add(reg)
        else:
            out.append({"start": s, "end": e, "types": {typ}, "regions": {reg}})
    return out

def _alerts_store_rows(db, rows: list, day_of, scan_uid: Optional[str] = None):
    for r in rows:
        db.add(DBLessonAlert(day=day_of(r), region_id=r["region_id"], region_name=r["region_name"], alert_type=r["alert_type"],
                             start_dt=_sched_iso(r["start"]), end_dt=_sched_iso(r["end"]), is_continue=r["cont"], scan_uid=scan_uid))

ALERT_BACKFILL_GAP = 20.0            # стартова пауза між запитами у фоні, с (сама підлаштовується до ліміту, не більше 65 с)
ALERT_BACKFILL_MAX_GAP = 65.0
ALERT_TODAY_REFRESH_SEC = 600        # поточну добу оновлюємо раз на 10 хв
ALERT_ERROR_RETRY_SEC = 300          # день із помилкою (не ліміт) пробуємо ще раз через 5 хв
ALERT_HISTORY_FROM_DEFAULT = "2026-09-01"
_alert_worker = {"task": None, "pace": ALERT_BACKFILL_GAP, "ok": 0}

def _alerts_history_from(cfg) -> str:
    v = (cfg.history_from if cfg is not None and cfg.history_from else os.environ.get("ALERTS_HISTORY_FROM", "")) or ALERT_HISTORY_FROM_DEFAULT
    try:
        datetime.strptime(v, "%Y-%m-%d")
        return v
    except ValueError:
        return ALERT_HISTORY_FROM_DEFAULT

def _alerts_ids(regions, source) -> set:
    """Обрані регіони + їхні предки (тривога області чи району діє й на громаду)"""
    ids = {str(r["id"]) for r in regions}
    if source == "ukrainealarm":
        for r in regions:
            ids.update(str(x) for x in (r.get("ancestors") or []))
    return ids

def _alerts_backfill_state(db, cfg, now: datetime) -> dict:
    """Що з історії вже збережено остаточно, а що ще треба завантажити (у порядку важливості)."""
    regions = cfg.regions or []
    ids, types = _alerts_ids(regions, "ukrainealarm"), _alerts_types()
    cfg_hash = _alerts_cfg_hash("ukrainealarm", ids, types)
    start, today = _alerts_history_from(cfg), now.strftime("%Y-%m-%d")
    if start > today:
        start = today
    days, d = [], datetime.strptime(start, "%Y-%m-%d")
    while d.strftime("%Y-%m-%d") <= today and len(days) < 900:
        days.append(d.strftime("%Y-%m-%d"))
        d += timedelta(days=1)
    recs = {r.day: r for r in db.query(DBLessonAlertDay).filter(DBLessonAlertDay.day >= start, DBLessonAlertDay.day <= today).all()}
    with_cont = {x for (x,) in db.query(DBLessonAlert.day).filter(DBLessonAlert.day >= start, DBLessonAlert.is_continue.is_(True)).distinct().all()}
    lesson_days = {x for (x,) in db.query(DBLessonSchedItem.lesson_date).filter(DBLessonSchedItem.lesson_date >= start).distinct().all()}
    missing, stale = [], []
    for d in days:
        r = recs.get(d)
        if not r or r.cfg_hash != cfg_hash:
            missing.append(d)
            continue
        age = (now - _sched_dt(r.fetched_at)).total_seconds()
        if r.status == "error":
            if age >= ALERT_ERROR_RETRY_SEC:
                missing.append(d)
        elif r.fetched_at[:10] <= d or d in with_cont:           # доба ще тривала на момент завантаження → потрібне перезавантаження
            if d == today and age < ALERT_TODAY_REFRESH_SEC:
                stale.append(d)                                    # поточну добу оновлюємо не частіше, ніж раз на 10 хв
            else:
                missing.append(d)
    # порядок: поточна доба → дні з парами (свіжіші першими) → решта (свіжіші першими)
    order = sorted(missing, key=lambda x: (x != today, x not in lesson_days, -int(x.replace("-", ""))))
    return {"ids": ids, "types": types, "cfg_hash": cfg_hash, "start": start, "today": today, "days": days, "recs": recs,
            "need": order, "need_set": set(order), "done": len(days) - len(order)}

def _alerts_store_day(db, d: str, payload, ids, types, cfg_hash):
    stamp = _sched_iso(_sched_now())
    rows = _alerts_parse_day(payload, ids, types, _sched_now())
    db.query(DBLessonAlert).filter(DBLessonAlert.day == d).delete(synchronize_session=False)
    _alerts_store_rows(db, rows, lambda r, d=d: d)
    rec = db.query(DBLessonAlertDay).filter(DBLessonAlertDay.day == d).first() or DBLessonAlertDay(day=d, fetched_at=stamp)
    rec.status, rec.error, rec.count, rec.fetched_at, rec.cfg_hash = "ok", None, len(rows), stamp, cfg_hash
    db.add(rec)
    db.commit()

def _alerts_mark_error(db, d: str, err: str, cfg_hash):
    stamp = _sched_iso(_sched_now())
    rec = db.query(DBLessonAlertDay).filter(DBLessonAlertDay.day == d).first() or DBLessonAlertDay(day=d, fetched_at=stamp)
    rec.status, rec.error, rec.fetched_at, rec.cfg_hash = "error", err[:300], stamp, cfg_hash
    db.add(rec)
    db.commit()

async def _alerts_worker_step() -> float:
    """Один крок фонового завантаження історії: НЕ БІЛЬШЕ ОДНОГО запиту. Повертає, скільки секунд чекати до наступного кроку."""
    db = SessionLocal()
    try:
        cfg = db.query(DBLessonAlertConfig).first()
        if not cfg or not cfg.regions or (cfg.source or "ukrainealarm") != "ukrainealarm" or not _alerts_key("ukrainealarm"):
            return 60.0
        now = _sched_now()
        now_iso = _sched_iso(now)
        until = max(cfg.lease_until or "", cfg.cooldown_until or "")
        if until > now_iso:                                           # ще не час (пауза між запитами або ліміт API)
            return max(2.0, (_sched_dt(until) - now).total_seconds() + 0.5)
        st = _alerts_backfill_state(db, cfg, now)
        if not st["need"]:
            return 120.0
        d, pace = st["need"][0], _alert_worker["pace"]
        # резервуємо «слот» запиту в базі: так кілька процесів сервера не змагаються за один ліміт
        got = db.query(DBLessonAlertConfig).filter(DBLessonAlertConfig.id == cfg.id,
                                                    (DBLessonAlertConfig.lease_until.is_(None)) | (DBLessonAlertConfig.lease_until <= now_iso)
                                                    ).update({"lease_until": _sched_iso(now + timedelta(seconds=pace))}, synchronize_session=False)
        db.commit()
        if not got:
            return 5.0
        try:
            payload = await run_in_threadpool(_alerts_get, "ukrainealarm", "/api/v3/alerts/dateHistory", {"date": d.replace("-", "")})
        except AlertsApiError as e:
            if e.retry_after is not None:                             # ліміт: чекаємо, скільки просить API, і сповільнюємось
                wait = e.retry_after + 2
                cool = _sched_iso(_sched_now() + timedelta(seconds=wait))
                db.query(DBLessonAlertConfig).filter(DBLessonAlertConfig.id == cfg.id).update({"cooldown_until": cool, "lease_until": cool}, synchronize_session=False)
                db.commit()
                _alert_worker["pace"], _alert_worker["ok"] = min(ALERT_BACKFILL_MAX_GAP, pace * 1.5), 0
                return wait + 0.5
            _alerts_mark_error(db, d, str(e), st["cfg_hash"])         # інша помилка: позначили день, йдемо далі
            return pace
        except Exception as e:
            _alerts_mark_error(db, d, f"Помилка запиту ({e.__class__.__name__})", st["cfg_hash"])
            return pace
        _alerts_store_day(db, d, payload, st["ids"], st["types"], st["cfg_hash"])
        _alert_worker["ok"] += 1
        if _alert_worker["ok"] >= 5:                                  # довго без проблем — можна трохи швидше
            _alert_worker["pace"], _alert_worker["ok"] = max(ALERT_BACKFILL_GAP, pace * 0.8), 0
        return pace
    finally:
        db.close()

async def _alerts_worker_loop():
    while True:
        try:
            delay = await _alerts_worker_step()
        except Exception as e:                                        # ніколи не даємо працівнику впасти
            print(f"[alerts-worker] {e.__class__.__name__}: {e}")
            delay = 120.0
        await asyncio.sleep(max(1.0, delay))

def _alerts_worker_ensure():
    """Запускає фонового працівника, якщо його ще немає (на старті сервера і при відкритті екрана)."""
    t = _alert_worker["task"]
    if t is None or t.done():
        try:
            _alert_worker["task"] = asyncio.get_running_loop().create_task(_alerts_worker_loop())
        except RuntimeError:
            pass

@app.on_event("startup")
async def _alerts_worker_startup():
    _alerts_worker_ensure()

def _alerts_progress(db, cfg, now: datetime) -> dict:
    st = _alerts_backfill_state(db, cfg, now)
    until = max(cfg.lease_until or "", cfg.cooldown_until or "")
    wait = max(0, int((_sched_dt(until) - now).total_seconds()) + 1) if until > _sched_iso(now) else 0
    return {"from": st["start"], "total": len(st["days"]), "done": st["done"], "complete": not st["need"],
            "next_in": wait if st["need"] else 0, "rate_limited": bool(cfg.cooldown_until and cfg.cooldown_until > _sched_iso(now))}

async def _alerts_fetch_inua(db, ctx, ids, types, cfg_hash, scan_uids, d_from, now):
    """alerts.in.ua: один запит = місяць історії одного uid. Ліміт 2/хв, тому — не більше одного запиту за раз."""
    ctx["days_total"] = len(scan_uids)
    stale = []
    for uid in scan_uids:
        rec = db.query(DBLessonAlertDay).filter(DBLessonAlertDay.day == f"uid:{uid}").first()
        fresh = rec and rec.cfg_hash == cfg_hash and rec.status == "ok" and (now - _sched_dt(rec.fetched_at)).total_seconds() < ALERT_INUA_TTL_SEC
        if not fresh:
            stale.append(uid)
    limited = None
    if stale:
        uid = stale[0]
        stamp = _sched_iso(_sched_now())
        rec = db.query(DBLessonAlertDay).filter(DBLessonAlertDay.day == f"uid:{uid}").first() or DBLessonAlertDay(day=f"uid:{uid}", fetched_at=stamp)
        try:
            payload = await _alerts_call("alertsinua", f"/v1/regions/{uid}/alerts/month_ago.json")
            rows = _alerts_parse_inua(payload, ids, types, _sched_now())
            db.query(DBLessonAlert).filter(DBLessonAlert.scan_uid == uid).delete(synchronize_session=False)
            _alerts_store_rows(db, rows, lambda r: r["start"].strftime("%Y-%m-%d"), scan_uid=uid)
            rec.status, rec.error, rec.count = "ok", None, len(rows)
            rec.fetched_at, rec.cfg_hash = stamp, cfg_hash
            db.add(rec)
            stale = stale[1:]
        except AlertsApiError as e:
            if e.retry_after is not None:
                limited = e
            else:
                rec.status, rec.error, rec.fetched_at, rec.cfg_hash = "error", str(e), stamp, cfg_hash
                db.add(rec)
                ctx["ok"], ctx["error"] = False, str(e)
                stale = stale[1:]
        db.commit()
    ctx["pending_days"] = len(stale)
    if limited is not None:
        ctx["rate_limited"], ctx["retry_in"] = limited.kind == "limit", int(limited.retry_after) + 1
    elif stale:
        ctx["retry_in"] = int(_alert_rt["alertsinua"]["gap"]) + 2
    if d_from < (now - timedelta(days=30)).strftime("%Y-%m-%d"):
        ctx["history_limited"] = True                 # alerts.in.ua віддає лише останній місяць

async def _alerts_prepare(db, d_from: str, d_to: str) -> dict:
    """Готує тривоги для періоду: кеш → за потреби поступово докачує з API. Не кидає винятків:
    помилка/ліміт лише відображаються в ctx, а статуси рахуються з тим, що вже є."""
    types = _alerts_types()
    cfg = db.query(DBLessonAlertConfig).first()
    source = (cfg.source if cfg and cfg.source in ALERT_PROVIDERS else "ukrainealarm")
    regions = (cfg.regions if cfg and cfg.regions else [])
    ctx = {"source": source, "source_label": ALERT_PROVIDERS[source]["label"], "enabled": bool(_alerts_key(source)), "configured": bool(regions),
           "ok": True, "error": None, "regions": [r["name"] for r in regions], "types": sorted(types), "failed_days": [], "excuse_min": ALERT_EXCUSE_MIN,
           "pending_days": 0, "days_total": 0, "rate_limited": False, "retry_in": 0, "history_limited": False, "history_before_start": False,
           "backfill": None, "intervals": []}
    public_keys = ("source", "source_label", "enabled", "configured", "ok", "error", "regions", "types", "failed_days", "excuse_min",
                   "pending_days", "days_total", "rate_limited", "retry_in", "history_limited", "history_before_start", "backfill")
    def finish():
        ctx["public"] = {k: ctx[k] for k in public_keys} | {"days": ctx.get("pub_days", {})}
        return ctx
    if not ctx["enabled"] or not regions:
        return finish()
    ids = _alerts_ids(regions, source)
    now = _sched_now()
    if source == "alertsinua":
        cfg_hash = _alerts_cfg_hash(source, ids, types)
        scan = sorted({str(r["scan_uid"]) for r in regions if r.get("scan_uid")})
        await _alerts_fetch_inua(db, ctx, ids, types, cfg_hash, scan, d_from, now)
    else:
        # ukrainealarm: екран НЕ ходить в API — історію у фоні збирає працівник (повільно, у межах ліміту) і зберігає назавжди
        _alerts_worker_ensure()
        st = _alerts_backfill_state(db, cfg, now)
        lo_day = (datetime.strptime(d_from, "%Y-%m-%d") - timedelta(days=1)).strftime("%Y-%m-%d")
        in_range = [d for d in st["days"] if lo_day <= d <= d_to]
        pending = [d for d in in_range if d in st["need_set"] and not (d == st["today"] and d in st["recs"])]
        ctx["days_total"], ctx["pending_days"] = len(in_range), len(pending)
        ctx["backfill"] = _alerts_progress(db, cfg, now)
        if pending or not ctx["backfill"]["complete"]:
            ctx["retry_in"] = max(ctx["backfill"]["next_in"], int(_alert_worker["pace"]))
            ctx["rate_limited"] = ctx["backfill"]["rate_limited"]
        if d_from < st["start"]:
            ctx["history_before_start"] = True                        # історію до обраної дати не збираємо
        failed = [d for d in in_range if d in st["recs"] and st["recs"][d].status == "error" and d >= d_from]
        if failed:
            ctx["ok"], ctx["error"], ctx["failed_days"] = False, st["recs"][failed[0]].error, failed

    lo = (datetime.strptime(d_from, "%Y-%m-%d") - timedelta(days=1)).strftime("%Y-%m-%dT00:00:00")
    hi = d_to + "T23:59:59"
    ivs = sorted({(_sched_dt(a.start_dt), _sched_dt(a.end_dt), a.alert_type or "UNKNOWN", a.region_name or "")
                  for a in db.query(DBLessonAlert).filter(DBLessonAlert.start_dt <= hi, DBLessonAlert.end_dt >= lo).all()
                  if (source == "alertsinua") == bool(a.scan_uid)})
    ctx["intervals"] = ivs
    pub_days = {}
    for m in _alerts_merge(ivs):                       # тривога показується в кожному дні, якого торкається
        d = m["start"].date()
        while d <= m["end"].date():
            ds = d.strftime("%Y-%m-%d")
            if d_from <= ds <= d_to:
                day_s = datetime.combine(d, datetime.min.time())
                day_e = day_s + timedelta(days=1)
                s_, e_ = max(m["start"], day_s), min(m["end"], day_e)
                pub_days.setdefault(ds, []).append({
                    "start": s_.strftime("%H:%M"), "end": "24:00" if e_ >= day_e else e_.strftime("%H:%M"),
                    "types": sorted(m["types"]), "regions": sorted(m["regions"]),
                    "from_prev_day": m["start"] < day_s, "continues_next_day": m["end"] > day_e})
            d += timedelta(days=1)
    ctx["pub_days"] = {d: sorted(v, key=lambda x: x["start"]) for d, v in pub_days.items()}
    return finish()

# ── Налаштування й службові ендпоїнти ───────────────────────────
class AlertRegionSchema(BaseModel):
    id: str
    name: str
    type: Optional[str] = None
    scan_uid: Optional[str] = None
    ancestors: Optional[List[str]] = None

class AlertConfigSchema(BaseModel):
    source: str = "ukrainealarm"
    regions: List[AlertRegionSchema]
    history_from: Optional[str] = None          # з якої дати зберігати історію (YYYY-MM-DD)

def _alerts_err_http(e: AlertsApiError):
    return HTTPException(status_code=429 if e.retry_after is not None else 502,
                         detail=str(e) + (f". Спробуйте за {int(e.retry_after) + 1} с" if e.retry_after is not None else ""))

@app.get("/api/cmyo/schedule/alerts/config")
async def get_alerts_config(user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)):
    cfg = db.query(DBLessonAlertConfig).first()
    source = (cfg.source if cfg and cfg.source in ALERT_PROVIDERS else "ukrainealarm")
    saved = (cfg.regions if cfg and cfg.regions else [])
    out = {"source": source, "saved": bool(saved), "regions": saved, "suggested": [], "excuse_min": ALERT_EXCUSE_MIN, "ok_ratio": SCHED_OK_RATIO,
           "providers": {p: {"label": v["label"], "key_env": v["key_env"], "enabled": bool(_alerts_key(p))} for p, v in ALERT_PROVIDERS.items()},
           "types": [{"code": t, "label": ALERT_TYPE_LABELS.get(t, t)} for t in sorted(_alerts_types())],
           "updated_at": _sched_fmt_label(cfg.updated_at) if cfg else None}
    out["enabled"] = out["providers"][source]["enabled"]
    out["history_from"] = _alerts_history_from(cfg)
    out["history_from_default"] = ALERT_HISTORY_FROM_DEFAULT
    if saved and source == "ukrainealarm" and out["enabled"]:
        out["progress"] = _alerts_progress(db, cfg, _sched_now())
    if not saved and out["providers"]["ukrainealarm"]["enabled"]:
        try:
            out["suggested"] = _alerts_suggest(await run_in_threadpool(_alerts_regions_cached))
        except AlertsApiError as e:
            out["suggest_error"] = str(e)
    return out

@app.get("/api/cmyo/schedule/alerts/regions")
async def search_alert_regions(q: str = Query(default=""), user: dict = Depends(require_cmyo_admin)):
    """Пошук регіонів у довіднику ukrainealarm.com"""
    try:
        items = await run_in_threadpool(_alerts_regions_cached)
    except AlertsApiError as e:
        raise _alerts_err_http(e)
    needle = (q or "").strip().lower()
    items = [r for r in items if r["type"].lower() == "state"] if not needle else [r for r in items if needle in r["name"].lower() or needle in r["path"].lower()]
    return items[:40]

@app.get("/api/cmyo/schedule/alerts/scan")
async def scan_alerts_locations(uid: str = Query(..., min_length=1, max_length=12), user: dict = Depends(require_cmyo_admin)):
    """alerts.in.ua: які локації (область/район/громада/місто) трапляються в місячній історії цього uid. Звідси користувач обирає свою."""
    uid = re.sub(r"\D", "", uid)
    if not uid:
        raise HTTPException(status_code=400, detail="UID має бути числом (наприклад, 9 — Дніпропетровська область)")
    hit = _alert_scan_cache.get(uid)
    if hit and time.time() - hit[0] < 600:
        return hit[1]
    try:
        payload = await _alerts_call("alertsinua", f"/v1/regions/{uid}/alerts/month_ago.json")
    except AlertsApiError as e:
        raise _alerts_err_http(e)
    items = payload if isinstance(payload, list) else ((payload.get("alerts") or []) if isinstance(payload, dict) else [])
    locs = {}
    for a in items:
        if not isinstance(a, dict) or a.get("location_uid") is None:
            continue
        k = str(a["location_uid"])
        d = locs.setdefault(k, {"uid": k, "title": str(a.get("location_title") or k), "type": str(a.get("location_type") or ""),
                                "raion": a.get("location_raion"), "count": 0, "last": None})
        d["count"] += 1
        st = _alerts_to_kyiv(a.get("started_at"))
        if st and (d["last"] is None or _sched_iso(st) > d["last"]):
            d["last"] = _sched_iso(st)
    res = {"scan_uid": uid, "alerts": len(items), "locations": sorted(locs.values(), key=lambda x: (-x["count"], x["title"]))}
    _alert_scan_cache[uid] = (time.time(), res)
    return res

@app.put("/api/cmyo/schedule/alerts/config")
async def put_alerts_config(data: AlertConfigSchema, user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)):
    if data.source not in ALERT_PROVIDERS:
        raise HTTPException(status_code=400, detail="Невідоме джерело тривог")
    if not data.regions:
        raise HTTPException(status_code=400, detail="Оберіть хоча б один регіон")
    if len(data.regions) > 30:
        raise HTTPException(status_code=400, detail="Забагато регіонів (максимум 30)")
    seen, regions = set(), []
    for r in data.regions:
        rid = r.id.strip()
        if not rid or rid in seen:
            continue
        if data.source == "alertsinua" and not (r.scan_uid or "").strip():
            raise HTTPException(status_code=400, detail="Для alerts.in.ua кожну локацію потрібно обрати зі списку «Знайти локації»")
        seen.add(rid)
        item = {"id": rid, "name": _clean(r.name)[:200], "type": (r.type or "")[:30]}
        if r.scan_uid:
            item["scan_uid"] = re.sub(r"\D", "", r.scan_uid)[:12]
        if r.ancestors:
            item["ancestors"] = [str(x)[:40] for x in r.ancestors[:6]]
        regions.append(item)
    hist = None
    if data.history_from:
        try:
            hist = datetime.strptime(data.history_from.strip(), "%Y-%m-%d").strftime("%Y-%m-%d")
        except ValueError:
            raise HTTPException(status_code=400, detail="Невірна дата початку історії (потрібно РРРР-ММ-ДД)")
        if hist < "2022-02-24" or hist > _sched_now().strftime("%Y-%m-%d"):
            raise HTTPException(status_code=400, detail="Дата початку історії має бути між 24.02.2022 і сьогодні")
    cfg = db.query(DBLessonAlertConfig).first()
    if not cfg:
        cfg = DBLessonAlertConfig()
        db.add(cfg)
    types = _alerts_types()
    old_sig = (_alerts_cfg_hash(cfg.source or "ukrainealarm", _alerts_ids(cfg.regions or [], cfg.source or "ukrainealarm"), types) if cfg.regions else None)
    new_sig = _alerts_cfg_hash(data.source, _alerts_ids(regions, data.source), types)
    cfg.source, cfg.regions, cfg.updated_at, cfg.updated_by = data.source, regions, _sched_iso(_sched_now()), user.get("sub")
    if hist:
        cfg.history_from = hist
    if old_sig != new_sig:       # інше джерело чи регіони — стару історію не змішуємо: скидаємо збережене (якщо змінилась лише дата початку — нічого не втрачаємо)
        db.query(DBLessonAlert).delete(synchronize_session=False)
        db.query(DBLessonAlertDay).delete(synchronize_session=False)
    db.commit()
    _alerts_worker_ensure()
    return {"source": data.source, "regions": regions, "history_from": _alerts_history_from(cfg)}

@app.post("/api/cmyo/schedule/alerts/check")
async def check_alerts_api(source: str = Query(default="ukrainealarm"), user: dict = Depends(require_cmyo_admin)):
    """Перевірка ключа і зв'язку з обраним джерелом тривог"""
    if source not in ALERT_PROVIDERS:
        raise HTTPException(status_code=400, detail="Невідоме джерело тривог")
    pv = ALERT_PROVIDERS[source]
    if not _alerts_key(source):
        return {"ok": False, "error": f"Не задано змінну {pv['key_env']} на сервері"}
    try:
        if source == "ukrainealarm":
            return {"ok": True, "info": f"Зв'язок є, регіонів у довіднику: {len(await run_in_threadpool(_alerts_regions_cached, True))}"}
        await _alerts_call("alertsinua", "/v1/alerts/active.json")
        return {"ok": True, "info": "Зв'язок із alerts.in.ua є, токен прийнято"}
    except AlertsApiError as e:
        return {"ok": False, "error": str(e), "retry_in": int(e.retry_after) + 1 if e.retry_after is not None else None}

class AlertsRefreshSchema(BaseModel):
    date_from: str
    date_to: Optional[str] = None

@app.post("/api/cmyo/schedule/alerts/refresh")
async def refresh_alerts(data: AlertsRefreshSchema, user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)):
    """Перезавантажує свіжі дані. Збережена історія минулих днів не змінюється, тому для ukrainealarm скидаємо лише вчора й сьогодні
    (щоб не витрачати ліміт API на те, що вже є); для alerts.in.ua — місячну історію."""
    d_from = _parse_iso_date(data.date_from, "Від")
    d_to = _parse_iso_date(data.date_to, "До") or d_from
    cfg = db.query(DBLessonAlertConfig).first()
    if cfg and cfg.source == "alertsinua":
        n = db.query(DBLessonAlertDay).filter(DBLessonAlertDay.day.like("uid:%")).delete(synchronize_session=False)
    else:
        recent = (_sched_now() - timedelta(days=1)).strftime("%Y-%m-%d")
        n = db.query(DBLessonAlertDay).filter(DBLessonAlertDay.day >= max(recent, d_from), DBLessonAlertDay.day <= d_to,
                                              ~DBLessonAlertDay.day.like("uid:%")).delete(synchronize_session=False)
    db.commit()
    _alerts_worker_ensure()
    return {"reset_days": n}


@app.get("/api/cmyo/schedule/overview")
async def schedule_overview(date_from: str, date_to: Optional[str] = None,
                            user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)):
    d_from = _parse_iso_date(date_from, "Від")
    d_to = _parse_iso_date(date_to, "До") or d_from
    if d_to < d_from:
        d_from, d_to = d_to, d_from
    if (datetime.strptime(d_to, "%Y-%m-%d") - datetime.strptime(d_from, "%Y-%m-%d")).days > 62:
        raise HTTPException(status_code=400, detail="Максимальний період — 62 дні")

    teachers = {t.id: t for t in db.query(DBLessonTeacher).all()}
    items = db.query(DBLessonSchedItem).filter(DBLessonSchedItem.lesson_date >= d_from, DBLessonSchedItem.lesson_date <= d_to)\
        .order_by(DBLessonSchedItem.lesson_date, DBLessonSchedItem.start_time).all()

    accounts = db.query(DBLessonZoomAccount).filter(DBLessonZoomAccount.lesson_teacher_id.isnot(None),
                                                    DBLessonZoomAccount.link_status.in_(("auto", "manual"))).all()
    acc_by_teacher = defaultdict(set)
    for a in accounts:
        acc_by_teacher[a.lesson_teacher_id].add(a.id)
    range_s = _sched_iso(datetime.strptime(d_from, "%Y-%m-%d") - timedelta(hours=6))
    range_e = _sched_iso(datetime.strptime(d_to, "%Y-%m-%d") + timedelta(days=1, hours=6))
    meetings = db.query(DBLessonZoomMeeting).filter(DBLessonZoomMeeting.start_dt >= range_s, DBLessonZoomMeeting.start_dt <= range_e).all()
    m_by_acc = defaultdict(list)
    m_by_mid = defaultdict(list)
    for m in meetings:
        m_by_acc[m.account_id].append(m)
        if m.meeting_id:
            m_by_mid[m.meeting_id].append(m)
    cov, global_until = _sched_zoom_coverage(db)
    alerts_ctx = await _alerts_prepare(db, d_from, d_to)      # тривоги обраних регіонів (з кешу або з API)

    cards = {}
    used_meeting_ids = defaultdict(set)
    for it in items:
        t = teachers.get(it.lesson_teacher_id)
        if not t:
            continue
        slot_s = datetime.strptime(f"{it.lesson_date} {it.start_time}", "%Y-%m-%d %H:%M")
        slot_e = slot_s + timedelta(minutes=SCHED_SLOT_MINUTES)
        cand = []
        for aid in acc_by_teacher.get(t.id, ()):
            cand.extend(m_by_acc.get(aid, ()))
        if it.zoom_meeting_id:
            cand.extend(m_by_mid.get(it.zoom_meeting_id, ()))
        seen, ivs, hit = set(), [], []
        for m in cand:
            if m.id in seen:
                continue
            seen.add(m.id)
            ms, me = _sched_dt(m.start_dt), _sched_dt(m.end_dt)
            if min(me, slot_e) > max(ms, slot_s):
                ivs.append((ms, me))
                hit.append(m)
                used_meeting_ids[t.id].add(m.id)
        overlap = _sched_overlap_minutes(slot_s, slot_e, ivs)
        covered = any(a <= slot_s and slot_e <= b + timedelta(minutes=5) for a, b in cov)
        status = _sched_lesson_status(it, slot_s, slot_e, overlap, bool(acc_by_teacher.get(t.id)), covered, global_until)
        # тривога — офіційна підстава не проводити пару: якщо Zoom разом із тривогою покривають пару достатньо — статус «Тривога»
        a_hit = [a for a in alerts_ctx["intervals"] if min(a[1], slot_e) > max(a[0], slot_s)]
        alert_min = _sched_overlap_minutes(slot_s, slot_e, [(a[0], a[1]) for a in a_hit]) if a_hit else 0.0
        if status in ("missed", "partial") and alert_min >= ALERT_EXCUSE_MIN:
            if _sched_overlap_minutes(slot_s, slot_e, ivs + [(a[0], a[1]) for a in a_hit]) >= SCHED_SLOT_MINUTES * SCHED_OK_RATIO:
                status = "alert"
        card = cards.setdefault(t.id, {"id": t.id, "name": t.name, "has_account": bool(acc_by_teacher.get(t.id)), "note": t.note,
                                       "counts": defaultdict(int), "planned_min": 0, "conducted_min": 0, "lessons": [], "other_meetings": []})
        card["counts"][status] += 1
        if status in ("ok", "partial", "missed"):
            card["planned_min"] += SCHED_SLOT_MINUTES
            card["conducted_min"] += int(round(min(overlap, SCHED_SLOT_MINUTES)))
        card["lessons"].append({
            "id": it.id, "date": it.lesson_date, "start": it.start_time, "end": slot_e.strftime("%H:%M"), "slot_no": it.slot_no,
            "subject": it.subject_name, "type": it.lesson_type, "groups": it.groups_text, "place": it.place, "online": bool(it.is_online),
            "note": it.note, "substitute_for": (it.source_owner if it.source_owner and _norm(it.source_owner) != t.name_norm else None),
            "status": status, "overlap_min": int(round(overlap)),
            "alert_min": int(round(alert_min)),
            "alerts": [{"start": max(m["start"], slot_s).strftime("%H:%M"), "end": min(m["end"], slot_e).strftime("%H:%M"),
                        "types": sorted(m["types"]), "regions": sorted(m["regions"])} for m in _alerts_merge(a_hit)],
            # у зустрічах під час пари був лише ведучий — студентів не було
            "alone": bool(hit) and max((m.participants or 0) for m in hit) <= 1,
            "meetings": [{"topic": m.topic, "start": _sched_dt(m.start_dt).strftime("%H:%M"), "end": _sched_dt(m.end_dt).strftime("%H:%M"),
                          "duration_min": int(round(m.duration_sec / 60)), "participants": m.participants, "organizer": m.organizer_name}
                         for m in sorted(hit, key=lambda x: x.start_dt)],
        })
    # зустрічі викладача в ці дні, що не потрапили в жоден слот розкладу
    for tid, card in cards.items():
        for aid in acc_by_teacher.get(tid, ()):
            for m in m_by_acc.get(aid, ()):
                ds = m.start_dt[:10]
                if m.id in used_meeting_ids[tid] or ds < d_from or ds > d_to or m.duration_sec < 300:
                    continue
                card["other_meetings"].append({"date": ds, "start": _sched_dt(m.start_dt).strftime("%H:%M"), "end": _sched_dt(m.end_dt).strftime("%H:%M"),
                                               "duration_min": int(round(m.duration_sec / 60)), "topic": m.topic, "participants": m.participants})
        card["other_meetings"].sort(key=lambda x: (x["date"], x["start"]))
        card["other_meetings"] = card["other_meetings"][:12]
        card["counts"] = dict(card["counts"])

    summary = defaultdict(int)
    for c in cards.values():
        for k, v in c["counts"].items():
            summary[k] += v
    rng = db.query(func.min(DBLessonSchedItem.lesson_date), func.max(DBLessonSchedItem.lesson_date)).first()
    last_sched = db.query(DBLessonSchedBatch).filter(DBLessonSchedBatch.kind == "schedule").order_by(DBLessonSchedBatch.id.desc()).first()
    last_zoom = db.query(DBLessonSchedBatch).filter(DBLessonSchedBatch.kind == "zoom").order_by(DBLessonSchedBatch.id.desc()).first()
    return {
        "date_from": d_from, "date_to": d_to, "slot_minutes": SCHED_SLOT_MINUTES,
        "alerts": alerts_ctx["public"],
        "coverage": {
            "schedule_from": rng[0], "schedule_to": rng[1],
            "schedule_uploaded": _sched_fmt_label(last_sched.created_at) if last_sched else None,
            "zoom_from": _sched_iso(min(c[0] for c in cov)) if cov else None,
            "zoom_until": _sched_iso(global_until) if global_until else None,
            "zoom_uploaded": _sched_fmt_label(last_zoom.created_at) if last_zoom else None,
        },
        "summary": {"teachers": len(cards), "lessons": sum(summary.values()), **dict(summary)},
        "teachers": sorted(cards.values(), key=lambda c: c["name"]),
    }

# ── Акаунти Zoom ↔ викладачі ────────────────────────────────────
class ZoomAccountLinkSchema(BaseModel):
    teacher_id: Optional[int] = None
    ignore: bool = False

@app.get("/api/cmyo/schedule/zoom-accounts")
async def list_zoom_accounts(user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)):
    teachers = db.query(DBLessonTeacher).order_by(DBLessonTeacher.name).all()
    tname = {t.id: t.name for t in teachers}
    index = _zm_teacher_index(teachers)
    counts = dict(db.query(DBLessonZoomMeeting.account_id, func.count(DBLessonZoomMeeting.id)).group_by(DBLessonZoomMeeting.account_id).all())
    out, linked_teachers = [], set()
    for a in db.query(DBLessonZoomAccount).order_by(DBLessonZoomAccount.display_name).all():
        sugg = []
        if not a.lesson_teacher_id and a.link_status != "ignored":
            g = _zm_guess(a.email_key if "@" in a.email_key else "", a.display_name or "", index)
            sugg = [{"id": i, "name": tname[i]} for i in g["suggestions"] if i in tname]
        if a.lesson_teacher_id:
            linked_teachers.add(a.lesson_teacher_id)
        out.append({"id": a.id, "email": a.email_key if "@" in a.email_key else None, "name": a.display_name,
                    "meetings": counts.get(a.id, 0), "teacher_id": a.lesson_teacher_id, "teacher_name": tname.get(a.lesson_teacher_id),
                    "status": a.link_status if a.lesson_teacher_id or a.link_status == "ignored" else "none", "suggestions": sugg})
    sched_counts = dict(db.query(DBLessonSchedItem.lesson_teacher_id, func.count(DBLessonSchedItem.id))
                        .filter(DBLessonSchedItem.is_online.is_(True)).group_by(DBLessonSchedItem.lesson_teacher_id).all())
    without = [{"id": tid, "name": tname[tid], "lessons": n} for tid, n in sched_counts.items() if tid in tname and tid not in linked_teachers]
    return {"accounts": out, "teachers": [{"id": t.id, "name": t.name} for t in teachers],
            "teachers_without_account": sorted(without, key=lambda x: x["name"])}

@app.put("/api/cmyo/schedule/zoom-accounts/{account_id}")
async def link_zoom_account(account_id: int, data: ZoomAccountLinkSchema,
                            user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)):
    a = db.query(DBLessonZoomAccount).filter(DBLessonZoomAccount.id == account_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Акаунт не знайдено")
    if data.teacher_id:
        if not db.query(DBLessonTeacher.id).filter(DBLessonTeacher.id == data.teacher_id).first():
            raise HTTPException(status_code=404, detail="Викладача не знайдено в списку")
        a.lesson_teacher_id, a.link_status = data.teacher_id, "manual"
    elif data.ignore:
        a.lesson_teacher_id, a.link_status = None, "ignored"
    else:
        a.lesson_teacher_id, a.link_status = None, "none"
    db.commit()
    return {"id": a.id, "teacher_id": a.lesson_teacher_id, "status": a.link_status}

@app.post("/api/cmyo/schedule/zoom-accounts/relink")
async def relink_zoom_accounts(user: dict = Depends(require_cmyo_admin), db: Session = Depends(get_db)):
    """Повторно шукає викладачів для ще не прив'язаних акаунтів (наприклад, після поповнення списку викладачів)."""
    n = _zm_autolink(db, db.query(DBLessonZoomAccount).all(), db.query(DBLessonTeacher).all())
    db.commit()
    return {"linked": n}

# =========================================================
# 📝 ГЕНЕРАТОР ЗАЯВ ЦСК
# =========================================================
@app.get("/api/csk/generator/config")
async def get_generator_config(user: dict = Depends(require_csk_admin)):
    try:
        with open('config/config.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Config error: {e}")
        return {"application_reasons": {}}

@app.get("/api/csk/generator/students")
async def search_gen_students(
    q: str = "", db: Session = Depends(get_db), user: dict = Depends(require_csk_admin)
):
    if not q: return []
    students = db.query(DBUser).filter(DBUser.role == "student", DBUser.full_name.ilike(f"%{q}%")).limit(10).all()
    res = []
    for s in students:
        s_data = s.student_data if isinstance(s.student_data, dict) else {}
        studies = s_data.get("навчання", [])
        if not studies:
            res.append({"id": f"{s.id}_0", "text": f"{s.full_name} (Немає даних про групу)"})
        else:
            for idx, study in enumerate(studies):
                group = study.get("Група", "Невідомо")
                spec = study.get("Спеціальність", "")
                res.append({"id": f"{s.id}_{idx}", "text": f"{s.full_name} — {group} ({spec})"})
    return res

@app.get("/api/csk/generator/student/{composite_id}")
async def get_gen_student_data(
    composite_id: str, db: Session = Depends(get_db), user: dict = Depends(require_csk_admin)
):
    parts = composite_id.split("_")
    student_id = parts[0]
    study_idx = int(parts[1]) if len(parts) > 1 else 0
    student = db.query(DBUser).filter(DBUser.id == student_id).first()
    if not student:
        raise HTTPException(status_code=404, detail="Студента не знайдено")
    name_parts = student.full_name.split() if student.full_name else ["", "", ""]
    orig_last_name = name_parts[0] if len(name_parts) > 0 else "Прізвище"
    first_name = name_parts[1] if len(name_parts) > 1 else "Ім'я"
    patronymic = name_parts[2] if len(name_parts) > 2 else "Побатькові"
    gender = GrammaticalGender.FEMININE if patronymic.lower().endswith('на') else GrammaticalGender.MASCULINE
    student_title = "Здобувачки вищої освіти" if gender == GrammaticalGender.FEMININE else "Здобувача вищої освіти"
    try:
        person = DeclensionInput(givenName=first_name, familyName=orig_last_name, patronymicName=patronymic, gender=gender)
        declined = in_genitive(person)
        fn_gen, pn_gen, ln_gen = declined['givenName'], declined['patronymicName'], declined['familyName']
        if gender == GrammaticalGender.MASCULINE and orig_last_name.lower().endswith('ий'):
            ln_gen = orig_last_name[:-2] + "ого"
        ln_gen_title = ln_gen.title()
        ln_gen = ln_gen.upper()
    except Exception:
        fn_gen, ln_gen, pn_gen = first_name, orig_last_name.upper(), patronymic
        ln_gen_title = orig_last_name.title()
    s_data = student.student_data if isinstance(student.student_data, dict) else {}
    studies = s_data.get("навчання", [])
    navch = studies[study_idx] if study_idx < len(studies) else {}
    academic_unit_full = navch.get("Підрозділ", "")
    if academic_unit_full and not academic_unit_full.isupper():
        academic_unit_full = academic_unit_full[0].lower() + academic_unit_full[1:]
    funding_raw = str(navch.get("Фінансування", "")).lower()
    funding_source = " державним замовленням" if "бюджет" in funding_raw else " кошти фізичних осіб"
    course_val = str(navch.get("Курс", ""))
    phone = s_data.get("Телефон", "")
    return {
        "course": course_val, "group": navch.get("Група", ""),
        "spec": navch.get("Спеціальність", ""), "academic_unit": academic_unit_full,
        "edu_form": navch.get("Форма", "денної").lower(),
        "name": f"{fn_gen} {ln_gen}", "first_name": fn_gen, "last_name": ln_gen,
        "last_name_title": ln_gen_title, "patronymic": pn_gen, "student_title": student_title,
        "phone": phone, "funding_source": funding_source
    }

@app.post("/api/csk/generator/generate")
async def generate_document(data: dict, user: dict = Depends(require_csk_admin)):
    doc_type = data.get('doc_type')
    if doc_type == 'template_application_lost_doc_graduate':
        lost_doc = data.get('document', '')
        if 'та' in lost_doc: data['pronoun'] = 'їх'
        elif 'книжки' in lost_doc: data['pronoun'] = 'її'
        else: data['pronoun'] = 'його'
    for key in ['academic_unit', 'academic_unit_new', 'academic_unit_prev', 'uni_unit_prev']:
        val = data.get(key, '').strip()
        if val and not val.isupper(): data[key] = val[0].lower() + val[1:]
    reason_doc = data.get('reason_document', '').strip()
    if reason_doc:
        data['reason_document'] = f"2. {reason_doc}." if doc_type == 'template_application_individual' else f"До заяви додаю:\n1. {reason_doc}."
    if data.get('last_name_new'):
        data['last_name_new_r'] = data['last_name_new'].upper()
        data['last_name_new'] = data['last_name_new'].upper()
    if doc_type == 'template_application_refund' and data.get('amount'):
        try:
            amount_float = float(data['amount'].replace(',', '.'))
            hrn_int, kop_int = int(amount_float), int(round((amount_float - int(amount_float)) * 100))
            hrn_text = num2words(hrn_int, lang='uk')
            if hrn_text.endswith('один'): hrn_text = hrn_text[:-4] + 'одна'
            if hrn_text.endswith('два'): hrn_text = hrn_text[:-3] + 'дві'
            data['amount_text'] = f"{hrn_text} гривень {kop_int:02d} копійок"
        except Exception: pass
    data['war_doc'] = " військово-облікового документу," if "здобувача" in data.get('student_title', '').lower() else ""
    name_parts = data.get('name', '').strip().split()
    if len(name_parts) >= 2:
        data['initials_signature'] = f"{name_parts[0].title()} {name_parts[1][0].upper()}." + (f"{name_parts[2][0].upper()}." if len(name_parts)>2 else "")
    else:
        data['initials_signature'] = data.get('name', '')
    for field in ['date_deduction', 'date_start', 'date_end', 'marriage_cert_date', 'date_renewal', 'order_date']:
        if data.get(field):
            try: data[field] = f"{datetime.strptime(data[field], '%Y-%m-%d').strftime('%d.%m.%Y')} р."
            except Exception: pass
    data['date_now'] = f"{datetime.now().strftime('%d.%m.%Y')} р."
    path = os.path.abspath(f"config/templates/{doc_type}.docx")
    try:
        doc = DocxTemplate(path)
        doc.render(data)
        output = io.BytesIO()
        doc.save(output)
        output.seek(0)
        safe_last = data.get('last_name', 'Student').replace(' ', '_').title()
        safe_group = data.get('group', 'Group').replace(' ', '_')
        filename = f"{doc_type.split('_')[-1]}_{safe_last}_{safe_group}_{datetime.now().strftime('%d.%m.%Y')}.docx"
        encoded_filename = quote(filename)
        return StreamingResponse(
            output,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": f"attachment; filename*=UTF-8''{encoded_filename}"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Генерація помилка: {str(e)}")

# =========================================================
# 📄 ЗАМОВЛЕННЯ ДОВІДОК
# =========================================================
@app.post("/api/student/certificates")
async def create_certificate_request(
    req: CertRequestCreateSchema,
    user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    new_req = DBCertificateRequest(
        student_id=user["user_id"], doc_type=req.doc_type, details=req.details
    )
    db.add(new_req)
    db.commit()
    return {"message": "Заявку успішно створено!"}

@app.get("/api/student/certificates")
async def get_my_certificate_requests(
    user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    return db.query(DBCertificateRequest).filter(
        DBCertificateRequest.student_id == user["user_id"]
    ).order_by(DBCertificateRequest.id.desc()).all()

@app.get("/api/csk/certificates")
async def get_all_certificate_requests(
    admin: dict = Depends(require_csk_admin), db: Session = Depends(get_db)
):
    requests = db.query(DBCertificateRequest).order_by(DBCertificateRequest.id.desc()).all()
    result = []
    for r in requests:
        student = db.query(DBUser).filter(DBUser.id == r.student_id).first()
        result.append({
            "id": r.id, "doc_type": r.doc_type, "details": r.details,
            "status": r.status, "admin_comment": r.admin_comment,
            "created_at": r.created_at, "completed_at": r.completed_at,
            "student_name": student.full_name if student else "Невідомий",
            "student_email": student.email if student else "",
            "student_data": student.student_data if student else {}
        })
    return result

@app.put("/api/csk/certificates/{req_id}/status")
async def update_certificate_status(
    req_id: int, status_data: CertStatusUpdateSchema, request: Request,
    admin: dict = Depends(require_csk_admin), db: Session = Depends(get_db)
):
    req = db.query(DBCertificateRequest).filter(DBCertificateRequest.id == req_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Заявку не знайдено")
    req.status = status_data.status
    req.admin_comment = status_data.admin_comment
    if status_data.status in ["ready", "rejected"]:
        req.completed_at = datetime.now().strftime("%d.%m.%Y %H:%M")
    write_audit(db, request,
        action="update", user=admin, content_type="Certificates | Довідки",
        object_id=req_id, object_repr=req.doc_type,
        details={"status": status_data.status, "comment": status_data.admin_comment},
    )
    db.commit()
    return {"message": "Статус оновлено!"}

@app.delete("/api/superadmin/certificates/{req_id}")
async def delete_certificate_request(
    req_id: int, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    req = db.query(DBCertificateRequest).filter(DBCertificateRequest.id == req_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Заявку не знайдено")
    write_audit(db, request,
        action="delete", user=admin, content_type="Certificates | Довідки",
        object_id=req_id, object_repr=req.doc_type,
    )
    db.delete(req)
    db.commit()
    return {"message": "Заявку видалено"}

@app.get("/api/superadmin/audit")
async def get_audit_logs(
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db),
    limit: int = Query(default=50, le=200), offset: int = Query(default=0),
    action: str = Query(default=None), search: str = Query(default=None),
):
    q = db.query(DBAuditLog)
    if action and action != "all":
        q = q.filter(DBAuditLog.action == action)
    if search:
        q = q.filter(DBAuditLog.user_email.ilike(f"%{search}%"))
    total = q.count()
    logs = q.order_by(DBAuditLog.id.desc()).offset(offset).limit(limit).all()
    return {
        "total": total,
        "logs": [{
            "id": l.id, "timestamp": l.timestamp, "user_email": l.user_email,
            "ip_address": l.ip_address, "user_agent": l.user_agent, "path": l.path,
            "method": l.method, "action": l.action, "content_type": l.content_type,
            "object_id": l.object_id, "object_repr": l.object_repr, "details": l.details,
        } for l in logs],
    }

@app.delete("/api/superadmin/audit")
async def clear_audit_logs(
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db),
):
    deleted = db.query(DBAuditLog).delete()
    db.commit()
    return {"message": f"Видалено {deleted} записів"}

# =========================================================
# 🏓 PING
# =========================================================
@app.get("/api/structure/tree")
async def get_structure_tree(
    user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    """Повертає повне дерево: Інститут → Кафедра (+ викладачі) → ОПП (+ предмети: семестр/форма
    контролю) → Навчальний план (+ групи, + години предметів у цьому плані)."""
    institutes = db.query(DBInstitute).order_by(DBInstitute.name).all()
    result = []
    for inst in institutes:
        departments = db.query(DBDepartment).filter(DBDepartment.institute_id == inst.id).order_by(DBDepartment.name).all()
        dept_list = []
        for dept in departments:
            teachers = db.query(DBTeacher).filter(DBTeacher.department_id == dept.id).order_by(DBTeacher.full_name).all()
            opps = db.query(DBOpp).filter(DBOpp.department_id == dept.id).order_by(DBOpp.name).all()
            opp_list = []
            for opp in opps:
                subjects = db.query(DBSubject).filter(DBSubject.opp_id == opp.id).order_by(DBSubject.semester, DBSubject.name).all()
                plans = db.query(DBStudyPlan).filter(DBStudyPlan.opp_id == opp.id).order_by(DBStudyPlan.name).all()
                plan_list = []
                for plan in plans:
                    groups = db.query(DBAcademicGroup).filter(DBAcademicGroup.study_plan_id == plan.id).order_by(DBAcademicGroup.name).all()
                    hours_rows = db.query(DBPlanSubjectHours).filter(DBPlanSubjectHours.study_plan_id == plan.id).all()
                    plan_list.append({
                        "id": plan.id, "name": plan.name,
                        "groups": [{"id": g.id, "name": g.name, "level": g.level} for g in groups],
                        "subject_hours": [_plan_subject_hours_to_dict(h) for h in hours_rows],
                    })
                opp_list.append({
                    "id": opp.id, "name": opp.name, "level": opp.level, "full_name": opp.full_name,
                    "subjects": [_subject_to_dict(s) for s in subjects],
                    "plans": plan_list
                })
            dept_list.append({
                "id": dept.id, "name": dept.name, "full_name": dept.full_name,
                "teachers": [_teacher_to_dict(t) for t in teachers],
                "opps": opp_list
            })
        result.append({
            "id": inst.id, "name": inst.name, "full_name": inst.full_name,
            "departments": dept_list
        })
    return result

@app.get("/api/ping")
async def ping(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ok", "db": "awake"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}