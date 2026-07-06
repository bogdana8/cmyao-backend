from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import List, Optional, Generator
import uuid
from sqlalchemy import create_engine, Column, String, Integer, JSON, ForeignKey, Boolean, text
from sqlalchemy.orm import declarative_base, sessionmaker, Session
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================================================
# 🛡️ RATE LIMITER
# =========================================================
_login_attempts: dict = defaultdict(list)
LOGIN_RATE_LIMIT = 10
LOGIN_RATE_WINDOW = 60 * 15

def check_login_rate_limit(request: Request):
    ip = request.client.host
    now = time.time()
    _login_attempts[ip] = [
        t for t in _login_attempts[ip]
        if now - t < LOGIN_RATE_WINDOW
    ]
    if len(_login_attempts[ip]) >= LOGIN_RATE_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=f"Забагато спроб входу. Спробуйте через 15 хвилин."
        )
    _login_attempts[ip].append(now)

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

class DBAnnouncement(Base):
    __tablename__ = "announcements"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    title = Column(String, nullable=False)
    content = Column(String, nullable=True)
    date = Column(String)
    sender = Column(String)
    is_important = Column(Boolean, default=False)
    is_edited = Column(Boolean, default=False)

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

class DBSubject(Base):
    """Предмет (дисципліна) навчального плану — єдина база для ЦСК і опитувань"""
    __tablename__ = "subjects"
    id            = Column(Integer, primary_key=True, index=True, autoincrement=True)
    study_plan_id = Column(String, ForeignKey("study_plans.id", ondelete="CASCADE"), nullable=False)
    name          = Column(String, nullable=False)          # напр. "Французька мова", "Бази даних"
    semester      = Column(Integer, nullable=True)
    # elective_slot: null/"" = обов'язковий предмет; "ВК1", "ВК2" і т.д. = слот вибіркового блоку
    elective_slot = Column(String, nullable=True)
    teachers      = Column(JSON, default=list)              # список імен викладачів

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
        "ALTER TABLE templates ADD COLUMN IF NOT EXISTS feathers_reward INTEGER DEFAULT 0",
        "ALTER TABLE templates ADD COLUMN IF NOT EXISTS hashtags JSON DEFAULT '[]'",
        "ALTER TABLE templates ADD COLUMN IF NOT EXISTS deadline VARCHAR",
        # Нові таблиці академічної структури — Base.metadata.create_all їх вже створює,
        # але на випадок якщо БД старіша — страхуємо ALTER-ами де потрібно
        "ALTER TABLE academic_groups ADD COLUMN IF NOT EXISTS level VARCHAR",
        "ALTER TABLE subjects ADD COLUMN IF NOT EXISTS elective_slot VARCHAR",
        "ALTER TABLE subjects ADD COLUMN IF NOT EXISTS teachers JSON DEFAULT '[]'",
    ]
    with engine.connect() as conn:
        for sql in migrations:
            try:
                conn.execute(text(sql))
                conn.commit()
            except Exception:
                pass

_run_migrations()
_seed_db = SessionLocal()
try:
    _seed_hashtags(_seed_db)
finally:
    _seed_db.close()

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
    study_plan_id: str
    name: str
    semester: Optional[int] = None
    elective_slot: Optional[str] = None
    teachers: List[str] = []

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
            ip_address   = request.client.host if request.client else None,
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
    check_login_rate_limit(request)
    db_user = db.query(DBUser).filter(DBUser.email == user.email).first()
    dummy_hash = "$2b$12$KIX6s9S8sS8sS8sS8sS8sOKIX6s9S8sS8sS8sS8sS8sS8sS8sS8s"
    hash_to_check = db_user.hashed_password if db_user else dummy_hash
    password_valid = pwd_context.verify(user.password, hash_to_check)
    if not db_user or not password_valid:
        raise HTTPException(status_code=401, detail="Неправильна пошта або пароль")
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
    check_login_rate_limit(request)
    try:
        idinfo = id_token.verify_oauth2_token(
            auth_data.credential, google_requests.Request(), GOOGLE_CLIENT_ID
        )
        email = idinfo.get("email")
        db_user = db.query(DBUser).filter(DBUser.email == email).first()
        if not db_user:
            raise HTTPException(status_code=403, detail="Вашої пошти немає в базі.")
        access_token = create_access_token(
            data={"sub": db_user.email, "role": db_user.role, "user_id": db_user.id}
        )
        write_audit(db, request,
            action="login", user={"user_id": db_user.id, "sub": db_user.email},
            content_type="Users | Користувач", object_id=db_user.id,
            object_repr=f"{db_user.email} (Google)",
        )
        db.commit()
        return {"access_token": access_token, "role": db_user.role}
    except ValueError:
        raise HTTPException(status_code=401, detail="Помилка Google")

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

@app.post("/api/superadmin/users")
async def create_or_update_user(
    user: UserCreateSchema, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    db_user = db.query(DBUser).filter(DBUser.email == user.email).first()
    if db_user:
        if user.password:
            db_user.hashed_password = pwd_context.hash(user.password)
        db_user.role = user.role
        db_user.full_name = user.full_name
        db_user.student_data = user.student_data
        msg = f"Профіль {user.email} успішно оновлено!"
    else:
        if not user.password:
            raise HTTPException(status_code=400, detail="Для нового користувача пароль обов'язковий!")
        new_user = DBUser(
            id=str(uuid.uuid4())[:8], email=user.email,
            hashed_password=pwd_context.hash(user.password),
            role=user.role, full_name=user.full_name, student_data=user.student_data
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
    for u in users_data:
        existing = db.query(DBUser).filter(DBUser.email == u.get("email")).first()
        if existing:
            existing.role = u.get("role", existing.role)
            existing.full_name = u.get("full_name", existing.full_name)
            existing.student_data = u.get("student_data", existing.student_data)
            if u.get("password"):
                existing.hashed_password = pwd_context.hash(u["password"])
            updated += 1
        else:
            new_user = DBUser(
                id=str(uuid.uuid4())[:8], email=u.get("email"),
                hashed_password=pwd_context.hash(u.get("password", "changeme")),
                role=u.get("role", "student"), full_name=u.get("full_name"),
                student_data=u.get("student_data")
            )
            db.add(new_user)
            added += 1
    write_audit(db, request,
        action="bulk_import", user=admin, content_type="Users | Користувач",
        details={"added": added, "updated": updated},
    )
    db.commit()
    return {"message": f"Імпорт завершено: додано {added}, оновлено {updated}."}

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
    for sheet_name, df in xls.items():
        group_name = str(sheet_name).strip()
        if df.empty:
            continue
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
                            new_grade = DBGrade(
                                student_id=student_id, group_name=group_name,
                                subject=subjects[i - 1].strip(),
                                semester=semesters[i - 1] if i - 1 < len(semesters) else 1,
                                score=score,
                                control_form=control_row[i].strip() if i < len(control_row) else "",
                                teacher=teacher_row[i].strip() if i < len(teacher_row) else ""
                            )
                            db.add(new_grade)
                            added_count += 1
    write_audit(db, request,
        action="create", user=admin, content_type="Grades | Оцінки",
        object_repr=file.filename, details={"added_count": added_count},
    )
    db.commit()
    return {"message": f"Успіх! Оброблено та додано/оновлено {added_count} оцінок."}

@app.get("/api/csk/students")
async def get_all_students_for_csk(
    admin: dict = Depends(require_csk_admin), db: Session = Depends(get_db)
):
    students = db.query(DBUser).filter(DBUser.role == "student").all()
    result = []
    for s in students:
        grades = db.query(DBGrade).filter(DBGrade.student_id == s.id).all()
        group_name = "Невідомо"
        if s.student_data and isinstance(s.student_data, dict):
            studies = s.student_data.get("навчання", [])
            if studies:
                group_name = studies[0].get("Група", "Невідомо")
        result.append({
            "id": s.id, "full_name": s.full_name or "Без імені",
            "email": s.email, "group": group_name, "student_data": s.student_data,
            "grades": [{
                "id": g.id, "subject": g.subject, "score": g.score,
                "semester": g.semester, "control_form": g.control_form,
                "teacher": g.teacher, "group_name": g.group_name
            } for g in grades]
        })
    return result

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

@app.get("/api/templates/{template_id}")
async def get_single_template(
    template_id: str,
    user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    template = db.query(DBTemplate).filter(DBTemplate.id == template_id).first()
    if not template:
        raise HTTPException(status_code=404, detail="Опитування не знайдено")
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

# ── ПРЕДМЕТИ ─────────────────────────────────────────────
@app.get("/api/structure/subjects")
async def get_subjects(
    study_plan_id: str = Query(default=None),
    user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    q = db.query(DBSubject)
    if study_plan_id:
        q = q.filter(DBSubject.study_plan_id == study_plan_id)
    items = q.order_by(DBSubject.semester, DBSubject.name).all()
    return [{
        "id": s.id, "study_plan_id": s.study_plan_id, "name": s.name,
        "semester": s.semester, "elective_slot": s.elective_slot, "teachers": s.teachers or []
    } for s in items]

@app.post("/api/superadmin/structure/subjects")
async def create_subject(
    data: SubjectSchema, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    if not db.query(DBStudyPlan).filter(DBStudyPlan.id == data.study_plan_id).first():
        raise HTTPException(status_code=404, detail="Навчальний план не знайдено")
    obj = DBSubject(
        study_plan_id=data.study_plan_id, name=data.name, semester=data.semester,
        elective_slot=data.elective_slot or None, teachers=data.teachers or [],
    )
    db.add(obj)
    write_audit(db, request, action="create", user=admin, content_type="Structure | Предмет", object_repr=data.name)
    db.commit()
    db.refresh(obj)
    return {"id": obj.id, "study_plan_id": obj.study_plan_id, "name": obj.name, "semester": obj.semester, "elective_slot": obj.elective_slot, "teachers": obj.teachers or []}

@app.put("/api/superadmin/structure/subjects/{item_id}")
async def update_subject(
    item_id: int, data: SubjectSchema, request: Request,
    admin: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    obj = db.query(DBSubject).filter(DBSubject.id == item_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Не знайдено")
    obj.study_plan_id = data.study_plan_id
    obj.name = data.name
    obj.semester = data.semester
    obj.elective_slot = data.elective_slot or None
    obj.teachers = data.teachers or []
    write_audit(db, request, action="update", user=admin, content_type="Structure | Предмет", object_id=item_id, object_repr=data.name)
    db.commit()
    return {"id": obj.id, "study_plan_id": obj.study_plan_id, "name": obj.name, "semester": obj.semester, "elective_slot": obj.elective_slot, "teachers": obj.teachers or []}

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
    """Повертає всі вибіркові слоти і варіанти предметів для конкретного плану"""
    subjects = db.query(DBSubject).filter(
        DBSubject.study_plan_id == study_plan_id,
        DBSubject.elective_slot.isnot(None)
    ).all()
    slots = {}
    for s in subjects:
        slots.setdefault(s.elective_slot, []).append({
            "id": s.id, "name": s.name, "semester": s.semester, "teachers": s.teachers or []
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
    if subject.elective_slot != data.elective_slot or subject.study_plan_id != data.study_plan_id:
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
        entry = {"id": r.id, "answers": r.answers}
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

    db.add(DBResponse(
        survey_id=base_survey_id,
        answers=response.answers,
        respondent_id=respondent_id,
        respondent_name=respondent_name,
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
            reason=f"Опитування: {template.title}" + (f" [{opp_context}]" if opp_context else ""),
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
    return db.query(DBAnnouncement).order_by(DBAnnouncement.id.desc()).all()

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
async def download_opp():
    file_path = "static/uploads/current_opp.pdf"
    if os.path.exists(file_path):
        return FileResponse(file_path, media_type="application/pdf", filename="OPP.pdf")
    raise HTTPException(status_code=404, detail="Файл не знайдено")

@app.get("/api/opp")
async def get_opp():
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
    """Повертає повне дерево: Інститут → Кафедра → ОПП → Plan → Групи + Предмети плану"""
    institutes = db.query(DBInstitute).order_by(DBInstitute.name).all()
    result = []
    for inst in institutes:
        departments = db.query(DBDepartment).filter(DBDepartment.institute_id == inst.id).order_by(DBDepartment.name).all()
        dept_list = []
        for dept in departments:
            opps = db.query(DBOpp).filter(DBOpp.department_id == dept.id).order_by(DBOpp.name).all()
            opp_list = []
            for opp in opps:
                plans = db.query(DBStudyPlan).filter(DBStudyPlan.opp_id == opp.id).order_by(DBStudyPlan.name).all()
                plan_list = []
                for plan in plans:
                    groups = db.query(DBAcademicGroup).filter(DBAcademicGroup.study_plan_id == plan.id).order_by(DBAcademicGroup.name).all()
                    subjects = db.query(DBSubject).filter(DBSubject.study_plan_id == plan.id).order_by(DBSubject.semester, DBSubject.name).all()
                    plan_list.append({
                        "id": plan.id, "name": plan.name,
                        "groups": [{"id": g.id, "name": g.name, "level": g.level} for g in groups],
                        "subjects": [{
                            "id": s.id, "name": s.name, "semester": s.semester,
                            "elective_slot": s.elective_slot, "teachers": s.teachers or []
                        } for s in subjects],
                    })
                opp_list.append({
                    "id": opp.id, "name": opp.name, "level": opp.level, "full_name": opp.full_name,
                    "plans": plan_list
                })
            dept_list.append({
                "id": dept.id, "name": dept.name, "full_name": dept.full_name,
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