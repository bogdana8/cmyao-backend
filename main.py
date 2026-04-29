from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
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
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# =========================================================
# ⚙️ КОНФІГУРАЦІЯ — читаємо з оточення, не хардкодимо!
# =========================================================
from dotenv import load_dotenv
load_dotenv()  # Завантажує змінні з .env файлу (якщо є)

SECRET_KEY = os.environ.get("SECRET_KEY")
DATABASE_URL = os.environ.get("DATABASE_URL")
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")

# Перевіряємо, що всі критичні змінні задані
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY не задано! Додайте його в .env або змінні оточення.")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL не задано! Додайте його в .env або змінні оточення.")
if not GOOGLE_CLIENT_ID:
    raise RuntimeError("GOOGLE_CLIENT_ID не задано! Додайте його в .env або змінні оточення.")

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
# 🗄️ БАЗА ДАНИХ — правильне управління сесіями
# =========================================================
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db() -> Generator[Session, None, None]:
    """
    Dependency для FastAPI.
    Гарантує закриття сесії навіть якщо виникла помилка.
    Використовуйте як: db: Session = Depends(get_db)
    """
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
    questions = Column(JSON)
    target_audience = Column(JSON, nullable=True)

class DBResponse(Base):
    __tablename__ = "responses"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    survey_id = Column(String, index=True)
    answers = Column(JSON)

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

class DBDictionary(Base):
    __tablename__ = "dictionaries"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    data = Column(JSON, nullable=False)

Base.metadata.create_all(bind=engine)

# =========================================================
# 📋 СХЕМИ (Pydantic)
# =========================================================
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
    questions: List[QuestionSchema]
    target_audience: Optional[dict] = None

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

# =========================================================
# 🔐 АВТОРИЗАЦІЯ
# =========================================================
@app.post("/api/login")
async def login(user: UserLoginSchema, db: Session = Depends(get_db)):
    db_user = db.query(DBUser).filter(DBUser.email == user.email).first()
    if not db_user or not pwd_context.verify(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Неправильна пошта або пароль")
    access_token = create_access_token(data={"sub": db_user.email, "role": db_user.role, "user_id": db_user.id})
    return {"access_token": access_token, "role": db_user.role}

@app.post("/api/google-login")
async def google_login(auth_data: GoogleLoginSchema, db: Session = Depends(get_db)):
    try:
        idinfo = id_token.verify_oauth2_token(auth_data.credential, google_requests.Request(), GOOGLE_CLIENT_ID)
        email = idinfo.get("email")
        db_user = db.query(DBUser).filter(DBUser.email == email).first()
        if not db_user:
            raise HTTPException(status_code=403, detail="Вашої пошти немає в базі.")
        access_token = create_access_token(data={"sub": db_user.email, "role": db_user.role, "user_id": db_user.id})
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
        "id": u.id,
        "email": u.email,
        "full_name": u.full_name,
        "role": u.role,
        "student_data": u.student_data
    } for u in users]

@app.post("/api/superadmin/users")
async def create_or_update_user(
    user: UserCreateSchema,
    admin: dict = Depends(require_superadmin),
    db: Session = Depends(get_db)
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
            id=str(uuid.uuid4())[:8],
            email=user.email,
            hashed_password=pwd_context.hash(user.password),
            role=user.role,
            full_name=user.full_name,
            student_data=user.student_data
        )
        db.add(new_user)
        msg = f"Нового користувача {user.email} створено!"

    db.commit()
    return {"message": msg}

@app.post("/api/superadmin/users/bulk")
async def bulk_import_users(
    payload: dict,
    admin: dict = Depends(require_superadmin),
    db: Session = Depends(get_db)
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
                id=str(uuid.uuid4())[:8],
                email=u.get("email"),
                hashed_password=pwd_context.hash(u.get("password", "changeme")),
                role=u.get("role", "student"),
                full_name=u.get("full_name"),
                student_data=u.get("student_data")
            )
            db.add(new_user)
            added += 1

    db.commit()
    return {"message": f"Імпорт завершено: додано {added}, оновлено {updated}."}

# =========================================================
# 📊 ЦСК — ЗАВАНТАЖЕННЯ ТА РЕДАГУВАННЯ ОЦІНОК
# =========================================================
@app.post("/api/csk/upload-grades")
async def upload_grades(
    file: UploadFile = File(...),
    admin: dict = Depends(require_csk_admin),
    db: Session = Depends(get_db)
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
                                student_id=student_id,
                                group_name=group_name,
                                subject=subjects[i - 1].strip(),
                                semester=semesters[i - 1] if i - 1 < len(semesters) else 1,
                                score=score,
                                control_form=control_row[i].strip() if i < len(control_row) else "",
                                teacher=teacher_row[i].strip() if i < len(teacher_row) else ""
                            )
                            db.add(new_grade)
                            added_count += 1

    db.commit()
    return {"message": f"Успіх! Оброблено та додано/оновлено {added_count} оцінок."}

@app.get("/api/csk/students")
async def get_all_students_for_csk(
    admin: dict = Depends(require_csk_admin),
    db: Session = Depends(get_db)
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
            "id": s.id,
            "full_name": s.full_name or "Без імені",
            "email": s.email,
            "group": group_name,
            "student_data": s.student_data,
            "grades": [{
                "id": g.id, "subject": g.subject, "score": g.score,
                "semester": g.semester, "control_form": g.control_form,
                "teacher": g.teacher, "group_name": g.group_name
            } for g in grades]
        })
    return result

@app.put("/api/csk/grades/{grade_id}")
async def update_single_grade(
    grade_id: int,
    grade_data: GradeUpdateSchema,
    admin: dict = Depends(require_csk_admin),
    db: Session = Depends(get_db)
):
    grade = db.query(DBGrade).filter(DBGrade.id == grade_id).first()
    if not grade:
        raise HTTPException(status_code=404, detail="Оцінку не знайдено")

    grade.score = grade_data.score
    grade.subject = grade_data.subject
    grade.semester = grade_data.semester
    grade.control_form = grade_data.control_form
    grade.teacher = grade_data.teacher

    db.commit()
    return {"message": "Оцінку успішно оновлено!"}

# =========================================================
# 🎓 СТУДЕНТ — ПРОФІЛЬ ТА ОПИТУВАННЯ
# =========================================================
@app.get("/api/student/me")
async def get_student_profile(
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
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
        "subject": g.subject,
        "score": g.score,
        "semester": g.semester,
        "teacher": g.teacher,
        "group_name": g.group_name,
        "control_form": g.control_form
    } for g in grades]

    return {
        "full_name": db_user.full_name,
        "email": db_user.email,
        "student_data": s_data,
        "grades": grades_list
    }

@app.get("/api/student/surveys")
async def get_student_surveys(
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    db_user = db.query(DBUser).filter(DBUser.id == user["user_id"]).first()
    s_data = (db_user.student_data or {}) if db_user else {}
    if isinstance(s_data, str):
        try:
            s_data = json.loads(s_data)
        except Exception:
            s_data = {}

    student_studies = s_data.get("навчання", []) if isinstance(s_data, dict) else []
    all_templates = db.query(DBTemplate).all()
    completed_records = db.query(DBCompletedSurvey).filter(
        DBCompletedSurvey.user_id == user["user_id"]
    ).all()
    completed_ids = {record.survey_id for record in completed_records}

    result = []
    for t in all_templates:
        t_audience = t.target_audience or {}
        if isinstance(t_audience, str):
            try:
                t_audience = json.loads(t_audience)
            except Exception:
                t_audience = {}

        is_allowed = True
        if t_audience:
            is_allowed = any(
                all(study.get(k) == v for k, v in t_audience.items())
                for study in student_studies
            )

        if is_allowed:
            result.append({"id": t.id, "title": t.title, "is_completed": t.id in completed_ids})

    return result

# =========================================================
# 📝 ЦМЯО — УПРАВЛІННЯ ОПИТУВАННЯМИ
# =========================================================
@app.get("/api/templates")
async def get_templates(
    user: dict = Depends(require_cmyo_admin),
    db: Session = Depends(get_db)
):
    templates = db.query(DBTemplate).all()
    return [{"id": t.id, "title": t.title, "questions": t.questions, "target_audience": t.target_audience} for t in templates]

@app.post("/api/templates")
async def save_template(
    survey: SurveyTemplateSchema,
    user: dict = Depends(require_cmyo_admin),
    db: Session = Depends(get_db)
):
    if not survey.id:
        survey.id = str(uuid.uuid4())[:8]

    db_template = db.query(DBTemplate).filter(DBTemplate.id == survey.id).first()
    questions_data = [q.model_dump() for q in survey.questions]

    if db_template:
        db_template.title = survey.title
        db_template.questions = questions_data
        db_template.target_audience = survey.target_audience
    else:
        db.add(DBTemplate(
            id=survey.id,
            title=survey.title,
            questions=questions_data,
            target_audience=survey.target_audience
        ))

    db.commit()
    return {"message": "Шаблон збережено!", "id": survey.id}

@app.delete("/api/templates/{template_id}")
async def delete_template(
    template_id: str,
    user: dict = Depends(require_cmyo_admin),
    db: Session = Depends(get_db)
):
    template = db.query(DBTemplate).filter(DBTemplate.id == template_id).first()
    if template:
        db.delete(template)
        db.commit()
    return {"message": "Видалено"}

@app.get("/api/templates/{template_id}")
async def get_single_template(template_id: str, db: Session = Depends(get_db)):
    template = db.query(DBTemplate).filter(DBTemplate.id == template_id).first()
    if template:
        return {"id": template.id, "title": template.title, "questions": template.questions}
    raise HTTPException(status_code=404)

@app.post("/api/responses")
async def save_student_response(
    response: StudentResponseSchema,
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    db.add(DBResponse(survey_id=response.survey_id, answers=response.answers))

    if user.get("role") != "stakeholder":
        db.add(DBCompletedSurvey(user_id=user["user_id"], survey_id=response.survey_id))

    db.commit()
    return {"message": "Збережено."}

# =========================================================
# 📢 ОГОЛОШЕННЯ
# =========================================================
@app.post("/api/announcements")
async def create_announcement(
    ann: AnnouncementCreateSchema,
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    sender_map = {
        "admin_csk": "ЦСК",
        "admin_cmyo": "ЦМЯО",
        "superadmin": "Адміністрація"
    }
    sender = sender_map.get(user["role"], "Деканат")

    db.add(DBAnnouncement(
        title=ann.title,
        content=ann.content,
        date=datetime.now().strftime("%d.%m.%Y %H:%M"),
        sender=sender,
        is_important=ann.is_important
    ))
    db.commit()
    return {"message": "Оголошення опубліковано!"}

@app.get("/api/announcements")
async def get_announcements(
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return db.query(DBAnnouncement).order_by(DBAnnouncement.id.desc()).all()

@app.put("/api/announcements/{ann_id}")
async def update_announcement(
    ann_id: int,
    ann: AnnouncementCreateSchema,
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if user["role"] not in ["superadmin", "admin_csk", "admin_cmyo"]:
        raise HTTPException(status_code=403, detail="Немає прав")

    db_ann = db.query(DBAnnouncement).filter(DBAnnouncement.id == ann_id).first()
    if db_ann:
        db_ann.title = ann.title
        db_ann.content = ann.content
        db_ann.is_important = ann.is_important
        db.commit()
    return {"message": "Оголошення оновлено"}

@app.delete("/api/announcements/{ann_id}")
async def delete_announcement(
    ann_id: int,
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if user["role"] == "student":
        raise HTTPException(status_code=403)

    ann = db.query(DBAnnouncement).filter(DBAnnouncement.id == ann_id).first()
    if ann:
        db.delete(ann)
        db.commit()
    return {"message": "Видалено"}

# =========================================================
# 📄 ФАЙЛИ (ОПП)
# =========================================================
@app.post("/api/upload-opp")
async def upload_opp(
    file: UploadFile = File(...),
    user: dict = Depends(get_current_user)
):
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
    "floor": [],  # хе-хе, не смей трогать — прокляну
    "finances": [], "study_forms": [], "faculties": [],
    "curriculum": [], "program": [], "departments": [],
    "teacher_positions": [], "degrees": [], "companies": [],
    "industries": [], "admin_departments": []
}

@app.get("/api/dictionaries")
async def get_dictionaries(db: Session = Depends(get_db)):
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
    admin: dict = Depends(require_superadmin),
    db: Session = Depends(get_db)
):
    dict_record = db.query(DBDictionary).first()
    if dict_record:
        dict_record.data = new_data
    else:
        db.add(DBDictionary(data=new_data))
    db.commit()
    return {"message": "Довідники успішно оновлено!"}

# =========================================================
# 🏓 PING
# =========================================================
@app.get("/api/ping")
async def ping(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ok", "db": "awake"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}
