from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import List, Optional
import uuid
from sqlalchemy import create_engine, Column, String, Integer, JSON, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt, JWTError
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import json
import pandas as pd
import io
import re

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_URL = "postgresql://neondb_owner:npg_AlvcYP6VQsZ4@ep-morning-credit-a41lvtxp-pooler.us-east-1.aws.neon.tech/neondb?sslmode=require"

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- КРИПТОГРАФІЯ ТА ТОКЕНИ ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "cmyo-super-secret-key-change-later" 
ALGORITHM = "HS256"
security = HTTPBearer()

# --- МОДЕЛІ БАЗИ ДАНИХ ---
class DBUser(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String) # 'superadmin', 'admin_cmyo', 'admin_csk', 'student'
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

# НОВЕ: Таблиця Оцінок (З твого старого коду)
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

Base.metadata.create_all(bind=engine)

# --- СХЕМИ ---
class UserLoginSchema(BaseModel):
    email: str
    password: str

class GoogleLoginSchema(BaseModel):
    credential: str

class UserCreateSchema(BaseModel):
    email: str
    password: str
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

# --- ФУНКЦІЇ ДОСТУПУ (РОЛІ) ---
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=1)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("sub") is None: raise HTTPException(status_code=401, detail="Недійсний токен")
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Недійсний токен")

def require_superadmin(user: dict = Depends(get_current_user)):
    if user.get("role") != "superadmin": raise HTTPException(status_code=403, detail="Доступ заборонено")
    return user

def require_csk_admin(user: dict = Depends(get_current_user)):
    if user.get("role") not in ["superadmin", "admin_csk"]: raise HTTPException(status_code=403, detail="Тільки для ЦСК")
    return user

def require_cmyo_admin(user: dict = Depends(get_current_user)):
    if user.get("role") not in ["superadmin", "admin_cmyo"]: raise HTTPException(status_code=403, detail="Тільки для ЦМЯО")
    return user

# --- АВТОРИЗАЦІЯ ---
@app.post("/api/login")
async def login(user: UserLoginSchema):
    db = SessionLocal()
    db_user = db.query(DBUser).filter(DBUser.email == user.email).first()
    db.close()
    if not db_user or not pwd_context.verify(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Неправильна пошта або пароль")
    access_token = create_access_token(data={"sub": db_user.email, "role": db_user.role, "user_id": db_user.id})
    return {"access_token": access_token, "role": db_user.role}

GOOGLE_CLIENT_ID = "721585809833-756v703e49731ch3drcvn02c312m5fsn.apps.googleusercontent.com"
@app.post("/api/google-login")
async def google_login(auth_data: GoogleLoginSchema):
    try:
        idinfo = id_token.verify_oauth2_token(auth_data.credential, google_requests.Request(), GOOGLE_CLIENT_ID)
        email = idinfo.get('email')
        db = SessionLocal()
        db_user = db.query(DBUser).filter(DBUser.email == email).first()
        db.close()
        if not db_user:
            raise HTTPException(status_code=403, detail="Вашої пошти немає в базі.")
        access_token = create_access_token(data={"sub": db_user.email, "role": db_user.role, "user_id": db_user.id})
        return {"access_token": access_token, "role": db_user.role}
    except ValueError:
        raise HTTPException(status_code=401, detail="Помилка Google")

# =========================================================
# 👑 ЗОНА СУПЕРАДМІНА (КЕРУВАННЯ КОРИСТУВАЧАМИ)
# =========================================================
@app.get("/api/superadmin/users")
async def get_all_users(admin: dict = Depends(require_superadmin)):
    db = SessionLocal()
    users = db.query(DBUser).all()
    db.close()
    return [{"id": u.id, "email": u.email, "full_name": u.full_name, "role": u.role} for u in users]

@app.post("/api/superadmin/users")
async def create_or_update_user(user: UserCreateSchema, admin: dict = Depends(require_superadmin)):
    """Тут ти можеш створювати нових адмінів або міняти їм паролі"""
    db = SessionLocal()
    db_user = db.query(DBUser).filter(DBUser.email == user.email).first()
    hashed_pwd = pwd_context.hash(user.password)

    if db_user:
        db_user.hashed_password = hashed_pwd
        db_user.role = user.role
        db_user.full_name = user.full_name
        msg = f"Пароль та роль для {user.email} оновлено!"
    else:
        new_user = DBUser(
            id=str(uuid.uuid4())[:8], email=user.email, hashed_password=hashed_pwd, 
            role=user.role, full_name=user.full_name, student_data=user.student_data
        )
        db.add(new_user)
        msg = f"Користувача {user.email} створено!"
    
    db.commit()
    db.close()
    return {"message": msg}

# =========================================================
# 📊 ЗОНА ЦСК (ЗАВАНТАЖЕННЯ ОЦІНОК)
# =========================================================
@app.post("/api/csk/upload-grades")
async def upload_grades(file: UploadFile = File(...), admin: dict = Depends(require_csk_admin)):
    """Твій парсер Excel, перероблений під Web і PostgreSQL"""
    content = await file.read()
    
    try:
        # Читаємо Excel прямо з пам'яті (без збереження на диск сервера)
        xls = pd.read_excel(io.BytesIO(content), sheet_name=None, header=None)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Помилка читання Excel: {str(e)}")

    db = SessionLocal()
    added_count = 0

    for sheet_name, df in xls.items():
        group_name = str(sheet_name).strip()
        if df.empty: continue

        subjects = df.iloc[0, 1:].fillna('').astype(str).tolist()
        semester_row, teacher_row, control_row = None, [], []

        for index, row in df.iterrows():
            val0 = str(row[0]).strip().lower()
            if "семестр" in val0 or any("семестр" in str(cell).lower() for cell in row):
                semester_row = row.fillna('').astype(str).tolist()
            elif val0 == 'викладач':
                teacher_row = row.fillna('').astype(str).tolist()
            elif val0 == 'вид контролю':
                control_row = row.fillna('').astype(str).tolist()

        semesters = []
        current_sem = 1
        if semester_row is not None:
            for cell in semester_row[1:]:
                val = str(cell).strip().lower()
                if "семестр" in val:
                    match = re.search(r'\d+', val)
                    if match: current_sem = int(match.group())
                semesters.append(current_sem)
        else:
            semesters = [1] * len(subjects)

        for index, row in df.iterrows():
            student_name = str(row[0]).strip()
            if not student_name or student_name.lower() == 'nan': continue

            # Шукаємо студента в БД за ПІБ
            student_in_db = db.query(DBUser).filter(DBUser.full_name == student_name).first()
            
            if student_in_db:
                student_id = student_in_db.id
                # Видаляємо старі оцінки для цієї групи (як у твоєму старому коді)
                db.query(DBGrade).filter(DBGrade.student_id == student_id, DBGrade.group_name == group_name).delete()

                for i in range(1, len(row)):
                    score = str(row[i]).strip()
                    if score and score.lower() != 'nan':
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
    db.close()
    return {"message": f"Успіх! Оброблено та додано/оновлено {added_count} оцінок."}

# =========================================================
# 🎓 ЗОНА СТУДЕНТА (ПРОФІЛЬ ТА ОЦІНКИ)
# =========================================================
@app.get("/api/student/me")
async def get_student_profile(user: dict = Depends(get_current_user)):
    db = SessionLocal()
    db_user = db.query(DBUser).filter(DBUser.id == user["user_id"]).first()
    
    if not db_user:
        db.close()
        raise HTTPException(status_code=404, detail="Користувача не знайдено")
        
    s_data = db_user.student_data if db_user.student_data else {}
    if isinstance(s_data, str):
        try: s_data = json.loads(s_data)
        except: s_data = {}
    
    # Дістаємо оцінки з нової таблиці!
    grades = db.query(DBGrade).filter(DBGrade.student_id == db_user.id).all()
    grades_list = [
        {"subject": g.subject, "score": g.score, "semester": g.semester, "teacher": g.teacher} 
        for g in grades
    ]
            
    db.close()
    return {
        "full_name": db_user.full_name,
        "email": db_user.email,
        "student_data": s_data,
        "grades": grades_list # Тепер Кабінет Студента може показувати оцінки!
    }

@app.get("/api/student/surveys")
async def get_student_surveys(user: dict = Depends(get_current_user)):
    db = SessionLocal()
    db_user = db.query(DBUser).filter(DBUser.id == user["user_id"]).first()
    s_data = db_user.student_data if db_user and db_user.student_data else {}
    if isinstance(s_data, str):
        try: s_data = json.loads(s_data)
        except: s_data = {}
            
    student_studies = s_data.get("навчання", []) if isinstance(s_data, dict) else []
    all_templates = db.query(DBTemplate).all()
    completed_records = db.query(DBCompletedSurvey).filter(DBCompletedSurvey.user_id == user["user_id"]).all()
    completed_ids = [record.survey_id for record in completed_records]
    
    result = []
    for t in all_templates:
        is_allowed = True 
        t_audience = t.target_audience if t.target_audience else {}
        if isinstance(t_audience, str):
            try: t_audience = json.loads(t_audience)
            except: t_audience = {}

        if t_audience:
            is_allowed = False 
            for study in student_studies:
                match = True
                for key, required_value in t_audience.items():
                    if study.get(key) != required_value:
                        match = False
                        break
                if match:
                    is_allowed = True 
                    break
        if is_allowed:
            result.append({"id": t.id, "title": t.title, "is_completed": t.id in completed_ids})
    db.close()
    return result

# =========================================================
# 📝 ЗОНА ЦМЯО (ОПИТУВАННЯ)
# =========================================================
@app.get("/api/templates")
async def get_templates(user: dict = Depends(require_cmyo_admin)):
    db = SessionLocal()
    templates = db.query(DBTemplate).all()
    db.close()
    return [{"id": t.id, "title": t.title, "questions": t.questions, "target_audience": t.target_audience} for t in templates]

@app.post("/api/templates")
async def save_template(survey: SurveyTemplateSchema, user: dict = Depends(require_cmyo_admin)):
    db = SessionLocal()
    if not survey.id:
        survey.id = str(uuid.uuid4())[:8]
        new_template = DBTemplate(id=survey.id, title=survey.title, questions=[q.model_dump() for q in survey.questions], target_audience=survey.target_audience)
        db.add(new_template)
    else:
        db_template = db.query(DBTemplate).filter(DBTemplate.id == survey.id).first()
        if db_template:
            db_template.title = survey.title
            db_template.questions = [q.model_dump() for q in survey.questions]
            db_template.target_audience = survey.target_audience
        else:
            new_template = DBTemplate(id=survey.id, title=survey.title, questions=[q.model_dump() for q in survey.questions], target_audience=survey.target_audience)
            db.add(new_template)
    db.commit()
    db.close()
    return {"message": "Шаблон збережено!", "id": survey.id}

@app.delete("/api/templates/{template_id}")
async def delete_template(template_id: str, user: dict = Depends(require_cmyo_admin)):
    db = SessionLocal()
    template = db.query(DBTemplate).filter(DBTemplate.id == template_id).first()
    if template:
        db.delete(template)
        db.commit()
    db.close()
    return {"message": "Видалено"}

@app.get("/api/templates/{template_id}")
async def get_single_template(template_id: str):
    db = SessionLocal()
    template = db.query(DBTemplate).filter(DBTemplate.id == template_id).first()
    db.close()
    if template: return {"id": template.id, "title": template.title, "questions": template.questions}
    raise HTTPException(status_code=404)

@app.post("/api/responses")
async def save_student_response(response: StudentResponseSchema, user: dict = Depends(get_current_user)):
    db = SessionLocal()
    new_response = DBResponse(survey_id=response.survey_id, answers=response.answers)
    db.add(new_response)
    completed_mark = DBCompletedSurvey(user_id=user["user_id"], survey_id=response.survey_id)
    db.add(completed_mark)
    db.commit()
    db.close()
    return {"message": "Збережено."}

@app.get("/api/ping")
async def ping():
    return {"status": "ok"}