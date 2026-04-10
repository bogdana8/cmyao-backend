from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import List, Optional
import uuid
from sqlalchemy import create_engine, Column, String, Integer, JSON
from sqlalchemy.orm import declarative_base, sessionmaker
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt, JWTError
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

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

# Ініціалізуємо "охоронця" для перевірки токенів
security = HTTPBearer()

# --- МОДЕЛІ БАЗИ ДАНИХ ---
class DBTemplate(Base):
    __tablename__ = "templates"
    id = Column(String, primary_key=True, index=True)
    title = Column(String, index=True)
    questions = Column(JSON)
    target_audience = Column(JSON, nullable=True) # НОВЕ: Кому призначено

class DBResponse(Base):
    __tablename__ = "responses"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    survey_id = Column(String, index=True)
    answers = Column(JSON)

class DBUser(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String)
    full_name = Column(String, nullable=True) # НОВЕ: ПІБ
    student_data = Column(JSON, nullable=True) # НОВЕ: Група, Курс і т.д.

class DBCompletedSurvey(Base):
    __tablename__ = "completed_surveys"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(String, index=True)
    survey_id = Column(String, index=True)

Base.metadata.create_all(bind=engine)

# --- СХЕМИ ДЛЯ ФРОНТЕНДУ ---
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
    target_audience: Optional[dict] = None  # НОВЕ: Правила, кому показувати

class StudentResponseSchema(BaseModel):
    survey_id: str
    answers: list

class UserCreateSchema(BaseModel):
    email: str
    password: str
    role: str
    full_name: Optional[str] = None      # НОВЕ
    student_data: Optional[dict] = None  # НОВЕ

class UserLoginSchema(BaseModel):
    email: str
    password: str
    
class GoogleLoginSchema(BaseModel):
    credential: str

# --- ДОПОМІЖНІ ФУНКЦІЇ ---
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=1)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# НОВЕ: Функція, яка розшифровує токен і перевіряє, чи він дійсний
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Недійсний токен")
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Недійсний токен або термін його дії минув")

# --- ВІДКРИТІ МАРШРУТИ (БЕЗ ПАРОЛІВ) ---

@app.post("/api/secret-register")
async def secret_register(user: UserCreateSchema):
    db = SessionLocal()
    db_user = db.query(DBUser).filter(DBUser.email == user.email).first()
    if db_user:
        db.close()
        raise HTTPException(status_code=400, detail="Така пошта вже зареєстрована")
    
    hashed_pwd = pwd_context.hash(user.password)
    new_user = DBUser(
        id=str(uuid.uuid4())[:8], 
        email=user.email, 
        hashed_password=hashed_pwd, 
        role=user.role,
        full_name=user.full_name,          # Зберігаємо ПІБ
        student_data=user.student_data     # Зберігаємо рюкзак
    )
    db.add(new_user)
    db.commit()
    db.close()
    return {"message": f"Акаунт {user.full_name or user.email} успішно створено!"}

GOOGLE_CLIENT_ID = "721585809833-756v703e49731ch3drcvn02c312m5fsn.apps.googleusercontent.com"

@app.post("/api/google-login")
async def google_login(auth_data: GoogleLoginSchema):
    try:
        # 1. Гугл перевіряє, чи токен справжній і не підроблений
        idinfo = id_token.verify_oauth2_token(
            auth_data.credential, 
            google_requests.Request(), 
            GOOGLE_CLIENT_ID
        )

        # 2. Дістаємо пошту, яку підтвердив Гугл
        email = idinfo.get('email')

        # 3. Шукаємо студента в нашій базі
        db = SessionLocal()
        db_user = db.query(DBUser).filter(DBUser.email == email).first()
        db.close()

        # Якщо Гугл сказав, що людина справжня, але її немає в нашій базі:
        if not db_user:
            raise HTTPException(status_code=403, detail="Вашої пошти немає в базі університету. Зверніться до деканату.")

        # 4. Якщо все супер - видаємо наш ключ-перепустку (токен)
        access_token = create_access_token(data={"sub": db_user.email, "role": db_user.role, "user_id": db_user.id})
        return {"access_token": access_token, "role": db_user.role}

    except ValueError:
        raise HTTPException(status_code=401, detail="Помилка перевірки Google")

@app.post("/api/login")
async def login(user: UserLoginSchema):
    db = SessionLocal()
    db_user = db.query(DBUser).filter(DBUser.email == user.email).first()
    db.close()
    if not db_user or not pwd_context.verify(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Неправильна пошта або пароль")
    access_token = create_access_token(data={"sub": db_user.email, "role": db_user.role, "user_id": db_user.id})
    return {"access_token": access_token, "role": db_user.role}

# Студентам треба бачити питання, щоб відповісти (Відкрито)
@app.get("/api/templates/{template_id}")
async def get_single_template(template_id: str):
    db = SessionLocal()
    template = db.query(DBTemplate).filter(DBTemplate.id == template_id).first()
    db.close()
    if template:
        return {"id": template.id, "title": template.title, "questions": template.questions}
    raise HTTPException(status_code=404, detail="Опитування не знайдено")

# --- ОНОВЛЕНИЙ МАРШРУТ: Зберігаємо відповіді + фіксуємо, хто пройшов ---
@app.post("/api/responses")
async def save_student_response(response: StudentResponseSchema, user: dict = Depends(get_current_user)):
    db = SessionLocal()
    
    # 1. Зберігаємо самі відповіді
    new_response = DBResponse(survey_id=response.survey_id, answers=response.answers)
    db.add(new_response)
    
    # 2. Робимо відмітку в базі, що цей конкретний студент ПРОЙШОВ це опитування
    completed_mark = DBCompletedSurvey(user_id=user["user_id"], survey_id=response.survey_id)
    db.add(completed_mark)
    
    db.commit()
    db.close()
    return {"message": "Дякуємо! Ваші відповіді збережено."}

# --- НОВИЙ МАРШРУТ: Видаємо список опитувань для Кабінету Студента ---
@app.get("/api/student/surveys")
async def get_student_surveys(user: dict = Depends(get_current_user)):
    db = SessionLocal()
    
    # 1. Дістаємо "рюкзак" студента
    db_user = db.query(DBUser).filter(DBUser.id == user["user_id"]).first()
    student_studies = db_user.student_data.get("навчання", []) if db_user and db_user.student_data else []
    
    all_templates = db.query(DBTemplate).all()
    completed_records = db.query(DBCompletedSurvey).filter(DBCompletedSurvey.user_id == user["user_id"]).all()
    completed_ids = [record.survey_id for record in completed_records]
    
    result = []
    for t in all_templates:
        is_allowed = True # За замовчуванням показуємо всім (глобальне опитування)
        
        # 2. Якщо в опитуванні є правила (наприклад {"Група": "ІПЗ-23-2"})
        if t.target_audience:
            is_allowed = False # Забороняємо, поки не знайдемо збіг
            for study in student_studies:
                match = True
                for key, required_value in t.target_audience.items():
                    # Перевіряємо, чи є в студента така група/спеціальність
                    if study.get(key) != required_value:
                        match = False
                        break
                if match:
                    is_allowed = True # Знайшли збіг! Пускаємо!
                    break
                    
        if is_allowed:
            result.append({
                "id": t.id,
                "title": t.title,
                "is_completed": t.id in completed_ids
            })
            
    db.close()
    return result

# --- ЗАКРИТІ МАРШРУТИ (ТІЛЬКИ З ТОКЕНОМ 🔐) ---
# Зверни увагу на `user: dict = Depends(get_current_user)` - це і є замок!

# --- НОВИЙ МАРШРУТ: Віддаємо профіль студента ---
@app.get("/api/student/me")
async def get_student_profile(user: dict = Depends(get_current_user)):
    db = SessionLocal()
    db_user = db.query(DBUser).filter(DBUser.id == user["user_id"]).first()
    db.close()
    
    if not db_user:
        raise HTTPException(status_code=404, detail="Користувача не знайдено")
        
    return {
        "full_name": db_user.full_name,
        "email": db_user.email,
        "student_data": db_user.student_data
    }
    
@app.get("/api/templates")
async def get_templates(user: dict = Depends(get_current_user)):
    db = SessionLocal()
    templates = db.query(DBTemplate).all()
    db.close()
    return [{"id": t.id, "title": t.title, "questions": t.questions, "target_audience": t.target_audience} for t in templates]

@app.post("/api/templates")
async def save_template(survey: SurveyTemplateSchema, user: dict = Depends(get_current_user)):
    db = SessionLocal()
    if not survey.id:
        survey.id = str(uuid.uuid4())[:8]
        new_template = DBTemplate(
            id=survey.id, 
            title=survey.title, 
            questions=[q.model_dump() for q in survey.questions],
            target_audience=survey.target_audience # Зберігаємо цільову аудиторію
        )
        db.add(new_template)
    else:
        db_template = db.query(DBTemplate).filter(DBTemplate.id == survey.id).first()
        if db_template:
            db_template.title = survey.title
            db_template.questions = [q.model_dump() for q in survey.questions]
            db_template.target_audience = survey.target_audience # Оновлюємо
        else:
            new_template = DBTemplate(
                id=survey.id, 
                title=survey.title, 
                questions=[q.model_dump() for q in survey.questions],
                target_audience=survey.target_audience
            )
            db.add(new_template)
    db.commit()
    db.close()
    return {"message": "Шаблон надійно збережено в БД!", "id": survey.id}

@app.delete("/api/templates/{template_id}")
async def delete_template(template_id: str, user: dict = Depends(get_current_user)):
    db = SessionLocal()
    template = db.query(DBTemplate).filter(DBTemplate.id == template_id).first()
    if template:
        db.delete(template)
        db.commit()
    db.close()
    return {"message": "Видалено"}

# Відкритий маршрут спеціально для бота-будильника
@app.get("/api/ping")
async def ping():
    return {"status": "ok", "message": "Я не сплю!"}
