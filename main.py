from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import uuid
from sqlalchemy import create_engine, Column, String, Integer, JSON
from sqlalchemy.orm import declarative_base, sessionmaker
from passlib.context import CryptContext

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_URL = "postgresql://neondb_owner:npg_AlvcYP6VQsZ4@ep-morning-credit-a41lvtxp-pooler.us-east-1.aws.neon.tech/neondb?sslmode=require"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- КРИПТОГРАФІЯ (для паролів) ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# --- МОДЕЛІ БАЗИ ДАНИХ ---
class DBTemplate(Base):
    __tablename__ = "templates"
    id = Column(String, primary_key=True, index=True)
    title = Column(String, index=True)
    questions = Column(JSON)


class DBResponse(Base):
    __tablename__ = "responses"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    survey_id = Column(String, index=True)
    answers = Column(JSON)


# НОВЕ: Таблиця користувачів
class DBUser(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String)  # 'superadmin', 'admin', 'student'


# НОВЕ: Таблиця пройдених опитувань (щоб не проходили двічі)
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


class StudentResponseSchema(BaseModel):
    survey_id: str
    answers: list


class UserCreateSchema(BaseModel):
    email: str
    password: str
    role: str


# --- МАРШРУТИ ---

# НОВЕ: Секретна реєстрація
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
        role=user.role
    )
    db.add(new_user)
    db.commit()
    db.close()
    return {"message": f"Акаунт {user.email} (роль: {user.role}) успішно створено!"}


@app.get("/api/templates")
async def get_templates():
    db = SessionLocal()
    templates = db.query(DBTemplate).all()
    db.close()
    return [{"id": t.id, "title": t.title, "questions": t.questions} for t in templates]


@app.post("/api/templates")
async def save_template(survey: SurveyTemplateSchema):
    db = SessionLocal()
    if not survey.id:
        survey.id = str(uuid.uuid4())[:8]
        new_template = DBTemplate(id=survey.id, title=survey.title,
                                  questions=[q.model_dump() for q in survey.questions])
        db.add(new_template)
    else:
        db_template = db.query(DBTemplate).filter(DBTemplate.id == survey.id).first()
        if db_template:
            db_template.title = survey.title
            db_template.questions = [q.model_dump() for q in survey.questions]
        else:
            new_template = DBTemplate(id=survey.id, title=survey.title,
                                      questions=[q.model_dump() for q in survey.questions])
            db.add(new_template)
    db.commit()
    db.close()
    return {"message": "Шаблон надійно збережено в БД!", "id": survey.id}


@app.post("/api/templates/clone/{template_id}")
async def clone_template(template_id: str):
    db = SessionLocal()
    template = db.query(DBTemplate).filter(DBTemplate.id == template_id).first()
    if not template:
        db.close()
        raise HTTPException(status_code=404, detail="Не знайдено")

    new_id = str(uuid.uuid4())[:8]
    new_copy = DBTemplate(id=new_id, title=f"{template.title} (Копія)", questions=template.questions)
    db.add(new_copy)
    db.commit()
    db.close()
    return {"message": "Дубльовано успішно", "new_id": new_id}


@app.delete("/api/templates/{template_id}")
async def delete_template(template_id: str):
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
    if template:
        return {"id": template.id, "title": template.title, "questions": template.questions}
    raise HTTPException(status_code=404, detail="Опитування не знайдено")


@app.post("/api/responses")
async def save_student_response(response: StudentResponseSchema):
    db = SessionLocal()
    new_response = DBResponse(survey_id=response.survey_id, answers=response.answers)
    db.add(new_response)
    db.commit()
    db.close()
    return {"message": "Дякуємо! Ваші відповіді збережено."}