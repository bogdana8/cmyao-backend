from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import json
import os
import uuid

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

FILE_PATH = "templates_db.json"
RESPONSES_FILE = "responses_db.json"


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


def read_db():
    if not os.path.exists(FILE_PATH): return []
    with open(FILE_PATH, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except:
            return []


@app.get("/api/templates")
async def get_templates():
    return read_db()


@app.post("/api/templates")
async def save_template(survey: SurveyTemplateSchema):
    db = read_db()
    if not survey.id:
        survey.id = str(uuid.uuid4())[:8]
        db.append(survey.model_dump())
    else:
        for idx, item in enumerate(db):
            if item['id'] == survey.id:
                db[idx] = survey.model_dump()
    with open(FILE_PATH, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=4)
    return {"message": "Шаблон збережено", "id": survey.id}


@app.post("/api/templates/clone/{template_id}")
async def clone_template(template_id: str):
    db = read_db()
    template = next((item for item in db if item["id"] == template_id), None)
    if not template: raise HTTPException(status_code=404, detail="Не знайдено")

    new_copy = template.copy()
    new_copy["id"] = str(uuid.uuid4())[:8]
    new_copy["title"] = f"{template['title']} (Копія)"
    db.append(new_copy)
    with open(FILE_PATH, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=4)
    return {"message": "Дубльовано успішно", "new_id": new_copy["id"]}


@app.delete("/api/templates/{template_id}")
async def delete_template(template_id: str):
    db = read_db()
    db = [item for item in db if item["id"] != template_id]
    with open(FILE_PATH, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=4)
    return {"message": "Видалено"}


# --- МАРШРУТИ ДЛЯ СТУДЕНТІВ ---

@app.get("/api/templates/{template_id}")
async def get_single_template(template_id: str):
    db = read_db()
    for item in db:
        if item["id"] == template_id:
            return item
    raise HTTPException(status_code=404, detail="Опитування не знайдено")


@app.post("/api/responses")
async def save_student_response(response: StudentResponseSchema):
    if not os.path.exists(RESPONSES_FILE):
        db = []
    else:
        with open(RESPONSES_FILE, "r", encoding="utf-8") as f:
            try:
                db = json.load(f)
            except:
                db = []

    db.append(response.model_dump())
    with open(RESPONSES_FILE, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=4)
    return {"message": "Дякуємо! Ваші відповіді збережено."}