import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Any, Dict

from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr
import bcrypt
import jwt
from dotenv import load_dotenv

from database import db, create_document, get_documents
from bson import ObjectId

# Load env
load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

app = FastAPI(title="FlowPlan API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer(auto_error=False)

# -------------------- Utils --------------------

def oid(id_str: str) -> ObjectId:
    try:
        return ObjectId(id_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID")

def serialize_id(value: Any) -> Any:
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, list):
        return [serialize_id(v) for v in value]
    if isinstance(value, dict):
        return {k: serialize_id(v) for k, v in value.items()}
    return value


def serialize_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    if not doc:
        return doc
    doc["id"] = str(doc.pop("_id"))
    return serialize_id(doc)


async def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> dict:
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
    user_id = payload.get("sub")
    user = db["user"].find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return serialize_doc(user)


def create_access_token(user_id: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": user_id, "exp": expire}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

# -------------------- Models --------------------

class RegisterInput(BaseModel):
    name: str
    email: EmailStr
    password: str

class LoginInput(BaseModel):
    email: EmailStr
    password: str

class ProjectInput(BaseModel):
    name: str
    description: Optional[str] = None

class TaskInput(BaseModel):
    project_id: str
    title: str
    description: Optional[str] = None
    status: str = Field("todo")  # todo, doing, done
    priority: str = Field("medium")  # low, medium, high
    due_date: Optional[str] = None

class TaskUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    due_date: Optional[str] = None

class CommentInput(BaseModel):
    task_id: str
    content: str

class AISuggestTasksInput(BaseModel):
    project_name: str
    description: Optional[str] = None
    count: int = 5

class AISummaryInput(BaseModel):
    text: str

# -------------------- Root & Health --------------------

@app.get("/")
def read_root():
    return {"message": "FlowPlan API running"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = os.getenv("DATABASE_NAME") or "❌ Not Set"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
                response["connection_status"] = "Connected"
            except Exception as e:
                response["database"] = f"⚠️ Connected but Error: {str(e)[:60]}"
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:60]}"
    return response

# -------------------- Auth --------------------

@app.post("/auth/register")
def register(payload: RegisterInput):
    existing = db["user"].find_one({"email": payload.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed = bcrypt.hashpw(payload.password.encode(), bcrypt.gensalt()).decode()
    doc = {
        "name": payload.name,
        "email": payload.email,
        "password": hashed,
        "roles": ["member"],
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc)
    }
    res = db["user"].insert_one(doc)
    user_id = str(res.inserted_id)
    token = create_access_token(user_id)
    return {"token": token, "user": {"id": user_id, "name": payload.name, "email": payload.email, "roles": ["member"]}}

@app.post("/auth/login")
def login(payload: LoginInput):
    user = db["user"].find_one({"email": payload.email})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not bcrypt.checkpw(payload.password.encode(), user.get("password", "").encode()):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token(str(user["_id"]))
    suser = serialize_doc(user)
    suser.pop("password", None)
    return {"token": token, "user": suser}

# -------------------- Projects --------------------

@app.get("/projects")
def list_projects(current=Depends(get_current_user)):
    cursor = db["project"].find({"owner_id": current["id"]}).sort("created_at", -1)
    return [serialize_doc(p) for p in cursor]

@app.post("/projects")
def create_project(payload: ProjectInput, current=Depends(get_current_user)):
    doc = {
        "name": payload.name,
        "description": payload.description,
        "owner_id": current["id"],
        "members": [current["id"]],
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc)
    }
    res = db["project"].insert_one(doc)
    return serialize_doc(db["project"].find_one({"_id": res.inserted_id}))

@app.get("/projects/{project_id}")
def get_project(project_id: str, current=Depends(get_current_user)):
    proj = db["project"].find_one({"_id": oid(project_id)})
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")
    if current["id"] not in proj.get("members", []):
        raise HTTPException(status_code=403, detail="Forbidden")
    return serialize_doc(proj)

@app.put("/projects/{project_id}")
def update_project(project_id: str, payload: ProjectInput, current=Depends(get_current_user)):
    proj = db["project"].find_one({"_id": oid(project_id)})
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")
    if current["id"] != proj.get("owner_id"):
        raise HTTPException(status_code=403, detail="Only owner can update")
    db["project"].update_one({"_id": oid(project_id)}, {"$set": {
        "name": payload.name,
        "description": payload.description,
        "updated_at": datetime.now(timezone.utc)
    }})
    return serialize_doc(db["project"].find_one({"_id": oid(project_id)}))

@app.delete("/projects/{project_id}")
def delete_project(project_id: str, current=Depends(get_current_user)):
    proj = db["project"].find_one({"_id": oid(project_id)})
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")
    if current["id"] != proj.get("owner_id"):
        raise HTTPException(status_code=403, detail="Only owner can delete")
    db["task"].delete_many({"project_id": project_id})
    db["project"].delete_one({"_id": oid(project_id)})
    return {"ok": True}

# -------------------- Tasks --------------------

@app.get("/projects/{project_id}/tasks")
def list_tasks(project_id: str, current=Depends(get_current_user)):
    proj = db["project"].find_one({"_id": oid(project_id)})
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")
    if current["id"] not in proj.get("members", []):
        raise HTTPException(status_code=403, detail="Forbidden")
    tasks = db["task"].find({"project_id": project_id}).sort("created_at", -1)
    return [serialize_doc(t) for t in tasks]

@app.post("/tasks")
def create_task(payload: TaskInput, current=Depends(get_current_user)):
    proj = db["project"].find_one({"_id": oid(payload.project_id)})
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")
    if current["id"] not in proj.get("members", []):
        raise HTTPException(status_code=403, detail="Forbidden")
    doc = {
        "project_id": payload.project_id,
        "title": payload.title,
        "description": payload.description,
        "status": payload.status,
        "priority": payload.priority,
        "due_date": payload.due_date,
        "assignees": [current["id"]],
        "created_by": current["id"],
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc)
    }
    res = db["task"].insert_one(doc)
    return serialize_doc(db["task"].find_one({"_id": res.inserted_id}))

@app.put("/tasks/{task_id}")
def update_task(task_id: str, payload: TaskUpdate, current=Depends(get_current_user)):
    task = db["task"].find_one({"_id": oid(task_id)})
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    proj = db["project"].find_one({"_id": oid(task["project_id"])})
    if current["id"] not in proj.get("members", []):
        raise HTTPException(status_code=403, detail="Forbidden")
    updates = {k: v for k, v in payload.model_dump(exclude_none=True).items()}
    updates["updated_at"] = datetime.now(timezone.utc)
    db["task"].update_one({"_id": oid(task_id)}, {"$set": updates})
    return serialize_doc(db["task"].find_one({"_id": oid(task_id)}))

@app.delete("/tasks/{task_id}")
def delete_task(task_id: str, current=Depends(get_current_user)):
    task = db["task"].find_one({"_id": oid(task_id)})
    if not task:
        return {"ok": True}
    proj = db["project"].find_one({"_id": oid(task["project_id"])})
    if current["id"] not in proj.get("members", []):
        raise HTTPException(status_code=403, detail="Forbidden")
    db["task"].delete_one({"_id": oid(task_id)})
    return {"ok": True}

# -------------------- Comments --------------------

@app.post("/tasks/{task_id}/comments")
def add_comment(task_id: str, payload: CommentInput, current=Depends(get_current_user)):
    task = db["task"].find_one({"_id": oid(task_id)})
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    proj = db["project"].find_one({"_id": oid(task["project_id"])})
    if current["id"] not in proj.get("members", []):
        raise HTTPException(status_code=403, detail="Forbidden")
    doc = {
        "task_id": task_id,
        "content": payload.content,
        "author_id": current["id"],
        "created_at": datetime.now(timezone.utc),
    }
    res = db["comment"].insert_one(doc)
    return serialize_doc(db["comment"].find_one({"_id": res.inserted_id}))

@app.get("/tasks/{task_id}/comments")
def list_comments(task_id: str, current=Depends(get_current_user)):
    task = db["task"].find_one({"_id": oid(task_id)})
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    proj = db["project"].find_one({"_id": oid(task["project_id"])})
    if current["id"] not in proj.get("members", []):
        raise HTTPException(status_code=403, detail="Forbidden")
    items = db["comment"].find({"task_id": task_id}).sort("created_at", -1)
    return [serialize_doc(i) for i in items]

# -------------------- AI Endpoints --------------------

@app.post("/ai/suggest-tasks")
def ai_suggest_tasks(payload: AISuggestTasksInput, current=Depends(get_current_user)):
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        # Return deterministic fallback suggestions without calling OpenAI
        suggestions = [
            {"title": f"Milestone {i+1}", "description": f"Auto-suggested task {i+1} for {payload.project_name}", "priority": "medium"}
            for i in range(max(1, payload.count))
        ]
        return {"provider": "fallback", "tasks": suggestions}
    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)
        prompt = (
            f"Project: {payload.project_name}\n"
            f"Description: {payload.description or 'N/A'}\n"
            f"Generate {payload.count} actionable tasks in JSON array with fields: title, description, priority (low|medium|high)."
        )
        chat = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": prompt}], temperature=0.2)
        content = chat.choices[0].message.content
        import json
        tasks: List[Dict[str, Any]] = []
        try:
            tasks = json.loads(content)
        except Exception:
            # Try to extract JSON block
            import re
            match = re.search(r"\[.*\]", content, re.S)
            if match:
                tasks = json.loads(match.group(0))
        if not isinstance(tasks, list):
            tasks = []
        return {"provider": "openai", "tasks": tasks}
    except Exception as e:
        # Graceful fallback
        suggestions = [
            {"title": f"Kickoff Meeting", "description": "Align on scope, roles, and timeline", "priority": "high"},
            {"title": f"Define Requirements", "description": "Document user stories and acceptance criteria", "priority": "high"}
        ]
        return {"provider": "error-fallback", "error": str(e)[:120], "tasks": suggestions}

@app.post("/ai/summary")
def ai_summary(payload: AISummaryInput, current=Depends(get_current_user)):
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        # naive fallback
        text = payload.text.strip()
        sentences = text.split(".")
        summary = ". ".join([s.strip() for s in sentences[:2] if s.strip()])
        return {"provider": "fallback", "summary": summary}
    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)
        prompt = f"Summarize the following project update in 3 bullet points:\n\n{payload.text}"
        chat = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": prompt}], temperature=0.2)
        content = chat.choices[0].message.content
        return {"provider": "openai", "summary": content}
    except Exception as e:
        return {"provider": "error-fallback", "summary": payload.text[:200], "error": str(e)[:120]}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
