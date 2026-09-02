import os, time, hmac, hashlib
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
import requests

app = FastAPI(title="Devdhar AI")
PIN = os.getenv("DEVDHAR_PIN", "")
SECRET = os.getenv("DEVDHAR_SECRET", "")
GROQ_KEY = os.getenv("GROQ_API_KEY", "")
MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")

def make_token():
    payload = str(int(time.time()) // 86400).encode()
    sig = hmac.new(SECRET.encode(), payload, hashlib.sha256).hexdigest()
    return payload.decode() + "." + sig

def valid_token(token):
    if not SECRET or not token or "." not in token:
        return False
    payload, sig = token.split(".", 1)
    if payload != str(int(time.time()) // 86400):
        return False
    expected = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected)

def authorized(request: Request):
    return valid_token(request.cookies.get("devdhar_session"))

class LoginRequest(BaseModel):
    pin: str

class ChatRequest(BaseModel):
    message: str

@app.get("/")
def home():
    return FileResponse("static/index.html")

@app.get("/api/health")
def health():
    return {"ok": True, "ai_configured": bool(GROQ_KEY and SECRET and PIN)}

@app.post("/api/login")
def login(req: LoginRequest):
    if not PIN or not SECRET:
        raise HTTPException(500, "Owner security is not configured")
    if not hmac.compare_digest(req.pin, PIN):
        raise HTTPException(401, "Wrong owner PIN")
    response = JSONResponse({"ok": True})
    response.set_cookie(
        "devdhar_session", make_token(),
        httponly=True, secure=True, samesite="lax", max_age=172800
    )
    return response

@app.post("/api/logout")
def logout():
    response = JSONResponse({"ok": True})
    response.delete_cookie("devdhar_session")
    return response

@app.post("/api/chat")
def chat(req: ChatRequest, request: Request):
    if not authorized(request):
        raise HTTPException(401, "Please unlock Devdhar first")
    if not GROQ_KEY:
        raise HTTPException(503, "AI provider is not configured yet")

    messages = [
        {"role":"system","content":
         "You are Devdhar AI, a private personal assistant. "
         "Reply naturally in Hindi, Hinglish, or English matching the user. "
         "Be concise and helpful. Never claim you performed a phone action unless the system actually did it."},
        {"role":"user","content":req.message}
    ]
    try:
        r = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {GROQ_KEY}", "Content-Type":"application/json"},
            json={"model": MODEL, "messages": messages, "temperature": 0.4},
            timeout=60
        )
        r.raise_for_status()
        data = r.json()
        reply = data["choices"][0]["message"]["content"].strip()
        return {"reply": reply}
    except requests.RequestException:
        raise HTTPException(502, "Devdhar AI service is temporarily unavailable")

