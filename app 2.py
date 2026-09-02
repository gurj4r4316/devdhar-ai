import os, time, hmac, hashlib, base64
from fastapi import FastAPI, Request, HTTPException, UploadFile, File
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
import requests

app = FastAPI(title="Devdhar AI")
PIN = os.getenv("DEVDHAR_PIN", "")
SECRET = os.getenv("DEVDHAR_SECRET", "")
GROQ_KEY = os.getenv("GROQ_API_KEY", "")
MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")
VISION_MODEL = os.getenv("GROQ_VISION_MODEL", "qwen/qwen3.6-27b")

MAX_IMAGE_BYTES = 10 * 1024 * 1024
ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp", "image/gif"}

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
    profile: dict | None = None

@app.get("/")
def home():
    return FileResponse("index.html")

@app.get("/api/health")
def health():
    return {
        "ok": True,
        "ai_configured": bool(GROQ_KEY and SECRET and PIN),
        "vision_configured": bool(GROQ_KEY and SECRET and PIN),
    }

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
         "You are Devdhar AI, a private personal assistant owned by the user. "
         "Reply naturally in Hindi, Hinglish, or English matching the user. "
         "Be concise and helpful. Never claim you performed a phone action unless the system actually did it. "
         "Owner social-profile rule: only discuss information explicitly marked PUBLIC. "
         "If a profile is marked PRIVATE, do not reveal, infer, search for, or summarize private information from it. "
         "If public-profile data has not been fetched yet, clearly say that live public lookup is not configured yet."},
        {"role":"user","content": "Owner profile context:\n" + str(req.profile or {}) + "\n\nUser request:\n" + req.message}
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

@app.post("/api/analyze-image")
async def analyze_image(request: Request, image: UploadFile = File(...), question: str = "Is photo ko describe karo aur jo main pooch raha hoon uska jawab do."):
    if not authorized(request):
        raise HTTPException(401, "Please unlock Devdhar first")
    if not GROQ_KEY:
        raise HTTPException(503, "AI provider is not configured yet")
    if image.content_type not in ALLOWED_IMAGE_TYPES:
        raise HTTPException(400, "Please upload a JPG, PNG, WEBP, or GIF image")
    raw = await image.read()
    if len(raw) > MAX_IMAGE_BYTES:
        raise HTTPException(413, "Image is too large. Maximum size is 10 MB.")
    encoded = base64.b64encode(raw).decode("utf-8")
    data_url = f"data:{image.content_type};base64,{encoded}"
    prompt = (question or "Is photo ko describe karo.").strip()
    messages = [{
        "role": "user",
        "content": [
            {"type": "text", "text": prompt},
            {"type": "image_url", "image_url": {"url": data_url}}
        ]
    }]
    try:
        r = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {GROQ_KEY}", "Content-Type":"application/json"},
            json={"model": VISION_MODEL, "messages": messages, "temperature": 0.2, "max_completion_tokens": 1200},
            timeout=90
        )
        r.raise_for_status()
        data = r.json()
        reply = data["choices"][0]["message"]["content"].strip()
        return {"reply": reply, "filename": image.filename}
    except requests.RequestException as e:
        detail = "Photo analysis service is temporarily unavailable"
        try:
            detail = r.json().get("error", {}).get("message", detail)
        except Exception:
            pass
        raise HTTPException(502, detail)
