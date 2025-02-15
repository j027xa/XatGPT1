from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import List, Dict, Optional
import requests
from pydantic import BaseModel
import logging
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.responses import RedirectResponse
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
from google.auth.transport import requests
import json
import os

# Add logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# Templates and static files
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Security settings
SECRET_KEY = os.environ.get("SECRET_KEY", "your-secret-key-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Models
class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None

class UserInDB(User):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class ChatRequest(BaseModel):
    message: str

class UserRegister(BaseModel):
    username: str
    email: str
    password: str

# Fake user database
fake_users_db = {}

# Chat history database
chat_histories = {}

# API settings
API_KEY = os.environ.get("API_KEY", "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")
API_URL = "https://openrouter.ai/api/v1/chat/completions"

# Port va host sozlamalari
PORT = int(os.environ.get("PORT", 8000))
HOST = "0.0.0.0"

# Google OAuth sozlamalari
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "sizning-client-id")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "sizning-client-secret")

# Test uchun xavfsizlik o'chirilgan
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Google OAuth konfiguratsiyasi
GOOGLE_CONFIG = {
    "web": {
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": [os.environ.get("REDIRECT_URI", "http://localhost:8000/auth/google/callback")]
    }
}

# Security functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

# Routes
@app.get("/")
async def home(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/chat")
async def chat_page(request: Request, current_user: User = Depends(get_current_user)):
    return templates.TemplateResponse("chat.html", {
        "request": request,
        "user": current_user,
        "chat_history": chat_histories.get(current_user.username, [])
    })

@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/register")
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
async def register(user: UserRegister):
    # Validate username
    if len(user.username) < 3:
        raise HTTPException(
            status_code=400,
            detail="Username must be at least 3 characters long"
        )
    
    # Check if username exists
    if user.username in fake_users_db:
        raise HTTPException(
            status_code=400,
            detail="Username already registered"
        )
    
    # Validate email format
    if not "@" in user.email:
        raise HTTPException(
            status_code=400,
            detail="Invalid email format"
        )
    
    # Validate password
    if len(user.password) < 6:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 6 characters long"
        )
    
    # Create new user
    hashed_password = get_password_hash(user.password)
    user_dict = {
        "username": user.username,
        "email": user.email,
        "hashed_password": hashed_password,
        "full_name": None
    }
    
    fake_users_db[user.username] = user_dict
    return {"message": "User created successfully"}

@app.post("/chat/{user_id}")
async def chat(
    user_id: str, 
    request: ChatRequest, 
    current_user: User = Depends(get_current_user)
):
    try:
        if current_user.username not in chat_histories:
            chat_histories[current_user.username] = []
        
        # Add user message to history
        chat_histories[current_user.username].append({
            "role": "user",
            "content": request.message,
            "timestamp": datetime.now().isoformat()
        })

        headers = {
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json",
            "HTTP-Referer": "http://localhost:8000",
            "X-Title": "My Chatbot"
        }

        payload = {
            "model": "openai/gpt-3.5-turbo",
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": request.message}
            ]
        }

        response = requests.post(API_URL, json=payload, headers=headers)
        response.raise_for_status()
        
        bot_reply = response.json()["choices"][0]["message"]["content"]
        
        # Add bot response to history
        chat_histories[current_user.username].append({
            "role": "assistant",
            "content": bot_reply,
            "timestamp": datetime.now().isoformat()
        })

        return {
            "response": bot_reply,
            "chat_history": chat_histories[current_user.username]
        }

    except Exception as e:
        logger.error(f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/")
    return response

@app.get("/login/google")
async def google_login():
    try:
        flow = Flow.from_client_config(
            GOOGLE_CONFIG,
            scopes=['openid', 'email', 'profile']
        )
        flow.redirect_uri = "http://localhost:8000/auth/google/callback"
        
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true'
        )
        
        print(f"Authorization URL: {authorization_url}")  # Debug uchun
        return RedirectResponse(url=authorization_url)
        
    except Exception as e:
        print(f"Google login error: {str(e)}")  # Debug uchun
        return {"error": str(e)}

@app.get("/auth/google/callback")
async def google_callback(request: Request):
    try:
        print("Callback received")  # Debug uchun
        
        flow = Flow.from_client_config(
            GOOGLE_CONFIG,
            scopes=['openid', 'email', 'profile'],
            state=request.query_params.get("state")
        )
        flow.redirect_uri = "http://localhost:8000/auth/google/callback"
        
        # Token olish
        flow.fetch_token(
            authorization_response=str(request.url)
        )
        
        credentials = flow.credentials
        user_info = id_token.verify_oauth2_token(
            credentials.id_token,
            requests.Request(),
            GOOGLE_CLIENT_ID
        )
        
        print(f"User info: {user_info}")  # Debug uchun
        
        # Foydalanuvchini bazaga qo'shish
        email = user_info.get("email")
        username = email.split("@")[0]
        
        if username not in fake_users_db:
            fake_users_db[username] = {
                "username": username,
                "email": email,
                "full_name": user_info.get("name"),
                "hashed_password": "google-oauth"
            }
        
        # Token yaratish
        access_token = create_access_token(data={"sub": username})
        
        response = RedirectResponse(url="/chat")
        response.set_cookie(
            key="access_token",
            value=f"Bearer {access_token}",
            httponly=True
        )
        return response
        
    except Exception as e:
        print(f"Callback error: {str(e)}")  # Debug uchun
        return RedirectResponse(url="/?error=google_auth_failed")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("XatGPT:app", host=HOST, port=PORT, reload=True)
