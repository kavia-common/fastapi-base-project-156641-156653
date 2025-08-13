from datetime import datetime, timedelta, timezone
import os
from typing import Dict, Optional, Set

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel, Field
from passlib.context import CryptContext

# ------------------------------------------------------------------------------
# App metadata and OpenAPI tags
# ------------------------------------------------------------------------------

openapi_tags = [
    {
        "name": "Health",
        "description": "Service health and status checks.",
    },
    {
        "name": "Auth",
        "description": "User registration and JWT-based login endpoints.",
    },
    {
        "name": "Users",
        "description": "User-facing endpoints requiring authentication.",
    },
    {
        "name": "Admin",
        "description": "Admin-only endpoints demonstrating role-based access control.",
    },
    {
        "name": "RBAC",
        "description": "Examples showing role-based access control using dependencies.",
    },
]

app = FastAPI(
    title="FastAPI RBAC Demo",
    description=(
        "A demonstration FastAPI backend implementing user registration, JWT login, "
        "and Role Based Access Control (RBAC) using in-memory storage. "
        "Set JWT_SECRET in the environment to sign tokens."
    ),
    version="1.0.0",
    openapi_tags=openapi_tags,
)

# ------------------------------------------------------------------------------
# CORS
# ------------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # demo-friendly; restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------------------------
# Security and configuration
# ------------------------------------------------------------------------------

# Environment variables (do not hardcode secrets)
SECRET_KEY = os.getenv("JWT_SECRET")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

# OAuth2 scheme for Swagger "Authorize" button
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token", scheme_name="JWT")

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Valid roles in this demo
VALID_ROLES: Set[str] = {"user", "admin"}

# ------------------------------------------------------------------------------
# In-memory storage (for demo only; not for production use)
# ------------------------------------------------------------------------------

# demo user record: {"username": str, "hashed_password": str, "role": "user"|"admin"}
USERS_DB: Dict[str, Dict[str, str]] = {}


# ------------------------------------------------------------------------------
# Models
# ------------------------------------------------------------------------------

class Token(BaseModel):
    access_token: str = Field(..., description="The JWT access token.")
    token_type: str = Field("bearer", description="The type of the token. Always 'bearer'.")


class TokenPayload(BaseModel):
    sub: str = Field(..., description="Subject (username) for whom the token was issued.")
    role: str = Field(..., description="Role of the subject.")
    exp: int = Field(..., description="Expiration timestamp (Unix seconds).")


class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="Unique username.")
    password: str = Field(..., min_length=6, max_length=128, description="User password.")
    role: Optional[str] = Field(
        default="user", description="Role for the new user. Allowed: 'user', 'admin'."
    )


class UserLogin(BaseModel):
    username: str = Field(..., description="Username used for login.")
    password: str = Field(..., description="Password for the account.")


class UserPublic(BaseModel):
    username: str = Field(..., description="User's username.")
    role: str = Field(..., description="User's role.")


# ------------------------------------------------------------------------------
# Utility functions
# ------------------------------------------------------------------------------

# PUBLIC_INTERFACE
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a hashed password."""
    return pwd_context.verify(plain_password, hashed_password)


# PUBLIC_INTERFACE
def get_password_hash(password: str) -> str:
    """Hash a plaintext password for secure storage."""
    return pwd_context.hash(password)


# PUBLIC_INTERFACE
def create_access_token(data: Dict[str, str], expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a signed JWT access token.

    Args:
        data: Claims to embed in the token. Must include 'sub' (username) and 'role'.
        expires_delta: Optional custom expiration delta.

    Returns:
        Encoded JWT string.

    Raises:
        HTTPException: If SECRET_KEY is not configured.
    """
    if not SECRET_KEY:
        # Enforce external configuration of secrets
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="JWT secret not configured. Please set JWT_SECRET in the environment.",
        )
    to_encode = data.copy()
    expire = datetime.now(tz=timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# PUBLIC_INTERFACE
def authenticate_user(username: str, password: str) -> Optional[Dict[str, str]]:
    """
    Authenticate a user against the in-memory user store.

    Returns:
        The user dict if authentication succeeds, otherwise None.
    """
    user = USERS_DB.get(username)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return user


# PUBLIC_INTERFACE
async def get_current_user(token: str = Depends(oauth2_scheme)) -> Dict[str, str]:
    """
    Decode and validate a JWT, returning the corresponding user.

    Raises:
        HTTPException: If token is invalid or user does not exist.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY or "", algorithms=[ALGORITHM])
        username: Optional[str] = payload.get("sub")
        role: Optional[str] = payload.get("role")
        if username is None or role is None:
            raise credentials_exception
        token_data = TokenPayload(sub=username, role=role, exp=int(payload.get("exp", 0)))
    except JWTError:
        raise credentials_exception

    user = USERS_DB.get(token_data.sub)
    if user is None:
        raise credentials_exception
    return {"username": token_data.sub, "role": user["role"]}


# PUBLIC_INTERFACE
def role_required(required_roles: Set[str]):
    """
    Dependency factory enforcing that the current user has one of the required roles.

    Usage:
        @app.get(..., dependencies=[Depends(role_required({'admin'}))])
    """
    invalid_roles = required_roles - VALID_ROLES
    if invalid_roles:
        raise ValueError(f"Unknown roles in requirement: {invalid_roles}")

    async def _checker(current_user: Dict[str, str] = Depends(get_current_user)) -> Dict[str, str]:
        role = current_user.get("role")
        if role not in required_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient privileges. Requires one of roles: {sorted(required_roles)}",
            )
        return current_user

    return _checker


# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------

@app.get("/", tags=["Health"], summary="Health Check", operation_id="health_check")
# PUBLIC_INTERFACE
def health_check():
    """Simple health check endpoint."""
    return {"message": "Healthy"}


@app.post(
    "/auth/register",
    tags=["Auth"],
    response_model=UserPublic,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    operation_id="auth_register",
)
# PUBLIC_INTERFACE
def register_user(payload: UserRegister) -> UserPublic:
    """
    Register a new user with a role and hashed password.

    Args:
        payload: User registration data including username, password, and optional role.

    Returns:
        The registered user's public information.

    Raises:
        HTTPException: If username already exists or role is invalid.
    """
    username = payload.username.strip().lower()
    if username in USERS_DB:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists.")

    role = (payload.role or "user").strip().lower()
    if role not in VALID_ROLES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid role. Allowed: {sorted(VALID_ROLES)}")

    USERS_DB[username] = {
        "username": username,
        "hashed_password": get_password_hash(payload.password),
        "role": role,
    }
    return UserPublic(username=username, role=role)


@app.post(
    "/auth/login",
    tags=["Auth"],
    response_model=Token,
    summary="Login (JSON) and receive JWT",
    operation_id="auth_login_json",
)
# PUBLIC_INTERFACE
def login_json(payload: UserLogin) -> Token:
    """
    Login using JSON body and receive a JWT.

    Args:
        payload: JSON body containing username and password.

    Returns:
        Bearer token for subsequent authenticated requests.

    Raises:
        HTTPException: If credentials are invalid or secret is not configured.
    """
    user = authenticate_user(payload.username.strip().lower(), payload.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password.")
    token = create_access_token({"sub": user["username"], "role": user["role"]})
    return Token(access_token=token, token_type="bearer")


@app.post(
    "/auth/token",
    tags=["Auth"],
    response_model=Token,
    summary="OAuth2 Password login (form) and receive JWT",
    operation_id="auth_login_oauth2",
)
# PUBLIC_INTERFACE
def login_oauth2(form_data: OAuth2PasswordRequestForm = Depends()) -> Token:
    """
    OAuth2-compatible login using form data (username and password).

    This endpoint is referenced by the Swagger UI "Authorize" button.

    Args:
        form_data: OAuth2 form data with fields 'username' and 'password'.

    Returns:
        Bearer token for subsequent authenticated requests.

    Raises:
        HTTPException: If credentials are invalid or secret is not configured.
    """
    user = authenticate_user(form_data.username.strip().lower(), form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password.")
    token = create_access_token({"sub": user["username"], "role": user["role"]})
    return Token(access_token=token, token_type="bearer")


@app.get(
    "/users/me",
    tags=["Users"],
    response_model=UserPublic,
    summary="Get current user profile",
    operation_id="users_me",
)
# PUBLIC_INTERFACE
def read_users_me(current_user: Dict[str, str] = Depends(get_current_user)) -> UserPublic:
    """
    Return the authenticated user's profile.
    """
    return UserPublic(username=current_user["username"], role=current_user["role"])


@app.get(
    "/user/area",
    tags=["RBAC"],
    summary="User area (role: user or admin)",
    operation_id="user_area",
)
# PUBLIC_INTERFACE
def user_area(_: Dict[str, str] = Depends(role_required({"user", "admin"}))):
    """
    Example endpoint accessible by users with role 'user' or 'admin'.
    """
    return {"message": "Welcome to the user area. Your role is sufficient to access this resource."}


@app.get(
    "/admin/dashboard",
    tags=["Admin"],
    summary="Admin dashboard (role: admin)",
    operation_id="admin_dashboard",
)
# PUBLIC_INTERFACE
def admin_dashboard(_: Dict[str, str] = Depends(role_required({"admin"}))):
    """
    Example admin-only endpoint.
    """
    return {"message": "Welcome to the admin dashboard.", "stats": {"users_count": len(USERS_DB)}}
