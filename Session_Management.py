from fastapi import FastAPI ,HTTPException ,Depends ,status, Request,Body,Form,APIRouter
from pydantic import BaseModel
from typing import Annotated
import modelsmysql
from dbtestmysql import engine,SessionLocal
from sqlalchemy.orm import Session
from datetime import datetime
from typing import List,Optional
from modelsmysql import Patient,auth, Billing, Doctors,Clinical_services,Nurses # Import models from external file
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
import random,os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
import math,uuid
from user_agents import parse  # Add the user_agents library for parsing the User-Agent
from jose import jwt, JWTError, ExpiredSignatureError
import bcrypt
from datetime import datetime, timedelta
from math import radians, sin, cos, sqrt, atan2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os,base64
import base64  # Add this import at the top of your file
import requests


Session_Management_router = APIRouter(
    tags=["Session Management"]  # Optional OpenAPI tag
)

def get_db():
    db=SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
db_dependency=Annotated[Session,Depends(get_db)]

class RefreshTokenRequest(BaseModel):
    refresh_token: str



# Secret key and algorithm for JWT
SECRET_KEY = "your-secret-key"  # Replace with a strong secret key in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 5 # Increased for better user experience
REFRESH_TOKEN_EXPIRE_MINUTES = 5
key_session = os.urandom(32)  # 256-bit key
# OAuth2 scheme for token authentication
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="/auth/login")



class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    user_id: int  
    email: str    
    role: str     
    session_auth: str  
    access_token_expires: int  
    refresh_token_expires: int  
    user_info: str  # Changed from bytes to str for JSON serialization
    
class RefreshTokenRequest(BaseModel):
    access_token: str
    refresh_token: str
    current_location: str
    os: Optional[str] = None
    browser: Optional[str] = None

@Session_Management_router.post("/auth", response_model=auth)
def authenticate_user(db: db_dependency, username: str = Form(...), password: str = Form(...)):
    user = db.query(auth).filter(auth.Email == username).first()
    if not user:
        return False #There is no user ind db with this username
    if not bcrypt.checkpw(password.encode('utf-8'), user.Password.encode('utf-8')):
        return False #The entered password is incorrect
    return user #Success


# In-memory revoked tokens set (for short-lived tokens)
REVOKED_TOKENS = set()


async def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]):
    try:
        # First check if token is revoked
        if token in REVOKED_TOKENS:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked"
            )

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get('type') != 'access':
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token type')
        email: str = payload.get('sub')
        user_id: int = payload.get('id')
        role: str = payload.get('role')
        user_info: str = payload.get('user_info')  # Extract concatenated user info from the token payload
        if email is None or user_id is None or role is None or user_info is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not validate user')
        return {'email': email, 'user_id': user_id, 'role': role, 'user_info': user_info ,'token':token}
    except JWTError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f'Could not validate user: {str(e)}')



#This function is responsible for the Token creation and notice that returned value includes the credentials which
#will be an authorized token form due to including the secret key of the server
def create_token(email: str, user_id: int, role: str, expires_delta: timedelta, token_type: str, user_info: str):
    encode = {
        'sub': email,
        'id': user_id,
        'role': role,
        'type': token_type,
        'exp': datetime.utcnow() + expires_delta,
        'user_info': user_info  # Ensure this is a string or JSON-serializable object
    }
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

class BanRequest(BaseModel):
    user_id: int
    ban_minutes: int = 15  # Default 15 minute ban

async def ban_user(
    ban_request: BanRequest,
    db: Session
):
    """
    Bans a user for specified duration
    
    Args:
        ban_request: BanRequest containing user_id and ban_minutes
        db: SQLAlchemy session
        
    Returns:
        dict: Ban confirmation with status, user_id and banned_until
        
    Raises:
        HTTPException: If user not found or database error
    """
    # Find the user
    user = db.query(auth).filter(auth.User_ID == ban_request.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Calculate ban expiration time
    ban_duration = timedelta(minutes=ban_request.ban_minutes)
    user.banned_until = datetime.now() + ban_duration
    
    try:
        db.commit()
        return {
            "status": "success",
            "user_id": user.User_ID,
            "banned_until": user.banned_until,
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to ban user: {str(e)}"
        )
        
#to use the ban
#  if action_type == "ban":
#         # Create a BanRequest object
#         ban_request = BanRequest(
#             user_id=user_id,
#             ban_minutes=60,  # 1 hour ban
#         )
#ban_result = await ban_user(ban_request, db)

@Session_Management_router.post("/ban-user/", status_code=status.HTTP_200_OK)
async def ban_user(
    ban_request: BanRequest,
    db: Session = Depends(get_db)  # Assuming you have a get_db dependency
):
    # Find the user
    user = db.query(auth).filter(auth.User_ID == ban_request.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Calculate ban expiration time
    ban_duration = timedelta(minutes=ban_request.ban_minutes)
    user.banned_until = datetime.now() + ban_duration
    
    # Optional: Store ban reason if you have that column
    # user.ban_reason = ban_request.reason
    
    try:
        db.commit()
        return {
            "status": "success",
            "user_id": user.User_ID,
            "banned_until": user.banned_until,
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to ban user: {str(e)}"
        )      
#@Patient_record_router.post("/revoke-token")
async def revoke_token(token: str = Depends(oauth2_bearer)):
    """Revokes the current user's token by adding it to the blocklist."""
    REVOKED_TOKENS.add(token)  # Add to in-memory set
    return {"message": "Token revoked successfully"}




@Session_Management_router .post("/auth/login", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: db_dependency,
    current_location: str = Form(...),
    os: Optional[str] = Form(None),
    browser: Optional[str] = Form(None)
):
    user = authenticate_user(form_data.username, form_data.password, db)
    logstash_url = "http://localhost:5044"
    if not user:
        user_info1 = {
            "username": form_data.username,
            "location": current_location,
            "os": os,
            "browser": browser,
            "status" : 'failed' }
        requests.post(logstash_url, json=user_info1)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Couldn't validate this user")
    # Check if user is banned
    if user.banned_until and user.banned_until > datetime.now():
        remaining_time = user.banned_until - datetime.now()
        remaining_minutes = int(remaining_time.total_seconds() / 60)
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Account is temporarily banned. Try again in {remaining_minutes} minutes."
        )
    
    # Send data to Logstash
    # Prepare data for Logstash
    user_info = {
        "username": form_data.username,
        "location": current_location,
        "os": os,
        "browser": browser,
        "email": user.Email,
        "user_id": user.User_ID,
        "Role": user.Role,
        "status": "SUCCESSFUL"
    }

    
    requests.post(logstash_url, json=user_info)

    # Concatenate loc, os, and browser into a single string
    user_info_before_encryption = f"loc: {current_location}, os: {os}, browser: {browser}"
    
    # Encrypt the user info and encode it using Base64
    encrypted_user_info = encrypt_message(key_session, user_info_before_encryption)
    user_info = base64.b64encode(encrypted_user_info).decode('utf-8')  # Encode to Base64 and decode to string
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    
    access_token = create_token(user.Email, user.User_ID, user.Role, access_token_expires, "access", user_info)
    refresh_token = create_token(user.Email, user.User_ID, user.Role, refresh_token_expires, "refresh", user_info)
    
    # Decode tokens to get expiry time
    access_token_payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
    refresh_token_payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
    
    print(user_info)
    return {
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_type': 'bearer',
        'user_id': user.User_ID,
        'email': user.Email,
        'role': user.Role,
        'session_auth': 'active',  # Populate this field
        'access_token_expires': int(access_token_payload['exp']),  # Convert to timestamp
        'refresh_token_expires': int(refresh_token_payload['exp']),  # Convert to timestamp
        'user_info': user_info  # Include Base64-encoded user info in the response
    }

@Session_Management_router .post("/auth/refresh")
async def refresh_access_token(db: db_dependency, request: RefreshTokenRequest = Body(...)):
    try:
        print(f"Incoming request: {request}")  # Log the incoming request
        accesst=request.access_token
        get_current_user(accesst)
        # Decode the refresh token
        payload = jwt.decode(request.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        print(f"Decoded payload: {payload}")  # Log the decoded payload

        # Check if the token is a refresh token
        if payload.get('type') != 'refresh':
            print("Invalid token type: expected 'refresh'")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token type')

        # Check if the token has expired
        if datetime.utcnow() > datetime.fromtimestamp(payload.get('exp')):
            print("Refresh token has expired")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Refresh token has expired')
        
        
        # Time left before token expires
        time_remaining =  datetime.utcnow()-datetime.fromtimestamp(payload.get('exp')) 

        # Check if more than (1/1.5 ≈ 60%) of the lifetime remains
        if (time_remaining > timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES / 1.5)) and (time_remaining > timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES / 1.5)):
            print("Refresh token overload")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Refresh token overload')

        # Extract user details from the token
        email: str = payload.get('sub')
        user_id: int = payload.get('id')
        role: str = payload.get('role')
        old_user_info_b64: str = payload.get('user_info')  # Extract Base64-encoded user info from the token payload

        # Decode Base64 to bytes
        old_user_info_encrypted = base64.b64decode(old_user_info_b64.encode('utf-8'))  # Convert Base64 string to bytes

        # Decrypt the user info
        old_user_info = decrypt_message(key_session, old_user_info_encrypted)  # Pass bytes to decrypt_message
        
        # Validate the user details
        if email is None or user_id is None or role is None or old_user_info is None:
            print("Missing required fields in token payload")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not validate user')

        # Fetch the user from the database
        user = db.query(auth).filter(auth.Email == email).first()
        if not user:
            print("User not found in database")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='User not found')

        # Extract old location from user_info
        try:
            old_loc_part = old_user_info.split(", ")[0]  # Extract "loc: 30.06024,30.961143"
            if not old_loc_part.startswith("loc: ") or "," not in old_loc_part:
                raise ValueError("Invalid location format in old_user_info")

            # Extract latitude and longitude
            lat_lon = old_loc_part.split("loc: ")[1].split(",")
            if len(lat_lon) != 2:
                raise ValueError("Invalid location format in old_user_info")

            old_lat = float(lat_lon[0])
            old_lon = float(lat_lon[1])
        except (IndexError, ValueError) as e:
            print(f"Error parsing old location: {e}")  # Log the error
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid location format in refresh token: {e}")

        # Extract new location from the request
        try:
            # Handle "xxx,xxx" format
            lat_lon = request.current_location.split(",")
            if len(lat_lon) != 2:
                raise ValueError("Invalid location format in request")

            new_lat = float(lat_lon[0])
            new_lon = float(lat_lon[1])
        except (IndexError, ValueError) as e:
            print(f"Error parsing new location: {e}")  # Log the error
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid location format in request: {e}")

        # Calculate the distance between the old and new locations
        distance = haversine(old_lat, old_lon, new_lat, new_lon)
        print(f"Distance between old and new location: {distance} km")

        # Check if the new location is within 1 km of the old location
        if distance > 1.0:  # 1 km threshold
            print("Location mismatch: new location is more than 1 km away")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid refresh token: location mismatch')

        # Concatenate new loc, os, and browser into a single string
        new_user_info = f"loc: {request.current_location}, os: {request.os}, browser: {request.browser}"

        # Compare old and new user_info (excluding location)
        old_user_info_without_loc = ", ".join(old_user_info.split(", ")[1:])  # Remove location part
        new_user_info_without_loc = ", ".join(new_user_info.split(", ")[1:])  # Remove location part
        print(f"Old user info without location: {old_user_info_without_loc}")
        print(f"New user info without location: {new_user_info_without_loc}")

        if old_user_info_without_loc != new_user_info_without_loc:
            print("User info mismatch")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid refresh token: user info mismatch')

        # If location and user_info match, proceed with creating new tokens
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        refresh_token_expires = timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)

        # Encrypt the new user info and encode it using Base64
        new_user_info_encrypted = encrypt_message(key_session, new_user_info)  # Pass the string directly
        new_user_info_b64 = base64.b64encode(new_user_info_encrypted).decode('utf-8')  # Encode to Base64 and decode to string

        access_token = create_token(user.Email, user.User_ID, user.Role, access_token_expires, "access", new_user_info_b64)
        refresh_token = create_token(user.Email, user.User_ID, user.Role, refresh_token_expires, "refresh", new_user_info_b64)

        # Decode tokens to get expiry time
        access_token_payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        refresh_token_payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])

        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'bearer',
            'user_id': user.User_ID,
            'email': user.Email,
            'role': user.Role,
            'session_auth': 'active',  # Populate this field
            'access_token_expires': int(access_token_payload['exp']),  # Convert to timestamp
            'refresh_token_expires': int(refresh_token_payload['exp']),  # Convert to timestamp
            'user_info': new_user_info_b64  # Include Base64-encoded user info in the response
        }
    except jwt.ExpiredSignatureError:
        print("Refresh token has expired")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Refresh token has expired. Please log in again.')
    except JWTError as e:
        print(f"JWTError: {e}")  # Log the JWTError
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f'Could not validate user: {str(e)}')
    except Exception as e:
        print(f"Unexpected error: {e}")  # Log any unexpected errors
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f'An error occurred: {str(e)}')




# Derive a fixed IV from the key
def derive_iv(key):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=12,  # 96-bit IV for AES-GCM
        salt=None,
        info=b"fixed-iv",
    )
    return hkdf.derive(key)



def haversine(lat1, lon1, lat2, lon2):
    """
    Calculate the great-circle distance between two points on the Earth (specified in decimal degrees).
    Returns the distance in kilometers.
    """
    # Convert decimal degrees to radians
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    
    # Haversine formula
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = sin(dlat / 2)*2 + cos(lat1) * cos(lat2) * sin(dlon / 2)*2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    
    # Radius of Earth in kilometers
    R = 6371.0
    distance = R * c
    return distance


# Encrypt a message (deterministic)
def encrypt_message(key, plaintext):
    # Derive a fixed IV from the key
    iv = derive_iv(key)

    # Construct an AES-GCM Cipher object with the given key and fixed IV
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv)
    ).encryptor()

    # Encrypt the plaintext and get the associated ciphertext
    ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()

    # Return the ciphertext and tag
    return ciphertext + encryptor.tag

# Decrypt a message (deterministic)
def decrypt_message(key, ciphertext_with_tag):
    # Derive the fixed IV from the key
    iv = derive_iv(key)

    # Split the ciphertext and tag
    ciphertext = ciphertext_with_tag[:-16]  # Last 16 bytes are the tag
    tag = ciphertext_with_tag[-16:]

    # Construct an AES-GCM Cipher object with the given key, fixed IV, and tag
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag)
    ).decryptor()

    # Decrypt the ciphertext and get the associated plaintext
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Return the decrypted plaintext
    return plaintext.decode()