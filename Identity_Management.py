from fastapi import FastAPI ,HTTPException ,Depends ,status, Request,Body,Form,APIRouter
from pydantic import BaseModel
from typing import Annotated
import modelsmysql
from dbtestmysql import engine,SessionLocal
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import bcrypt
from datetime import datetime, timedelta
from pydantic import BaseModel
from sqlalchemy.orm import Session

def get_db():
    db=SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
db_dependency=Annotated[Session,Depends(get_db)]

IM_router = APIRouter(
    tags=["Identity Management"]  # Optional OpenAPI tag
)


class AuthBase(BaseModel):
    User_ID: int
    Username: str
    Password: str
    National_ID: int
    Full_Name: str
    Email: str
    Role: str
    Last_Login_Date: datetime  # Use datetime in Pydantic
    Activity_Logs: str

    class Config:
        orm_mode = True

@IM_router.post("/auth", status_code=status.HTTP_201_CREATED)
async def create_auth(auth_data: AuthBase, db: Session = Depends(get_db)):

    hashed_password = bcrypt.hashpw(auth_data.Password.encode('utf-8'), bcrypt.gensalt())
    auth_data.Password = hashed_password.decode('utf-8')  # Store the hashed password as a string
    db_auth = modelsmysql.auth(**auth_data.dict())
    # If role is 'Doctor'
    if db_auth.Role == 'Doctor':
        db.add(db_auth)
        db.commit()
        db.refresh(db_auth)
        
        # Add doctor to the doctors table
        db_doctor = modelsmysql.Doctors(
            Doctor_ID=db_auth.User_ID,
            Department_ID=1,  # Placeholder
            Department_Name_x="Cardiology",  # Placeholder
            Contact="123-456-7890",  # Placeholder
            Available_Hours="9 AM - 5 PM",  # Placeholder
            Department_Name_y="Heart Care"  # Placeholder
        )
        db.add(db_doctor)
        db.commit()
        db.refresh(db_doctor)
        return db_auth

    # If Role is 'Patient'
    does_patient_acc_exist = db.query(modelsmysql.auth).filter(modelsmysql.auth.User_ID == db_auth.User_ID).first()
    if does_patient_acc_exist:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"There's already an account for patient with id {db_auth.User_ID}"
        )

    does_patient_exist = db.query(modelsmysql.Patient).filter(modelsmysql.Patient.User_ID == db_auth.User_ID).first()
    if does_patient_exist:
        db.add(db_auth)
        db.commit()
        db.refresh(db_auth)
        return db_auth
    else:
        raise HTTPException(
            status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
            detail=f"There is no patient with id {db_auth.User_ID}"
        )

# Define request model for password reset
class ResetPasswordRequest(BaseModel):
    email: str
    newPassword: str

# Password Reset Route
@IM_router.post("/reset-password")
def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)): # Query the user from the database):
    user = db.query(modelsmysql.auth).filter(modelsmysql.auth.Email == request.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.Password = request.newPassword  
    user.Password = bcrypt.hashpw(user.Password.encode('utf-8'), bcrypt.gensalt())
    db.commit()

    if not bcrypt.checkpw(user.Password.encode('utf-8'), user.Password.encode('utf-8')):
        return False
    
    return {"message": "Password reset successful!"}


# Define check model for email check
class CheckEmailRequest(BaseModel):
    email: str
    
# Check Email Route
@IM_router.post("/check-email")
def check_email(request: CheckEmailRequest, db: Session = Depends(get_db)): # Query the user from the database):
    user = db.query(modelsmysql.auth).filter(modelsmysql.auth.Email == request.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Please enter a valid email!")  # Explicit error message
    
    return {"message": "Email found! You can proceed with password reset."}
