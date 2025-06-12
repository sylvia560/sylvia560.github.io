from fastapi import FastAPI ,HTTPException ,Depends ,status, Request,Body,Form,APIRouter, Query
from pydantic import BaseModel
from typing import Annotated
import modelsmysql
from dbtestmysql import engine,SessionLocal
from sqlalchemy.orm import Session
from datetime import datetime
from typing import List,Optional
from modelsmysql import Patient,auth, Billing, Doctors,Clinical_services,Nurses,PatientUpdate # Import models from external file
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
import math,uuid
from jose import jwt, JWTError, ExpiredSignatureError
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from Session_Management import SECRET_KEY,ALGORITHM,oauth2_bearer,REVOKED_TOKENS,revoke_token,get_current_user

# Generate a key for encryption/decryption (store this securely)
ENCRYPTION_KEY = "dVis0RwmM8y9jvckrSxFM3WrHOQfvbNN9gstq7CT8S4="
cipher = Fernet(ENCRYPTION_KEY)

# Encryption and Decryption Functions
def encrypt_data(plain_text: str) -> str:
    return cipher.encrypt(plain_text.encode()).decode()



def decrypt_data(encrypted_text: str) -> str:
    try:
        # try to decrypt – if it's a valid token this will succeed
        return cipher.decrypt(encrypted_text.encode()).decode()
    except (InvalidToken, ValueError):
        # not a valid token (or bad padding), just return as‐is
        return encrypted_text

    
Patient_record_router = APIRouter(
    tags=["Patients Record Server"]  # Optional OpenAPI tag
)

def get_db():
    db=SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
db_dependency=Annotated[Session,Depends(get_db)]

# Define the Pydantic model for the request body
class DoctorsBase(BaseModel):
    Doctor_ID: int
    Department_ID: int
    Contact: str
    Available_Hours: str
    Department_Name: str

    class Config:
        orm_mode = True    

# Define the Pydantic model for the request body
class NursesBase(BaseModel):
    Nurse_ID: int
    Department_ID: int
    Department_Name: str
    Contact: str
    Shift_Hours: str

    class Config:
        orm_mode = True
        
class ClinicalServicesBase(BaseModel):
    Patient_ID: int
    Department_ID: int
    Medication_Name: str
    Dosage_Instructions: str
    Responsible_Doctor_ID: int
    Treatment_Details: str
    Department_Name: str

    class Config:
        orm_mode = True
      
class BillingBase(BaseModel):
    Patient_ID: int
    Status: str
    Payment_Mode: str
    Amount_Paid: float  # Use float for Double in Pydantic

    class Config:
        orm_mode = True

class PatientBase(BaseModel):
    User_ID: int
    Patient_ID_Clinical: int
    Patient_ID_Billing: int
    Gender: str
    Contact: str
    Allergies: str
    Chronic_Conditions: str
    Purpose_of_Visit: str
    Prescribing_Doctor_ID: int
    Prescribing_Nurse_ID: Optional[int] = None

    class Config:
        orm_mode = True

# Optional: If you want to include the relationship in the schema
class PatientWithBilling(PatientBase):
    billing: BillingBase = None

class BillingWithPatient(BillingBase):
    patient: PatientBase = None

# New schema to combine Patient and ClinicalServices data
class PatientWithClinicalServices(BaseModel):
    patient: PatientBase
    clinical_services: List[ClinicalServicesBase]

    class Config:
        orm_mode = True
 
class ClinicalServiceUpdate(BaseModel):
    Dosage_Instructions: Optional[str] = None
    Medication_Name: Optional[str] = None

    class Config:
        orm_mode = True
        
class UpdatePatientRequest(BaseModel):
    Department_ID: int
    Medication_Name: str
    Dosage_Instructions: str
    Responsible_Doctor_ID: str
    Treatment_Details: str
    Department_Name: str
        
# Schema to include billing information with patient
class PatientWithBilling(PatientBase):
    billing: BillingBase | None = None

class PatientForDoctor(BaseModel):
    User_ID: int
    Patient_ID_Clinical: int
    Patient_ID_Billing: int
    Gender: str
    Contact: str
    Allergies: str
    Chronic_Conditions: str
    Purpose_of_Visit: str
    Prescribing_Doctor_ID: int
    clinical_services: list[ClinicalServicesBase] = []  # Include clinical services

    class Config:
        orm_mode = True

class PatientForNurse(BaseModel):
    User_ID: int
    Patient_ID_Clinical: int
    Patient_ID_Billing: int
    Gender: str
    Contact: str
    Allergies: str
    Chronic_Conditions: str
    Purpose_of_Visit: str
    Prescribing_Doctor_ID: int
    Prescribing_Nurse_ID: int
    clinical_services: list[ClinicalServicesBase] = []  # Include clinical services

    class Config:
        orm_mode = True
        
# Schema to include nurse details and clinical services cases
class NurseWithClinicalServices(NursesBase):
    clinical_services: list[ClinicalServicesBase] = []

    class Config:
        orm_mode = True




async def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get('type') != 'access':
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token type')
        email: str = payload.get('sub')
        user_id: int = payload.get('id')
        role: str = payload.get('role')
        user_info: str = payload.get('user_info')  # Extract concatenated user info from the token payload
        if email is None or user_id is None or role is None or user_info is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not validate user')
        return {'email': email, 'user_id': user_id, 'role': role, 'user_info': user_info}
    except JWTError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f'Could not validate user: {str(e)}')

@Patient_record_router.get("/hello")
async def hello_world():
    return {"message": "Hello, World!"}

@Patient_record_router.get("/doctors")
async def get_doctor_details(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    user_id= current_user["user_id"]
    Role=current_user["role"]
    if(Role=="Doctor"):
        # Query the auth table for the doctor's name and email
        auth_data = db.query(auth).filter(auth.User_ID == user_id).first()
        
        # Query the doctors table for the doctor's department name
        doctor_data = db.query(Doctors).filter(Doctors.Doctor_ID == user_id).first()

        if not auth_data or not doctor_data:
            raise HTTPException(status_code=404, detail="Doctor not found")

        return {
            "Full_Name": auth_data.Full_Name,
            "Email": auth_data.Email,
            "Department_Name": doctor_data.Department_Name,
        }
    else:
        revoke_token(current_user["token"])
        raise HTTPException(status_code=403, detail="RBAC unauthorized !")
 


# POST endpoint to create a new nurse
@Patient_record_router.post("/nurses", status_code=status.HTTP_201_CREATED)
async def create_nurse(nurse: NursesBase, db: Session = Depends(get_db)):
    db_nurse = modelsmysql.Nurses(**nurse.dict())
    db.add(db_nurse)
    db.commit()
    db.refresh(db_nurse)
    return db_nurse



# GET endpoint to retrieve a nurse by Nurse_ID
@Patient_record_router.get("/nurses", response_model=NursesBase)
async def get_nurse(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    nurse_id= current_user["user_id"]
    Role=current_user["role"]
    if(Role=="Nurse"):
        db_nurse = db.query(modelsmysql.Nurses).filter(modelsmysql.Nurses.Nurse_ID == nurse_id).first()
        if db_nurse is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Nurse not found")
        return db_nurse
    else:
        revoke_token(current_user["token"])
        raise HTTPException(status_code=403, detail="RBAC unauthorized !")
    
# Add these functions to Patient_record_Server.py

# Get function to retrieve all patients for a specific nurse
def get_patients_by_nurse(db: Session, nurse_id: int):
    # First determine the actual Nurse_ID
    nurse = db.query(Nurses).filter(Nurses.Nurse_ID == nurse_id).first()
    
    if not nurse:
        raise HTTPException(status_code=404, detail="Nurse not found")
    
    # Get patients for this nurse
    patients = db.query(Patient).filter(Patient.Prescribing_Nurse_ID == nurse.Nurse_ID).all()
    
    if not patients:
        return []
    
    # Build response
    response = []
    for patient in patients:
        clinical_services = db.query(Clinical_services).filter(
            Clinical_services.Patient_ID == patient.User_ID
        ).all()
        
        response.append(PatientForNurse(
            User_ID=patient.User_ID,
            Patient_ID_Clinical=patient.Patient_ID_Clinical,
            Patient_ID_Billing=patient.Patient_ID_Billing,
            Gender=patient.Gender,
            Contact=decrypt_data(patient.Contact),
            Allergies=decrypt_data(patient.Allergies),
            Chronic_Conditions=decrypt_data(patient.Chronic_Conditions),
            Purpose_of_Visit=decrypt_data(patient.Purpose_of_Visit),
            Prescribing_Doctor_ID=patient.Prescribing_Doctor_ID,
            Prescribing_Nurse_ID=patient.Prescribing_Nurse_ID,
            clinical_services=[
                ClinicalServicesBase(
                    Patient_ID=cs.Patient_ID,
                    Department_ID=cs.Department_ID,
                    Medication_Name=decrypt_data(cs.Medication_Name),
                    Dosage_Instructions=decrypt_data(cs.Dosage_Instructions),
                    Responsible_Doctor_ID=cs.Responsible_Doctor_ID,
                    Treatment_Details=decrypt_data(cs.Treatment_Details),
                    Department_Name=cs.Department_Name,
                )
                for cs in clinical_services
            ]
        ))
    
    return response

# FastAPI endpoint to expose the get function
@Patient_record_router.get("/nurses/responsible/patients", response_model=list[PatientForNurse])
def read_patients_by_nurse(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    nurse_id = current_user["user_id"]
    Role = current_user["role"]
    if(Role == "Nurse"):
        return get_patients_by_nurse(db, nurse_id)
    else:
        revoke_token(current_user["token"])
        raise HTTPException(status_code=403, detail="RBAC unauthorized!")

# POST endpoint to create a new clinical service record
@Patient_record_router.post("/clinical-services", status_code=status.HTTP_201_CREATED)
async def create_clinical_service(service: ClinicalServicesBase, db: Session = Depends(get_db)):
    service.Medication_Name = encrypt_data(service.Medication_Name)
    service.Dosage_Instructions = encrypt_data(service.Dosage_Instructions)
    service.Treatment_Details = encrypt_data(service.Treatment_Details)
    db_service = modelsmysql.Clinical_services(**service.dict())
    db.add(db_service)
    db.commit()
    db.refresh(db_service)
    return db_service




# GET endpoint to retrieve a clinical service record by Patient_ID
@Patient_record_router.get("/clinical-services", response_model=ClinicalServicesBase)
async def get_clinical_service(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    patient_id= current_user["user_id"]
    Role=current_user["role"]
    if(Role=="Client"):
        db_service = db.query(modelsmysql.Clinical_services).filter(modelsmysql.Clinical_services.Patient_ID == patient_id).first()
        if db_service is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Clinical service record not found")
        return {
            "Patient_ID": db_service.Patient_ID,
            "Department_ID": db_service.Department_ID,
            "Medication_Name": decrypt_data(db_service.Medication_Name),
            "Dosage_Instructions": decrypt_data(db_service.Dosage_Instructions),
            "Responsible_Doctor_ID": db_service.Responsible_Doctor_ID,
            "Treatment_Details": decrypt_data(db_service.Treatment_Details),
            "Department_Name": db_service.Department_Name}
    else:
        revoke_token(current_user["token"])
        raise HTTPException(status_code=403, detail="RBAC unauthorized !")




# POST endpoint to create a new billing record
@Patient_record_router.post("/billing", status_code=status.HTTP_201_CREATED)
async def create_billing(billing: BillingBase, db: Session = Depends(get_db)):
    db_billing =modelsmysql. Billing(**billing.dict())
    db.add(db_billing)
    db.commit()
    db.refresh(db_billing)
    return db_billing

# GET endpoint to retrieve a billing record by Patient_ID
@Patient_record_router.get("/billing", response_model=BillingBase)
async def get_billing(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    patient_id= current_user["user_id"]
    Role=current_user["role"]
    if(Role=="Client"):
        db_billing = db.query(modelsmysql.Billing).filter(modelsmysql.Billing.Patient_ID == patient_id).first()
        if db_billing is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Billing record not found")
        return db_billing
    else:
        revoke_token(current_user["token"])
        raise HTTPException(status_code=403, detail="RBAC unauthorized !")



@Patient_record_router.post(
    "/patients",
    status_code=status.HTTP_201_CREATED,
    response_model=PatientWithBilling
)
async def create_patient(request: PatientBase, db: Session = Depends(get_db)):
    try:
        # 1) encrypt everything up‑front
        encrypted_contact = encrypt_data(request.Contact)
        encrypted_allergies = encrypt_data(request.Allergies)
        encrypted_chronic = encrypt_data(request.Chronic_Conditions)
        encrypted_purpose = encrypt_data(request.Purpose_of_Visit)

        # 2) build your Patient object
        patient = modelsmysql.Patient(
            User_ID=request.User_ID,
            Patient_ID_Clinical=request.Patient_ID_Clinical,
            Patient_ID_Billing=request.Patient_ID_Billing,
            Gender=request.Gender,
            Contact=encrypted_contact,
            Allergies=encrypted_allergies,
            Chronic_Conditions=encrypted_chronic,
            Purpose_of_Visit=encrypted_purpose,
            Prescribing_Doctor_ID=request.Prescribing_Doctor_ID,
        )
        db.add(patient)

        # 3) default clinical service (also encrypted)
        cs = modelsmysql.Clinical_services(
            Patient_ID=patient.User_ID,
            Department_ID=1,
            Medication_Name=encrypt_data("None"),
            Dosage_Instructions=encrypt_data("None"),
            Responsible_Doctor_ID=patient.Prescribing_Doctor_ID,
            Treatment_Details=encrypt_data("Initial consultation"),
            Department_Name="General",
        )
        db.add(cs)

        # 4) default billing (no encryption needed here)
        billing = modelsmysql.Billing(
            Patient_ID=patient.User_ID,
            Status="Pending",
            Payment_Mode="Unpaid",
            Amount_Paid=0.0,
        )
        db.add(billing)

        # 5) commit everything in one go
        db.commit()

        # 6) return a fully decrypted view via your helper
        return get_patient_with_billing(db, patient.User_ID)

    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not create patient: {e}"
        )
   
   
# DELETE endpoint to delete a patient and related records
@Patient_record_router.delete("/patients/{patient_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_patient(
    patient_id: int,  # Accept patient_id as a path parameter
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    Role=current_user["role"]
    if(Role=="Doctor"):
        try:
            # Fetch the patient record
            db_patient = db.query(modelsmysql.Patient).filter(modelsmysql.Patient.User_ID == patient_id).first()
            if not db_patient:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Patient with ID {patient_id} not found"
                )

            # Delete related Clinical_services records
            db.query(modelsmysql.Clinical_services).filter(modelsmysql.Clinical_services.Patient_ID == patient_id).delete()

            # Delete related Billing record
            db.query(modelsmysql.Billing).filter(modelsmysql.Billing.Patient_ID == patient_id).delete()

            # Delete the patient record
            db.delete(db_patient)

            # Commit all changes
            db.commit()

            return  # Return 204 No Content on successful deletion

        except Exception as e:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An error occurred while deleting the patient record: {str(e)}"
            )

        except Exception as e:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An error occurred while deleting the patient record: {str(e)}"
            )     
    else:
        revoke_token(current_user["token"])
        raise HTTPException(status_code=403, detail="RBAC unauthorized !") 
        
        
        
        
# GET endpoint to retrieve a patient record by Usert_ID
@Patient_record_router.get("/patients/{patient_id}", response_model=PatientBase)
async def get_patient(
    patient_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    Role = current_user["role"]
    if Role not in ["Doctor", "Nurse"]:  # Allow both doctors and nurses to view
        revoke_token(current_user["token"])
        raise HTTPException(status_code=403, detail="RBAC unauthorized!")
    
    db_patient = db.query(modelsmysql.Patient).filter(modelsmysql.Patient.User_ID == patient_id).first()
    db_clinical_services = db.query(modelsmysql.Clinical_services).filter(modelsmysql.Clinical_services.Patient_ID == patient_id).all()
    
    if db_patient is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Patient record not found")
    
    return {
        "User_ID": db_patient.User_ID,
        "Patient_ID_Clinical": db_patient.Patient_ID_Clinical,
        "Patient_ID_Billing": db_patient.Patient_ID_Billing,
        "Gender": db_patient.Gender,
        "Contact": decrypt_data(db_patient.Contact),
        "Allergies": decrypt_data(db_patient.Allergies),
        "Chronic_Conditions": decrypt_data(db_patient.Chronic_Conditions),
        "Purpose_of_Visit": decrypt_data(db_patient.Purpose_of_Visit),
        "Prescribing_Doctor_ID": db_patient.Prescribing_Doctor_ID,
        "Prescribing_Nurse_ID": db_patient.Prescribing_Nurse_ID,
        "clinical_services": [
            {
                "Patient_ID": cs.Patient_ID,
                "Department_ID": cs.Department_ID,
                "Medication_Name": decrypt_data(cs.Medication_Name),
                "Dosage_Instructions": decrypt_data(cs.Dosage_Instructions),
                "Responsible_Doctor_ID": cs.Responsible_Doctor_ID,
                "Treatment_Details": decrypt_data(cs.Treatment_Details),
                "Department_Name": cs.Department_Name,
            }
            for cs in db_clinical_services
        ]
    }


@Patient_record_router.put("/patients/{patient_id}", response_model=PatientBase)
async def update_patient(
    patient_id: int,
    update_data: PatientUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    Role = current_user["role"]
    if Role != "Doctor":
        revoke_token(current_user["token"])
        raise HTTPException(status_code=403, detail="RBAC unauthorized!")

    db_patient = db.query(modelsmysql.Patient).filter(modelsmysql.Patient.User_ID == patient_id).first()
    if db_patient is None:
        raise HTTPException(status_code=404, detail="Patient not found")

    # Encrypt sensitive fields before updating
    if update_data.Contact is not None:
        update_data.Contact = encrypt_data(update_data.Contact)
    if update_data.Allergies is not None:
        update_data.Allergies = encrypt_data(update_data.Allergies)
    if update_data.Chronic_Conditions is not None:
        update_data.Chronic_Conditions = encrypt_data(update_data.Chronic_Conditions)
    if update_data.Purpose_of_Visit is not None:
        update_data.Purpose_of_Visit = encrypt_data(update_data.Purpose_of_Visit)

    for field, value in update_data.dict(exclude_unset=True).items():
        setattr(db_patient, field, value)

    db.commit()
    db.refresh(db_patient)
    
    # Return decrypted data
    return {
        "User_ID": db_patient.User_ID,
        "Patient_ID_Clinical": db_patient.Patient_ID_Clinical,
        "Patient_ID_Billing": db_patient.Patient_ID_Billing,
        "Gender": db_patient.Gender,
        "Contact": decrypt_data(db_patient.Contact),
        "Allergies": decrypt_data(db_patient.Allergies),
        "Chronic_Conditions": decrypt_data(db_patient.Chronic_Conditions),
        "Purpose_of_Visit": decrypt_data(db_patient.Purpose_of_Visit),
        "Prescribing_Doctor_ID": db_patient.Prescribing_Doctor_ID,
        "Prescribing_Nurse_ID": db_patient.Prescribing_Nurse_ID
    }


# @Patient_record_router.put("/patients", response_model=PatientBase)
# async def update_patient(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
#     user_id= current_user["user_id"]
#     db_patient = db.query(modelsmysql.Patient).filter(modelsmysql.Patient.User_ID == user_id).first()
#     if db_patient is None:
#         raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Patient not found")

#     # Update fields
#     for key, value in updated_patient.dict().items():
#         setattr(db_patient, key, value)

#     db.commit()
#     db.refresh(db_patient)

#     return db_patient



@Patient_record_router.put("/clinical-services", status_code=status.HTTP_200_OK)
async def update_dosage_instructions(
    dosage_update: str, 
    current_user: dict = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    Patient_ID= current_user["user_id"]
    # Fetch the existing clinical service record by Patient_ID
    db_service = db.query(modelsmysql.Clinical_services).filter(modelsmysql.Clinical_services.Patient_ID == Patient_ID).first()
    
    # If no record is found, raise a 404 error
    if not db_service:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Clinical service record for Patient_ID {Patient_ID} not found"
        )
    
    # Update the Dosage_Instructions
    db_service.Dosage_Instructions = dosage_update
    
    # Commit the changes to the database
    db.commit()
    db.refresh(db_service)
    
    # Return the updated record
    return db_service


# GET endpoint to retrieve a patient record by User_ID along with clinical services
@Patient_record_router.get("/patientsfetchrelated", response_model=PatientWithClinicalServices)
async def get_patient(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    user_id= current_user["user_id"]
    Role=current_user["role"]
    if(Role=="Client"):
        # Fetch the patient record
        db_patient = db.query(modelsmysql.Patient).filter(modelsmysql.Patient.User_ID == user_id).first()
        if db_patient is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Patient record not found")
        
        # Fetch the related clinical services records
        db_clinical_services = db.query(modelsmysql.Clinical_services).filter(modelsmysql.Clinical_services.Patient_ID == user_id).all()
        
        # Combine the data into the response schema
        response_data = {
            "patient": db_patient,
            "clinical_services": db_clinical_services
        }
        
        return response_data
    else:
        revoke_token(current_user["token"])
        raise HTTPException(status_code=403, detail="RBAC unauthorized !")


async def update_clinical_service(
    
    update_data: ClinicalServiceUpdate, 
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    Patient_ID= current_user["user_id"]
    # Fetch the existing clinical service record by Patient_ID
    db_service = db.query(modelsmysql.Clinical_services).filter(modelsmysql.Clinical_services.Patient_ID == Patient_ID).first()
    
    # If no record is found, raise a 404 error
    if not db_service:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Clinical service record for Patient_ID {Patient_ID} not found"
        )
    
    # Update the fields if they are provided in the request
    if update_data.Dosage_Instructions is not None:
        db_service.Dosage_Instructions = encrypt_data(update_data.Dosage_Instructions)
    
    if update_data.Medication_Name is not None:
        db_service.Medication_Name = encrypt_data(update_data.Medication_Name)
    
    # Commit the changes to the database
    db.commit()
    db.refresh(db_service)
    
    # Log the updated record
    print("Updated Record:", db_service)
    
    # Return the updated record
    return db_service



# Get function to retrieve patient and billing information
def get_patient_with_billing(db: Session, user_id: int):
    """
    Retrieve patient information along with billing details, including decrypted clinical services.
    """
    # Query the Patient table
    patient = db.query(Patient).filter(Patient.User_ID == user_id).first()
    
    # If no patient is found, raise a 404 error
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    
    # Access the related billing information through the relationship
    billing_info = patient.billing

    # Fetch the related clinical services
    clinical_services = db.query(Clinical_services).filter(Clinical_services.Patient_ID == user_id).all()

    # Construct the response using the PatientWithBilling schema
    response = PatientWithBilling(
        User_ID=patient.User_ID,
        Patient_ID_Clinical=patient.Patient_ID_Clinical,
        Patient_ID_Billing=patient.Patient_ID_Billing,
        Gender=patient.Gender,
        Contact=decrypt_data(patient.Contact),
        Allergies=decrypt_data(patient.Allergies),
        Chronic_Conditions=decrypt_data(patient.Chronic_Conditions),
        Purpose_of_Visit=patient.Purpose_of_Visit,
        Prescribing_Doctor_ID=patient.Prescribing_Doctor_ID,
        Prescribing_Nurse_ID=patient.Prescribing_Nurse_ID,
        billing=BillingBase(
            Patient_ID=billing_info.Patient_ID if billing_info else None,
            Status=billing_info.Status if billing_info else None,
            Payment_Mode=billing_info.Payment_Mode if billing_info else None,
            Amount_Paid=billing_info.Amount_Paid if billing_info else None,
        ) if billing_info else None,
        clinical_services=[
            ClinicalServicesBase(
                Patient_ID=cs.Patient_ID,
                Department_ID=cs.Department_ID,
                Medication_Name=decrypt_data(cs.Medication_Name),
                Dosage_Instructions=decrypt_data(cs.Dosage_Instructions),
                Responsible_Doctor_ID=cs.Responsible_Doctor_ID,
                Treatment_Details=decrypt_data(cs.Treatment_Details),
                Department_Name=cs.Department_Name,
            ) for cs in clinical_services
        ]
    )

    return response

# FastAPI endpoint to expose the get function
@Patient_record_router.get("/patientswbilling", response_model=PatientWithBilling)
def read_patient_with_billing(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    user_id = current_user["user_id"]
    Role = current_user["role"]
    if (Role == "Client"):
        return get_patient_with_billing(db, user_id)
    else:
        revoke_token(current_user["token"])
        raise HTTPException(status_code=403, detail="RBAC unauthorized!")


# Get function to retrieve all patients and their clinical services for a specific doctor
def get_patients_by_doctor(db: Session, user_id: int):
    # First determine the actual Doctor_ID
    doctor = db.query(Doctors).filter(Doctors.Doctor_ID == user_id).first()
    
    # If not found, check if auth table has Doctor_ID reference
    if not doctor:
        auth_record = db.query(auth).filter(auth.User_ID == user_id).first()
        if auth_record and hasattr(auth_record, 'Doctor_ID'):
            doctor = db.query(Doctors).filter(Doctors.Doctor_ID == auth_record.Doctor_ID).first()
    
    if not doctor:
        raise HTTPException(status_code=404, detail="Doctor not found")
    
    # Get patients for this doctor
    patients = db.query(Patient).filter(Patient.Prescribing_Doctor_ID == doctor.Doctor_ID).all()
    
    if not patients:
        return []  # Return empty list instead of error if no patients
    
    # Build response
    response = []
    for patient in patients:
        clinical_services = db.query(Clinical_services).filter(
            Clinical_services.Patient_ID == patient.User_ID
        ).all()
        
        response.append(PatientForDoctor(
            User_ID=patient.User_ID,
            Patient_ID_Clinical=patient.Patient_ID_Clinical,
            Patient_ID_Billing=patient.Patient_ID_Billing,
            Gender=patient.Gender,
            Contact=decrypt_data(patient.Contact),
            Allergies=decrypt_data(patient.Allergies),
            Chronic_Conditions=decrypt_data(patient.Chronic_Conditions),
            Purpose_of_Visit=decrypt_data(patient.Purpose_of_Visit),
            Prescribing_Doctor_ID=patient.Prescribing_Doctor_ID,
            clinical_services=[
                ClinicalServicesBase(
                    Patient_ID=cs.Patient_ID,
                    Department_ID=cs.Department_ID,
                    Medication_Name=decrypt_data(cs.Medication_Name),
                    Dosage_Instructions=decrypt_data(cs.Dosage_Instructions),
                    Responsible_Doctor_ID=cs.Responsible_Doctor_ID,
                    Treatment_Details=decrypt_data(cs.Treatment_Details),
                    Department_Name=cs.Department_Name,
                )
                for cs in clinical_services
            ]
        ))
    
    return response


# FastAPI endpoint to expose the get function
@Patient_record_router.get("/doctors/responsible/patients", response_model=list[PatientForDoctor])
def read_patients_by_doctor(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    doctor_id= current_user["user_id"]
    Role=current_user["role"]
    if(Role=="Doctor"):
        return get_patients_by_doctor(db, doctor_id)
    else:
        revoke_token(current_user["token"])
        raise HTTPException(status_code=403, detail="RBAC unauthorized !")
        


# Get function to retrieve all clinical services cases for the department a nurse is responsible for
def get_clinical_services_by_nurse(db: Session, nurse_id: int):
    """
    Retrieve all clinical services cases for the department a specific nurse is responsible for.
    """
    # Query the Nurses table to find the nurse and their Department_ID
    nurse = db.query(Nurses).filter(Nurses.Nurse_ID == nurse_id).first()
    
    # If no nurse is found, raise a 404 error
    if not nurse:
        raise HTTPException(status_code=404, detail="Nurse not found")
    
    # Query the Clinical_services table to find all cases in the nurse's department
    clinical_services = db.query(Clinical_services).filter(Clinical_services.Department_ID == nurse.Department_ID).all()
    
    # Construct the response
    response = NurseWithClinicalServices(
        Nurse_ID=nurse.Nurse_ID,
        Department_ID=nurse.Department_ID,
        Department_Name=nurse.Department_Name,
        Contact=nurse.Contact,
        Shift_Hours=nurse.Shift_Hours,
        clinical_services=[
            ClinicalServicesBase(
                Patient_ID=cs.Patient_ID,
                Department_ID=cs.Department_ID,
                Medication_Name=decrypt_data(cs.Medication_Name),  # Decrypt here
                Dosage_Instructions=decrypt_data(cs.Dosage_Instructions),  # Decrypt here
                Responsible_Doctor_ID=cs.Responsible_Doctor_ID,
                Treatment_Details=decrypt_data(cs.Treatment_Details),  # Decrypt here
                Department_Name=cs.Department_Name,
            )
            for cs in clinical_services
        ],
    )
    
    return response

# FastAPI endpoint to expose the get function
@Patient_record_router.get("/nurses/clinical-services", response_model=NurseWithClinicalServices)
def read_clinical_services_by_nurse(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    nurse_id= current_user["user_id"]
    Role=current_user["role"]
    if(Role=="Nurse"):
        return get_clinical_services_by_nurse(db, nurse_id)
    else:
        revoke_token(current_user["token"])
        raise HTTPException(status_code=403, detail="RBAC unauthorized !")
