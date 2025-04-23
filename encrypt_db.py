from sqlalchemy.orm import sessionmaker
from dbtestmysql import engine
from cryptography.fernet import Fernet
import modelsmysql

# Encryption Key (Use the same key in your FastAPI app)
ENCRYPTION_KEY = "dVis0RwmM8y9jvckrSxFM3WrHOQfvbNN9gstq7CT8S4="
cipher = Fernet(ENCRYPTION_KEY)

def encrypt_data(plain_text: str) -> str:
    return cipher.encrypt(plain_text.encode()).decode()

# Create a database session
SessionLocal = sessionmaker(bind=engine)
db = SessionLocal()

# Encrypt National_ID in auth table
'''auth_records = db.query(modelsmysql.auth).all()
for record in auth_records:
    if not record.National_ID.startswith("gAAAAA"):  # Avoid double encryption
        record.National_ID = encrypt_data(str(record.National_ID))'''

# Encrypt fields in Clinical_services_modified table
clinical_services_records = db.query(modelsmysql.Clinical_services).all()
for record in clinical_services_records:
    if not record.Medication_Name.startswith("gAAAAA"):
        record.Medication_Name = encrypt_data(record.Medication_Name)
        record.Dosage_Instructions = encrypt_data(record.Dosage_Instructions)
        record.Treatment_Details = encrypt_data(record.Treatment_Details)

# Encrypt fields in Patients table
patients_records = db.query(modelsmysql.Patient).all()
for record in patients_records:
    if not record.Contact.startswith("gAAAAA"):
        record.Contact = encrypt_data(record.Contact)
        record.Allergies = encrypt_data(record.Allergies)
        record.Chronic_Conditions = encrypt_data(record.Chronic_Conditions)
        record.Purpose_of_Visit = encrypt_data(record.Purpose_of_Visit)

# Commit the encrypted data
db.commit()
db.close()

print("Existing data has been encrypted successfully.")
