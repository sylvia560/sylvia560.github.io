import bcrypt
from sqlalchemy.orm import sessionmaker
from dbtestmysql import engine
from cryptography.fernet import Fernet
import modelsmysql

# Create a database session
SessionLocal = sessionmaker(bind=engine)
db = SessionLocal()

users = db.query(modelsmysql.auth).all()
for user in users:
    # Hash the password
    user.Password = bcrypt.hashpw(user.Password.encode('utf-8'), bcrypt.gensalt())



db.commit()
db.close()

print("Existing data has been hashed successfully.")
