from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DATABASE_URL="mysql+pymysql://root:MAK2025@localhost:3306/authentication_database"
engine=create_engine(SQLALCHEMY_DATABASE_URL,connect_args={"check_same_thread":False})

SessionLocal=sessionmaker(bind=engine,autoflush=False)

Base=declarative_base()

