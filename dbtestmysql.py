from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session
# URL_db="mysql+pymysql://root:Dbase1mysql@localhost:3306/hospital_db"
URL_db="mysql+pymysql://root:eDegOSSTFoTLNdAUJkdeVZfwtAWNKaze@nozomi.proxy.rlwy.net:23704/railway"

engine=create_engine(URL_db)

SessionLocal=sessionmaker(bind=engine,autoflush=False)

Base=declarative_base()