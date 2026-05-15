from sqlalchemy import Column, Integer, String
from database import Base

class prodi (Base):
    __tablename__ = "prodi"

    id = Column(Integer, primary_key=True, index=True)
    nama = Column(String(100))
    fakultas = Column(String(100))

class user (Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(100))
    password = Column(String(255))
    role = Column(String(20), default="user")