from sqlalchemy import create_engine, Column, Integer, String, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from plugins.core.player_manager.manager import _autoclosing_session

Base = declarative_base()


class AuthManager(object):
    def __init__(self, db_path):
        self.engine = create_engine(db_path)
        Base.metadata.create_all(self.engine)
        self.sessionmaker = sessionmaker(bind=self.engine, autoflush=True)

    def get_all_auth(self):
        with _autoclosing_session(self.sessionmaker) as session:
            return session.query(Accounts).all()

class Accounts(Base):
    __tablename__ = 'auth'
    id = Column(Integer, primary_key=True, autoincrement=True)
    account = Column(String, unique=True)
    password = Column(String)