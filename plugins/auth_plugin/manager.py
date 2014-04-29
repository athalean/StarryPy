from sqlalchemy import create_engine, Column, Integer, String, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from plugins.core.player_manager.manager import _autoclosing_session
from hashlib import sha256

Base = declarative_base()


class AuthManager(object):
    def __init__(self, db_path):
        self.engine = create_engine(db_path)
        Base.metadata.create_all(self.engine)
        self.sessionmaker = sessionmaker(bind=self.engine, autoflush=True)

    def get_all_auth(self):
        with _autoclosing_session(self.sessionmaker) as session:
            return session.query(Accounts).all()

    def create_account(self, name, password, plaintext_pw=False):
        with _autoclosing_session(self.sessionmaker) as session:
            if not plaintext_pw: # passwords are saved as sha256 hashes
                password = sha256(password).hexdigest()
            user = session.query(Accounts).filter(Accounts.account==name).first()
            if user is not None:
                raise ValueError("Name already exists")
            session.add(Accounts(account=name, password=password))
            session.commit()

    def change_password(self, name, password, plaintext_pw=False):
        with _autoclosing_session(self.sessionmaker) as session:
            if not plaintext_pw: # passwords are saved as sha256 hashes
                password = sha256(password).hexdigest()
            account = session.query(Accounts).filter(Accounts.account==name).first()
            account.password = password
            session.commit()


class Accounts(Base):
    __tablename__ = 'auth'
    id = Column(Integer, primary_key=True, autoincrement=True)
    account = Column(String, unique=True)
    password = Column(String)