from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
 
Base = declarative_base()
 
class CurrentScan(Base):
    __tablename__ = 'current_scan'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    proto= Column(String(250), nullable=False)
    port = Column(Integer)
    port_state = Column(String(250), nullable=False)

engine = create_engine('sqlite:///sqlalchemy_example.db')
Base.metadata.create_all(engine)