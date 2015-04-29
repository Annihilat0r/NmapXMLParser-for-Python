from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, BLOB


base = declarative_base()

class ConfigNmap(base):
    __tablename__ = 'config_nmap'
    id = Column(Integer, primary_key=True)
    property = Column(String(255), nullable=False)
    value = Column(String(255), nullable=False)


class NmapDiff(base):
    __tablename__ = 'nmap_diff'
    id = Column(Integer, primary_key=True)
    result = Column(BLOB)