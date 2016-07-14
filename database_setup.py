import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))
    password = Column(String(250))

    # Add serialize function to send JSON objects in a serialize format
    @property
    def serialize(self):
        return {
            'name'		: self.name,
            'id'			: self.id,
            'email'			: self.email,
            'picture'		: self.picture,
        }


class Admin(Base):
    __tablename__ = 'admin'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)


class School(Base):
    __tablename__ = 'school'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'name': self.name,
            'id': self.id,
        }


class CatalogItem(Base):
    __tablename__= 'catalog_item'

    course_name=Column(String(80), nullable=False)
    id=Column(Integer, primary_key=True)
    description=Column(String(250))
    course_number=Column(String(80))
    department=Column(String(80))
    reviews = Column(String(500))
    catalog_id = Column(Integer, ForeignKey('school.id'))
    catalog = relationship(School)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    # Add serialize function to send JSON objects in a serialize format
    @property
    def serialize(self):
        return {
            'course_name'   : self.name,
            'id'		    : self.id,
            'description'	: self.description,
            'course_number'	: self.course_number,
            'department'	: self.department,
            'reviews'	    : self.reviews,
            'catalog_id'	:self.catalog_id,
        }

engine = create_engine('sqlite:///coursecatalog.db')

Base.metadata.create_all(engine)