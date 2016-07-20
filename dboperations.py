#
# Database access functions for the Course Catalog application.
#
"""dboperations - This module contains database access functions for the Course Catalog application."""

from datetime import datetime
from passlib.hash import pbkdf2_sha256

# Database related stuff
from sqlalchemy import create_engine, func
from sqlalchemy.sql import collate
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from database_setup import Base, School, CatalogItem, User, Admin
engine = create_engine('sqlite:///coursecatalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


# Get a list of all the schools
def get_schools():
    """Returns a result of all school in alphabetical order, case sensitive"""
    return session.query(School).order_by('name collate NOCASE').all()

# Get a list of the 10 most recent items added.
def get_recent_items():
    """Returns a result set of the ten most recent items added to the database."""
    return session.query(CatalogItem).join(School).filter('school.id==catalog_item.school_id').order_by\
        ('catalog_item.id desc').limit(10).all()


# Get a school.
def get_school(school_id):
	"""Returns a result set for a given school ID."""
	try:
		return session.query(School).filter_by(id = school_id).one()
	except NoResultFound as e:
		return None


# Get the info for all courses for a given school
def get_school_courses(school_id):
    """Returns a result set of all the courses for a given school"""
    return session.query(CatalogItem).filter_by(school_id=school_id).order_by('catalog_item.name').all()



