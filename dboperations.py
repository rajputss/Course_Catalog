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

from addcourses import item
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
    return session.query(CatalogItem).join(School).filter('school.id==catalog_item.catalog_id').order_by\
        ('catalog_item.id desc').limit(10).all()


# Get a school.
def get_school(catalog_id):
    """Returns a result set for a given school ID."""
    try:
        return session.query(School).filter_by(id=catalog_id).one()
    except NoResultFound as e:
        return None


# Get the info for all courses for a given school
def get_school_courses(catalog_id):
    """Returns a result set of all the courses for a given school"""
    return session.query(CatalogItem).filter_by(catalog_id=catalog_id).order_by('catalog_item.course_name').all()


# Get the info about an item
def get_courses_info(item_id):
    """Returns a result set for a given item ID."""
    try:
        return session.query(CatalogItem).filter_by(id=item_id).one()
    except NoResultFound as e:
        return None


# Check if school already exists
def does_school_exists(new_school):
    """Returns False if school doesn't exists, i.e. school is not found."""
    try:
        return session.query(School).filter(func.lower(School.name) == func.lower(new_school)).one()
    except NoResultFound as e:
        return False


# Create a new school
def create_new_school(new_school):
    """Creates a new school."""
    new_school = School(name=new_school)
    session.add(new_school)
    session.commit()


# Update the name of school
def update_school(school, new_school):
    """Updates school name."""
    school.name = new_school
    session.add(school)
    session.commit()


# Delete school
def delete_school(school):
    """Deletes a school."""
    session.delete(school)
    session.commit()


# Delete all the items from school
def delete_school_items(school_id):
    """Deletes all items from school."""
    items = session.query(CatalogItem).filter_by(school_id=school_id).all()
    if items:
        for item in items:
            session.delete(item)
            session.commit()


# Create a new item
def create_new_item(name, description, course_number, department, reviews, catalog_id, user_id):
    """Creates a new item."""
    new_item = CatalogItem(name=name, description=description, course_number=course_number, department=department, reviews=reviews, catalog_id=catalog_id, user_id=user_id)
    session.add(new_item)
    session.commit()


# Update an item.
def update_item(item, name, description, course_number, department, reviews, catalog_id):
    """Updates an item."""
    item.name = name
    item.description = description
    item.course_number = course_number
    item.department = department
    item.reviews = reviews
    item.catalog_id = catalog_id
    # item.last_updated = datetime.utcnow()
    session.add(item)
    session.commit()


# Delete an item.
def delete_catalog_item(catalog_item):
    """Deletes an item."""
    session.delete(catalog_item)
    session.commit()


# Get a list of items created by the user.
def get_user_items(user_id):
    """Returns a result set of items created by a given user ID."""
    return session.query(CatalogItem).filter_by(user_id = user_id).all()


# User Helper Functions
# Add the user to the database.
def create_user(login_session):
    """Creates a new user in the database."""
    new_user = User(name = login_session['username'], email = login_session['email'])
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(email = login_session['email']).one()
    return user.id


# Get a list of all the users that have registered.
def get_users():
    """Returns a result set of all users registered in the database."""
    return session.query(User).order_by('name collate NOCASE').all()


# Get the user's info from the database.
def get_user_info(user_id):
    """Returns a result set of user information for a given user ID."""
    try:
        return session.query(User).filter_by(id = user_id).one()
    except:
        return None


# Get the user ID from the database.
def get_user_id(email):
    """Gets the user ID for a given email."""
    try:
        user = session.query(User).filter_by(email = email).one()
        return user.id
    except:
        return None


# Check if a user exists.
def does_user_exist(user, password):
    """Returns True if a user is found having the given username and password; False if not."""
    try:
        user = session.query(User).filter_by(email=user).one()
        # Check if the password verifies against the hash stored in the database.
        if pbkdf2_sha256.verify(password, user.password):
            return user
        else:
            return False
    except NoResultFound as e:
        return False


# Check if a user is an admin.
def is_user_admin(user_id):
    """Returns True if the logged in user is an Admin; False if not."""
    try:
        return session.query(Admin).filter_by(user_id=user_id).one()
    except NoResultFound as e:
        return False