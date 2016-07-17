from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from passlib.hash import pbkdf2_sha256

import json

from database_setup import Base, School, CatalogItem, User, Admin

engine = create_engine('sqlite:///coursecatalog.db')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

session = DBSession()

# Creating Admin user and storing the password as a hash
phash = pbkdf2_sha256.encrypt('manager', rounds=1000, salt_size=16)

user1 = User(name='Admin', email='admin', picture='', password=phash)
session.add(user1)
session.commit()

# Setting up admin user
admin1 = Admin(user_id=1)
session.add(admin1)
session.commit()

# Reading JSON file and populate the database with course categories and items
itemsFile = open('items.json')

data = json.load(itemsFile)

# To determine number of catalog courses
cnum = len(data['Schools'])
for c in range(0, cnum):
    print(data['Schools'][c]['name'])

    school1 = School(name=data['Schools'][c]['name'])
    session.add(school1)
    session.commit()

    inum = len(data['Schools'][c]['items'])
    for i in range(0, inum):
        item = CatalogItem(course_name=data['Schools'][c]['items'][i]['course_name'],
                           description=data['Schools'][c]['items'][i]['description'],
                           course_number=data['Schools'][c]['items'][i]['course_number'],
                           department=data['Schools'][c]['items'][i]['department'],
                           reviews=data['Schools'][c]['items'][i]['review'],
                           catalog=school1)
        session.add(item)
        session.commit()


print('Added catalog and courses.')