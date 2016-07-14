from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from passlib.hash import pbkdf2_sha256

import json

from database_setup import Base, Catalog, CatalogItem, User, Admin

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
itemsFile = open('catalog_items.json')

data = json.load(itemsFile)

# To determine number of catalog courses
cnum = len(data['Catalogs'])
for c in range(0, cnum):
    print(data['Catalogs'][c]['name'])

    catalog1 = Catalog(name=data['Catalogs'][c]['name'])
    session.add(catalog1)
    session.commit()

    inum = len(data['Catalogs'][c]['items'])
    for i in range(0, inum):
        item = CatalogItem(name=data['Catalogs'][c]['items'][i]['name'],
                           description=data['Catalogs'][c]['items'][i]['description'],
                           course_number=data['Catalogs'][c]['items'][i]['course_number'],
                           department=data['Catalogs'][c]['items'][i]['department'],
                           reviews=data['Catalogs'][c]['items'][i]['reviews'],
                           catalog=catalog1)
        session.add(item)
        session.commit()


print('Added catalog and courses.')