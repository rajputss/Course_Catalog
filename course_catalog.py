# Miscellaneous imports
from flask import Flask, render_template, url_for, request, redirect, flash, jsonify
from datetime import datetime
from functools import wraps

# Libraries needed for OAuth authentication.
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
from urllib import urlencode
import json
from flask import make_response
import requests
from base64 import b64encode

# Used to create our XML feed.
from xml.etree.ElementTree import Element, SubElement, Comment, tostring
from flask import Response
from xml.dom import minidom

# Used for receiving image files.
import os
import os.path
import random
from werkzeug import secure_filename

# Used to keep session information.
from flask import session as login_session

import random, string

# Used to prevent CSRF.
from flask.ext.seasurf import SeaSurf

app = Flask(__name__)
csrf = SeaSurf(app)

import dboperations as dbops

# Google client ID
CLIENT_ID = json.load(open('client_secrets.json', 'r').read())['web']['client_id']

# Set GitHub variables used for OAUTH authentication
GH_CLIENT_ID = json.load(open('gh_client_secrets.json', 'r').read())['web']['app_id']
GH_AUTHORIZATION_BASE_URL = 'https://github.com/login/oauth/authorize'
GH_TOKEN_URL = 'https://github.com/login/oauth/access_token'
GH_USER_URL = 'https://api.github.com/user'
GH_SCOPE = 'user:email'


# Decorator to check if the user is logged in.
def login_required(f):
    """Decorator that checks if a user is logged in."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if login_session.get('username') is None:
            return redirect(url_for('show_login'))
        return f(*args, **kwargs)

    return decorated_function


# Decorator to check if the user is an admin.
def admin_access_required(f):
    """Decorator that checks if the logged in user is an admin."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if login_session.get('isadmin') is None or not login_session['isadmin']:
            return redirect(url_for('courses'))
        return f(*args, **kwargs)

    return decorated_function


# Decorator to verify the state.
def verify_state(f):
    """Decorator that verifies the session state."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If our session state is not valid, abort.
        clientstate = request.args.get('state') or request.form.get('state')
        if clientstate != login_session['state']:
            response = make_response(json.dumps('Invalid state parameter.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response
        return f(*args, **kwargs)

    return decorated_function


# Function to return "Invalid school" message to user if an invalid ID was specified.
def invalid_school():
    """Function that returns an 'Invalid school' message if an invalid school ID was specified."""
    response = make_response(json.dumps('Invalid school ID.'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response


# Function to return "Invalid catalog item" message to user if an invalid ID was specified.
def invalid_item():
    """Function that returns an 'Invalid item' message if an invalid catalog item ID was specified."""
    response = make_response(json.dumps('Invalid item ID.'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response


# Function to return "Invalid user" message to user if an invalid ID was specified.
def invalid_user():
    """Function that returns an 'Invalid user' message if an invalid user ID was specified."""
    response = make_response(json.dumps('Invalid user ID.'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response


# Login page route
@app.route('/login')
def show_login():
    """Route that shows the user login page and creates an anti-forgery session state and token."""
    # Check if the user is already logged in, and if they are, redirect to the home page.
    if 'username' in login_session:
        flash("You are already logged in. No need to log in again.")
        return redirect(url_for('courses'))

    # Creating anti-forgery state token
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state, gh_auth_link=('%s?scope=%s&client_id=%s&state=%s' % (GH_AUTHORIZATION_BASE_URL, GH_SCOPE, GH_CLIENT_ID, state)))


# Admin login page route
@app.route('/admin')
def admin_login():
    """Route that shows the admin login page and creates and anti-forgery session state and token."""
    # Check if admin is already logged in, and if they are redirect to the home page.
    if 'username' in login_session and login_session['isadmin']:
        flash("You are already logged in. No need to log in again.")
        return redirect(url_for('courses'))

    # Creating anti-forgery state token for admin
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state

    return render_template('admin.html', STATE=state)