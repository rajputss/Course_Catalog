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


# User profile routing
@app.route("userprofile", methods = ['GET', 'POST'])
@login_required
def user_profile():
    """Route that shows the user profile page."""
    # Get the user info from the database
    user = dbops.get_user_info(login_session['user_id'])
    return render_template('userprofile.html', user=user)


# List of registered users (Admin access only) route
@app.route("/users")
@admin_access_required
def users():
    """Route that shows a list of registered user (Admin access only)."""
    # Get a list of regustered users from the database
    users = dbops.get_users()
    return render_template('users.html', users=users)


# Items created by a given user (Admin access only) route
@app.route("/useritems/<int:user_id>")
@admin_access_required
def user_items(user_id):
    """Route that shows the items created by a given user (Admin access only)."""
    # Get a list of registered users from the database
    user = dbops.get_user_info(user_id)
    if user is None:
        return invalid_user()
    useritems = dbops.get_user_items(user_id)
    return render_template('useritems.html', user=user, useritems=useritems)


# Local authentication route
@app.route('lconnect', methods=['POST'])
@verify_state
def lconnect():
    """Route used to authenticate the Admin login."""
    # Gather our form values, remove leading and trailing whitespace.
    user = request.form['user'].strip()
    password = request.form['password'].strip()

    # if nothing was entered, redirect to login with message.
    if user == '' or password == '':
        flash("Please enter a username and password.")
        return redirect(url_for('admin_login'))

    # Check if the user exists.
    user = dbops.does_user_exist(user, password)
    if not user:
        flash("Incorrect username and / or password.")
        return redirect(url_for('admin_login'))
    print(user)

    # Check if the user is an admin.
    if dbops.is_user_admin(user.id):
        login_session['isadmin'] = True
    else:
        login_session['isadmin'] = False

    # Set the rest of the session.
    login_session['provider'] = 'local'
    login_session['user_id'] = user.id
    login_session['username'] = user.name
    if login_session['username'] == '':
        login_session['username'] = 'Anonymous'
    login_session['email'] == user.email

    flash("Welcome %s..." % user.name)

    return redirect(url_for('courses'))


# Facebook authentication route
@csrf.exempt # We won't worry about CSRF here.
@app.route('/fbconnect', methods=['POST'])
@verify_state
def fbconnect():
    """Route used for Facebook OAuth authentication.
    1. To set up a connection to Facebook, login at: https://developers.facebook.com
    2. Go to MyApps -> Add a New App and select **Website.**
    3. Enter a name for the app, for example Catalog App, and click **Create New Facebook App ID.**
    4. Choose a Category and click **Create App ID.**
    5. For the Site URL, enter http://localhost:8000 and click **Next.**
    6. Under **Next Steps,** click **Skip to Developer Dashboard** and note your app ID and app secret.
    7. The next step is to add your Facebook app ID and secret to the fb_client_secrets.json file that is located in the folder this application resides.
    8. Open fb_client_secrets.json in a text editor.
    9. Replace YOUR_FACEBOOK_APP_ID with your Facebook app ID and replace YOUR_FACEBOOK_APP_SECRET with your Facebook app secret and save the file.
    10. Open login.html located in the application/templates folder. Look for the following line:
    appId : 'YOUR_FACEBOOK_APP_ID_GOES_HERE',
    11. Replace YOUR_FACEBOOK_APP_ID_GOES_HERE with your Facebook app ID and save the file."""
    access_token = request.data
    print("access token received %s" % access_token)

    # Exchange client token for long-lived server-side token.
    # GET /oauth/access_token?grant_type=fb_exchange_token&client_id={app-id}&client_secret={app-secret}&fb_exchange_token={short-lived-token}
    app_id = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_id']
    app_secret = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (app_id,app_secret,access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    print (app_id)

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.2/me"

    # Strip expire tag from access token.
    token = result.split("&")[0]

    # Let's go grab the user data from Facebook.
    url = 'https://graph.facebook.com/v2.2/me?%s' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    print(result)

    # Set the session info
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    if login_session['username'] == '':
        login_session['username'] = 'Anonymous'
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]
    login_session['isadmin'] = False

    # Get user picture
    url = 'https://graph.facebook.com/v2.2/me/picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # See if user exists in the database, and if not, create the user.
    user_id = dbops.get_user_id(login_session['email'])
    if user_id is None:
        user_id = dbops.create_user(login_session)
    login_session['user_id'] = user_id

    # Create HTML message to welcome the user.
    output = ''
    output +='<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output +=' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    return output


# Facebook logout route
@app.route('/fbdisconnect')
def fbdisconnect():
    """Route to disconnect the Facebook OAuth authentication."""
    facebook_id = login_session['facebook_id']
    url = 'https://graph.facebook.com/%s/permissions' % facebook_id
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return


# Google authentication route
@csrf.exempt # We won't worry about CSRF here.
@app.route('/gconnect', methods=['POST'])
@verify_state
def gconnect():
    """Route used for Google OAuth authentication.
    1. To set up a connection with Google, login in at: https://console.developers.google.com
    2. Create a new project and give it a name such as Catalog app. Leave the Project ID as is.
    3. Once you've created the app, go to **APIs & auth -> Credentials** and click **Create new Client ID.**
    4. Select **Web application** for the Application type, then click **Configure consent screen.**
    5. Designate an email address, enter a Product name, and click **Save.**
    6. In the box that says **Authorized JavaScript origins,** add http://localhost:8000, then click **Create Client ID.**
    7. Click the **Download JSON** button and save the file to the same folder where this application resides.
    8. Rename the file to: client_secrets.json
    9. Open login.html located in the application/templates folder. Look for the following line:
    data-clientid="YOUR_GOOGLE_CLIENT_ID_GOES_HERE"
    10. Replace YOUR_GOOGLE_CLIENT_ID_GOES_HERE with your Google client ID and save the file.
    """
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object.
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check to see if user is already logged in.
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps("Current user is already connected."), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt':'json'}
    answer = requests.get(userinfo_url, params=params)
    data = json.loads(answer.text)
    #print(answer.text)

    # Set our session information
    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    if login_session['username'] == '':
        login_session['username'] = 'Anonymous'
    login_session['email'] = data['email'] # to get the email from google, make sure login page has data-scope="openid email"
    login_session['picture'] = data['picture']
    # see if the user exists in the database; if not create a new user
    user_id = dbops.get_user_id(login_session['email'])
    if user_id is None:
        user_id = dbops.create_user(login_session)
    login_session['user_id'] = user_id
    login_session['isadmin'] = False

    # Create HTML message to welcome the user.
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output +=' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;">'

    return output


# Function to log out a Google user.
def gdisconnect():
    """Route to disconnect the Google OAuth authentication."""
    # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(json.dumps('Current user not connected.'),401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = credentials
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    # For whatever reason, the given token was invalid.
    if result['status'] != '200':
        response = make_response(
        json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response
    return


# GitHub authentication route
@csrf.exempt # We won't worry about CSRF here.
@app.route('/ghconnect', methods=['GET'])
@verify_state
def ghconnect():
    """Route used for GitHub OAuth authentication.
    1. To set up a connection with GitHub, go to: https://github.com/settings/applications
    2. Click on **Register new application.**
    3. For the **Application name** give it a name such as Catalog App.
    4. For the **Homepage URL** enter: http://localhost:8000
    5. For the **Authorization callback URL** enter: http://localhost:8000/ghconnect
    6. Click on **Register Application** then at the top right of the page, note your Client ID and Client Secret.
    7. The next step is to add your GitHub app ID and secret to the gh_client_secrets.json file that is located in the folder this application resides.
    8. Open gh_client_secrets.json in a text editor.
    9. Replace YOUR_GITHUB_APP_ID with your GitHub app ID and replace YOUR_GITHUB_APP_SECRET with your GitHub app secret and save the file.
    """
    # Let's take the code we received from GitHub and get an access token.
    code = request.args.get('code')
    h = httplib2.Http()
    postdata = dict(client_id=GH_CLIENT_ID, client_secret=GH_CLIENT_SECRET, code=code)
    response, content = h.request(GH_TOKEN_URL, "POST", urlencode(postdata), headers={'Accept':'application/json'} )
    data = json.loads(content)

    try:
        access_token = data['access_token']
    except KeyError:
        access_tokan = False

    # If we didn't get an access token, abort.
    if not access_token:
        response = make_response(json.dumps('Failed to obtain access token.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Let's take the access token and grab GitHub's profile on the user.
    url = GH_USER_URL
    headers = {'Authorization': 'token %s' % access_token}
    h = httplib2.Http()
    result = h.request(url, 'GET', headers=headers)[1]
    profile = json.loads(result)

    # We have the user data; let's set the session.
    login_session['provider'] = 'github'
    login_session['username'] = profile['name']
    if login_session['username'] == '':
        login_session['username'] = 'Anonymous'
    login_session['email'] = profile['email']
    login_session['picture'] = profile['avatar_url']
    login_session['github_id'] = profile['id']
    login_session['isadmin'] = False

    # See if the user exists in the database; if not create a new user.
    user_id = dbops.get_user_id(login_session['email'])
    if user_id is None:
        user_id = dbops.create_user(login_session)
    login_session['user_id'] = user_id

    flash("Welcome %s. You are logged in." % login_session['username'])

    return redirect(url_for('sports'))


# GitHub logout route
@app.route('/ghdisconnect')
def ghdisconnect():
    """Route to disconnect GitHub OAuth authentication."""

    return

    # tried to use the code below to disconnect from GitHub, but it doesn't work
    # no matter what username/password is used, the response is "Bad credentials"
    # not sure what GitHub is looking for
    github_id = login_session['github_id']
    url = 'https://api.github.com/authorizations/:%s' % github_id
    h = httplib2.Http()
    # h.add_credentials(GH_CLIENT_ID, GH_CLIENT_SECRET)
    auth = b64encode('%s : %s' % (GH_CLIENT_ID, GH_CLIENT_SECRET))
    headers = { 'Authorization' : 'Basic %s' % auth }
    result = h.request(url, 'DELETE', headers=headers)[1]
    print(result)
    return


# LOGOUT - Revoke a current user's token and reset their login_session.
@app.route('/disconnect')
def disconnect():
    """Route used to logout a user by revoking the authentication token and resetting the login session."""
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            # Reset Google specific session vars
            del login_session['credentials']
            del login_session['gplus_id']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            # Reset Facebook specific session vars
            del login_session['facebook_id']
        if login_session['provider'] == 'github':
            ghdisconnect()
            # Reset GitHub specific session vars
            del login_session['github_id']
# if login_session['provider'] == 'local': There is nothing to do for the local provider other than what we do below.

        # Reset the user's session.
        del login_session['provider']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['isadmin']
        del login_session['user_id']

        # Redirect user to home page and give message they have been logged out.
        flash("You have been successfully logged out")
        return redirect(url_for('sports'))
    else:
        return redirect(url_for('sports'))