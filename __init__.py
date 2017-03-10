import random
import string
import httplib2
import json
import requests
from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, MenuItem, User
from flask import session as login_session
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from flask import make_response


app = Flask(__name__)

CLIENT_ID = json.loads(
    open('/var/www/catalog/catalog/client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Item Application"


# Connect to Database and create database session
engine = create_engine("postgresql://catalogitem:choxutimeo@localhost/tutor")
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # print login_session['state']
    return render_template('login.html', STATE=state)




@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data

    print "access token received %s " % access_token

    app_id = json.loads(open('/var/www/catalog/catalog/fb_client_secrets.json', 'r').read())['web']['app_id']
    app_secret = json.loads(open('/var/www/catalog/catalog/fb_client_secrets.json', 'r').read())['web']['app_secret']

    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.4/me"
    # strip expire tag from access token
    token = result.split("&")[0]


    url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout, let's strip out the information before the equals sign in our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"







# gconnect
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('/var/www/catalog/catalog/client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    #data = answer.json()
    data = json.loads(answer.text)

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    #******************************

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    #******************************
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['email'])
    print "done!"
    return output


# User Helper Functions
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# This can be replace with /gdisconnect
@app.route('/clear')
def clearSession():
    login_session.clear()
    return "Login Session cleared"


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
        # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# JSON APIs to view Category Information
# JSON endpoint: List all latest menu_items
@app.route('/json')
@app.route('/latest/json')
def newItemJSON():
    items = session.query(MenuItem).filter_by(kind="new").all()
    return jsonify(MenuItem=[i.serialize for i in items])


# JSON APIs to view Category Information
#@app.route('/categories/json')
#def newItemJSON():
#    categories = session.query(Category).all()
#    return jsonify(Categories=[i.serialize for i in categories])


# JSON endpoint: List all users who's in database
@app.route('/users/json')
def UserJSON():
    items = session.query(User).all()
    return jsonify(Users=[i.serialize for i in items])


# JSON endpoint: Lists all menu_items with specified category's name
@app.route('/catalog/<string:category_name>/items/json')
def categoryMenuJSON(category_name):
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(MenuItem).filter_by(category_id=category.id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


# JSON endpoint: Lists all menu_items with specified category_id
@app.route('/catalog/<int:category_id>/items/json')
def categoryidMenuJSON(category_id):
    items = session.query(MenuItem).filter_by(category_id=category_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


# JSON endpoint: List contents of a menu_item has specified
# category_name and item_id
@app.route('/catalog/<string:category_name>/<int:item_id>/item/json')
def menuItemJSON(category_name, item_id):
    category = session.query(Category).filter_by(name=category_name).one()
    menuItem = session.query(MenuItem).filter_by(category_id=category.id,                                                 id=item_id).one()
    return jsonify(MenuItem=menuItem.serialize)


# JSON endpoint: List contents of a menu_item has specified
# category_id and item_id
@app.route('/catalog/<int:category_id>/<int:item_id>/item/json')
def menuidItemJSON(category_id, item_id):
    menuItem = session.query(MenuItem).filter_by(category_id=category_id,
                                                 id=item_id).one()
    return jsonify(MenuItem=menuItem.serialize)


# JSON endpoint: List a menu_item has specified item_id
@app.route('/catalog/<int:item_id>/item/json')
def idItemJSON(item_id):
    menuItem = session.query(MenuItem).filter_by(id=item_id).one()
    return jsonify(MenuItem=menuItem.serialize)


# JSON endpoint: List all categories has specified user_id
@app.route('/category/<int:user_id>/user/json')
def categoryuserJSON(user_id):
    categories = session.query(Category).filter_by(user_id=user_id).all()
    return jsonify(categories=[i.serialize for i in categories])


# JSON endpoint: List all menu_items has specified user_id
@app.route('/menuitem/<int:user_id>/user/json')
def menuitemuserJSON(user_id):
    menuitems = session.query(MenuItem).filter_by(user_id=user_id).all()
    return jsonify(menuitems=[i.serialize for i in menuitems])


# The first page in public mode
@app.route('/')
@app.route('/catalog')
def catalogMenu():

    categories = session.query(Category)
    items = session.query(MenuItem).filter_by(kind="new").all()
    return render_template('pub_catalog.html', categories=categories, items=items)



# List all categories and menu_items in public mode
@app.route('/catalog/<string:category_name>/items')
def categoryitemMenu(category_name):
    categories = session.query(Category)
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(MenuItem).filter_by(category_id=category.id)
    return render_template('pub_categoryitem.html', categories=categories,
                           category=category, items=items,
                           category_name=category.name)


# Show the already menu_item's description when click on it's image
# in descriptionitem.html
@app.route('/describemenuitem/<string:item_name>', methods=['GET'])
def describeMenuItem(item_name):
    if request.method == 'GET':

        menuItem = session.query(MenuItem).filter_by(name=item_name).one()
        return render_template('descriptionitem.html', menuItem=menuItem)
    else:
        return redirect(url_for('catalogMenu'))


@app.route('/secdescribemenuitem/<string:item_name>', methods=['GET'])
def secdescribeMenuItem(item_name):
    if request.method == 'GET':

	# see if user exists, if it doesn't make a new one
        user_id = getUserID(login_session['email'])
        if not user_id:
            user_id = createUser(login_session)
            login_session['user_id'] = user_id

        menuItem = session.query(MenuItem).filter_by(name=item_name).one()
        return render_template('descriptionitem.html', menuItem=menuItem, email_user=login_session['email'])
    else:
        return redirect(url_for('seccatalogMenu'))



# List all categories and latest menu_items in security mode
@app.route('/seccatalog')
def seccatalogMenu():


    # see if user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
        login_session['user_id'] = user_id

    categories = session.query(Category)
    items = session.query(MenuItem).filter_by(kind="new").all()
    return render_template('sec_catalog.html', categories=categories,
                           items=items, email_user=login_session['email'])


# List all category's menu_items in security mode
@app.route('/seccatalog/<string:category_name>/items')
def seccategoryitemMenu(category_name):

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
        login_session['user_id'] = user_id

    categories = session.query(Category)
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(MenuItem).filter_by(category_id=category.id)
    return render_template('sec_categoryitem.html', categories=categories,
                           category=category, items=items,
                           category_name=category.name,
                           email_user=login_session['email'])


# Change the contents for an already menu_item
@app.route('/catalog/<string:category_name>/<string:item_name>/edit',
           methods=['GET', 'POST'])
def editMenuItem(category_name, item_name):
    if 'username' not in login_session:
        return redirect('/login')
    category = session.query(Category).filter_by(name=category_name).one()
    editedItem = session.query(MenuItem).filter_by(name=item_name).one()
    user = session.query(User).filter_by(email=login_session['email']).one()
    if editedItem.user_id == user.id:
        if request.method == 'POST':
            if request.form['name']:
                editedItem.name = request.form['name']
            if request.form['description']:
                editedItem.description = request.form['description']
            if request.form['price']:
                editedItem.price = request.form['price']
            if request.form['image']:
                editedItem.price = request.form['image']
            if request.form['kind']:
                editedItem.kind = request.form['kind']
            editedItem.category_id = category.id
            session.add(editedItem)
            flash("Menu Item: %s has been edited" % editedItem.name)
            session.commit()
            return redirect(url_for('seccategoryitemMenu',
                                    category_name=category_name))
        else:
            return render_template('editmenuitem.html',
                                   category_name=category_name,
                                   item_name=item_name,
                                   item=editedItem,
                                   email_user=login_session['email'])
    else:
        flash("User cann't edit this Menu Item")
        return redirect(url_for('seccategoryitemMenu',
                                category_name=category_name))


# Delete an already menu_item off the database
@app.route('/catalog/<string:category_name>/<string:item_name>/delete',
           methods=['GET', 'POST'])
def deleteMenuItem(category_name, item_name):
    if 'username' not in login_session:
        return redirect('/login')
    category = session.query(Category).filter_by(name=category_name).one()
    itemToDelete = session.query(MenuItem).\
    filter_by(name=item_name, category_id=category.id).one()
    login_user = session.query(User).\
    filter_by(email=login_session['email']).one()
    if itemToDelete.user_id == login_user.id:
        if request.method == 'POST':
            session.delete(itemToDelete)
            session.commit()
            flash("Menu Item: %s has been deleted" % itemToDelete.name)
            return redirect(url_for('seccategoryitemMenu',
                                    category_name=category_name))
        else:
            return render_template('deletemenuitem.html',
                                   category_name=category_name,
                                   item_name=item_name,
                                   email_user=login_session['email'])
    else:
        flash("User cann't delete this Menu Item")
        return redirect(url_for('seccategoryitemMenu',
                        category_name=category_name))


# Create a new menu_item
@app.route('/catalog/<string:category_name>/new',
           methods=['GET', 'POST'])
def newMenuItem(category_name):
    if 'username' not in login_session:
        return redirect('/login')
    login_UserID = getUserID(login_session['email'])
    if request.method == 'POST':
        category = session.query(Category).filter_by(name=category_name).one()
        newItem = MenuItem(name=request.form['name'],
                           description=request.form['description'],
                           price=request.form['price'],
                           image=request.form['image'],
                           kind=request.form['kind'],
                           user_id=login_UserID,
                           category_id=category.id)
        session.add(newItem)
        session.commit()
        flash("new Menu Item: %s created!" % newItem.name)
        return redirect(url_for('seccategoryitemMenu',
                        category_name=category_name))
    else:
        return render_template('newmenuitem.html', category_name=category_name)


# Create a new category
@app.route('/category/<string:category_name>/new', methods=['GET', 'POST'])
def newCategory(category_name):
    if 'username' not in login_session:
        return redirect('/login')
    login_UserID = getUserID(login_session['email'])
    if request.method == 'POST':
        newCategory = Category(name=request.form['name'], user_id=login_UserID)
        session.add(newCategory)
        session.commit()
        flash("new Category Item: %s created!" % newCategory.name)
        return redirect(url_for('seccategoryitemMenu',
                        category_name=category_name, email_user=login_session['email']))
    else:
        return render_template('newcategory.html', category_name=category_name, email_user=login_session['email'])


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            clearSession()
            del login_session['gplus_id']
            del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('catalogMenu'))
    else:
        flash("You were not logged in")
        return redirect(url_for('catalogMenu'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)

