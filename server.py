from flask import Flask, request, abort
from flask.ext.bcrypt import Bcrypt
from flask_restful import reqparse
from urlparse import parse_qs
import requests
import os

from database import init_db
from models import User

app = Flask(__name__)
bcrypt = Bcrypt(app)

@app.route('/', methods = ['GET'])
def hello_world():
    return 'Hey there!'

@app.route('/api/loginreg/email', methods = ['GET', 'PUT'])
def loginregister():
    parser = reqparse.RequestParser()
    parser.add_argument('email', required=True)
    parser.add_argument('password', required=True)
    args = parser.parse_args()

    user = User.query.filter_by(email=args['email']).first()

    if request.method == 'PUT':
        if user is not None:
            # User already exists
            abort(409)
        pw_hash = bcrypt.generate_password_hash(args['password'])
        user = User.add_user({'email': args['email'], 'password_hash': pw_hash})

    if user is None:
        # Email doesn't exist in the database
        abort(401)

    if bcrypt.check_password_hash(user.password_hash, args['password']):
        return user.generate_token()
    else:
        # Password is incorrect
        abort(401)

@app.route('/api/loginreg/fb', methods = ['PUT'])
def fb():
    parser = reqparse.RequestParser()
    parser.add_argument('token', required=True)
    shortToken =  parser.parse_args()['token']
    req = requests.get(
        'https://graph.facebook.com/oauth/access_token?' +
        'grant_type=fb_exchange_token&client_id=' +
        os.environ['FB_ID'] + '&client_secret=' +
        os.environ['FB_SECRET'] + '&fb_exchange_token=' + shortToken
    )

    try:
        token = parse_qs(r.text)['access_token'][0]
    except:
        # Invalid token
        abort(401)

    md5token = hashlib.md5(token).hexdigest()
    req = requests.get('https://graph.facebook.com/me?access_token=' + token)
    fb_id = req.json()['id']
    user = User.query.filter_by(fb_id=fb_id).first()

    if user is None:
        user = User.add_user({'is_facebook': True, 'fb_id': fb_id})

    return user.generate_token()

@app.route('/api/test', methods = ['GET', 'POST'])
def number():
    parser = reqparse.RequestParser()
    parser.add_argument('token', required=True)
    parser.add_argument('number')
    args = parser.parse_args()
    data = User.get_data(args['token'])
    user = User.query.filter_by(id=data['id']).first()

    if user is None:
        abort(401)

    if request.method == 'POST':
        user.update_number(args['number'])

    return str(user.number)

if __name__ ==  '__main__' :
    init_db()
    app.run()
