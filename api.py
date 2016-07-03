from flask import Flask, Blueprint, request, abort, jsonify
from flask_restful import reqparse
from urllib.parse import parse_qs, urlencode
from werkzeug.security import safe_str_cmp
from collections import defaultdict
import bcrypt
import hashlib
import json
import hmac

import requests
import os

api = Blueprint('api', __name__)

from models import User

##################################################
# TODO:
#
# - Don't hardcode stuff
# - Use geocode instead of precise zipcode search
#
##################################################

# Ticketmaster API constants
DISCOVERY_V2_BASE = 'https://app.ticketmaster.com/discovery/v2'
AUTH = {'apikey': 'EKDjnHhA4O31rZKAAByw8YAFszvX1A2x'}

def get_query(base, endpoint, query_dict):
    return os.path.join(base, endpoint + '.json?', urlencode({**AUTH, **query_dict}))


def generate_password_hash(password):
    if not password:
        raise ValueError('Password must be non-empty.')

    if isinstance(password, str):
        password = bytes(password, 'utf-8')

    return bcrypt.hashpw(password, bcrypt.gensalt(12))


def check_password_hash(pw_hash, password):
    if isinstance(pw_hash, str):
        pw_hash = bytes(pw_hash, 'utf-8')
    if isinstance(password, str):
        password = bytes(password, 'utf-8')

    return safe_str_cmp(bcrypt.hashpw(password, pw_hash), pw_hash)


def gen_proof(app_secret, access_token):
    return hmac.new (
        app_secret.encode('utf-8'),
        msg=access_token.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()


@api.route('/api/loginreg/email', methods = ['GET', 'PUT'])
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
        pw_hash = generate_password_hash(args['password'])
        print(pw_hash)
        print('##########')
        user = User.add_user({'email': args['email'], 'password_hash': pw_hash})

    if user is None:
        # Email doesn't exist in the database
        abort(401)

    print(user.password_hash)
    print('##########')
    if check_password_hash(user.password_hash, args['password']):
        return user.generate_token()
    else:
        # Password is incorrect
        abort(401)


@api.route('/api/loginreg/fb', methods = ['PUT'])
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
        token = parse_qs(req.text)['access_token'][0]
    except:
        # Invalid token
        abort(401)

    md5token = hashlib.md5(token.encode('utf-8')).hexdigest()
    appsecret_proof = gen_proof(os.environ['FB_SECRET'], token)
    req = requests.get('https://graph.facebook.com/me?appsecret_proof=' +
        appsecret_proof + '&access_token=' + token)
    print('#####################')
    print(req.json())
    print('#####################')
    print(token)
    print('#####################')
    fb_id = req.json()['id']
    user = User.query.filter_by(fb_id=fb_id).first()

    if user is None:
        user = User.add_user({'is_facebook': True, 'fb_id': fb_id})

    return user.generate_token()


@api.route('/api/events', methods = ['GET'])
def get_nearby_events():
    parser = reqparse.RequestParser()
    parser.add_argument('zip_code', required=True)
    parser.add_argument('num_results', required=True)
    args = parser.parse_args()
    query_dict = {
        'classificationName': 'music',
        'postalCode': args['zip_code'],
        'size': args['num_results']
    }
    url = get_query(DISCOVERY_V2_BASE, 'events', query_dict)
    response = requests.get(url)
    data = json.loads(response.text)
    trimmed_data = []
    for event in data['_embedded']['events']:
        trimmed_data.append({
            'name': event['name'] if 'name' in event else '',
            'images': event['images'] if 'images' in event else '',
            'venues': event['_embedded']['venues'] if 'venues' in event['_embedded'] else ''
        })
    return jsonify({'results': trimmed_data})


@api.route('/api/test', methods = ['GET', 'POST'])
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
