from flask import Flask, request, abort
from flask_restful import reqparse
from urllib.parse import parse_qs
from waitress import serve
from flask.ext.sqlalchemy import SQLAlchemy

import requests
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

import api
app.register_blueprint(api.api)

@app.route('/', methods = ['GET'])
def hello_world():
    return 'Hey there!'

if __name__ ==  '__main__' :
    serve(app)
