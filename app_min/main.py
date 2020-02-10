
import os
from flask import Flask, render_template, request, abort, Response, redirect,jsonify

from flask_cors import CORS, cross_origin

app = Flask(__name__)

cors = CORS(app, expose_headers='Authorization' , resources={r"/user": {"origins": "https://sp.providerdomain.com:38080"}})


@app.route('/', methods=['GET'])
def main():
  resp = Response("ok")
  return resp

@app.route('/_ah/health', methods=['GET'])
def hc():
  return "ok"

@app.route('/user')
def user():
  h = request.headers.get('X-Goog-Authenticated-User-Email')
  u = request.headers.get('X-Goog-Authenticated-User-ID')
  jwt =request.headers.get('x-goog-iap-jwt-assertion')

  resp = {
    'X-Goog-Authenticated-User-Email': h,
    'X-Goog-Authenticated-User-ID': u,
    'x-goog-iap-jwt-assertion': jwt
  }
  return jsonify(resp)
  





