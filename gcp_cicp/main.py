import logging
import json
import uuid

from flask import Flask, render_template, request, Response,  send_from_directory, abort, redirect, jsonify, session

import google_auth_oauthlib.flow
import google_auth_httplib2

import httplib2
import os
import pprint
import sys

from apiclient.discovery import build
from apiclient.discovery import build_from_document
from oauth2client.service_account import ServiceAccountCredentials
from google.auth.credentials import Credentials

import firebase_admin
from firebase_admin import credentials
from firebase_admin import auth

app = Flask(__name__, static_url_path='')
app.secret_key = 'notasecret'

cred = credentials.Certificate('svc_account.json')
default_app = firebase_admin.initialize_app(cred)   


@app.route('/public/<path:path>')
def send_file(path):
    return send_from_directory('public', path)

@app.route('/')
def index():
  return render_template('index.html')

@app.route('/_ah/health')
def health():
    return('ok')

@app.route('/portal', methods=["GET"])
def portal():
    app_location = "https://ip-iap-auth.appspot.com/user"
    return render_template('portal.html', app_location=app_location)

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/logout')
def logout():
    return render_template('logout.html')

def verifyIdToken(id_token):
    try:
      decoded_token = auth.verify_id_token(id_token)
      uid = decoded_token['uid']
      return True
    # except auth.AuthError as e:
    #   logging.error(e.detail)
    except Exception as e:
      logging.error(e)
    return False

@app.route('/verifyIdToken', methods = ['POST'])
def verifyIdTokenRequest():
    return str(verifyIdToken(request.form['id_token']))


if __name__ == '__main__':

    context = ('server.crt','server.key')
    app.run(host='0.0.0.0', port=38080,   threaded=True, ssl_context=context)


