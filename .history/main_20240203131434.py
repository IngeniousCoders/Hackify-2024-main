import string
import urllib.parse
import datetime
import os
from discord_webhook import DiscordWebhook
import json
from flask import Flask, render_template, request, redirect, jsonify
import emailsend
import logging
import firebase_admin
from firebase_admin import firestore, credentials
import random
from random import randint
from argon2 import PasswordHasher, exceptions

# Application Default credentials are automatically created.
cred = credentials.Certificate("./fbkey.json")
firebase_app = firebase_admin.initialize_app(cred)
db = firestore.client()
ph = PasswordHasher()

# logging.getLogger("werkzeug").disabled = True
app = Flask(__name__)


def generaterandomid(length):
    range_start = 10**(length-1)
    range_end = (10**length)-1
    return randint(range_start, range_end)


def generate_cookie(length):
    cookie = ''.join(
        random.choice(
            string.ascii_uppercase +
            string.ascii_lowercase +
            string.digits
        ) for _ in range(length)
    )
    return cookie


@app.route('/')
def homepage():
    return render_template('templates/my_home_page.html')


@app.route('/account')
def account():
    return render_template("account.html")


@app.route("/terms-conditions")
def termsandconditions():
    return render_template("terms_and_conditions.html")


@app.route("/login", methods=["POST"])
def login():
    docs_ref = db.collection("users")
    docs = docs_ref.stream()
    request_content = request.form.to_dict()
    error_reason = ""
    return_status = {
        "status": "",  # can be "success" or "failed"
        "reason": "",  # reason for failed authentication - e.g. "empty-email" or "invalid-password"
        "cookie": ""
    }
    for doc in docs:
        user_info = doc.to_dict()
        hash = user_info["password"]
        try:
            ph.verify(hash, request_content["password"])
            if (request_content["email"] == user_info["email"]):
                if request_content["email"].isspace():
                    error_reason = "empty-email"
                    raise Exception
                elif request_content["password"].isspace():
                    error_reason = "empty-password"
                    raise Exception
                return_status["status"] = "success"
                return_status["cookie"] = generate_cookie(40)
                return return_status
            else:
                error_reason = "invalid-email"
                raise Exception
        except Exception as e:
            print(e)
            if (error_reason == ""):
                error_reason = "invalid-password"
            pass
    return_status["status"] = "failed"
    return_status["reason"] = error_reason
    return return_status


@app.route("/signup", methods=["POST"])
def signup():
    request_content = request.form.to_dict()
    random_id = generaterandomid(10)
    # print("RANDOM ID: " + str(random_id))
    hashed_password = ph.hash(request_content["password"])
    # print("HASH: " + hashed_password)
    username = request_content["username"]
    user_email = request_content["email"]
    user_data = {
        "username": username,
        "password": hashed_password,
        "email": user_email,
        "email-verified": False
    }
    db.collection("users").document(str(random_id)).set(user_data)
    verification_link = f"http://192.168.1.234:5000/verify/{random_id}"
    emailsend.sendEmail(
        user_email,
        "Account Verification",
        "<!DOCTYPE html> <html lang='en'> <head> <meta charset='UTF-8'> <meta name='viewport' content='width=device-width,initial-scale=1'> <title>Email Verification</title> <style>.btn-home:hover {background-color:#5ad35e}</style> </head> <body style='font-family:Arial, sans-serif'> <div class='container' style='background-color:#6095e2; border-radius:8px; box-shadow:0 0 10px rgba(0, 0, 0, 0.1); height:fit-content; margin:auto; padding:50px; text-align:center; width:fit-content' bgcolor='#6095e2' height='fit-content' align='center' width='fit-content'> <div class='subcontainer' style='top:50%'> <h2 style='color:#000; margin:0'>Welcome!</h2> <div class='thank-you-message' style='color:#000; font-size:18px; margin-bottom:20px; margin-top:20px; text-align:center' align='center'> Hello, " + username + ". <br> Thank you for signing up for City Bug Reports. <br> Click the button below to verify your email address. </div> <a href='" + verification_link + "' style='cursor:pointer'><button class='btn-home' style='background-color:#55be59; border:none; border-radius:4px; color:#fff; font-size:16px; margin:0; margin-left:auto; margin-right:auto; padding:10px 20px; width:300px' bgcolor='#55be59' width='300'>Verify email</button></a> </div> </div> </body> </html>")
    return "Success", 200


@app.route("/verify/<id>")
def verifyuser(id):
    user_ref = db.collection("users").document(id)
    user = user_ref.get()
    if (user.exists):
        print("User exists!")
    else:
        print("User does not exist.")
    return "User successfully verified."


@app.errorhandler(500)
def fivehundrederror(error):
    return render_template("error.html", errorcode=error)


@app.errorhandler(404)
def invalid_route(error):
    return render_template("error.html", errorcode="404 resource not found")


app.run(host='0.0.0.0', port=5000, debug=False)
