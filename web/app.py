#imports what is needed to run the application as an instance of the Flask Object and handle json requests
from flask import Flask, request, jsonify
#imports what is needed to run application as an API
from flask_restful import Resource, Api
#imports mongodb and its python client
from pymongo import MongoClient
#imports bcrypt to handle the hashing of passwords
import bcrypt

import requests
import subprocess
import json

#define the app and instantiates it as an API
app = Flask(__name__)
api = Api(app)


#starts database and create collection
client = MongoClient("mongodb://db:27017")
db = client.ImageRecognition
users = db["Users"]

#search for the user's input username and check if already exists in the database
def UserExist(username):
    if users.find({"Username": username}).count() == 0:
        return False
    else:
        return True

def CountTokens(username):
    tokens = users.find({
        "Username": username
    })[0]["Tokens"]
    return tokens

def RefillAccount(username, refill_amount):
    current_count = CountTokens(username)
    new_count = current_count + refill_amount
    users.update({
        "Username": username
    },{
        "$set": {
            "Tokens": new_count
        }
    })

def ChargeAccount(username):
    current_count = CountTokens(username)
    new_count = current_count-1
    users.update({
        "Username": username
    },{
        "$set": {
            "Tokens": new_count
        }
    })

def verifyPassword(username, password):
    if not UserExist(username):
        return False
    hashed_pw = users.find({
        "Username": username
    })[0]["Password"]

    if bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
        return True
    else:
        return False

def generateReturnJson(status, message):
    retJson = {
        "status": status,
        "message": message
    }
    return retJson

def VerifyCredentials(username, password):
    if not UserExist(username):
        return generateReturnJson(301, "username not found, please register to use this API")
    correct_pw = verifyPassword(username, password)
    if not correct_pw:
        return generateReturnJson(302, "Incorrect password")

    return None, False


#Handles the registration of the user
class Register(Resource):
    #handles it as a post request
    def post(self):
        #gets data entered by the user and assigns it to local variables
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]

        #if user already exist, tell user to pick a new username
        if UserExist(username):
            return jsonify(generateReturnJson(301, "Invalid Username"))

        #hashes pw entered by the user and adds a little salt to it
        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        #insert user in the database with the hashed password
        users.insert({
            "Username": username,
            "Password": password,
            "Tokens": 5
        })

        #prepares and return the message to be displayed once user successfully registers
        return jsonify(generateReturnJson(200, "User Registered to use the API"))


class Refill(Resource):
    def post(self):

        postedData = request.get_json()

        username = postedData["username"]
        admin_pw = postedData["admin_pw"]
        refill_amount = postedData["refill"]

        correct_pw = "admin123"

        if not UserExist(username):
            return jsonify(generateReturnJson(301, "Invalid Username"))

        if not admin_pw == correct_pw:
            return jsonify(generateReturnJson(302, "Invalid Admin Password"))

        RefillAccount(username, refill_amount)

        return jsonify(generateReturnJson(200, str(refill_amount) + " tokens added to User Account"))

class Classify(Resource):
    def post(self):

        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        url = postedData["url"]

        #retJson, error = VerifyCredentials(username, password)
        #if error:
        #    return jsonify(retJson)

        tokens = users.find({"Username":username})[0]["Tokens"]
        if tokens <= 0:
            return jsonify( generateReturnJson(303, "You don't have enough tokens to use the API"))

        r = requests.get(url)
        retJson = {}
        with open("temp.jpg", "wb") as f:
            f.write(r.content)
            proc = subprocess.Popen('python classify_image.py --model_dir=. --image_file=./temp.jpg', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
            proc.communicate()[0]
            proc.wait()
            with open("text.txt") as f:
                retJson = json.load(f)

        ChargeAccount(username)
        return retJson

api.add_resource(Register, '/register')
api.add_resource(Refill, '/refill')
api.add_resource(Classify, '/classify')

if __name__=="__main__":
    app.run('0.0.0.0')
