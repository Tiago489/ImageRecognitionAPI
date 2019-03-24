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
            retJson = {
                "status": 301,
                "message": "Invalid Username"
            }
            return jsonify(retJson)

        #hashes pw entered by the user and adds a little salt to it
        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        #insert user in the database with the hashed password
        users.insert({
            "Username": username,
            "Password": password,
            "Tokens": 5
        })

        #prepares and return the message to be displayed once user successfully registers
        retJson = {
            "status": 200,
            "message": "User sucessfully registered"
        }
        return jsonify(retJson)


class Refill(Resource):
    def post(self):

        postedData = request.get_json()

        username = postedData["username"]
        admin_pw = postedData["admin_pw"]
        refill_amount = postedData["refill"]

        correct_pw = "admin123"

        if not admin_pw == correct_pw:
            retJson = {
                "status": 302,
                "message": "Invalid admin password"
            }
            return jsonify(retJson)

        RefillAccount(username, refill_amount)

        retJson = {
            "status": 200,
            "message": str(refill_amount) + " tokens added to User Account"
        }
        return jsonify(retJson)






api.add_resource(Register, '/register')
api.add_resource(Refill, '/refill')


if __name__=="__main__":
    app.run('0.0.0.0')
