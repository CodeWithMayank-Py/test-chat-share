from flask import Flask, render_template, request, redirect, url_for, flash
import json
from passlib.hash import pbkdf2_sha256
import secrets

app = Flask(__name__)

# Define the route for the index page
@app.route('/')
def index():
    return render_template('index.html')

# Define the route for the registration page
@app.route('/register')
def register():
    return render_template('registration.html')


if __name__ == '__main__':
    app.run(debug=True) 
