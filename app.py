from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_socketio import join_room, leave_room, send, SocketIO
from flask_session import Session
import json, secrets,random
from passlib.hash import pbkdf2_sha256
from string import ascii_uppercase
from flask import jsonify
import jwt
from datetime import datetime, timedelta

# Functions to create secret key
def generate_secret_key():
    """
    Generate a random 32-byte secret key.
    Returns:
        str: The generated secret key as a hexadecimal string.
    """
    secret_key_bytes = secrets.token_bytes(32)
    return secret_key_bytes.hex()

# Function to hash a password
def hash_password(password):
    return pbkdf2_sha256.hash(password)

# Functions to verify a password
def verify_password(password, hashed_password):
    return pbkdf2_sha256.verify(password, hashed_password)

def generate_unique_code(length):
    while True:
        code = ""
        for _ in range(length):
            code += random.choice(ascii_uppercase)
        
        if code not in rooms:
            break
    return code


app = Flask(__name__)
app.config["SECRET_KEY"] = "hjhjsdaaads"
socketio = SocketIO(app)

# Path to the JSON file
json_file = '/tmp/users.json'
rooms = {}

# Define the route for the index page
@app.route('/')
def index():
    return render_template('index.html')

# Define the route for the registration page
@app.route('/register')
def register():
    return render_template('registration.html')

# Function to load user data from JSON file
def load_users():
    try:
        with open(json_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

# Function to save user data to JSON file
def save_users(users_data):
    with open(json_file, 'w') as f:
        json.dump(users_data, f, indent=4)


# Function to generate JWT token
def generate_jwt_token(user_id, username):
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.utcnow() + timedelta(hours=1)  # Token expiration time (e.g., 1 hour)
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return token

# Route for handling user registration
@app.route('/signup', methods=['POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        # Load existing user data from JSON file
        users_data = load_users()

        # Check if the email already exists in the user data
        if email in users_data:
            flash('Email already exists. Please choose another email.', 'error')
            return redirect(url_for('register'))  # Redirect to the signup page

        # Hash the password before storing
        hashed_password = hash_password(password)

        # Add new user data to the dictionary
        users_data[email] = {'name': name, 'password': hashed_password}

        # Save updated user data to JSON file
        save_users(users_data)

        # Generate JWT token for the newly registered user
        token = generate_jwt_token(email, name)

        # Return JWT token as JSON response
        return jsonify({'token': token.decode('utf-8')})

# Route for handling user sign-in
@app.route('/signin', methods=['POST'])
def signin():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Load existing user data from JSON file
        users_data = load_users()

        # Check if the email exists in the user data
        if email in users_data:
            # Verify the password
            stored_password = users_data[email]['password']
            if verify_password(password, stored_password):
                # Generate JWT token for the authenticated user
                token = generate_jwt_token(email, users_data[email]['name'])
                
                # Return JWT token as JSON response
                return jsonify({'token': token.decode('utf-8')})
            else:
                return jsonify({'error': 'Invalid email or password'}), 401  # Unauthorized
        else:
            return jsonify({'error': 'User does not exist'}), 404  # Not Found


# Define the route for the dashboard page
@app.route('/dashboard', methods=["POST", "GET"])
def dashboard():
    session.clear()
    if request.method == "POST":
        name = request.form.get("name")
        code = request.form.get("code")
        join = request.form.get("join", False)
        create = request.form.get("create", False)

        if not name:
            return render_template("dashboard.html", error="Please enter a name.", code=code, name=name)

        if join != False and not code:
            return render_template("dashboard.html", error="Please enter a room code.", code=code, name=name)
        
        room = code
        if create != False:
            room = generate_unique_code(4)
            rooms[room] = {"members": 0, "messages": []}
        elif code not in rooms:
            return render_template("dashboard.html", error="Room does not exist.", code=code, name=name)
        
        session["room"] = room
        session["name"] = name
        return redirect(url_for("room"))

    return render_template("dashboard.html")


@app.route("/room")
def room():
    room = session.get("room")
    if room is None or session.get("name") is None or room not in rooms:
        return redirect(url_for("dashboard"))

    return render_template("room.html", code=room, messages=rooms[room]["messages"])


@socketio.on("message")
def message(data):
    room = session.get("room")
    if room not in rooms:
        return 
    
    content = {
        "name": session.get("name"),
        "message": data["data"]
    }
    send(content, to=room)
    rooms[room]["messages"].append(content)
    print(f"{session.get('name')} said: {data['data']}")

@socketio.on("connect")
def connect(auth):
    room = session.get("room")
    name = session.get("name")
    if not room or not name:
        return
    if room not in rooms:
        leave_room(room)
        return
    
    join_room(room)
    send({"name": name, "message": "has entered the room"}, to=room)
    rooms[room]["members"] += 1
    print(f"{name} joined room {room}")

@socketio.on("disconnect")
def disconnect():
    room = session.get("room")
    name = session.get("name")
    leave_room(room)

    if room in rooms:
        rooms[room]["members"] -= 1
        if rooms[room]["members"] <= 0:
            del rooms[room]
    
    send({"name": name, "message": "has left the room"}, to=room)
    print(f"{name} has left the room {room}")


@app.route('/exit')
def exit_room():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True) 
