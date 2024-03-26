from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_socketio import join_room, leave_room, send, SocketIO
import json, secrets,random
from passlib.hash import pbkdf2_sha256
from string import ascii_uppercase

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

        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('dashboard'))  # Redirect to the dashboard page after successful registration

    # Render the signup page template (if the request method is not POST)
    return render_template('registration.html')

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
                flash('Login successful.', 'success')
                return redirect(url_for('dashboard'))  # Redirect to the dashboard page
            else:
                flash('Invalid email or password. Please try again.', 'error')
        else:
            flash('User does not exist. Please sign up.', 'error')

    # Render the signin page template (if the request method is not POST or authentication fails)
    return redirect(url_for('register'))


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
