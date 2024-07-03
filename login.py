from flask import Flask, jsonify, request
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['MONGO_URI'] = 'mongodb://localhost:27017/mummy'
app.config['SECRET_KEY'] = 'rajatmummy'
mongo = PyMongo(app)

# Decorator to protect routes
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = mongo.db.users.find_one({'_id': data['_id']})
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# User registration
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']

    # Check if user already exists
    user = mongo.db.users.find_one({'username': username})
    if user:
        return jsonify({'error': 'Username already exists'}), 400

    # Hash the password
    hashed_password = generate_password_hash(password)

    # Insert the new user
    user_id = mongo.db.users.insert_one({'username': username, 'password': hashed_password}).inserted_id
    return jsonify({'message': 'User registered successfully'}), 201

# User login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']

    # Check if user exists
    user = mongo.db.users.find_one({'username': username})
    if not user:
        return jsonify({'error': 'Invalid username or password'}), 401

    # Verify the password
    if not check_password_hash(user['password'], password):
        return jsonify({'error': 'Invalid username or password'}), 401

    # Generate a JWT token
    token = jwt.encode({'_id': str(user['_id']), 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
    return jsonify({'token': token.decode('UTF-8')}), 200

# Protected API endpoint
@app.route('/protected', methods=['GET'])
@token_required
def protected(current_user):
    return jsonify({'message': f'Welcome, {current_user["username"]}!'})

if __name__=='__main__':
    app.run(debug=True)
