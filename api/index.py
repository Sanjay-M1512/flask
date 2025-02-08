from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_restful import Api

app = Flask(__name__)
CORS(app)  # Enable CORS
api = Api(app)

# ✅ Update MongoDB Configuration for Deployment (Use MongoDB Atlas)
app.config['MONGO_URI'] = 'your_mongodb_atlas_connection_string'  # Replace with your cloud MongoDB URI
mongo = PyMongo(app)
bcrypt = Bcrypt(app)

# ✅ User Registration Route
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    mobile = data.get('mobile')
    password = data.get('password')

    if not name or not email or not mobile or not password:
        return jsonify({'error': 'All fields are required.'}), 400

    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters long.'}), 400

    # Hash the password
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Create user in DB
    mongo.db.users.insert_one({
        'name': name,
        'email': email,
        'mobile': mobile,
        'password': hashed_password
    })

    return jsonify({'message': 'User registered successfully.'}), 201

# ✅ User Login Route
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    user = mongo.db.users.find_one({'email': email})

    if not user or not bcrypt.check_password_hash(user['password'], password):
        return jsonify({'error': 'Invalid email or password.'}), 401

    return jsonify({'message': 'Login Successful! Welcome back!'}), 200

# ✅ Required for Vercel (Vercel looks for 'handler' function)
def handler(request, *args, **kwargs):
    return app(request.environ, *args, **kwargs)
