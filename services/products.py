import requests
import os
import json
import jwt
from flask import Flask, jsonify, request, make_response
from functools import wraps
from jwt.exceptions import DecodeError
app = Flask(__name__)
port = int(os.environ.get('PORT',5010))
app.config['SECRET_KEY'] = os.urandom(24)

with open('users.json','r') as f:
    users = json.load(f)
    print("users", users)
        
@app.route('/auth', methods=['POST'])
def authenticate_user():
    print("Users: ",users)
    if request.headers['Content-Type'] != 'application/json':
        return jsonify({'error':'Unsupported Media Type'}), 415
    username = request.json.get('username')
    password = request.json.get('password')
    for user in users:
        if user['userame'] == username and user['password'] == password:
            token = jwt.encode({'user_id':user['id']},app.config['SECRET_KEY'],algorithm="HS256")
            response = make_response(jsonify({'message':'Authentication successful'}))
            response.set_cookie('token',token)
            return response, 200
    return jsonify({'error':'Invalid username or password'}), 401

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            return jsonify({'error':'Authorization token is missing'}),401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'],algorithms=["HS256"])
            current_user_id = data['user_id']
        except DecodeError:
            return jsonify({'error':'Authorization token is invalid'}),401
        return f(current_user_id,*args, **kwargs)
    return decorated

BASE_URL = "https://dummyjson.com"
@app.route('/products', methods=['GET'])
@token_required
def get_products(current_user_id):
    headers = {'Authorization':f'Bearer {request.cookies.get("token")}'}
    response = requests.get(f"{BASE_URL}/products",headers=headers)
    if response.status_code != 200:
        return jsonify({'error': response.json()['message']}),response.status_code
    products = []
    for product in response.json()['products']:
        brand ='N/A'
        if 'brand' in product:
            brand = product['brand']
            
        product_data = {
            'id': product['id'],
            'title': product['title'],
            'brand': brand,
            'price':product['price'],
            'description': product['description']
        }
        products.append(product_data)
    
    return jsonify({'data':products}), 200 if products else 204
    
    


if __name__ == "__main__":
    app.run(debug=True,host="0.0.0.0", port=port)