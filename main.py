from flask import Flask
from flask_pymongo import PyMongo
from bson.json_util import dumps
from bson.objectid import ObjectId
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
from flask_bcrypt import Bcrypt 
import json
import datetime
import hashlib
import urllib

app = Flask(__name__)
jwt = JWTManager(app)
bcrypt = Bcrypt(app) 
app.config["MONGO_URI"] = ""
app.config['JWT_SECRET_KEY'] = '38dd56f56d405e02ec0ba4be4607eaab'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=1)
mongo = PyMongo(app)

# Auth Routes
@app.route("/", methods=["GET"])
def healthCheck():
    return jsonify({
        "message": "Application is healthy"
    }), 200
    
@app.route("/auth/signup", methods=["POST"])
def signUp():
    reqBody = request.get_json()
    user = mongo.db.users.find_one({"email": reqBody["email"]})
    if not user:
        hashedPassword = bcrypt.generate_password_hash(reqBody["password"]).decode('utf-8')
        mongo.db.users.insert_one({
            "email": reqBody["email"],
            "password": hashedPassword,
            "role": "user",
            "username": reqBody["username"]
        })
        return jsonify({"message": "User created successfully"}), 201
    else:
        return jsonify({"message": "User already exists"}), 409
    
@app.route("/auth/signin", methods=["POST"])
def signIn():
    reqBody = request.get_json()
    user = mongo.db.users.find_one({"email": reqBody["email"]})
    if user:
        isValidPassword = bcrypt.check_password_hash(user['password'], reqBody["password"])
        if isValidPassword:
            accessToken = create_access_token(identity=user["email"])
            return jsonify(access_token=accessToken), 200
    return jsonify({"message": "Incorrect email or password"}), 409

# books route
@app.route("/books", methods=["POST"])
@jwt_required()
def postBook():
    currentUser = get_jwt_identity();
    user = mongo.db.users.find_one({"email": currentUser})
    if user:
        reqBody = request.get_json()
        mongo.db.books.insert_one({
        "email": user["email"],
        "title": reqBody["title"],
        "author": reqBody["author"],
        "genre": reqBody["genre"],
        "year": reqBody["year"],
        "user_id": user["_id"]
        })
        return jsonify({"message": "Book posted successfully"}), 201
    return jsonify({"message": "Unauthorized access"}), 401

@app.route("/books", methods=["GET"])
@jwt_required()
def getBooks():
    searchParams = []
    author = request.args.get('author')
    if(author):
        searchParams.append({
            'author': author
        })
    title = request.args.get('title')
    if(title):
        searchParams.append({
            'title': title
        })
    genre = request.args.get('genre')
    if(genre):
        searchParams.append({
            'genre': genre
        })
    year = request.args.get('year')
    if(year):
        searchParams.append({
            'year': year
        })
    currentUser = get_jwt_identity();
    user = mongo.db.users.find_one({"email": currentUser})
    if user:
        if len(searchParams) > 0:
            books = mongo.db.books.find({"$and": searchParams})
        else:
            books = mongo.db.books.find()
        return json.loads(dumps(books)), 200
    return jsonify({"message": "Unauthorized access"}), 401

@app.route("/books/<string:book_id>/reviews", methods=["POST"])
@jwt_required()
def postReviews(book_id):
    try:
        currentUser = get_jwt_identity();
        user = mongo.db.users.find_one({"email": currentUser})
        if user:
            book = mongo.db.books.find({"_id": ObjectId(book_id)})
            if len(list(book)) == 1:
                reqBody = request.get_json()
                mongo.db.reviews.insert_one({
                    "rating": reqBody["rating"],
                    "text": reqBody["text"],
                    "book_id": ObjectId(book_id),
                    "user_id": user["_id"]
                })
                return jsonify({"message" : "Review posted successfully"}), 201
            else: 
                return jsonify({"message" : "Data not found"}), 404
        return jsonify({"message": "Unauthorized access"}), 401
    except Exception:
        return jsonify({"Internal server error"})
    
@app.route("/books/<string:book_id>/reviews", methods=["GET"])
@jwt_required()
def getReviews(book_id):
    try:
        currentUser = get_jwt_identity();
        user = mongo.db.users.find_one({"email": currentUser})
        if user:
            book = mongo.db.books.find({"_id": ObjectId(book_id)})
            if len(list(book)) > 0:
                reviews = mongo.db.reviews.find({"book_id": ObjectId(book_id)})
                return json.loads(dumps(reviews)), 200
            else: 
                return jsonify({"message" : "Data not found"}), 404
        return jsonify({"message": "Unauthorized access"}), 401
    except Exception:
        return jsonify({"Internal server error"})
    
@app.route("/books/<string:book_id>/reviews/<string:review_id>", methods=["PATCH", "DELETE"])
@jwt_required()
def updateReview(book_id, review_id):
    if request.method == 'PATCH':
        try:
            currentUser = get_jwt_identity();
            user = mongo.db.users.find_one({"email": currentUser})
            if user:
                book = mongo.db.books.find({"_id": ObjectId(book_id)})
                if len(list(book)) == 1:
                    if user["role"] == "user":
                        reviews = mongo.db.reviews.find({"book_id": ObjectId(book_id), "_id": ObjectId(review_id), "user_id": user['_id']})
                        if len(list(reviews)) == 1:
                            reqBody = request.get_json()
                            mongo.db.reviews.update_one({"_id": ObjectId(review_id)}, { '$set': {
                                "rating": reqBody["rating"],
                                "text": reqBody["text"]
                            }})
                            return jsonify({"message": "Review updated successfully"}), 200
                        else:
                            return jsonify({"message" : "Data not found"}), 404 
                    elif user["role"] == "admin":
                        reviews = mongo.db.reviews.find({"book_id": ObjectId(book_id), "_id": ObjectId(review_id)})
                        if len(list(reviews)) == 1:
                            reqBody = request.get_json()
                            mongo.db.reviews.update_one({"_id": ObjectId(review_id)}, { '$set': {
                                "rating": reqBody["rating"],
                                "text": reqBody["text"]
                            }})
                            return jsonify({"message": "Review updated successfully"}), 200
                        else:
                            return jsonify({"message" : "Data not found"}), 404 
                    else:
                        return jsonify({"message" : "Unauthorized access"}), 401 
                else: 
                    return jsonify({"message" : "Data not found"}), 404
            return jsonify({"message": "Unauthorized access"}), 401
        except Exception:
            return jsonify({"Internal server error"})
    if request.method == 'DELETE':
        try:
            currentUser = get_jwt_identity();
            user = mongo.db.users.find_one({"email": currentUser})
            if user:
                if user['role'] == "user":
                    book = mongo.db.books.find({"_id": ObjectId(book_id)})
                    if len(list(book)) == 1:
                        reviews = mongo.db.reviews.find({"book_id": ObjectId(book_id), "_id": ObjectId(review_id), "user_id": user['_id']})
                        if len(list(reviews)) == 1:
                            mongo.db.reviews.delete_one({"_id": ObjectId(review_id)})
                            return jsonify({"message": "Review deleted successfully"}), 200
                        else:
                            return jsonify({"message" : "Data not found"}), 404 
                    else: 
                        return jsonify({"message" : "Data not found"}), 404
                elif user['role'] == "admin":
                    book = mongo.db.books.find({"_id": ObjectId(book_id)})
                    if len(list(book)) == 1:
                        reviews = mongo.db.reviews.find({"book_id": ObjectId(book_id), "_id": ObjectId(review_id)})
                        if len(list(reviews)) == 1:
                            mongo.db.reviews.delete_one({"_id": ObjectId(review_id)})
                            return jsonify({"message": "Review deleted successfully"}), 200
                        else:
                            return jsonify({"message" : "Data not found"}), 404 
                    else: 
                        return jsonify({"message" : "Data not found"}), 404
                else:
                    return jsonify({"message": "Unauthorized access"}), 401
            return jsonify({"message": "Unauthorized access"}), 401
        except Exception:
            return jsonify({"Internal server error"})

@app.route("/books/<string:book_id>/reviews/<string:review_id>/comments", methods=["POST"])
@jwt_required()
def postComments(book_id, review_id):
    try:
        currentUser = get_jwt_identity();
        user = mongo.db.users.find_one({"email": currentUser})
        if user:
            book = mongo.db.books.find({"_id": ObjectId(book_id)})
            if len(list(book)) == 1:
                review = mongo.db.reviews.find({"_id": ObjectId(review_id)})
                if len(list(review)) == 1:
                    reqBody = request.get_json()
                    mongo.db.comments.insert_one({
                        "review_id": ObjectId(review_id),
                        "user_id": user["_id"],
                        "text": reqBody["text"]  
                    })
                else:
                    return jsonify({"message" : "Data not found"}), 404
                return jsonify({"message" : "Comment posted successfully"}), 201
            else: 
                return jsonify({"message" : "Data not found"}), 404
        return jsonify({"message": "Unauthorized access"}), 401
    except Exception:
        return jsonify({"Internal server error"})
        
@app.route("/books/<string:book_id>/reviews/<string:review_id>/comments", methods=["GET"])
@jwt_required()
def getComments(book_id, review_id):
    try:
        currentUser = get_jwt_identity();
        user = mongo.db.users.find_one({"email": currentUser})
        if user:
            book = mongo.db.books.find({"_id": ObjectId(book_id)})
            if len(list(book)) == 1:
                review = mongo.db.reviews.find({"_id": ObjectId(review_id)})
                if len(list(review)) == 1:
                    comments = mongo.db.comments.find({"review_id": ObjectId(review_id), "user_id": ObjectId(user["_id"])})
                    return json.loads(dumps(comments)), 200
                else:
                    return jsonify({"message" : "Data not found"}), 404
            else: 
                return jsonify({"message" : "Data not found"}), 404
        return jsonify({"message": "Unauthorized access"}), 401
    except Exception:
        return jsonify({"Internal server error"})
    
@app.route("/books/<string:book_id>/reviews/<string:review_id>/comments/<string:comment_id>", methods=["PATCH", "DELETE"])
@jwt_required()
def updateComment(book_id, review_id, comment_id):
    if request.method == 'PATCH':
        try:
            currentUser = get_jwt_identity();
            user = mongo.db.users.find_one({"email": currentUser})
            if user:
                book = mongo.db.books.find({"_id": ObjectId(book_id)})
                if len(list(book)) == 1:
                    if user["role"] == "user":
                        reviews = mongo.db.reviews.find({"book_id": ObjectId(book_id), "_id": ObjectId(review_id)})
                        if len(list(reviews)) == 1:
                            comment = mongo.db.comments.find({"_id": ObjectId(comment_id), "user_id": user['_id']})
                            if comment:
                                reqBody = request.get_json()
                                mongo.db.comments.update_one({"_id": ObjectId(comment_id)}, { '$set': {
                                    "text": reqBody["text"]
                                }})
                            return jsonify({"message": "Comment updated successfully"}), 200
                        else:
                            return jsonify({"message" : "Data not found"}), 404 
                    elif user["role"] == "admin":
                        reviews = mongo.db.reviews.find({"book_id": ObjectId(book_id), "_id": ObjectId(review_id)})
                        if len(list(reviews)) == 1:
                            comment = mongo.db.comments.find({"_id": ObjectId(comment_id)})
                            if comment:
                                reqBody = request.get_json()
                                mongo.db.comments.update_one({"_id": ObjectId(comment_id)}, { '$set': {
                                    "text": reqBody["text"]
                                }})
                            return jsonify({"message": "Review updated successfully"}), 200
                        else:
                            return jsonify({"message" : "Data not found"}), 404 
                    else:
                        return jsonify({"message" : "Unauthorized access"}), 401 
                else: 
                    return jsonify({"message" : "Data not found"}), 404
            return jsonify({"message": "Unauthorized access"}), 401
        except Exception:
            return jsonify({"Internal server error"})
    if request.method == 'DELETE':
        try:
            currentUser = get_jwt_identity();
            user = mongo.db.users.find_one({"email": currentUser})
            if user:
                if user['role'] == "user":
                    book = mongo.db.books.find({"_id": ObjectId(book_id)})
                    if len(list(book)) == 1:
                        reviews = mongo.db.reviews.find({"book_id": ObjectId(book_id), "_id": ObjectId(review_id)})
                        if len(list(reviews)) == 1:
                            comment = mongo.db.comments.find({"_id": ObjectId(comment_id), "user_id": user['_id']})
                            if comment:
                                mongo.db.comments.delete_one({"_id": ObjectId(comment_id)})
                                return jsonify({"message": "Comment deleted successfully"}), 200
                        else:
                            return jsonify({"message" : "Data not found"}), 404 
                    else: 
                        return jsonify({"message" : "Data not found"}), 404
            return jsonify({"message": "Unauthorized access"}), 401
        except Exception:
            return jsonify({"Internal server error"})
