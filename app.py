from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from bson import ObjectId
from flask_cors import CORS
import datetime

app = Flask(__name__)
@app.before_request
def log_request_info():
    print("➡️ Method:", request.method)
    print("➡️ Path:", request.path)
    print("➡️ Headers:", dict(request.headers))
    
CORS(app, resources={r"/*": {"origins": [
    "http://localhost:3000",
    "https://eco-finds-sigma.vercel.app"
]}}, supports_credentials=True)

app.config["MONGO_URI"] = "mongodb+srv://sonukumarm_db_user:Asdf%401234@cluster0.atgi1eg.mongodb.net/eco-finds"
app.config["JWT_SECRET_KEY"] = "300253d378818f5de098b6a67f53a0f7a015872f8f25bf80ce9189eaa80f6b4e"

# Initialize extensions
mongo = PyMongo(app)
jwt = JWTManager(app)

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================
def to_json(data):
    """Convert MongoDB documents to JSON-serializable format"""
    if isinstance(data, list):
        return [to_json(doc) for doc in data]
    if isinstance(data, dict):
        if "_id" in data:
            data["_id"] = str(data["_id"])
        return data
    return data

def validate_object_id(id_string):
    """Validate if string is a valid ObjectId"""
    try:
        ObjectId(id_string)
        return True
    except:
        return False

# =============================================================================
# AUTHENTICATION ENDPOINTS
# =============================================================================

@app.route("/auth/signup", methods=["POST"])
def signup():
    """
    Create a new user account
    Required fields: email, password
    Optional fields: username
    """
    try:
        data = request.json
        
        # Validate required fields
        if not data or not data.get("email") or not data.get("password"):
            return jsonify({"error": "Email and password are required"}), 400
        
        # Check if user already exists
        if mongo.db.User.find_one({"email": data["email"]}):
            return jsonify({"error": "User already exists"}), 400

        # Create user document
        hashed_pw = generate_password_hash(data["password"])
        user = {
            "email": data["email"],
            "passwordHash": hashed_pw,
            "username": data.get("username", ""),
            "createdAt": datetime.datetime.utcnow(),
            "updatedAt": datetime.datetime.utcnow()
        }
        
        result = mongo.db.User.insert_one(user)
        user["_id"] = str(result.inserted_id)
        
        return jsonify({
            "message": "User created successfully",
            "userId": str(result.inserted_id)
        }), 201
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/auth/login", methods=["POST"])
def login():
    """
    Authenticate user and return JWT token
    Required fields: email, password
    """
    try:
        data = request.json
        
        if not data or not data.get("email") or not data.get("password"):
            return jsonify({"error": "Email and password are required"}), 400

        # Find user by email
        user = mongo.db.User.find_one({"email": data["email"]})
        if not user:
            return jsonify({"error": "Invalid credentials"}), 401

        # Verify password
        if not check_password_hash(user["passwordHash"], data["password"]):
            return jsonify({"error": "Invalid credentials"}), 401

        # Create JWT token
        token = create_access_token(identity=str(user["_id"]))
        
        return jsonify({
            "token": token,
            "user": {
                "id": str(user["_id"]),
                "email": user["email"],
                "username": user.get("username", "")
            }
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/auth/me", methods=["GET", "PUT"])
@jwt_required()
def me():
    """
    GET: Get current user profile
    PUT: Update current user profile
    """
    try:
        user_id = get_jwt_identity()
        
        if not validate_object_id(user_id):
            return jsonify({"error": "Invalid user ID"}), 400
            
        user = mongo.db.User.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"error": "User not found"}), 404

        if request.method == "GET":
            # Return user profile (exclude password)
            user_data = to_json(user)
            user_data.pop("passwordHash", None)
            return jsonify(user_data), 200

        elif request.method == "PUT":
            # Update user profile
            data = request.json
            update_data = {}
            
            # Allow updating specific fields only
            allowed_fields = ["username", "email"]
            for field in allowed_fields:
                if field in data:
                    update_data[field] = data[field]
            
            if update_data:
                update_data["updatedAt"] = datetime.datetime.utcnow()
                mongo.db.User.update_one(
                    {"_id": ObjectId(user_id)}, 
                    {"$set": update_data}
                )
            
            return jsonify({"message": "Profile updated successfully"}), 200
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =============================================================================
# CATEGORY ENDPOINTS (Full CRUD)
# =============================================================================

@app.route("/categories", methods=["GET", "POST"])
def categories():
    """
    GET: Get all categories
    POST: Create new category (requires authentication)
    """
    try:
        if request.method == "GET":
            # Get all categories
            categories = list(mongo.db.Category.find())
            return jsonify(to_json(categories)), 200

        elif request.method == "POST":
            # Create new category (admin only ideally, but allowing for now)
            data = request.json
            
            if not data or not data.get("name"):
                return jsonify({"error": "Category name is required"}), 400
            
            # Check if category already exists
            if mongo.db.Category.find_one({"name": data["name"]}):
                return jsonify({"error": "Category already exists"}), 400
            
            category = {
                "name": data["name"],
                "description": data.get("description", ""),
                "createdAt": datetime.datetime.utcnow(),
                "updatedAt": datetime.datetime.utcnow()
            }
            
            result = mongo.db.Category.insert_one(category)
            category["_id"] = str(result.inserted_id)
            
            return jsonify({
                "message": "Category created successfully",
                "category": to_json(category)
            }), 201
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/categories/<category_id>", methods=["GET", "PUT", "DELETE"])
def category_detail(category_id):
    """
    GET: Get specific category
    PUT: Update category
    DELETE: Delete category
    """
    try:
        if not validate_object_id(category_id):
            return jsonify({"error": "Invalid category ID"}), 400

        category = mongo.db.Category.find_one({"_id": ObjectId(category_id)})
        if not category:
            return jsonify({"error": "Category not found"}), 404

        if request.method == "GET":
            return jsonify(to_json(category)), 200

        elif request.method == "PUT":
            data = request.json
            update_data = {}
            
            allowed_fields = ["name", "description"]
            for field in allowed_fields:
                if field in data:
                    update_data[field] = data[field]
            
            if update_data:
                update_data["updatedAt"] = datetime.datetime.utcnow()
                mongo.db.Category.update_one(
                    {"_id": ObjectId(category_id)}, 
                    {"$set": update_data}
                )
            
            return jsonify({"message": "Category updated successfully"}), 200

        elif request.method == "DELETE":
            # Check if category has listings
            listing_count = mongo.db.Listing.count_documents({"categoryId": category_id})
            if listing_count > 0:
                return jsonify({"error": "Cannot delete category with existing listings"}), 400
            
            mongo.db.Category.delete_one({"_id": ObjectId(category_id)})
            return jsonify({"message": "Category deleted successfully"}), 200
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =============================================================================
# LISTING ENDPOINTS (Full CRUD)
# =============================================================================

@app.route("/listings", methods=["GET", "POST"])
@jwt_required(optional=True)
def listings():
    """
    GET: Get all listings with optional search and filtering
    POST: Create new listing (requires authentication)
    """
    try:
        if request.method == "GET":
            # Build query based on parameters
            query = {}
            
            # Search by title
            search = request.args.get("search")
            if search:
                query["title"] = {"$regex": search, "$options": "i"}
            
            # Filter by category
            category = request.args.get("category")
            if category:
                query["categoryId"] = category
            
            # Filter by price range
            min_price = request.args.get("min_price")
            max_price = request.args.get("max_price")
            if min_price or max_price:
                query["price"] = {}
                if min_price:
                    query["price"]["$gte"] = float(min_price)
                if max_price:
                    query["price"]["$lte"] = float(max_price)
            
            # Pagination
            page = int(request.args.get("page", 1))
            limit = int(request.args.get("limit", 10))
            skip = (page - 1) * limit
            
            # Get listings with pagination
            listings = list(mongo.db.Listing.find(query).skip(skip).limit(limit).sort("createdAt", -1))
            total = mongo.db.Listing.count_documents(query)
            
            return jsonify({
                "listings": to_json(listings),
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": total,
                    "pages": (total + limit - 1) // limit
                }
            }), 200

        elif request.method == "POST":
            # Create new listing (requires authentication)
            user_id = get_jwt_identity()
            if not user_id:
                return jsonify({"error": "Authentication required"}), 401
            
            data = request.json
            
            # Validate required fields
            required_fields = ["title", "description", "price", "categoryId"]
            for field in required_fields:
                if not data or not data.get(field):
                    return jsonify({"error": f"{field} is required"}), 400
            
            # Validate category exists
            if not validate_object_id(data["categoryId"]):
                return jsonify({"error": "Invalid category ID"}), 400
                
            category = mongo.db.Category.find_one({"_id": ObjectId(data["categoryId"])})
            if not category:
                return jsonify({"error": "Category not found"}), 400
            
            listing = {
                "title": data["title"],
                "description": data["description"],
                "price": float(data["price"]),
                "imageUrl": data.get("imageUrl", ""),
                "categoryId": data["categoryId"],
                "sellerId": user_id,
                "status": "active",  # active, sold, inactive
                "createdAt": datetime.datetime.utcnow(),
                "updatedAt": datetime.datetime.utcnow()
            }
            
            result = mongo.db.Listing.insert_one(listing)
            listing["_id"] = str(result.inserted_id)
            
            return jsonify({
                "message": "Listing created successfully",
                "listing": to_json(listing)
            }), 201
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/listings/<listing_id>", methods=["GET", "PUT", "DELETE"])
@jwt_required(optional=True)
def listing_detail(listing_id):
    """
    GET: Get specific listing
    PUT: Update listing (owner only)
    DELETE: Delete listing (owner only)
    """
    try:
        if not validate_object_id(listing_id):
            return jsonify({"error": "Invalid listing ID"}), 400

        listing = mongo.db.Listing.find_one({"_id": ObjectId(listing_id)})
        if not listing:
            return jsonify({"error": "Listing not found"}), 404

        if request.method == "GET":
            return jsonify(to_json(listing)), 200

        # For PUT and DELETE, check ownership
        user_id = get_jwt_identity()
        if not user_id or user_id != listing["sellerId"]:
            return jsonify({"error": "Access denied"}), 403

        if request.method == "PUT":
            data = request.json
            update_data = {}
            
            allowed_fields = ["title", "description", "price", "imageUrl", "categoryId", "status"]
            for field in allowed_fields:
                if field in data:
                    if field == "categoryId" and data[field]:
                        # Validate category exists
                        if not validate_object_id(data[field]):
                            return jsonify({"error": "Invalid category ID"}), 400
                        category = mongo.db.Category.find_one({"_id": ObjectId(data[field])})
                        if not category:
                            return jsonify({"error": "Category not found"}), 400
                    update_data[field] = data[field]
            
            if update_data:
                update_data["updatedAt"] = datetime.datetime.utcnow()
                mongo.db.Listing.update_one(
                    {"_id": ObjectId(listing_id)}, 
                    {"$set": update_data}
                )
            
            return jsonify({"message": "Listing updated successfully"}), 200

        elif request.method == "DELETE":
            # Remove from all carts first
            mongo.db.CartItem.delete_many({"listingId": listing_id})
            
            # Delete the listing
            mongo.db.Listing.delete_one({"_id": ObjectId(listing_id)})
            
            return jsonify({"message": "Listing deleted successfully"}), 200
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/users/<user_id>/listings", methods=["GET"])
def user_listings(user_id):
    """Get all listings by a specific user"""
    try:
        if not validate_object_id(user_id):
            return jsonify({"error": "Invalid user ID"}), 400
            
        # Check if user exists
        user = mongo.db.User.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        listings = list(mongo.db.Listing.find({"sellerId": user_id}))
        return jsonify(to_json(listings)), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/auth/me/listings", methods=["GET"])
@jwt_required()
def my_listings():
    """Get current user's listings"""
    try:
        user_id = get_jwt_identity()
        listings = list(mongo.db.Listing.find({"sellerId": user_id}))
        return jsonify(to_json(listings)), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =============================================================================
# CART ENDPOINTS (Full CRUD)
# =============================================================================

@app.route("/auth/cart", methods=["GET", "POST", "DELETE"])
@jwt_required()
def cart():
    """
    GET: Get user's cart items
    POST: Add item to cart
    DELETE: Clear entire cart
    """
    try:
        user_id = get_jwt_identity()

        if request.method == "GET":
            # Get cart items with listing details
            pipeline = [
                {"$match": {"userId": user_id}},
                {
                    "$lookup": {
                        "from": "Listing",
                        "localField": "listingId",
                        "foreignField": "_id",
                        "as": "listing"
                    }
                },
                {"$unwind": "$listing"}
            ]
            
            cart_items = list(mongo.db.CartItem.aggregate(pipeline))
            return jsonify(to_json(cart_items)), 200

        elif request.method == "POST":
            data = request.json
            
            if not data or not data.get("listingId") or not data.get("qty"):
                return jsonify({"error": "listingId and qty are required"}), 400
            
            # Validate listing exists
            if not validate_object_id(data["listingId"]):
                return jsonify({"error": "Invalid listing ID"}), 400
                
            listing = mongo.db.Listing.find_one({"_id": ObjectId(data["listingId"])})
            if not listing:
                return jsonify({"error": "Listing not found"}), 404
            
            if listing["status"] != "active":
                return jsonify({"error": "Listing is not available"}), 400
            
            # Check if item already in cart
            existing_item = mongo.db.CartItem.find_one({
                "userId": user_id,
                "listingId": data["listingId"]
            })
            
            if existing_item:
                # Update quantity
                new_qty = existing_item["qty"] + int(data["qty"])
                mongo.db.CartItem.update_one(
                    {"_id": existing_item["_id"]},
                    {"$set": {"qty": new_qty, "updatedAt": datetime.datetime.utcnow()}}
                )
            else:
                # Add new item
                cart_item = {
                    "userId": user_id,
                    "listingId": data["listingId"],
                    "qty": int(data["qty"]),
                    "createdAt": datetime.datetime.utcnow(),
                    "updatedAt": datetime.datetime.utcnow()
                }
                mongo.db.CartItem.insert_one(cart_item)
            
            return jsonify({"message": "Item added to cart successfully"}), 201

        elif request.method == "DELETE":
            # Clear entire cart
            mongo.db.CartItem.delete_many({"userId": user_id})
            return jsonify({"message": "Cart cleared successfully"}), 200
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/auth/cart/<item_id>", methods=["PUT", "DELETE"])
@jwt_required()
def cart_item(item_id):
    """
    PUT: Update cart item quantity
    DELETE: Remove specific item from cart
    """
    try:
        user_id = get_jwt_identity()
        
        if not validate_object_id(item_id):
            return jsonify({"error": "Invalid item ID"}), 400

        cart_item = mongo.db.CartItem.find_one({
            "_id": ObjectId(item_id),
            "userId": user_id
        })
        
        if not cart_item:
            return jsonify({"error": "Cart item not found"}), 404

        if request.method == "PUT":
            data = request.json
            
            if not data or "qty" not in data:
                return jsonify({"error": "qty is required"}), 400
            
            new_qty = int(data["qty"])
            if new_qty <= 0:
                return jsonify({"error": "Quantity must be greater than 0"}), 400
            
            mongo.db.CartItem.update_one(
                {"_id": ObjectId(item_id)},
                {"$set": {"qty": new_qty, "updatedAt": datetime.datetime.utcnow()}}
            )
            
            return jsonify({"message": "Cart item updated successfully"}), 200

        elif request.method == "DELETE":
            mongo.db.CartItem.delete_one({"_id": ObjectId(item_id)})
            return jsonify({"message": "Cart item removed successfully"}), 200
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =============================================================================
# ORDER ENDPOINTS (Full CRUD)
# =============================================================================

@app.route("/auth/checkout", methods=["POST"])
@jwt_required()
def checkout():
    """Process checkout and create order"""
    try:
        user_id = get_jwt_identity()
        
        # Get cart items
        cart_items = list(mongo.db.CartItem.find({"userId": user_id}))
        if not cart_items:
            return jsonify({"error": "Cart is empty"}), 400

        # Calculate total and prepare order items
        total = 0
        order_items = []
        
        for item in cart_items:
            listing = mongo.db.Listing.find_one({"_id": ObjectId(item["listingId"])})
            if listing and listing["status"] == "active":
                price = listing["price"]
                subtotal = price * item["qty"]
                total += subtotal
                
                order_items.append({
                    "listingId": str(listing["_id"]),
                    "title": listing["title"],
                    "priceAtPurchase": price,
                    "qty": item["qty"],
                    "subtotal": subtotal
                })

        if not order_items:
            return jsonify({"error": "No valid items in cart"}), 400

        # Create order
        order = {
            "userId": user_id,
            "total": total,
            "status": "pending",  # pending, confirmed, shipped, delivered, cancelled
            "createdAt": datetime.datetime.utcnow(),
            "updatedAt": datetime.datetime.utcnow()
        }
        
        order_result = mongo.db.Order.insert_one(order)
        order_id = str(order_result.inserted_id)

        # Create order items
        for oi in order_items:
            oi["orderId"] = order_id
            oi["createdAt"] = datetime.datetime.utcnow()
            mongo.db.OrderItem.insert_one(oi)

        # Clear cart
        mongo.db.CartItem.delete_many({"userId": user_id})

        return jsonify({
            "message": "Order placed successfully",
            "orderId": order_id,
            "total": total
        }), 201
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# 🟢 Get all categories
@app.route("/categories", methods=["GET"])
def get_categories():
    categories = list(mongo.db.categories.find())
    return jsonify([to_json(c) for c in categories])

# 🟢 Get all listings
@app.route("/listings", methods=["GET"])
def get_listings():
    listings = list(mongo.db.listings.find())
    return jsonify([to_json(l) for l in listings])

# 🟢 Get listings by categoryId
@app.route("/listings/<category_id>", methods=["GET"])
def get_listings_by_category(category_id):
    listings = list(mongo.db.listings.find({"categoryId": ObjectId(category_id)}))
    return jsonify([to_json(l) for l in listings])


@app.route("/auth/orders", methods=["GET"])
@jwt_required()
def orders():
    """Get user's orders"""
    try:
        user_id = get_jwt_identity()
        
        # Get orders with items
        pipeline = [
            {"$match": {"userId": user_id}},
            {
                "$lookup": {
                    "from": "OrderItem",
                    "localField": "_id",
                    "foreignField": "orderId",
                    "as": "items"
                }
            },
            {"$sort": {"createdAt": -1}}
        ]
        
        orders = list(mongo.db.Order.aggregate(pipeline))
        return jsonify(to_json(orders)), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/auth/orders/<order_id>", methods=["GET", "PUT"])
@jwt_required()
def order_detail(order_id):
    """
    GET: Get specific order details
    PUT: Update order status (limited updates allowed)
    """
    try:
        user_id = get_jwt_identity()
        
        if not validate_object_id(order_id):
            return jsonify({"error": "Invalid order ID"}), 400

        order = mongo.db.Order.find_one({
            "_id": ObjectId(order_id),
            "userId": user_id
        })
        
        if not order:
            return jsonify({"error": "Order not found"}), 404

        if request.method == "GET":
            # Get order with items
            order_items = list(mongo.db.OrderItem.find({"orderId": order_id}))
            order["items"] = order_items
            return jsonify(to_json(order)), 200

        elif request.method == "PUT":
            data = request.json
            
            # Only allow status updates to "cancelled" if order is pending
            if data.get("status") == "cancelled" and order["status"] == "pending":
                mongo.db.Order.update_one(
                    {"_id": ObjectId(order_id)},
                    {"$set": {
                        "status": "cancelled",
                        "updatedAt": datetime.datetime.utcnow()
                    }}
                )
                return jsonify({"message": "Order cancelled successfully"}), 200
            else:
                return jsonify({"error": "Invalid status update"}), 400
                
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =============================================================================
# USER MANAGEMENT ENDPOINTS
# =============================================================================

@app.route("/users", methods=["GET"])
def get_users():
    """Get all users (admin endpoint - should be protected in production)"""
    try:
        users = list(mongo.db.User.find({}, {"passwordHash": 0}))  # Exclude passwords
        return jsonify(to_json(users)), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/users/<user_id>", methods=["GET"])
def get_user(user_id):
    """Get specific user profile"""
    try:
        if not validate_object_id(user_id):
            return jsonify({"error": "Invalid user ID"}), 400
            
        user = mongo.db.User.find_one(
            {"_id": ObjectId(user_id)}, 
            {"passwordHash": 0}  # Exclude password
        )
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        return jsonify(to_json(user)), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =============================================================================
# SEED DATA ENDPOINT
# =============================================================================

@app.route("/seed", methods=["POST"])
def seed_data():
    """Seed database with initial data"""
    try:
        # Clear existing data
        mongo.db.Category.delete_many({})
        mongo.db.Listing.delete_many({})
        
        # Seed categories
        categories = [
            {
                "name": "Washing Machine",
                "description": "Energy-efficient washing machines for eco-friendly cleaning",
                "createdAt": datetime.datetime.utcnow(),
                "updatedAt": datetime.datetime.utcnow()
            },
            {
                "name": "Refrigerator",
                "description": "Eco-friendly refrigerators with energy-saving features",
                "createdAt": datetime.datetime.utcnow(),
                "updatedAt": datetime.datetime.utcnow()
            },
            {
                "name": "Microwave",
                "description": "Efficient microwave ovens for modern kitchens",
                "createdAt": datetime.datetime.utcnow(),
                "updatedAt": datetime.datetime.utcnow()
            },
            {
                "name": "Dishwasher",
                "description": "Water-saving dishwashers for sustainable living",
                "createdAt": datetime.datetime.utcnow(),
                "updatedAt": datetime.datetime.utcnow()
            }
        ]
        
        category_result = mongo.db.Category.insert_many(categories)
        
        # Get inserted category IDs
        cat_docs = list(mongo.db.Category.find())
        washing_machine_id = str(cat_docs[0]["_id"])
        refrigerator_id = str(cat_docs[1]["_id"])
        microwave_id = str(cat_docs[2]["_id"])
        dishwasher_id = str(cat_docs[3]["_id"])

        # Seed listings
        listings = [
            {
                "title": "Eco-Friendly Front Load Washing Machine",
                "description": "Energy efficient A+++ rated washing machine with 7kg capacity. Perfect for eco-conscious households.",
                "price": 450.00,
                "imageUrl": "https://example.com/washing-machine-1.jpg",
                "categoryId": washing_machine_id,
                "sellerId": None,  # No seller for seed data
                "status": "active",
                "createdAt": datetime.datetime.utcnow(),
                "updatedAt": datetime.datetime.utcnow()
            },
            {
                "title": "Smart Energy-Star Refrigerator",
                "description": "25 cu ft smart refrigerator with energy-saving features and WiFi connectivity.",
                "price": 800.00,
                "imageUrl": "https://example.com/refrigerator-1.jpg",
                "categoryId": refrigerator_id,
                "sellerId": None,
                "status": "active",
                "createdAt": datetime.datetime.utcnow(),
                "updatedAt": datetime.datetime.utcnow()
            },
            {
                "title": "Compact Countertop Microwave",
                "description": "Space-saving microwave with eco-mode and sensor cooking technology.",
                "price": 120.00,
                "imageUrl": "https://example.com/microwave-1.jpg",
                "categoryId": microwave_id,
                "sellerId": None,
                "status": "active",
                "createdAt": datetime.datetime.utcnow(),
                "updatedAt": datetime.datetime.utcnow()
            },
            {
                "title": "Water-Efficient Built-in Dishwasher",
                "description": "Quiet operation dishwasher that uses 40% less water than standard models.",
                "price": 350.00,
                "imageUrl": "https://example.com/dishwasher-1.jpg",
                "categoryId": dishwasher_id,
                "sellerId": None,
                "status": "active",
                "createdAt": datetime.datetime.utcnow(),
                "updatedAt": datetime.datetime.utcnow()
            }
        ]
        
        mongo.db.Listing.insert_many(listings)

        return jsonify({
            "message": "Database seeded successfully!",
            "categories_created": len(categories),
            "listings_created": len(listings)
        }), 201
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =============================================================================
# STATISTICS/ANALYTICS ENDPOINTS
# =============================================================================

@app.route("/stats", methods=["GET"])
def get_stats():
    """Get general platform statistics"""
    try:
        stats = {
            "total_users": mongo.db.User.count_documents({}),
            "total_listings": mongo.db.Listing.count_documents({}),
            "active_listings": mongo.db.Listing.count_documents({"status": "active"}),
            "total_categories": mongo.db.Category.count_documents({}),
            "total_orders": mongo.db.Order.count_documents({}),
            "pending_orders": mongo.db.Order.count_documents({"status": "pending"})
        }
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/auth/stats", methods=["GET"])
@jwt_required()
def get_user_stats():
    """Get user-specific statistics"""
    try:
        user_id = get_jwt_identity()
        
        stats = {
            "my_listings": mongo.db.Listing.count_documents({"sellerId": user_id}),
            "active_listings": mongo.db.Listing.count_documents({"sellerId": user_id, "status": "active"}),
            "my_orders": mongo.db.Order.count_documents({"userId": user_id}),
            "cart_items": mongo.db.CartItem.count_documents({"userId": user_id}),
            "total_spent": 0  # Calculate total from completed orders
        }
        
        # Calculate total spent
        completed_orders = list(mongo.db.Order.find({
            "userId": user_id, 
            "status": {"$in": ["delivered", "confirmed"]}
        }))
        stats["total_spent"] = sum(order["total"] for order in completed_orders)
        
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =============================================================================
# SEARCH AND FILTERING ENDPOINTS
# =============================================================================

@app.route("/search", methods=["GET"])
def search():
    """Advanced search across listings"""
    try:
        query = {}
        
        # Text search
        search_term = request.args.get("q")
        if search_term:
            query["$or"] = [
                {"title": {"$regex": search_term, "$options": "i"}},
                {"description": {"$regex": search_term, "$options": "i"}}
            ]
        
        # Category filter
        category = request.args.get("category")
        if category:
            query["categoryId"] = category
        
        # Price range
        min_price = request.args.get("min_price")
        max_price = request.args.get("max_price")
        if min_price or max_price:
            query["price"] = {}
            if min_price:
                query["price"]["$gte"] = float(min_price)
            if max_price:
                query["price"]["$lte"] = float(max_price)
        
        # Status filter (default to active only)
        status = request.args.get("status", "active")
        if status:
            query["status"] = status
        
        # Sorting
        sort_by = request.args.get("sort", "createdAt")
        sort_order = -1 if request.args.get("order", "desc") == "desc" else 1
        
        # Pagination
        page = int(request.args.get("page", 1))
        limit = min(int(request.args.get("limit", 10)), 50)  # Max 50 items per page
        skip = (page - 1) * limit
        
        # Execute search
        listings = list(
            mongo.db.Listing.find(query)
            .sort(sort_by, sort_order)
            .skip(skip)
            .limit(limit)
        )
        
        total = mongo.db.Listing.count_documents(query)
        
        return jsonify({
            "listings": to_json(listings),
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total,
                "pages": (total + limit - 1) // limit
            },
            "search_params": {
                "q": search_term,
                "category": category,
                "min_price": min_price,
                "max_price": max_price,
                "status": status,
                "sort": sort_by,
                "order": request.args.get("order", "desc")
            }
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =============================================================================
# WISHLIST ENDPOINTS (Bonus feature)
# =============================================================================

@app.route("/auth/wishlist", methods=["GET", "POST"])
@jwt_required()
def wishlist():
    """
    GET: Get user's wishlist
    POST: Add item to wishlist
    """
    try:
        user_id = get_jwt_identity()

        if request.method == "GET":
            # Get wishlist with listing details
            pipeline = [
                {"$match": {"userId": user_id}},
                {
                    "$lookup": {
                        "from": "Listing",
                        "localField": "listingId",
                        "foreignField": "_id",
                        "as": "listing"
                    }
                },
                {"$unwind": "$listing"}
            ]
            
            wishlist_items = list(mongo.db.Wishlist.aggregate(pipeline))
            return jsonify(to_json(wishlist_items)), 200

        elif request.method == "POST":
            data = request.json
            
            if not data or not data.get("listingId"):
                return jsonify({"error": "listingId is required"}), 400
            
            # Validate listing exists
            if not validate_object_id(data["listingId"]):
                return jsonify({"error": "Invalid listing ID"}), 400
                
            listing = mongo.db.Listing.find_one({"_id": ObjectId(data["listingId"])})
            if not listing:
                return jsonify({"error": "Listing not found"}), 404
            
            # Check if already in wishlist
            existing_item = mongo.db.Wishlist.find_one({
                "userId": user_id,
                "listingId": data["listingId"]
            })
            
            if existing_item:
                return jsonify({"error": "Item already in wishlist"}), 400
            
            # Add to wishlist
            wishlist_item = {
                "userId": user_id,
                "listingId": data["listingId"],
                "createdAt": datetime.datetime.utcnow()
            }
            
            mongo.db.Wishlist.insert_one(wishlist_item)
            return jsonify({"message": "Item added to wishlist successfully"}), 201
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/auth/wishlist/<listing_id>", methods=["DELETE"])
@jwt_required()
def remove_from_wishlist(listing_id):
    """Remove item from wishlist"""
    try:
        user_id = get_jwt_identity()
        
        result = mongo.db.Wishlist.delete_one({
            "userId": user_id,
            "listingId": listing_id
        })
        
        if result.deleted_count == 0:
            return jsonify({"error": "Item not found in wishlist"}), 404
        
        return jsonify({"message": "Item removed from wishlist successfully"}), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =============================================================================
# ERROR HANDLERS
# =============================================================================

@app.errorhandler(400)
def bad_request(error):
    return jsonify({"error": "Bad request"}), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({"error": "Unauthorized"}), 401

@app.errorhandler(403)
def forbidden(error):
    return jsonify({"error": "Forbidden"}), 403

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Resource not found"}), 404

@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({"error": "Internal server error"}), 500

# =============================================================================
# HEALTH CHECK ENDPOINT
# =============================================================================

@app.route("/health", methods=["GET"])
def health_check():
    """API health check endpoint"""
    try:
        # Test database connection
        mongo.db.list_collection_names()
        
        return jsonify({
            "status": "healthy",
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "version": "1.0.0"
        }), 200
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.datetime.utcnow().isoformat()
        }), 503

# =============================================================================
# API DOCUMENTATION ENDPOINT
# =============================================================================

@app.route("/", methods=["GET"])
def api_documentation():
    """API documentation and available endpoints"""
    endpoints = {
        "API Documentation": "EcoFinds REST API",
        "version": "1.0.0",
        "base_url": request.base_url,
        "endpoints": {
            "Authentication": {
                "POST /auth/signup": "Create new user account",
                "POST /auth/login": "Login user and get JWT token",
                "GET /auth/me": "Get current user profile",
                "PUT /auth/me": "Update current user profile"
            },
            "Categories": {
                "GET /categories": "Get all categories",
                "POST /categories": "Create new category",
                "GET /categories/{id}": "Get specific category",
                "PUT /categories/{id}": "Update category",
                "DELETE /categories/{id}": "Delete category"
            },
            "Listings": {
                "GET /listings": "Get all listings (with pagination and filters)",
                "POST /listings": "Create new listing (auth required)",
                "GET /listings/{id}": "Get specific listing",
                "PUT /listings/{id}": "Update listing (owner only)",
                "DELETE /listings/{id}": "Delete listing (owner only)",
                "GET /auth/me/listings": "Get current user's listings",
                "GET /users/{id}/listings": "Get specific user's listings"
            },
            "Cart": {
                "GET /auth/cart": "Get cart items",
                "POST /auth/cart": "Add item to cart",
                "PUT /auth/cart/{item_id}": "Update cart item quantity",
                "DELETE /auth/cart/{item_id}": "Remove specific cart item",
                "DELETE /auth/cart": "Clear entire cart"
            },
            "Orders": {
                "POST /auth/checkout": "Process checkout and create order",
                "GET /auth/orders": "Get user's orders",
                "GET /auth/orders/{id}": "Get specific order details",
                "PUT /auth/orders/{id}": "Update order (limited actions)"
            },
            "Search": {
                "GET /search": "Advanced search with filters and pagination"
            },
            "Wishlist": {
                "GET /auth/wishlist": "Get user's wishlist",
                "POST /auth/wishlist": "Add item to wishlist",
                "DELETE /auth/wishlist/{listing_id}": "Remove item from wishlist"
            },
            "Statistics": {
                "GET /stats": "Get platform statistics",
                "GET /auth/stats": "Get user-specific statistics"
            },
            "Admin/Utility": {
                "POST /seed": "Seed database with initial data",
                "GET /health": "API health check",
                "GET /users": "Get all users",
                "GET /users/{id}": "Get specific user profile"
            }
        },
        "authentication": {
            "type": "JWT Bearer Token",
            "header": "Authorization: Bearer <token>",
            "note": "Include JWT token in Authorization header for protected routes"
        },
        "query_parameters": {
            "listings": {
                "search": "Search term for title",
                "category": "Filter by category ID",
                "min_price": "Minimum price filter",
                "max_price": "Maximum price filter",
                "page": "Page number (default: 1)",
                "limit": "Items per page (default: 10, max: 50)"
            },
            "search": {
                "q": "Search term",
                "category": "Category ID filter",
                "min_price": "Minimum price",
                "max_price": "Maximum price",
                "status": "Listing status (default: active)",
                "sort": "Sort field (default: createdAt)",
                "order": "Sort order: asc/desc (default: desc)",
                "page": "Page number",
                "limit": "Items per page"
            }
        }
    }
    
    return jsonify(endpoints), 200

# =============================================================================
# RUN APPLICATION
# =============================================================================

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)