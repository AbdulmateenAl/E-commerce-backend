import json
import os

from flask import Flask, request, jsonify, render_template, session, make_response, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS

from dotenv import load_dotenv

import psycopg2
import jwt
from datetime import datetime, timedelta, timezone

from functools import wraps

from werkzeug.security import generate_password_hash, check_password_hash

from flask_swagger_ui import get_swaggerui_blueprint

secret_key = os.getenv("secret_key")

app = Flask(__name__)
# CORS(app, resources={r"/*": {"origins": "*"}})
CORS(app, resources={r"/*": {"origins": ["https://yourfrontend.com", "http://localhost:3000"]}})
app.config['SECRET_KEY'] = secret_key

SWAGGER_URL = '/api/docs'  # URL for exposing Swagger UI (without trailing '/')
API_URL = '/static/data/swagger.json'  # Our API url (can of course be a local resource)

# Call factory function to create our blueprint
swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,  # Swagger UI static files will be mapped to '{SWAGGER_URL}/dist/'
    API_URL,
    config={  # Swagger UI config overrides
        'app_name': "Test application"
    },
    # oauth_config={  # OAuth config. See https://github.com/swagger-api/swagger-ui#oauth2-configuration .
    #    'clientId': "your-client-id",
    #    'clientSecret': "your-client-secret-if-required",
    #    'realm': "your-realms",
    #    'appName': "your-app-name",
    #    'scopeSeparator': " ",
    #    'additionalQueryStringParams': {'test': "hello"}
    # }
)

app.register_blueprint(swaggerui_blueprint)

load_dotenv()  # Loads environment variables
user = os.getenv("user")
password = os.getenv("password")
dbname = os.getenv("dbname")
host = os.getenv("host")
port = os.getenv("port")

# Connects to my supabase database


def get_db_connection():
    return psycopg2.connect(
        dbname=dbname,
        user=user,
        password=password,
        host=host,
        port=port
    )


def validate_token(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')

        if not token:
            session.pop('logged_in', None)
            return render_template('login.html')

        try:
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            session.pop('logged_in', None)
            response = make_response(redirect(url_for('login')))
            response.set_cookie('token', '', expires=0)
            return response
        except jwt.InvalidTokenError:
            session.pop('logged_in', None)
            return redirect(url_for('login'))

        return func(*args, **kwargs)

    return decorated


# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per day", "20 per hour"],
    storage_uri="memory://"
)

@app.route('/register', methods=['GET', 'POST'])
def register_user():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            return jsonify({"message": "Missing username or password"}), 400
        
        hashed_password = generate_password_hash(password)
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute(
                """CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY, username VARCHAR(255), password VARCHAR(255) NOT NULL, role VARCHAR(255))""")
            cur.execute("""INSERT INTO users (username, password, role) VALUES (%s, %s, %s);""",
                        (username, hashed_password, "admin"))
            conn.commit()
            cur.close()
            conn.close()
            return redirect(url_for('login'))
        except Exception as e:
            return jsonify({"message": "An error occurred while creating the user", "error": str(e)}), 500


    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.content_type == 'application/json':
            response = request.get_json()
        else:
            response = request.form
        if not response:
            return jsonify({"message": "No login data provided"}), 400
        
        username = response.get("username")
        password = response.get("password")

        if not username or not password:
            return jsonify({"message": "Missing username or password"}), 400
        
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT username, password FROM users WHERE username = %s", (username,))
            db_username, db_password = cur.fetchone()
            cur.close()
            conn.close()

            if username == db_username and check_password_hash(db_password, password):
                session['logged_in'] = True
                token = jwt.encode(
                    {'user': username, 'exp': datetime.now(
                        timezone.utc) + timedelta(hours=1)},
                    app.config['SECRET_KEY'],
                    algorithm="HS256"
                )
                # If you want to set the token in a cookie
                # response = make_response(redirect(url_for("home", user=username)))
                # response.set_cookie(
                #     'token',
                #     token,
                #     httponly=True,
                #     secure=True,
                #     samesite='Strict'
                # )
                return jsonify({"message": "Login successful", "token": token}), 200
        except Exception as e:
            return jsonify({"message": "An error occurred while logging in", "error": str(e)}), 500

    return render_template('login.html')

@app.route("/", methods=["GET"])
def landing_page():
    return redirect(url_for("login"))

@app.route('/<user>', methods=['GET'])
@limiter.exempt
@validate_token
def home(user):

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
                    SELECT username from users WHERE username = %s""", (user,))
        real_user = cur.fetchone()
        cur.close()
        conn.close()

        if not real_user:
            return redirect(url_for("login"))
        print(real_user[0])
        
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("""
                SELECT name, price FROM products INNER JOIN users ON users.id = products.u_id WHERE username = %s;""", (user,))
            products = cur.fetchall()
            cur.close()
            conn.close()
        except Exception as e:
            return jsonify({"message": "An error occurred while fetching the products", "error": str(e)}),
    except Exception as e:
        return jsonify({"message": str(e)})
    return render_template('home.html', products=products, username=real_user[0])

@app.route('/auth', methods=['GET'])
@validate_token
def auth():
    return render_template('home.html')


@app.route('/admin/<user>', methods=['GET'])
def admin(user):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT username FROM users WHERE role = %s AND username = %s", ("admin", user))
        db_username = cur.fetchone()
        cur.close()
        conn.close()
        if db_username:
            return render_template("admin_page.html")
    except Exception as e:
        return jsonify({"message": str(e)})
    
    return jsonify({"message": "You are not an authorized user"})
    



@app.route('/<user>/product', methods=['POST'])  # Creates a product
def create_product(user):
    if request.content_type == 'application/json':
        response = request.get_json()
    else:
        response = request.form
    if not response:
        # Returns an error if no product is provided
        return jsonify({"message": "No product provided"}), 400

    # Reads the file and puts it in data
    # with open('static/data/newproducts.json', "r", encoding="utf-8") as f:
    #     data = json.load(f)
    # data["products"].append(response)  # Appends gotten product to the data
    # with open('static/data/newproducts.json', "w", encoding="utf-8") as f:
    #     json.dump(data, f)

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
                SELECT id FROM users WHERE username = %s""", (user,))
    result = cur.fetchone()
    user_id = result[0]
    cur.close()
    conn.close()

    # Connects to the database and inserts the product
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """CREATE TABLE IF NOT EXISTS products(
            id SERIAL PRIMARY KEY,
            name VARCHAR(255),
            price FLOAT,
            u_id INT,
            FOREIGN KEY (u_id) REFERENCES users(id)
            )""")
        cur.execute("""INSERT INTO products (name, price, u_id) VALUES (%s, %s, %s);""",
                    (response['name'], response['price'], user_id))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        return jsonify({"message": "An error occurred while creating the product", "error": str(e)}), 500

    return jsonify({"message": "Product created successfully", "product_name": response['name']}), 201


@app.route('/products', methods=['GET'])  # Fetches all products
def get_products():
    # Connects to the database and fetches all products
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "CREATE INDEX idx_products ON products(name, price); SELECT name, price FROM products")
        products = cur.fetchall()
        cur.close()
        conn.close()
    except Exception as e:
        return jsonify({"message": "An error occurred while fetching the products", "error": str(e)}), 500

    return jsonify({"message": "Products fetched successfully", "products": products}), 200


@app.route('/product/<int:id>', methods=['GET'])  # Fetches a product by id
def get_product(id):
    # Connects to the database and fetches the product by id
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT name, price FROM products WHERE id = %s", (id,))
        product = cur.fetchall()
        cur.close()
        conn.close()
    except Exception as e:
        return jsonify({"message": "An error occurred while fetching the product", "error": str(e)}), 500
    return jsonify({"message": "Product fetched successfully", "product": product}), 200


@app.route('/product/<int:id>', methods=['DELETE'])  # Deletes a product by id
def delete_product(id):
    # Connects to the database and deletes the product by id
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM products WHERE id = %s", (id,))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        return jsonify({"message": "An error occurred while deleting the product", "error": str(e)}), 500
    return jsonify({"message": "Product deleted successfully"}), 200


@app.route('/product/<int:id>', methods=['PUT'])  # Updates a product by id
def update_product(id):
    if request.content_type == 'application/json':
        response = request.get_json()
    else:
        response = request.form
    if not response:
        # Returns an error if no product is provided
        return jsonify({"message": "No product provided"}), 400

    # Connects to the database and updates the product by id
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE products SET name = %s, price = %s WHERE id = %s",
                    (response['name'], response['price'], id))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        return jsonify({"message": "An error occurred while updating the product", "error": str(e)}), 500
    return jsonify({"message": "Product updated successfully"}), 200


@app.route('/<user>/order', methods=['POST'])  # Creates an order
def create_order(user):
    if request.content_type == 'application/json':
        response = request.get_json()
    else:
        response = request.form

    print(response)

    if not response:
        return jsonify({"message": "No order provided"}), 400
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
                SELECT id FROM users WHERE username = %s""", (user,))
    result = cur.fetchone()
    user_id = result[0]
    cur.close()
    conn.close()

    # Connects to the database and inserts the order
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS orders(
                    order_id SERIAL PRIMARY KEY,
                    product_name VARCHAR(255),
                    quantity INT,
                    u_id INT,
                    FOREIGN KEY (u_id) REFERENCES users(id)
                    );""")
        cur.execute("""INSERT INTO orders
                    (product_name, quantity, u_id)
                    VALUES (%s, %s, %s);""",
                    (response.get('name'), response.get('quantity'), user_id))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        return jsonify({"message": "An error occurred while creating the order", "error": str(e)}), 500

    return jsonify({"message": "Order created successfully"}), 201


@app.route('/orders', methods=['GET'])  # Fetches all orders
def get_orders():
    # Connects to the database and fetches all orders
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT p.id, p.name, p.price, o.quantity FROM products p INNER JOIN orders o ON p.name = o.product_name INNER JOIN users u ON u.id = p.u_id;")
        orders = cur.fetchall()
        cur.close()
        conn.close()
    except Exception as e:
        return jsonify({"message": "An error occurred while fetching the orders", "error": str(e)}), 500

    return render_template("orders.html", orders=orders)


@app.route('/order/<int:id>', methods=['GET'])  # Fetches an order by id
def get_order(id):
    # Connects to the database and fetches the order by id
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT p.id, p.name, p.price, o.quantity FROM products p JOIN orders o ON p.name = o.product_name WHERE o.order_id = %s;", (id,))
        order = cur.fetchone()
        cur.close()
        conn.close()
    except Exception as e:
        return jsonify({"message": "An error occurred while fetching the order", "error": str(e)}), 500
    return jsonify({"message": "Order fetched successfully", "order": order}), 200


@app.route('/order/<int:id>', methods=['DELETE'])  # Deletes an order by id
def delete_order(id):
    # Connects to the database and deletes the order by id
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM orders WHERE order_id = %s", (id,))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        return jsonify({"message": "An error occurred while deleting the order", "error": str(e)}), 500
    return jsonify({"message": "Order deleted successfully"}), 200


@app.route('/order/<int:id>', methods=['PUT'])  # Updates an order by id
def update_order(id):
    if request.content_type == "application/json":
        response = request.get_json()  # Gets the order from the request
    else:
        response = request.form
    if not response:
        # Returns an error if no order is provided
        return jsonify({"message": "No order provided"}), 400

    # Connects to the database and updates the order by id
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE orders SET quantity = %s WHERE order_id = %s",
                    (response['quantity'], id))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        return jsonify({"message": "An error occurred while updating the order", "error": str(e)}), 500

    return jsonify({"message": "Order updated successfully"}), 200


if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)