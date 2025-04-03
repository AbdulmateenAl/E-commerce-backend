# 🛍️ Flask E-Commerce API

This is a **Flask-based E-Commerce API** that provides authentication, product management, and order management functionalities. It integrates with **PostgreSQL** and includes security features such as JWT authentication and rate limiting.

## 🚀 Features

- **User Authentication**
  - Register and login users securely
  - Password hashing with `werkzeug.security`
  - JWT authentication for secure access

- **Admin Panel**
  - Restricts access to admin users
  - Role-based access control (RBAC)

- **Product Management**
  - Add, update, delete, and fetch products
  - Uses PostgreSQL as the database

- **Order Management**
  - Create, update, delete, and fetch orders
  - Supports linking orders with products

- **Security & Performance**
  - Uses `flask_limiter` for API rate limiting
  - Implements JWT-based authentication
  - Uses `.env` for storing sensitive credentials

---

## 🛠️ Installation & Setup

### 1️⃣ Prerequisites
- Python 3.7+
- PostgreSQL
- `pip` package manager

### 2️⃣ Clone the Repository
```bash
git clone https://github.com/your-repo-name/flask-ecommerce-api.git
cd flask-ecommerce-api
```

### 3️⃣ Install Dependencies
```bash
pip install -r requirements.txt
```

### 4️⃣ Setup Environment Variables
Create a `.env` file in the project root and add:
```
SECRET_KEY=your_secret_key
DB_NAME=your_db_name
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_HOST=your_db_host
DB_PORT=your_db_port
```

### 5️⃣ Run the Application
```bash
python app.py
```

---

## 📌 API Endpoints

### 🏠 Home
| Method | Endpoint | Description |
|--------|---------|-------------|
| `GET`  | `/`     | Protected home page |

### 🔑 Authentication
| Method | Endpoint | Description |
|--------|---------|-------------|
| `POST` | `/register` | Register a new user |
| `POST` | `/login`    | Authenticate user and generate JWT |

### 🛒 Products
| Method | Endpoint | Description |
|--------|---------|-------------|
| `POST` | `/products` | Create a new product |
| `GET`  | `/products` | Get all products |
| `GET`  | `/products/<id>` | Get a product by ID |
| `PUT`  | `/products/<id>` | Update a product |
| `DELETE` | `/products/<id>` | Delete a product |

### 📦 Orders
| Method | Endpoint | Description |
|--------|---------|-------------|
| `POST` | `/orders` | Create a new order |
| `GET`  | `/orders` | Get all orders |
| `GET`  | `/orders/<id>` | Get an order by ID |
| `PUT`  | `/orders/<id>` | Update an order |
| `DELETE` | `/orders/<id>` | Delete an order |

---

## 🔐 Security Measures
- **JWT Authentication** for protecting routes
- **Rate Limiting** (100 requests/day, 20 requests/hour)
- **Password Hashing** with `werkzeug.security`

---

## 🎯 Future Improvements
- Add unit tests
- Implement admin dashboard with Flask-Admin
- Enhance API security with OAuth2

---

## 📝 License
This project is licensed under the **MIT License**.

---

"# E-commerce-backend" 
