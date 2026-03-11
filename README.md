# C2C Marketplace Platform

A full-stack **Customer-to-Customer (C2C) Marketplace Web Application** that allows users to list products, browse listings, communicate with sellers, and manage transactions through a secure and scalable system.

The platform provides a marketplace environment where individuals can **buy and sell products directly with each other** while the system manages authentication, product listings, messaging, and administrative controls.

---

# Features

### User Features

* User Registration & Login
* Secure Authentication
* Browse Products
* Product Details Page
* Contact Seller
* Messaging System
* User Profile Management

### Seller Features

* Add Product Listings
* Upload Product Images
* Edit Product Details
* Delete Products
* Manage Listings

### Buyer Features

* Search & Browse Products
* View Seller Information
* Contact Sellers
* Real-time Messaging

### Admin Features

* Admin Dashboard
* User Management
* Product Moderation
* Platform Monitoring

---

# Tech Stack

## Backend

* Node.js
* Express.js
* MySQL
* Socket.io
* Express Session

## Frontend

* HTML
* CSS
* JavaScript
* EJS Template Engine

## Security

* bcrypt (password hashing)
* helmet
* xss-clean
* express-mongo-sanitize
* hpp

## File Upload

* multer

## Payment Integration

* Razorpay

## Other Libraries

* dotenv
* axios
* uuid

---

# Project Structure

```
C2C/
│
├── app.js
├── database.js
│
├── controllers/
│   └── products.js
│
├── models/
│   ├── Admin.js
│   └── Product.js
│
├── routes/
│   └── products.js
│
├── middleware/
│   ├── upload.js
│   ├── validateId.js
│   └── validateProductId.js
│
├── services/
│   └── userService.js
│
├── views/
│   ├── admin/
│   ├── products/
│   ├── messages/
│   └── profile/
│
├── public/
│   ├── css/
│   ├── js/
│   ├── images/
│   └── uploads/
│
└── utils/
    └── AppError.js
```

---

# Installation

Clone the repository:

```
git clone https://github.com/yourusername/c2c-marketplace.git
```

Move to project folder:

```
cd c2c-marketplace
```

Install dependencies:

```
npm install
```

---

# Environment Variables

Create a `.env` file in the root directory and add:

```
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=yourpassword
DB_NAME=c2c_database

SESSION_SECRET=your_secret_key

RAZORPAY_KEY=your_key
RAZORPAY_SECRET=your_secret
```

---

# Running the Application

Start the server:

```
node app.js
```

or

```
npm start
```

Server will run on:

```
http://localhost:3000
```

---

# Security Features

* Password hashing using bcrypt
* XSS attack prevention
* HTTP security headers using helmet
* NoSQL injection protection
* HTTP Parameter Pollution protection

---

# File Upload System

Product images are uploaded using **Multer** and stored in:

```
public/uploads/
```

---

# Messaging System

The platform supports **real-time communication between buyers and sellers** using:

```
Socket.io
```

Features:

* Live messaging
* Conversation history
* Inbox system

---

# Admin Panel

Admin dashboard allows:

* Managing users
* Monitoring product listings
* Moderating marketplace content
* Platform activity control

---

# Future Improvements

* Product search filters
* Payment escrow system
* Mobile responsive UI improvements
* Notification system
* Rating & review system

---

# License

This project is licensed under the **MIT License**.

---

# Author

Developed by **ResiCode**

GitHub: https://github.com/wasim0168

---
