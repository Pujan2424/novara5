from flask import Flask, jsonify, request, make_response, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import os
import bcrypt
import jwt
from datetime import datetime, timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / 'novara.db'
SECRET_KEY = os.getenv('JWT_SECRET', 'novara-super-secret-change-me')
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin')

app = Flask(__name__, static_folder='public', static_url_path='')
CORS(app, supports_credentials=True)
limiter = Limiter(key_func=get_remote_address, app=app, default_limits=['200 per day', '50 per hour'])


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'admin'
        );
        CREATE TABLE IF NOT EXISTS products (
            id TEXT PRIMARY KEY,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            price REAL NOT NULL,
            pieces INTEGER NOT NULL,
            image TEXT
        );
        CREATE TABLE IF NOT EXISTS orders (
            id TEXT PRIMARY KEY,
            customer_name TEXT NOT NULL,
            customer_address TEXT NOT NULL,
            customer_phone TEXT NOT NULL,
            customer_email TEXT NOT NULL,
            items TEXT NOT NULL,
            total REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS slides (
            id TEXT PRIMARY KEY,
            category TEXT NOT NULL,
            idx INTEGER NOT NULL,
            image TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            UNIQUE(category, idx)
        );
        ''')
        conn.commit()

        user = conn.execute('SELECT 1 FROM users WHERE username = ?', (ADMIN_USERNAME,)).fetchone()
        if not user:
            conn.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                         (ADMIN_USERNAME, bcrypt.hashpw(ADMIN_PASSWORD.encode(), bcrypt.gensalt()).decode(), 'admin'))

        product_count = conn.execute('SELECT COUNT(*) as count FROM products').fetchone()['count']
        if product_count == 0:
            conn.executemany('INSERT INTO products (id, category, title, price, pieces, image) VALUES (?, ?, ?, ?, ?, ?)', [
                ('m1', 'men', 'Tailored Wool Coat', 18500, 5, 'https://images.unsplash.com/photo-1544022613-e87ca75a784a?q=80&w=500'),
                ('m2', 'men', 'Classic Knit Sweater', 8200, 12, 'https://images.unsplash.com/photo-1614975058789-41316d0e2e9c?q=80&w=500'),
                ('w1', 'women', 'Asymmetrical Blazer', 14500, 8, 'https://images.unsplash.com/photo-1548624149-f1bc346fe72b?q=80&w=500'),
                ('a1', 'accessories', 'Minimalist Timepiece', 24000, 4, 'https://images.unsplash.com/photo-1522312346375-d1a52e2b99b3?q=80&w=500')
            ])

        slide_count = conn.execute('SELECT COUNT(*) as count FROM slides').fetchone()['count']
        if slide_count == 0:
            conn.executemany('INSERT INTO slides (id, category, idx, image, title, description) VALUES (?, ?, ?, ?, ?, ?)', [
                ('men-0', 'men', 0, 'https://images.unsplash.com/photo-1490481651871-ab68de25d43d?q=80&w=1200', 'Men Autumn Collection', 'Luxury tailoring reinvented'),
                ('men-1', 'men', 1, 'https://images.unsplash.com/photo-1507679799987-c73779587ccf?q=80&w=1200', 'Sartorial Excellence', 'Premium Italian woven fabrics'),
                ('women-0', 'women', 0, 'https://images.unsplash.com/photo-1469334031218-e382a71b716b?q=80&w=1200', 'Haute Couture 26', 'Crafted exclusively in-house'),
                ('women-1', 'women', 1, 'https://images.unsplash.com/photo-1485968579580-b6d095142e6e?q=80&w=1200', 'Modern Femme Silhouette', 'Bold structures for the vanguard eye'),
                ('accessories-0', 'accessories', 0, 'https://images.unsplash.com/photo-1441986300917-64674bd600d8?q=80&w=1200', 'Timeless Statements', 'Minimalist structural design'),
                ('accessories-1', 'accessories', 1, 'https://images.unsplash.com/photo-1584917865442-de89df76afd3?q=80&w=1200', 'Leatherwork Binary Bags', 'Hand-stitched full grain masterpieces')
            ])
        conn.commit()


init_db()


def token_required(func):
    def wrapper(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            return jsonify({'error': 'Unauthorized'}), 401
        try:
            jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        except Exception:
            return jsonify({'error': 'Invalid token'}), 401
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper


@app.get('/api/health')
def health():
    return jsonify({'ok': True})


@app.post('/api/auth/login')
@limiter.limit('20 per 15 minutes')
def login():
    data = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')
    with get_db() as conn:
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if not user or not bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
        return jsonify({'error': 'Invalid credentials'}), 401
    token = jwt.encode({'username': username, 'exp': datetime.utcnow() + timedelta(hours=8)}, SECRET_KEY, algorithm='HS256')
    response = make_response(jsonify({'success': True, 'role': user['role']}))
    response.set_cookie('token', token, httponly=True, samesite='Lax')
    return response


@app.post('/api/auth/logout')
def logout():
    response = make_response(jsonify({'success': True}))
    response.set_cookie('token', '', expires=0)
    return response


@app.get('/api/products')
def products():
    with get_db() as conn:
        rows = conn.execute('SELECT * FROM products ORDER BY category, title').fetchall()
    return jsonify([dict(row) for row in rows])


@app.get('/api/slides')
def slides():
    with get_db() as conn:
        rows = conn.execute('SELECT * FROM slides ORDER BY category, idx').fetchall()
    return jsonify([dict(row) for row in rows])


@app.post('/api/orders')
def create_order():
    data = request.get_json() or {}
    customer = data.get('customer') or {}
    items = data.get('items') or []
    total = data.get('total', 0)
    if not customer.get('name') or not customer.get('address') or not customer.get('phone') or not customer.get('email'):
        return jsonify({'error': 'Incomplete order payload'}), 400
    order_id = 'NVR-' + str(__import__('random').randint(100000, 999999))
    item_summary = ', '.join(f"{item['title']} ({item['size']})" for item in items)
    with get_db() as conn:
        conn.execute('INSERT INTO orders (id, customer_name, customer_address, customer_phone, customer_email, items, total, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                     (order_id, customer['name'], customer['address'], customer['phone'], customer['email'], item_summary, float(total), 'pending'))
        for item in items:
            conn.execute('UPDATE products SET pieces = pieces - 1 WHERE id = ?', (item['id'],))
        conn.commit()
    return jsonify({'success': True, 'orderId': order_id})


@app.get('/api/orders')
@token_required
def get_orders():
    with get_db() as conn:
        rows = conn.execute('SELECT * FROM orders ORDER BY created_at DESC').fetchall()
    return jsonify([dict(row) for row in rows])


@app.post('/api/orders/<order_id>/confirm')
@token_required
def confirm_order(order_id):
    with get_db() as conn:
        conn.execute('UPDATE orders SET status = ? WHERE id = ?', ('confirmed', order_id))
        conn.commit()
    return jsonify({'success': True})


@app.post('/api/products')
@token_required
def add_product():
    data = request.get_json() or {}
    with get_db() as conn:
        conn.execute('INSERT INTO products (id, category, title, price, pieces, image) VALUES (?, ?, ?, ?, ?, ?)',
                     (data['id'], data['category'], data['title'], float(data['price']), int(data['pieces']), data.get('image')))
        conn.commit()
    return jsonify({'success': True})


@app.put('/api/products/<product_id>')
@token_required
def edit_product(product_id):
    data = request.get_json() or {}
    with get_db() as conn:
        conn.execute('UPDATE products SET title = ?, price = ?, pieces = ? WHERE id = ?', (data['title'], float(data['price']), int(data['pieces']), product_id))
        conn.commit()
    return jsonify({'success': True})


@app.delete('/api/products/<product_id>')
@token_required
def delete_product(product_id):
    with get_db() as conn:
        conn.execute('DELETE FROM products WHERE id = ?', (product_id,))
        conn.commit()
    return jsonify({'success': True})


@app.put('/api/slides/<category>/<int:idx>')
@token_required
def update_slide(category, idx):
    data = request.get_json() or {}
    with get_db() as conn:
        conn.execute('INSERT INTO slides (id, category, idx, image, title, description) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET image = excluded.image, title = excluded.title, description = excluded.description',
                     (f'{category}-{idx}', category, idx, data.get('image', ''), data.get('title', ''), data.get('description', '')))
        conn.commit()
    return jsonify({'success': True})


@app.route('/')
def serve_index():
    return send_from_directory(app.static_folder, 'index.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000, debug=False)
