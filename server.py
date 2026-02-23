#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, jsonify, request, send_from_directory, redirect
from flask_cors import CORS
import hashlib
import json
from datetime import datetime
import os

app = Flask(__name__)
CORS(app)

# ============================================
# ЗАВАНТАЖЕННЯ ДАНИХ З JSON
# ============================================

DATA_FILE = 'data.json'

def load_data():
    """Завантажити дані з JSON файлу"""
    try:
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"❌ Файл {DATA_FILE} не знайдено!")
        return {"recipes": [], "prices": {}}

def save_data(data):
    """Зберегти дані в JSON файл"""
    try:
        with open(DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print("✅ Дані збережені в JSON")
        return True
    except Exception as e:
        print(f"❌ Помилка при збереженні: {e}")
        return False

# Завантажити дані при старті
DATA = load_data()

# Безпека та аутентифікація
DEFAULT_PASSWORD = "castellllo"
AUTH_TOKENS = {}

# Безпека: примусити HTTPS
@app.before_request
def enforce_https():
    """Примусити HTTPS на продакшені"""
    if os.environ.get('FLASK_ENV') == 'production':
        if not request.is_secure and request.headers.get('X-Forwarded-Proto', 'http') == 'http':
            url = request.url.replace('http://', 'https://', 1)
            return redirect(url, code=301)

@app.after_request
def set_security_headers(response):
    """Додати security headers"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com"
    return response

# ============================================
# ПЕРЕВІРКА ТОКЕНА
# ============================================

def verify_token(token):
    """Перевірити чи токен валідний"""
    return token in AUTH_TOKENS

# ============================================
# API РОУТИ
# ============================================

@app.route('/api/auth', methods=['POST'])
def authenticate():
    """Аутентифікація користувача"""
    data = request.get_json()
    password = data.get('password', '')
    
    if password == DEFAULT_PASSWORD:
        token = hashlib.sha256(f"{password}{datetime.now()}".encode()).hexdigest()
        AUTH_TOKENS[token] = {"created": datetime.now().isoformat()}
        return jsonify({"success": True, "token": token})
    
    return jsonify({"success": False, "error": "Невірний пароль"}), 401

@app.route('/api/recipes', methods=['GET'])
def get_recipes():
    """Отримати всі рецепти"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not token or not verify_token(token):
        return jsonify({"error": "Не авторизовано"}), 401
    
    return jsonify({"recipes": DATA.get("recipes", [])})

@app.route('/api/prices', methods=['GET'])
def get_prices():
    """Отримати ціни"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not token or not verify_token(token):
        return jsonify({"error": "Не авторизовано"}), 401
    
    return jsonify(DATA.get("prices", {}))

@app.route('/api/recipes/<int:recipe_id>', methods=['PUT'])
def update_recipe(recipe_id):
    """Оновити рецепт"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not token or not verify_token(token):
        return jsonify({"error": "Не авторизовано"}), 401
    
    try:
        data = request.get_json()
        recipes = DATA.get("recipes", [])
        
        # Знайти рецепт
        for recipe in recipes:
            if recipe['id'] == recipe_id:
                # Оновити поля
                if 'name' in data:
                    recipe['name'] = data['name']
                if 'resources' in data:
                    recipe['resources'] = data['resources']
                if 'cat' in data:
                    recipe['cat'] = data['cat']
                
                # Зберегти
                if save_data(DATA):
                    return jsonify({"success": True, "recipe": recipe})
                else:
                    return jsonify({"success": False, "error": "Помилка при збереженні"}), 500
        
        return jsonify({"error": "Рецепт не знайдено"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/prices', methods=['PUT'])
def update_prices():
    """Оновити ціни"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not token or not verify_token(token):
        return jsonify({"error": "Не авторизовано"}), 401
    
    try:
        new_prices = request.get_json()
        DATA['prices'] = new_prices
        
        if save_data(DATA):
            return jsonify({"success": True, "prices": DATA['prices']})
        else:
            return jsonify({"success": False, "error": "Помилка при збереженні"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/health', methods=['GET'])
def health_check():
    """Перевірка статусу сервера"""
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})

@app.route('/')
def serve_index():
    """Служити index.html"""
    return send_from_directory('.', 'index.html')

# ============================================
# ЗАПУСК
# ============================================

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    print("🚀 Flask сервер запущено на port", port)
    print("📝 API доступна")
    print(f"📦 Дані завантажені з {DATA_FILE}")
    app.run(debug=debug, port=port, host='0.0.0.0')
