from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor
from urllib.parse import urlparse
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "clave_predeterminada")

# Configurar flask-login
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Crear un pool de conexiones PostgreSQL
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise Exception("DATABASE_URL no está definido en el entorno")

url = urlparse(DATABASE_URL)
db_pool = pool.SimpleConnectionPool(
    minconn=1,
    maxconn=10,
    user=url.username,
    password=url.password,
    host=url.hostname,
    port=url.port,
    database=url.path[1:],
    cursor_factory=RealDictCursor
)

# Función para obtener una conexión del pool
def get_db_connection():
    return db_pool.getconn()

# Clase Usuario
class User(UserMixin):
    def __init__(self, id, username, password, name=None, email=None):
        self.id = id
        self.username = username
        self.password = password
        self.name = name
        self.email = email

    @staticmethod
    def get_by_id(user_id):
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
                user = cursor.fetchone()
                if user:
                    return User(**user)
        finally:
            db_pool.putconn(conn)
        return None

    @staticmethod
    def get_by_username(username):
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
                user = cursor.fetchone()
                if user:
                    return User(**user)
        finally:
            db_pool.putconn(conn)
        return None

@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(user_id)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        hash_pass = generate_password_hash(password)

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    'INSERT INTO users (name, email, username, password) VALUES (%s, %s, %s, %s)',
                    (name, email, username, hash_pass)
                )
                conn.commit()
                flash("Usuario registrado correctamente, inicia sesión", 'success')
                return redirect(url_for("login"))
        except psycopg2.IntegrityError:
            conn.rollback()
            flash("El nombre de usuario ya existe", 'danger')
        finally:
            db_pool.putconn(conn)

    return render_template("register.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.get_by_username(username)
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Inicio de sesión exitoso', 'success')
            return redirect(url_for("dashboard"))
        else:
            flash("Credenciales inválidas", "danger")
    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", username=current_user.username, name=current_user.name)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Has cerrado sesión", "info")
    return redirect(url_for("login"))

if __name__ == '__main__':
    app.run(debug=True)
