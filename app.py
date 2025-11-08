from flask import Flask, render_template, request, redirect, url_for, flash, session
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime

load_dotenv()

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    subscription_type = db.Column(db.String(50), nullable=True, default='basic')

    payments = db.relationship('Payment', backref='user', lazy=True)
class Payment(db.Model):
    __tablename__ = 'payment'
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id') , nullable=False)
    amount = db.Column(db.Numeric(10,2), nullable=True)
    payment_date = db.Column(db.Date, nullable=True)
    payment_method = db.Column(db.String(20), nullable=True)
    status = db.Column(db.String(20), nullable=True)
    created_at = db.Column(db.TIMESTAMP, nullable=True)
    card_number = db.Column(db.String, nullable=True)

    
class Movie(db.Model):
    __tablename__ = 'movie'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    image_url = db.Column(db.String(200))

# -------- AUTENTICACIÓN --------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------- RUTAS --------
@app.route('/')
def home():
    movies = Movie.query.all()
    return render_template('home.html', movies=movies)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('home'))
        flash('Usuario o contraseña incorrectos', 'danger')
    return render_template('login.html')


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Verificar si el email ya existe
        if User.query.filter_by(email=email).first():
            flash('Este correo electrónico ya está registrado', 'warning')
            return redirect(url_for('register'))
        
        # Guardar temporalmente en la sesión
        session['temp_email'] = email
        session['temp_password'] = password
        
        return redirect(url_for('choose_plan'))
    
    return render_template('register_step1.html')

@app.route('/register/plan', methods=['GET', 'POST'])
def choose_plan():
    # Verificar que completó el paso 1
    if 'temp_email' not in session:
        flash('Por favor completa el registro desde el inicio', 'warning')
        return redirect(url_for('register'))
    
    if request.method == 'POST':
        plan = request.form['plan']  # basic, standard, premium
        
        # Guardar el plan en la sesión
        session['temp_plan'] = plan
        
        return redirect(url_for('payment_info'))
    
    return render_template('register_step2.html')

# PASO 3: Información de pago
@app.route('/register/payment', methods=['GET', 'POST'])
def payment_info():
    # Verificar que completó los pasos anteriores
    if 'temp_email' not in session or 'temp_plan' not in session:
        flash('Por favor completa el registro desde el inicio', 'warning')
        return redirect(url_for('register'))
    
    if request.method == 'POST':
        # Obtener información de la tarjeta
        card_number = request.form['card_number']
        card_holder = request.form['card_holder']
        expiry = request.form['expiry']
        cvv = request.form['cvv']
        
        # Crear username basado en el email
        email = session['temp_email']
        username = email.split('@')[0]
        base_username = username
        counter = 1

        while User.query.filter_by(username=username).first():
            username = f"{base_username}{counter}"
            counter += 1
        
        try:
            # Crear el nuevo usuario
            new_user = User(
                username=username,
                email=session['temp_email'],
                password=generate_password_hash(session['temp_password']),
                subscription_type=session['temp_plan'],
                is_active=True,
    
            )
            db.session.add(new_user)
            db.session.commit()

             # 2. Crear pago ASOCIADO a ese usuario
            payment_obj = Payment(
                user_id=new_user.id, 
                amount=10.99,
                payment_date=datetime.now().date(),
                payment_method='credit_card',
                status='completed',
                card_number=f"****{card_number[-4:]}",
                created_at=datetime.now()
            )
            db.session.add(payment_obj)
            db.session.commit()

            # Limpiar la sesión
            session.pop('temp_email', None)
            session.pop('temp_password', None)
            session.pop('temp_plan', None)
            # Login automático
            login_user(new_user)
            flash('¡Registro exitoso! Bienvenido a Netflix', 'success')
            return redirect(url_for('home'))
        
        except Exception as e:
            db.session.rollback()
            print("Error al crear usuario:", e)
            flash('Error al crear la cuenta. Intenta de nuevo.', 'danger')
            return redirect(url_for('register'))         
        
    return render_template('register_step3.html', plan=session.get('temp_plan'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

'''if __name__ == "__main__":
    app.run(debug=True)'''









