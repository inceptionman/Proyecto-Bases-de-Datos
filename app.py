from flask import Flask, render_template, request, redirect, url_for, flash, session
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text
import os
from datetime import datetime, date, timedelta
from urllib.parse import urlparse, urljoin

load_dotenv()

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# ============================================================================
#                                 MODELOS
# ============================================================================

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    subscription_type = db.Column(db.String(50), nullable=True, default='basic')
    subscription_active = db.Column(db.Boolean, default=True)
    #subscription_end = db.Column(db.Date, nullable=True)
    #preferred_genres = db.Column(db.Text, nullable=True)
    payments = db.relationship('Payment', backref='user', lazy=True)


class Payment(db.Model):
    __tablename__ = 'payment'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    amount = db.Column(db.Numeric(10, 2), nullable=True)
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


# ============================================================================
#                            AUTENTICACIÓN
# ============================================================================

@login_manager.user_loader
def load_user(user_id):
    """CORREGIDO: Usar db.session.get() en lugar de Query.get()"""
    return db.session.get(User, int(user_id))


def is_safe_url(target):
    """Verifica que 'target' sea una URL segura para redirección dentro del mismo host."""
    try:
        host_url = request.host_url
        ref_url = urlparse(host_url)
        test_url = urlparse(urljoin(host_url, target))
        return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc
    except Exception:
        return False


@app.before_request
def check_subscription_status():
    """Marca la suscripción como inactiva si la fecha de fin ya pasó."""
    try:
        if current_user.is_authenticated:
            if current_user.subscription_end and isinstance(current_user.subscription_end, date):
                if date.today() > current_user.subscription_end:
                    if current_user.subscription_active:
                        current_user.subscription_active = False
                        db.session.commit()
    except Exception:
        db.session.rollback()


# ============================================================================
#                            RUTAS PRINCIPALES
# ============================================================================

@app.route('/')
def home():
    if not current_user.is_authenticated:
        return render_template('landing.html')

    movies = Movie.query.all()
    return render_template('home.html', movies=movies)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if not user:
            user = User.query.filter_by(email=username.lower()).first()
        
        if user and check_password_hash(user.password, password):
            if not user.is_active:
                flash('Tu cuenta está desactivada. Contacta a soporte.', 'warning')
                return redirect(url_for('login'))

            login_user(user)
            flash(f'¡Bienvenido de vuelta, {user.username}!', 'success')

            next_param = request.args.get('next') or request.form.get('next')
            forbidden = {url_for('logout'), url_for('login'), url_for('register'), url_for('choose_plan'), url_for('payment_info')}

            if next_param and is_safe_url(next_param):
                try:
                    path = urlparse(next_param).path
                except Exception:
                    path = next_param

                if path not in forbidden:
                    return redirect(next_param)

            return redirect(url_for('home'))
        
        flash('Usuario o contraseña incorrectos', 'danger')
    
    return render_template('login.html')


@app.route('/profile')
@login_required
def profile():
    try:
        historial_suscripciones = db.session.execute(
            text("SELECT * FROM subscription_history WHERE user_id = :user_id ORDER BY fecha_cambio DESC LIMIT 5"),
            {'user_id': current_user.id}
        ).fetchall()
    except Exception:
        historial_suscripciones = []
    
    pagos = Payment.query.filter_by(user_id=current_user.id).order_by(Payment.payment_date.desc()).limit(5).all()
    
    return render_template('profile.html', 
                         user=current_user, 
                         historial_suscripciones=historial_suscripciones,
                         pagos=pagos)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión exitosamente', 'info')
    return redirect(url_for('login'))


# ============================================================================
#                      REGISTRO EN 3 PASOS
# ============================================================================

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        if User.query.filter_by(email=email.lower()).first():
            flash('Este correo electrónico ya está registrado', 'warning')
            return redirect(url_for('register'))
        
        session['temp_email'] = email
        session['temp_password'] = password
        
        return redirect(url_for('choose_plan'))
    
    return render_template('register_step1.html')


@app.route('/register/plan', methods=['GET', 'POST'])
def choose_plan():
    if 'temp_email' not in session:
        flash('Por favor completa el registro desde el inicio', 'warning')
        return redirect(url_for('register'))
    
    if request.method == 'POST':
        plan = request.form['plan']
        session['temp_plan'] = plan
        return redirect(url_for('payment_info'))
    
    return render_template('register_step2.html')


@app.route('/register/payment', methods=['GET', 'POST'])
def payment_info():
    if 'temp_email' not in session or 'temp_plan' not in session:
        flash('Por favor completa el registro desde el inicio', 'warning')
        return redirect(url_for('register'))
    
    if request.method == 'POST':
        card_number = request.form.get('card_number', '')
        card_holder = request.form.get('card_holder', '')
        expiry = request.form.get('expiry', '')
        cvv = request.form.get('cvv', '')
        
        email = session['temp_email']
        username = email.split('@')[0]
        base_username = username
        counter = 1
        
        while db.session.execute(
            text("SELECT 1 FROM \"user\" WHERE username = :username"),
            {'username': username}
        ).fetchone():
            username = f"{base_username}{counter}"
            counter += 1
        
        hashed_password = generate_password_hash(session['temp_password'])
        
        try:
            result = db.session.execute(
                text("SELECT registrar_usuario(:username, :email, :password, :plan)"),
                {
                    'username': username,
                    'email': email,
                    'password': hashed_password,
                    'plan': session['temp_plan']
                }
            )
            nuevo_user_id = result.scalar()
            db.session.commit()
            
            db.session.execute(
                text("SELECT registrar_pago(:user_id, :amount, :payment_method, :card_number)"),
                {
                    'user_id': nuevo_user_id,
                    'amount': 10.99,
                    'payment_method': 'credit_card',
                    'card_number': f"****{card_number[-4:]}" if card_number else '****0000'
                }
            )
            db.session.commit()
            
            session.pop('temp_email', None)
            session.pop('temp_password', None)
            session.pop('temp_plan', None)
            
            # CORREGIDO: Usar db.session.get() en lugar de User.query.get()
            new_user = db.session.get(User, nuevo_user_id)
            login_user(new_user)
            
            flash('¡Registro exitoso! Bienvenido a Netflix', 'success')
            return redirect(url_for('home'))
            
        except Exception as e:
            db.session.rollback()
            error_msg = str(e)
            print("Error al crear usuario:", error_msg)
            
            if "Email inválido" in error_msg:
                flash('El formato del email es inválido. Usa ejemplo@dominio.com', 'danger')
            elif "duplicate" in error_msg.lower() or "unique" in error_msg.lower():
                flash('El email o username ya está registrado', 'warning')
            else:
                flash('Error al crear la cuenta. Intenta de nuevo.', 'danger')
            
            return redirect(url_for('register'))
    
    return render_template('register_step3.html', plan=session.get('temp_plan'))


# ============================================================================
#                    GESTIÓN DE SUSCRIPCIÓN
# ============================================================================

@app.route('/profile/change-plan', methods=['POST'])
@login_required
def change_plan():
    """Cambiar plan de suscripción"""
    new_plan = request.form.get('plan')
    
    if new_plan not in ['basic', 'standard', 'premium']:
        flash('Plan inválido', 'danger')
        return redirect(url_for('profile'))
    
    try:
        plan_anterior = current_user.subscription_type
        current_user.subscription_type = new_plan
        
        # Registrar en historial
        db.session.execute(
            text("""
                INSERT INTO subscription_history (user_id, plan_anterior, plan_nuevo)
                VALUES (:user_id, :plan_anterior, :plan_nuevo)
            """),
            {
                'user_id': current_user.id,
                'plan_anterior': plan_anterior,
                'plan_nuevo': new_plan
            }
        )
        
        db.session.commit()
        flash(f'Plan actualizado a {new_plan.upper()} exitosamente', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash('Error al cambiar plan', 'danger')
    
    return redirect(url_for('profile'))

@app.route('/profile/cancel-subscription', methods=['GET', 'POST'])
@login_required
def cancel_subscription():
    """Cancelar suscripción del usuario"""
    
    if request.method == 'POST':
        motivo = request.form.get('motivo', '')
        confirmar = request.form.get('confirmar')
        
        if confirmar != 'CANCELAR':
            flash('Debes escribir CANCELAR para confirmar la cancelación', 'warning')
            return redirect(url_for('cancel_subscription'))
        
        try:
            plan_actual = current_user.subscription_type
            
            # Actualizar suscripción
            current_user.subscription_active = False
            current_user.subscription_type = 'cancelado'
            current_user.subscription_end = date.today()
            
            # Registrar motivo si existe
            if motivo:
                db.session.execute(
                    text("""
                        INSERT INTO cancellation_log (user_id, plan_cancelado, motivo)
                        VALUES (:user_id, :plan, :motivo)
                    """),
                    {
                        'user_id': current_user.id,
                        'plan': plan_actual,
                        'motivo': motivo
                    }
                )
            
            # Registrar en historial
            db.session.execute(
                text("""
                    INSERT INTO subscription_history (user_id, plan_anterior, plan_nuevo)
                    VALUES (:user_id, :plan_anterior, :plan_nuevo)
                """),
                {
                    'user_id': current_user.id,
                    'plan_anterior': plan_actual,
                    'plan_nuevo': 'none'
                }
            )
            
            db.session.commit()
            
            flash('Tu suscripción ha sido cancelada. Puedes volver a suscribirte cuando quieras.', 'info')
            return redirect(url_for('profile'))
            
        except Exception as e:
            db.session.rollback()
            print(f"Error al cancelar suscripción: {e}")
            flash('Error al cancelar la suscripción. Intenta de nuevo.', 'danger')
            return redirect(url_for('cancel_subscription'))
    
    return render_template('cancel_subscription.html')

@app.route('/profile/reactivate-subscription', methods=['POST'])
@login_required
def reactivate_subscription():
    """Reactivar suscripción cancelada"""
    
    new_plan = request.form.get('plan', 'basic')
    
    if new_plan not in ['basic', 'standard', 'premium']:
        flash('Plan inválido', 'danger')
        return redirect(url_for('profile'))
    
    try:
        plan_anterior = current_user.subscription_type
        
        # Reactivar suscripción
        current_user.subscription_active = True
        current_user.subscription_type = new_plan
        current_user.subscription_end = date.today() + timedelta(days=30)
        
        # Registrar en historial
        db.session.execute(
            text("""
                INSERT INTO subscription_history (user_id, plan_anterior, plan_nuevo)
                VALUES (:user_id, :plan_anterior, :plan_nuevo)
            """),
            {
                'user_id': current_user.id,
                'plan_anterior': plan_anterior,
                'plan_nuevo': new_plan
            }
        )
        
        db.session.commit()
        
        flash(f'¡Bienvenido de vuelta! Tu plan {new_plan.upper()} ha sido activado.', 'success')
        
    except Exception as e:
        db.session.rollback()
        print(f"Error al reactivar suscripción: {e}")
        flash('Error al reactivar suscripción', 'danger')
    
    return redirect(url_for('profile'))

@app.route('/profile/subscription-history')
@login_required
def subscription_history():
    """Ver historial completo de cambios de suscripción"""
    try:
        historial = db.session.execute(
            text("""
                SELECT plan_anterior, plan_nuevo, fecha_cambio 
                FROM subscription_history 
                WHERE user_id = :user_id 
                ORDER BY fecha_cambio DESC
            """),
            {'user_id': current_user.id}
        ).fetchall()
    except Exception:
        flash('No se pudo cargar el historial de suscripciones', 'warning')
        historial = []
    
    return render_template('subscription_history.html', historial=historial)


# ============================================================================
#                    ADMINISTRACIÓN
# ============================================================================

@app.route('/admin/users')
@login_required
def admin_users():
    """Panel de administración de usuarios"""
    users = User.query.all()
    return render_template('admin_users.html', users=users)


@app.route('/admin/deactivate-user/<int:user_id>', methods=['POST'])
@login_required
def deactivate_user(user_id):
    """Desactivar usuario (soft delete)"""
    try:
        # CORREGIDO: Usar db.session.get() en lugar de User.query.get()
        user = db.session.get(User, user_id)
        if not user:
            flash('Usuario no encontrado', 'danger')
            return redirect(url_for('admin_users'))
        
        user.is_active = False
        db.session.commit()
        
        flash(f'Usuario {user.username} desactivado correctamente', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error al desactivar usuario: {str(e)}', 'danger')
    
    return redirect(url_for('admin_users'))


@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    """Eliminar usuario completamente"""
    try:
        # CORREGIDO: Usar db.session.get() en lugar de User.query.get()
        user = db.session.get(User, user_id)
        if not user:
            flash('Usuario no encontrado', 'danger')
            return redirect(url_for('admin_users'))
        
        db.session.delete(user)
        db.session.commit()
        
        flash(f'Usuario {user.username} eliminado completamente', 'success')
        
    except Exception as e:
        db.session.rollback()
        error_msg = str(e)
        
        if "suscripción activa" in error_msg:
            flash('No se puede eliminar un usuario activo. Primero desactívalo.', 'warning')
        else:
            flash(f'Error al eliminar usuario: {error_msg}', 'danger')
    
    return redirect(url_for('admin_users'))


# ============================================================================
#                              AUDITORÍA
# ============================================================================

@app.route('/admin/audit-users')
@login_required
def audit_users():
    """Ver historial de auditoría de usuarios"""
    try:
        audit_records = db.session.execute(
            text("""
                SELECT user_id, username, email, subscription_type, accion, fecha_cambio, usuario_bd
                FROM user_audit
                ORDER BY fecha_cambio DESC
                LIMIT 100
            """)
        ).fetchall()
    except Exception:
        audit_records = []
        flash('Tabla de auditoría no disponible', 'warning')
    
    return render_template('audit_users.html', audit_records=audit_records)


@app.route('/admin/audit-payments')
@login_required
def audit_payments():
    """Ver historial de auditoría de pagos"""
    try:
        audit_records = db.session.execute(
            text("""
                SELECT payment_id, user_id, amount, payment_method, status, accion, fecha_auditoria
                FROM payment_audit
                ORDER BY fecha_auditoria DESC
                LIMIT 100
            """)
        ).fetchall()
    except Exception:
        audit_records = []
        flash('Tabla de auditoría no disponible', 'warning')
    
    return render_template('audit_payments.html', audit_records=audit_records)


# ============================================================================
#                          PAGE RENDERER
# ============================================================================

@app.route('/pages/<page>')
def render_page(page):
    templates_dir = os.path.join(app.root_path, 'templates')
    try:
        available = {os.path.splitext(f)[0] for f in os.listdir(templates_dir) if f.endswith('.html')}
    except Exception:
        available = set()

    if page in available:
        return render_template(f"{page}.html")
    else:
        return "Página no encontrada", 404


# ============================================================================
#                              MAIN
# ============================================================================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
