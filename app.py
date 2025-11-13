from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from functools import wraps
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text
from sqlalchemy import event
import os
from datetime import datetime, date, timedelta
from urllib.parse import urlparse, urljoin

load_dotenv()

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Asegurar que cada conexión al cliente DB tenga la zona horaria esperada (UTC+5)
def _set_db_timezone(dbapi_connection, connection_record):
    try:
        # Para psycopg2: usar cursor. Usar la configuración de la app si está disponible
        tz = None
        try:
            tz = app.config.get('DB_TIMEZONE')
        except Exception:
            tz = None

        if not tz:
            tz = '+05:00'

        cursor = dbapi_connection.cursor()
        cursor.execute(f"SET TIME ZONE '{tz}'")
        cursor.close()
    except Exception as e:
        print(f"WARNING: no se pudo establecer zona horaria en la conexión DB: {e}")

try:
    event.listen(db.engine, 'connect', _set_db_timezone)
except Exception as e:
    # En algunos contextos el engine puede no estar preparado aún; lo intentamos de forma segura
    print(f"DEBUG: no se pudo registrar el listener de timezone: {e}")


@app.route('/debug/db-timezone')
@login_required
def debug_db_timezone():
    """Devuelve la zona horaria de la sesión DB y la hora actual desde la BD para verificar la configuración."""
    if not app.config.get('DEBUG'):
        return "Not available", 404
    try:
        tz = db.session.execute(text("SELECT current_setting('TimeZone') as tz")).fetchone()
        nowv = db.session.execute(text('SELECT now() as now_at_db')).fetchone()
        return {
            'session_timezone': (tz.tz if tz is not None else None),
            'now_at_db': (nowv.now_at_db if nowv is not None else None),
            'app_config_db_timezone': app.config.get('DB_TIMEZONE')
        }
    except Exception as e:
        return {'error': str(e)}, 500


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
    is_admin = db.Column(db.Boolean, default=False)
    #subscription_end = db.Column(db.Date, nullable=True) # Asumido de tu lógica
    #preferred_genres = db.Column(db.Text, nullable=True) # Asumido
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

# --- MODELO MOVIE CORREGIDO ---
# Este modelo ahora refleja la estructura de tu tabla 'movie'
class Movie(db.Model):
    __tablename__ = 'movie'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    release_year = db.Column(db.Integer, nullable=False)
    age_rating = db.Column(db.String(10), nullable=False)
    country_id = db.Column(db.Integer, db.ForeignKey('country.id'))
    language_id = db.Column(db.Integer, db.ForeignKey('language.id'))
    duration_minutes = db.Column(db.Integer)
    imdb_rating = db.Column(db.Numeric(3, 1))
    image_url = db.Column(db.String(200))


# Modelo Series para CRUD en admin
class Series(db.Model):
    __tablename__ = 'series'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    release_year = db.Column(db.Integer)
    age_rating = db.Column(db.String(10))
    total_seasons = db.Column(db.Integer)
    imdb_rating = db.Column(db.Numeric(3, 1))
    image_url = db.Column(db.String(200))



# (Añade aquí otros modelos si los necesitas en SQLAlchemy, como Country, Language, Series)
# Por ahora, solo 'Movie' era necesario para arreglar la ruta /movies

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
            # Esta lógica asume que tienes una columna 'subscription_end' en tu tabla 'user'
            # Si no la tienes, esta función puede dar error o no hacer nada.
            if hasattr(current_user, 'subscription_end') and current_user.subscription_end and isinstance(current_user.subscription_end, date):
                if date.today() > current_user.subscription_end:
                    if current_user.subscription_active:
                        current_user.subscription_active = False
                        db.session.commit()
    except Exception:
        db.session.rollback()


# Decorador para rutas de administrador
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        # Comprueba el flag is_admin en el modelo User
        if not getattr(current_user, 'is_admin', False):
            flash('Acceso no autorizado: necesitas permisos de administrador', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated


# ============================================================================
#                            RUTAS PRINCIPALES
# ============================================================================

@app.route('/')
def home():
    if not current_user.is_authenticated:
        return render_template('landing.html')
    
    # Esta consulta usa el modelo Movie actualizado
    movies = Movie.query.order_by(Movie.imdb_rating.desc().nulls_last()).limit(12).all()

    # Obtener series destacadas (top por rating)
    try:
        series_list = db.session.execute(text("""
            SELECT id, title, description, imdb_rating, image_url
            FROM series
            ORDER BY imdb_rating DESC NULLS LAST
            LIMIT 8
        """)).fetchall()
    except Exception as e:
        print(f"DEBUG: error fetching featured series: {e}")
        series_list = []

    return render_template('home.html', movies=movies, series_list=series_list)


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
        # Obtener perfiles del usuario
        profiles = db.session.execute(text("""
            SELECT * FROM profiles WHERE user_id = :user_id
        """), {'user_id': current_user.id}).fetchall()

        # Determinar límite según el plan
        max_profiles = {
            'basic': 1,
            'standard': 2,
            'premium': 4
        }.get(current_user.subscription_type, 1)

        # Verificar si puede crear más perfiles
        can_create_more = len(profiles) < max_profiles

        # Obtener historial de suscripciones (últimos 5 cambios)
        historial_suscripciones = db.session.execute(
            text("""
                SELECT * FROM subscription_history 
                WHERE user_id = :user_id 
                ORDER BY fecha_cambio DESC 
                LIMIT 5
            """),
            {'user_id': current_user.id}
        ).fetchall()

    except Exception as e:
        print("Error al obtener datos del perfil:", e)
        profiles = []
        historial_suscripciones = []
        max_profiles = 1
        can_create_more = True

    # Obtener pagos recientes (últimos 5)
    pagos = Payment.query.filter_by(user_id=current_user.id)\
                         .order_by(Payment.payment_date.desc())\
                         .limit(5).all()

    # Determinar perfil seleccionado en sesión
    selected_id = session.get('profile_id')
    selected_profile = None
    if selected_id:
        for p in profiles:
            if p.id == selected_id:
                selected_profile = p
                break

    if not selected_profile and profiles:
        selected_profile = profiles[0]

    # Renderizar todo junto
    return render_template('profile.html',
                           user=current_user,
                           profiles=profiles,
                           selected_profile=selected_profile,
                           max_profiles=max_profiles,
                           can_create_more=can_create_more,
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
        # Verificar límite de perfiles para el nuevo plan
        max_profiles_for_plan = {
            'basic': 1,
            'standard': 2,
            'premium': 4
        }[new_plan]

        cnt = db.session.execute(text("SELECT COUNT(*) as cnt FROM profiles WHERE user_id = :uid"), {'uid': current_user.id}).fetchone()
        current_profiles_count = cnt.cnt if cnt else 0

        if current_profiles_count > max_profiles_for_plan:
            needed = current_profiles_count - max_profiles_for_plan
            # Redirigir a /profiles en modo eliminación forzada (sin opción de crear perfiles)
            flash(f'No se puede cambiar a {new_plan.upper()}: tienes {current_profiles_count} perfiles, el plan permite {max_profiles_for_plan}. Elimina al menos {needed} perfil(es).', 'warning')
            return redirect(url_for('profiles', deletion_required=1, needed=needed, target=new_plan))

        plan_anterior = current_user.subscription_type
        current_user.subscription_type = new_plan
        
        # Registrar en historial (Asumiendo que no tienes el trigger)
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
            # current_user.subscription_end = date.today() # Descomenta si tienes esta columna
            
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
            
            # Registrar en historial (Asumiendo que no tienes el trigger)
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
    
    # Asumiendo que tienes un 'cancel_subscription.html'
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
        # current_user.subscription_end = date.today() + timedelta(days=30) # Descomenta si tienes esta columna
        
        # Registrar en historial (Asumiendo que no tienes el trigger)
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
    
    # Asumiendo que tienes un 'subscription_history.html'
    return render_template('subscription_history.html', historial=historial)


# ============================================================================
#                    ADMINISTRACIÓN
# ============================================================================

@app.route('/admin/users')
@login_required
def admin_users():
    """Panel de administración - Lista de usuarios"""
    # Verificar si el usuario es admin
    if not current_user.is_admin:
        flash('No tienes permisos de administrador', 'danger')
        return redirect(url_for('home'))
    
    try:
        # Obtener todos los usuarios
        users = db.session.execute(text("""
            SELECT 
                id,
                username,
                email,
                subscription_type,
                subscription_active,
                is_active,
                is_admin
            FROM "user"
            ORDER BY id DESC
        """)).fetchall()
        
        return render_template('admin_users.html', 
                             users=users, 
                             total_users=len(users))
    except Exception as e:
        flash('Error al cargar usuarios', 'danger')
        print(f"Error: {e}")
        return redirect(url_for('home'))



@app.route('/admin/deactivate-user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def deactivate_user(user_id):
    """Desactivar usuario (soft delete)"""
    # (Añadir comprobación de admin)
    try:
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
@admin_required
def delete_user(user_id):
    """Eliminar usuario completamente"""
    # (Añadir comprobación de admin)
    try:
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
@admin_required
def audit_users():
    """Ver historial de auditoría de usuarios"""
    # (Añadir comprobación de admin)
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
    
    # Asumiendo que tienes un 'audit_users.html'
    return render_template('audit_users.html', audit_records=audit_records)


@app.route('/admin/audit-payments')
@login_required
@admin_required
def audit_payments():
    """Ver historial de auditoría de pagos"""
    # (Añadir comprobación de admin)
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
    
    # Asumiendo que tienes un 'audit_payments.html'
    return render_template('audit_payments.html', audit_records=audit_records)


# =====================
# ADMIN: DASHBOARD + CRUD
# =====================


@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')


@app.route('/admin/movies')
@login_required
@admin_required
def admin_movies():
    movies = Movie.query.order_by(Movie.title.asc()).all()
    return render_template('admin_movies.html', movies=movies)


@app.route('/admin/movies/add', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_add_movie():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        release_year = request.form.get('release_year') or None
        age_rating = request.form.get('age_rating') or ''
        duration_minutes = request.form.get('duration_minutes') or None
        country_id = request.form.get('country_id') or None
        language_id = request.form.get('language_id') or None
        imdb_rating = request.form.get('imdb_rating') or None
        image_url = request.form.get('image_url') or None

        try:
            movie = Movie(
                title=title,
                description=description,
                release_year=int(release_year) if release_year else None,
                age_rating=age_rating,
                duration_minutes=int(duration_minutes) if duration_minutes else None,
                country_id=int(country_id) if country_id else None,
                language_id=int(language_id) if language_id else None,
                imdb_rating=float(imdb_rating) if imdb_rating else None,
                image_url=image_url
            )
            db.session.add(movie)
            db.session.commit()
            flash('Película añadida correctamente', 'success')
            return redirect(url_for('admin_movies'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al añadir película: {e}', 'danger')

    return render_template('admin_movie_form.html', movie=None)


@app.route('/admin/movies/edit/<int:movie_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_movie(movie_id):
    movie = Movie.query.get(movie_id)
    if not movie:
        flash('Película no encontrada', 'danger')
        return redirect(url_for('admin_movies'))

    if request.method == 'POST':
        movie.title = request.form.get('title')
        movie.description = request.form.get('description')
        ry = request.form.get('release_year')
        movie.release_year = int(ry) if ry else None
        movie.age_rating = request.form.get('age_rating') or movie.age_rating
        dm = request.form.get('duration_minutes')
        movie.duration_minutes = int(dm) if dm else None
        movie.country_id = int(request.form.get('country_id')) if request.form.get('country_id') else None
        movie.language_id = int(request.form.get('language_id')) if request.form.get('language_id') else None
        ir = request.form.get('imdb_rating')
        movie.imdb_rating = float(ir) if ir else None
        movie.image_url = request.form.get('image_url') or movie.image_url

        try:
            db.session.commit()
            flash('Película actualizada', 'success')
            return redirect(url_for('admin_movies'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al actualizar: {e}', 'danger')

    return render_template('admin_movie_form.html', movie=movie)


@app.route('/admin/movies/delete/<int:movie_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_movie(movie_id):
    movie = Movie.query.get(movie_id)
    if not movie:
        flash('Película no encontrada', 'danger')
        return redirect(url_for('admin_movies'))

    try:
        db.session.delete(movie)
        db.session.commit()
        flash('Película eliminada', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al eliminar película: {e}', 'danger')

    return redirect(url_for('admin_movies'))


@app.route('/admin/series')
@login_required
@admin_required
def admin_series():
    series_list = Series.query.order_by(Series.title.asc()).all()
    return render_template('admin_series.html', series_list=series_list)


@app.route('/admin/series/add', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_add_series():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        release_year = request.form.get('release_year') or None
        age_rating = request.form.get('age_rating') or ''
        total_seasons = request.form.get('total_seasons') or None
        imdb_rating = request.form.get('imdb_rating') or None
        image_url = request.form.get('image_url') or None

        try:
            s = Series(
                title=title,
                description=description,
                release_year=int(release_year) if release_year else None,
                age_rating=age_rating,
                total_seasons=int(total_seasons) if total_seasons else None,
                imdb_rating=float(imdb_rating) if imdb_rating else None,
                image_url=image_url
            )
            db.session.add(s)
            db.session.commit()
            flash('Serie añadida correctamente', 'success')
            return redirect(url_for('admin_series'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al añadir serie: {e}', 'danger')

    return render_template('admin_series_form.html', series=None)


@app.route('/admin/series/edit/<int:series_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_series(series_id):
    s = Series.query.get(series_id)
    if not s:
        flash('Serie no encontrada', 'danger')
        return redirect(url_for('admin_series'))

    if request.method == 'POST':
        s.title = request.form.get('title')
        s.description = request.form.get('description')
        ry = request.form.get('release_year')
        s.release_year = int(ry) if ry else None
        s.age_rating = request.form.get('age_rating') or s.age_rating
        ts = request.form.get('total_seasons')
        s.total_seasons = int(ts) if ts else None
        ir = request.form.get('imdb_rating')
        s.imdb_rating = float(ir) if ir else None
        s.image_url = request.form.get('image_url') or s.image_url

        try:
            db.session.commit()
            flash('Serie actualizada', 'success')
            return redirect(url_for('admin_series'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al actualizar serie: {e}', 'danger')

    return render_template('admin_series_form.html', series=s)


@app.route('/admin/series/delete/<int:series_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_series(series_id):
    s = Series.query.get(series_id)
    if not s:
        flash('Serie no encontrada', 'danger')
        return redirect(url_for('admin_series'))

    try:
        db.session.delete(s)
        db.session.commit()
        flash('Serie eliminada', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al eliminar serie: {e}', 'danger')

    return redirect(url_for('admin_series'))


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

# Ruta para búsqueda de contenido con full-text search
@app.route('/search', methods=['GET'])
@login_required
def search_content():
    query = request.args.get('q', '')
    if not query:
        return render_template('search.html', results=[], query='') # Pasamos query vacío
    
    try:
        results = db.session.execute(
            text("SELECT * FROM search_content(:query)"),
            {'query': query}
        ).fetchall()

        # Normalizar resultados a dicts y, si faltan imágenes para series,
        # intentar recuperarlas directamente desde la tabla `series`.
        normalized_results = []
        for row in results:
            try:
                data = dict(row._mapping)
            except Exception:
                try:
                    data = dict(row)
                except Exception:
                    # Saltar si no podemos convertir
                    continue

            # Si es una serie y image_url es vacío/None, intentar buscar en la tabla series
            if data.get('content_type') == 'series' and not data.get('image_url'):
                try:
                    img = db.session.execute(
                        text("SELECT image_url FROM series WHERE id = :id"),
                        {'id': data.get('id')}
                    ).scalar()
                    data['image_url'] = img
                except Exception as e:
                    print(f"DEBUG: error al obtener image_url desde series para id={data.get('id')}: {e}")

            normalized_results.append(data)

        # DEBUG breve: listar claves y sample image_url
        try:
            if normalized_results:
                print("DEBUG: normalized result keys:", list(normalized_results[0].keys()))
                print("DEBUG: sample content_type:", normalized_results[0].get('content_type'))
                print("DEBUG: sample image_url:", normalized_results[0].get('image_url'))
        except Exception as e:
            print("DEBUG: error al imprimir normalized_results:", e)

        return render_template('search.html', results=normalized_results, query=query)
    except Exception as e:
        flash('Error en la búsqueda', 'danger')
        print(f"Error en search_content: {e}")
        return render_template('search.html', results=[], query=query)

# Ruta para estadísticas del usuario
@app.route('/profile/statistics')
@login_required
def user_statistics():
    try:
        stats = db.session.execute(
            text("SELECT * FROM get_user_statistics(:user_id)"),
            {'user_id': current_user.id}
        ).fetchone()
        # Asumiendo que tienes un 'statistics.html'
        return render_template('statistics.html', stats=stats)
    except Exception as e:
        flash('Error al cargar estadísticas', 'danger')
        return redirect(url_for('profile'))
    
@app.route('/profile/create', methods=['GET', 'POST'])
@login_required
def create_profile():
    if request.method == 'POST':
        profile_name = request.form.get('profile_name')
        profile_type = request.form.get('profile_type', 'adult')
        
        try:
            # Comprobar límite según suscripción
            count_res = db.session.execute(text("SELECT COUNT(*) as cnt FROM profiles WHERE user_id = :uid"), {'uid': current_user.id}).fetchone()
            current_count = count_res.cnt if count_res is not None else 0
            max_profiles = {
                'basic': 1,
                'standard': 2,
                'premium': 4
            }.get(getattr(current_user, 'subscription_type', 'basic'), 1)

            if current_count >= max_profiles:
                flash('Has alcanzado el límite de perfiles para tu plan. Actualiza tu suscripción para crear más perfiles.', 'warning')
                return redirect(url_for('profiles'))

            # Determinar si es el primer perfil (será el principal)
            is_main = True if current_count == 0 else False

            # Intentar insertar el perfil y obtener su id
            result = db.session.execute(text("""
                INSERT INTO profiles (user_id, profile_name, profile_type, is_main)
                VALUES (:user_id, :profile_name, :profile_type, :is_main)
                RETURNING id
            """), {
                'user_id': current_user.id,
                'profile_name': profile_name,
                'profile_type': profile_type,
                'is_main': is_main
            })
            inserted = result.fetchone()
            db.session.commit()

            # Si se creó, seleccionar el nuevo perfil en la sesión
            if inserted is not None:
                session['profile_id'] = inserted.id

            flash('Perfil creado exitosamente', 'success')
            return redirect(url_for('profiles'))
            
        except Exception as e:
            db.session.rollback()
            error_message = str(e)
            
            # Detectar si es el error del trigger
            if 'Has alcanzado el límite de perfiles' in error_message:
                flash('Has alcanzado el límite de perfiles para tu plan. Actualiza tu suscripción para crear más perfiles.', 'warning')
            else:
                flash('Error al crear el perfil', 'danger')
            
            return redirect(url_for('profiles'))
    
    return render_template('create_profile.html')


@app.route('/profiles')
@login_required
def profiles():
    """Mostrar y gestionar perfiles del usuario"""
    try:
        profiles = db.session.execute(text("""
            SELECT id, profile_name, profile_type, is_main, created_at
            FROM profiles
            WHERE user_id = :user_id
            ORDER BY is_main DESC, created_at ASC
        """), {'user_id': current_user.id}).fetchall()

        # Determinar perfil seleccionado en sesión
        selected_id = session.get('profile_id')
        selected_profile = None
        if selected_id:
            for p in profiles:
                if p.id == selected_id:
                    selected_profile = p
                    break

        # Si no hay seleccionado, marcar el principal
        if not selected_profile and profiles:
            selected_profile = profiles[0]

        # Ver si venimos en modo eliminación forzada desde cambio de plan
        deletion_required = request.args.get('deletion_required', default=0, type=int)
        needed = request.args.get('needed', default=0, type=int)
        target_plan = request.args.get('target')

        # Para depuración: pasar cantidad de perfiles encontrados
        profiles_count = len(profiles) if profiles is not None else 0
        print(f"DEBUG: user_id={current_user.id} profiles_count={profiles_count} deletion_required={deletion_required} needed={needed} target={target_plan}")

        return render_template('profiles.html', profiles=profiles, selected_profile=selected_profile, profiles_count=profiles_count, deletion_required=bool(deletion_required), needed=needed, target_plan=target_plan)
    except Exception as e:
        print(f"Error al cargar perfiles: {e}")
        flash('Error al cargar perfiles', 'danger')
        return redirect(url_for('profile'))


@app.route('/profiles/switch', methods=['POST'])
@login_required
def switch_profile():
    """Cambiar el perfil activo en sesión"""
    try:
        profile_id = request.form.get('profile_id') or (request.get_json() and request.get_json().get('profile_id'))
        if not profile_id:
            flash('Perfil no especificado', 'warning')
            return redirect(request.referrer or url_for('profiles'))

        # validar pertenece al usuario
        profile = db.session.execute(text("""
            SELECT id FROM profiles WHERE id = :pid AND user_id = :user_id LIMIT 1
        """), {'pid': int(profile_id), 'user_id': current_user.id}).fetchone()

        if not profile:
            flash('Perfil inválido', 'danger')
            return redirect(request.referrer or url_for('profiles'))

        session['profile_id'] = profile.id

        # Si es una petición JS/JSON devolvemos JSON
        if request.is_json:
            return {'success': True, 'message': 'Perfil cambiado'}

        flash('Perfil cambiado', 'success')
        return redirect(request.referrer or url_for('profiles'))
    except Exception as e:
        print(f"Error al cambiar perfil: {e}")
        db.session.rollback()
        flash('Error al cambiar perfil', 'danger')
        return redirect(request.referrer or url_for('profiles'))


@app.route('/profiles/delete', methods=['POST'])
@login_required
def delete_profile():
    """Eliminar un perfil y su watchlist. No permite eliminar el último perfil."""
    try:
        data = request.get_json() or request.form
        pid = data.get('profile_id')
        if not pid:
            if request.is_json:
                return {'success': False, 'message': 'profile_id es requerido'}, 400
            flash('profile_id es requerido', 'warning')
            return redirect(url_for('profiles'))

        # Comprobar que el perfil pertenece al usuario
        profile = db.session.execute(text("SELECT id, is_main FROM profiles WHERE id = :pid AND user_id = :uid"), {'pid': int(pid), 'uid': current_user.id}).fetchone()
        if not profile:
            if request.is_json:
                return {'success': False, 'message': 'Perfil no encontrado'}, 404
            flash('Perfil no encontrado', 'danger')
            return redirect(url_for('profiles'))

        # Contar perfiles del usuario
        cnt = db.session.execute(text("SELECT COUNT(*) as cnt FROM profiles WHERE user_id = :uid"), {'uid': current_user.id}).fetchone()
        total = cnt.cnt if cnt else 0
        if total <= 1:
            if request.is_json:
                return {'success': False, 'message': 'No puedes eliminar el último perfil'}, 400
            flash('No puedes eliminar el último perfil', 'warning')
            return redirect(url_for('profiles'))

        # Si el perfil es principal, debemos asignar otro como principal
        is_main = bool(profile.is_main)

        # Eliminar watchlist asociado
        db.session.execute(text("DELETE FROM watch_list WHERE profile_id = :pid"), {'pid': int(pid)})

        # Eliminar el perfil
        db.session.execute(text("DELETE FROM profiles WHERE id = :pid"), {'pid': int(pid)})

        # Si era principal, asignar otra como principal (la más antigua)
        if is_main:
            new_main = db.session.execute(text("SELECT id FROM profiles WHERE user_id = :uid ORDER BY created_at ASC LIMIT 1"), {'uid': current_user.id}).fetchone()
            if new_main:
                db.session.execute(text("UPDATE profiles SET is_main = true WHERE id = :nid"), {'nid': new_main.id})

        db.session.commit()

        if request.is_json:
            return {'success': True, 'message': 'Perfil eliminado'}

        flash('Perfil eliminado', 'success')
        return redirect(url_for('profiles'))
    except Exception as e:
        db.session.rollback()
        print(f"Error al eliminar perfil: {e}")
        if request.is_json:
            return {'success': False, 'message': 'Error al eliminar perfil'}, 500
        flash('Error al eliminar perfil', 'danger')
        return redirect(url_for('profiles'))

# Ruta para recomendaciones
@app.route('/recommendations')
@login_required
def recommendations():
    profile_id = request.args.get('profile_id', type=int)
    if not profile_id:
        flash('Selecciona un perfil', 'warning')
        return redirect(url_for('home'))
    
    try:
        recommendations = db.session.execute(
            text("SELECT * FROM get_movie_recommendations(:profile_id, :limit)"),
            {'profile_id': profile_id, 'limit': 20}
        ).fetchall()
        # Asumiendo que tienes un 'recommendations.html'
        return render_template('recommendations.html', recommendations=recommendations)
    except Exception as e:
        flash('Error al generar recomendaciones', 'danger')
        return redirect(url_for('home'))

# Ruta para panel de análisis (solo admin)
@app.route('/admin/analytics')
@login_required
def admin_analytics():
    # (Añadir comprobación de admin)
    try:
        # Obtener datos de vistas materializadas
        most_watched = db.session.execute(
            text("SELECT * FROM mv_most_watched_content LIMIT 10")
        ).fetchall()
        
        revenue_data = db.session.execute(
            text("SELECT * FROM mv_revenue_by_plan ORDER BY month DESC LIMIT 12")
        ).fetchall()
        
        retention_data = db.session.execute(
            text("SELECT * FROM user_retention_analysis ORDER BY signup_month DESC LIMIT 12")
        ).fetchall()
        
        # Asumiendo que tienes un 'admin_analytics.html'
        return render_template('admin_analytics.html', 
                             most_watched=most_watched,
                             revenue=revenue_data,
                             retention=retention_data)
    except Exception as e:
        flash('Error al cargar análisis', 'danger')
        return redirect(url_for('home'))

# ============================================================================
# RUTAS DE CONTENIDO - Agregar estas rutas a tu app.py
# ============================================================================

@app.route('/movies')
@login_required
def movies():
    """Página de películas"""
    try:
        # Esta consulta ahora usa el MODELO CORREGIDO
        movies = Movie.query.order_by(Movie.imdb_rating.desc().nulls_last()).all()
        # Obtener perfiles del usuario para permitir seleccionar en la UI
        profiles = db.session.execute(text("""
            SELECT id, profile_name, profile_type, is_main
            FROM profiles
            WHERE user_id = :user_id
            ORDER BY is_main DESC, created_at ASC
        """), {'user_id': current_user.id}).fetchall()

        # Determinar perfil actual (si el usuario tiene seleccionado uno en sesión)
        current_profile_id = session.get('profile_id') if session.get('profile_id') else (profiles[0].id if profiles else None)

        return render_template('movies.html', movies=movies, profiles=profiles, current_profile_id=current_profile_id)
    except Exception as e:
        flash('Error al cargar películas', 'danger')
        print(f"Error en movies: {e}")
        return redirect(url_for('home'))


@app.route('/series')
@login_required
def series():
    """Página de series"""
    try:
        # Obtener todas las series de la base de datos
        series_list = db.session.execute(text("""
            SELECT id, title, description, release_year, age_rating, 
                   total_seasons, imdb_rating, image_url
            FROM series
            ORDER BY imdb_rating DESC NULLS LAST
        """)).fetchall()
        
        print(f"DEBUG: Se encontraron {len(series_list)} series")  # Para verificar en logs

        # Obtener perfiles del usuario para permitir seleccionar en la UI
        profiles = db.session.execute(text("""
            SELECT id, profile_name, profile_type, is_main
            FROM profiles
            WHERE user_id = :user_id
            ORDER BY is_main DESC, created_at ASC
        """), {'user_id': current_user.id}).fetchall()

        current_profile_id = session.get('profile_id') if session.get('profile_id') else (profiles[0].id if profiles else None)

        return render_template('series.html', series_list=series_list, profiles=profiles, current_profile_id=current_profile_id)  # ← CAMBIO AQUÍ
    except Exception as e:
        flash('Error al cargar series', 'danger')
        print(f"Error en series: {e}")
        return redirect(url_for('home'))



@app.route('/my-list')
@login_required
def my_list():
    """Página de Mi Lista - contenido guardado por el usuario"""
    try:
        # Obtener perfiles del usuario
        profiles = db.session.execute(text("""
            SELECT id, profile_name, profile_type, is_main
            FROM profiles
            WHERE user_id = :user_id
            ORDER BY is_main DESC, created_at ASC
        """), {'user_id': current_user.id}).fetchall()
        
        # Si no hay perfiles, retornar vacío
        if not profiles:
            return render_template('my_list.html', watchlist=[], profiles=[], current_profile=None)
        
        # Determinar perfil a usar: session -> principal
        session_pid = session.get('profile_id')
        main_profile = None
        if session_pid:
            for p in profiles:
                if p.id == session_pid:
                    main_profile = p
                    break

        if not main_profile:
            main_profile = profiles[0]

        profile_id = main_profile.id
        
        # Obtener contenido de la watchlist
        watchlist = db.session.execute(text("""
            SELECT 
                wl.id,
                wl.status,
                wl.added_date,
                CASE 
                    WHEN wl.movie_id IS NOT NULL THEN 'movie'
                    ELSE 'series'
                END as content_type,
                COALESCE(m.title, s.title) as title,
                COALESCE(m.description, s.description) as description,
                COALESCE(m.imdb_rating, s.imdb_rating) as rating,
                m.image_url,
                wl.movie_id,
                wl.series_id
            FROM watch_list wl
            LEFT JOIN movie m ON wl.movie_id = m.id
            LEFT JOIN series s ON wl.series_id = s.id
            WHERE wl.profile_id = :profile_id
            ORDER BY wl.added_date DESC
        """), {'profile_id': profile_id}).fetchall()
        
        return render_template('my_list.html', 
                             watchlist=watchlist, 
                             profiles=profiles,
                             current_profile=main_profile)
    except Exception as e:
        flash('Error al cargar tu lista', 'danger')
        print(f"Error en my_list: {e}")
        return render_template('my_list.html', watchlist=[], profiles=[], current_profile=None)




@app.route('/account/settings')
@login_required
def account_settings():
    """Página de configuración de cuenta"""
    # Asumiendo que tienes un 'settings.html'
    return render_template('settings.html', user=current_user)


@app.route('/add-to-watchlist', methods=['POST'])
@login_required
def add_to_watchlist():
    """API para agregar contenido a la watchlist"""
    try:
        data = request.get_json()
        print(f"DEBUG add_to_watchlist payload: {data}")
        content_id = data.get('content_id')
        content_type = data.get('content_type')
        # Si el cliente envía un profile_id, validarlo
        requested_profile_id = data.get('profile_id')
        profile_id = None

        # Validaciones básicas
        if not content_id or not content_type:
            return {'success': False, 'message': 'content_id y content_type son requeridos'}, 400

        try:
            content_id = int(content_id)
        except Exception:
            return {'success': False, 'message': 'content_id inválido'}, 400

        if requested_profile_id:
            profile = db.session.execute(text("""
                SELECT id FROM profiles
                WHERE id = :pid AND user_id = :user_id
                LIMIT 1
            """), {'pid': requested_profile_id, 'user_id': current_user.id}).fetchone()

            if not profile:
                return {'success': False, 'message': 'Perfil no válido'}, 400

            profile_id = profile.id
        else:
            # Obtener el perfil principal del usuario si no se proporcionó
            profile = db.session.execute(text("""
                SELECT id FROM profiles
                WHERE user_id = :user_id
                ORDER BY is_main DESC, created_at ASC
                LIMIT 1
            """), {'user_id': current_user.id}).fetchone()

            if not profile:
                return {'success': False, 'message': 'No tienes perfiles creados'}, 400

            profile_id = profile.id
        
        # Verificar si ya existe
        if content_type == 'movie':
            existing = db.session.execute(text("""
                SELECT 1 FROM watch_list
                WHERE profile_id = :profile_id AND movie_id = :content_id
            """), {'profile_id': profile_id, 'content_id': content_id}).fetchone()
        else:
            existing = db.session.execute(text("""
                SELECT 1 FROM watch_list
                WHERE profile_id = :profile_id AND series_id = :content_id
            """), {'profile_id': profile_id, 'content_id': content_id}).fetchone()
        
        if existing:
            print('DEBUG: ya existe en watchlist')
            return {'success': False, 'message': 'Ya está en tu lista'}, 400

        # Agregar a la watchlist y devolver el id insertado
        if content_type == 'movie':
            result = db.session.execute(text("""
                INSERT INTO watch_list (profile_id, movie_id, status, added_date)
                VALUES (:profile_id, :content_id, 'to_watch', CURRENT_DATE)
                RETURNING id
            """), {'profile_id': profile_id, 'content_id': content_id})
        else:
            result = db.session.execute(text("""
                INSERT INTO watch_list (profile_id, series_id, status, added_date)
                VALUES (:profile_id, :content_id, 'to_watch', CURRENT_DATE)
                RETURNING id
            """), {'profile_id': profile_id, 'content_id': content_id})

        # Obtener el id insertado de forma robusta
        try:
            watchlist_id = result.scalar()
        except Exception:
            inserted = result.fetchone()
            watchlist_id = (inserted[0] if inserted is not None and len(inserted) > 0 else None)

        db.session.commit()

        print(f"DEBUG: inserted watchlist id: {watchlist_id}")
        return {'success': True, 'message': 'Agregado a tu lista', 'watchlist_id': watchlist_id}
    
    except Exception as e:
        db.session.rollback()
        print(f"Error al agregar a watchlist: {e}")
        return {'success': False, 'message': 'Error al agregar'}, 500


@app.route('/remove-from-watchlist', methods=['POST'])
@login_required
def remove_from_watchlist():
    """Eliminar un elemento de la watchlist asegurando que pertenezca al usuario."""
    try:
        data = request.get_json() or {}
        wid = data.get('watchlist_id')
        if not wid:
            return {'success': False, 'message': 'watchlist_id es requerido'}, 400

        # Comprobar que el elemento pertenece al usuario a través del perfil
        found = db.session.execute(text("""
            SELECT wl.id FROM watch_list wl
            JOIN profiles p ON wl.profile_id = p.id
            WHERE wl.id = :wid AND p.user_id = :uid
            LIMIT 1
        """), {'wid': wid, 'uid': current_user.id}).fetchone()

        if not found:
            return {'success': False, 'message': 'Elemento no encontrado o no pertenece al usuario'}, 404

        db.session.execute(text("DELETE FROM watch_list WHERE id = :wid"), {'wid': wid})
        db.session.commit()
        return {'success': True, 'message': 'Eliminado de tu lista'}
    except Exception as e:
        db.session.rollback()
        print(f"Error al eliminar de watchlist: {e}")
        return {'success': False, 'message': 'Error al eliminar'}, 500


@app.route('/movie/<int:movie_id>')
@login_required
def movie_detail(movie_id):
    """Página de detalle de película"""
    try:
        movie = db.session.execute(text("""
            SELECT m.*,
                   c.name as country_name,
                   l.name as language_name
            FROM movie m
            LEFT JOIN country c ON m.country_id = c.id
            LEFT JOIN language l ON m.language_id = l.id
            WHERE m.id = :movie_id
        """), {'movie_id': movie_id}).fetchone()
        
        if not movie:
            flash('Película no encontrada', 'warning')
            return redirect(url_for('movies'))
        
        # Obtener categorías
        categories = db.session.execute(text("""
            SELECT c.name
            FROM movie_category mc
            JOIN category c ON mc.category_id = c.id
            WHERE mc.movie_id = :movie_id
        """), {'movie_id': movie_id}).fetchall()
        
        # Obtener actores
        actors = db.session.execute(text("""
            SELECT a.first_name, a.last_name, ma.character_name
            FROM movie_actor ma
            JOIN actor a ON ma.actor_id = a.id
            WHERE ma.movie_id = :movie_id
            LIMIT 10
        """), {'movie_id': movie_id}).fetchall()
        
        # Asumiendo que tienes un 'movie_detail.html'
        return render_template('movie_detail.html', 
                             movie=movie, 
                             categories=categories,
                             actors=actors)
    except Exception as e:
        flash('Error al cargar detalles de la película', 'danger')
        print(f"Error en movie_detail: {e}")
        return redirect(url_for('movies'))


@app.route('/series/<int:series_id>')
@login_required
def series_detail(series_id):
    """Página de detalle de serie"""
    try:
        series = db.session.execute(text("""
            SELECT s.*,
                   c.name as country_name,
                   l.name as language_name
            FROM series s
            LEFT JOIN country c ON s.country_id = c.id
            LEFT JOIN language l ON s.language_id = l.id
            WHERE s.id = :series_id
        """), {'series_id': series_id}).fetchone()
        
        if not series:
            flash('Serie no encontrada', 'warning')
            return redirect(url_for('series'))
        
        # Obtener categorías
        categories = db.session.execute(text("""
            SELECT c.name
            FROM show_category sc
            JOIN category c ON sc.category_id = c.id
            WHERE sc.series_id = :series_id
        """), {'series_id': series_id}).fetchall()
        
        # Obtener actores
        actors = db.session.execute(text("""
            SELECT a.first_name, a.last_name, sa.character_name
            FROM series_actor sa
            JOIN actor a ON sa.actor_id = a.id
            WHERE sa.series_id = :series_id
            LIMIT 10
        """), {'series_id': series_id}).fetchall()
        
        # Asumiendo que tienes un 'series_detail.html'
        return render_template('series_detail.html', 
                             series=series, 
                             categories=categories,
                             actors=actors)
    except Exception as e:
        flash('Error al cargar detalles de la serie', 'danger')
        print(f"Error en series_detail: {e}")
        return redirect(url_for('series'))


@app.route('/play/movie/<int:movie_id>')
@login_required
def play_movie(movie_id):
    """Reproducción simulada de película"""
    try:
        content = db.session.execute(text("""
            SELECT m.id, m.title, m.description, m.imdb_rating
            FROM movie m
            WHERE m.id = :movie_id
        """), {'movie_id': movie_id}).fetchone()

        if not content:
            flash('Película no encontrada', 'warning')
            return redirect(url_for('movies'))

        # Determinar perfil y calidad
        profile_id = session.get('profile_id')
        profile = None
        if profile_id:
            profile = db.session.execute(text("SELECT profile_name, profile_type FROM profiles WHERE id = :pid AND user_id = :uid"),
                                         {'pid': profile_id, 'uid': current_user.id}).fetchone()

        plan = getattr(current_user, 'subscription_type', 'basic')
        quality = 'SD'
        if plan == 'standard':
            quality = 'HD'
        elif plan == 'premium':
            quality = '4K'

        return render_template('player.html', content=content, quality=quality, profile_name=(profile.profile_name if profile else None))
    except Exception as e:
        print(f"Error en play_movie: {e}")
        flash('Error al reproducir la película', 'danger')
        return redirect(url_for('movies'))


@app.route('/play/series/<int:series_id>')
@login_required
def play_series(series_id):
    """Reproducción simulada de serie (reproducirá la serie entera como simulación)"""
    try:
        content = db.session.execute(text("""
            SELECT s.id, s.title, s.description, s.imdb_rating
            FROM series s
            WHERE s.id = :series_id
        """), {'series_id': series_id}).fetchone()

        if not content:
            flash('Serie no encontrada', 'warning')
            return redirect(url_for('series'))

        profile_id = session.get('profile_id')
        profile = None
        if profile_id:
            profile = db.session.execute(text("SELECT profile_name, profile_type FROM profiles WHERE id = :pid AND user_id = :uid"),
                                         {'pid': profile_id, 'uid': current_user.id}).fetchone()

        plan = getattr(current_user, 'subscription_type', 'basic')
        quality = 'SD'
        if plan == 'standard':
            quality = 'HD'
        elif plan == 'premium':
            quality = '4K'

        return render_template('player.html', content=content, quality=quality, profile_name=(profile.profile_name if profile else None))
    except Exception as e:
        print(f"Error en play_series: {e}")
        flash('Error al reproducir la serie', 'danger')
        return redirect(url_for('series'))
    
# ============================================================================
#                              MAIN
# ============================================================================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)