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


# ============================================================================
#                            RUTAS PRINCIPALES
# ============================================================================

@app.route('/')
def home():
    if not current_user.is_authenticated:
        return render_template('landing.html')
    
    # Esta consulta usa el modelo Movie actualizado
    movies = Movie.query.order_by(Movie.imdb_rating.desc().nulls_last()).limit(12).all()
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
    """Panel de administración de usuarios"""
    # Deberías añadir una comprobación de 'is_admin' aquí
    # if not current_user.is_admin:
    #     flash('Acceso no autorizado', 'danger')
    #     return redirect(url_for('home'))
        
    users = User.query.all()
    # Asumiendo que tienes un 'admin_users.html'
    return render_template('admin_users.html', users=users)


@app.route('/admin/deactivate-user/<int:user_id>', methods=['POST'])
@login_required
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
        return render_template('search.html', results=results, query=query)
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
        
        return render_template('movies.html', movies=movies)
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
                   total_seasons, imdb_rating
            FROM series
            ORDER BY imdb_rating DESC NULLS LAST
        """)).fetchall()
        
        return render_template('series.html', series_list=series_list) # 'series_list' para no confundir
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
        
        # Usar el perfil principal o el primero
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


# =====================
# Perfiles de usuario
# =====================

@app.route('/profiles')
@login_required
def profiles():
    """Listar perfiles del usuario y formulario para crear"""
    try:
        profiles = db.session.execute(text("""
            SELECT id, profile_name, profile_type, is_main, created_at
            FROM profiles
            WHERE user_id = :user_id
            ORDER BY is_main DESC, created_at ASC
        """), {'user_id': current_user.id}).fetchall()

        # perfil seleccionado en sesión
        selected = None
        if session.get('profile_id'):
            selected = db.session.execute(text("SELECT id, profile_name FROM profiles WHERE id = :pid AND user_id = :uid"),
                                          {'pid': session.get('profile_id'), 'uid': current_user.id}).fetchone()

        return render_template('profiles.html', profiles=profiles, selected_profile=selected)
    except Exception as e:
        print(f"Error en profiles: {e}")
        flash('Error al cargar perfiles', 'danger')
        return redirect(url_for('profile'))


@app.route('/profiles/create', methods=['POST'])
@login_required
def create_profile():
    name = request.form.get('profile_name')
    ptype = request.form.get('profile_type', 'standard')
    if not name:
        flash('El nombre del perfil es requerido', 'warning')
        return redirect(url_for('profiles'))
    try:
        # si el usuario no tiene perfiles, este será el main
        has_any = db.session.execute(text("SELECT 1 FROM profiles WHERE user_id = :uid LIMIT 1"), {'uid': current_user.id}).fetchone()
        is_main = False if has_any else True
        db.session.execute(text("""
            INSERT INTO profiles (user_id, profile_name, profile_type, is_main, created_at)
            VALUES (:uid, :pname, :ptype, :is_main, CURRENT_TIMESTAMP)
        """), {'uid': current_user.id, 'pname': name, 'ptype': ptype, 'is_main': is_main})
        db.session.commit()
        flash('Perfil creado', 'success')
    except Exception as e:
        db.session.rollback()
        print(f"Error creando perfil: {e}")
        flash('Error al crear perfil', 'danger')
    return redirect(url_for('profiles'))


@app.route('/profiles/switch', methods=['POST'])
@login_required
def switch_profile():
    pid = request.form.get('profile_id') or request.json.get('profile_id') if request.is_json else None
    if not pid:
        return {'success': False, 'message': 'profile_id no proporcionado'}, 400
    # verificar que el perfil pertenezca al usuario
    p = db.session.execute(text("SELECT id FROM profiles WHERE id = :pid AND user_id = :uid"), {'pid': pid, 'uid': current_user.id}).fetchone()
    if not p:
        return {'success': False, 'message': 'Perfil no encontrado'}, 404
    session['profile_id'] = p.id
    return {'success': True, 'message': 'Perfil seleccionado', 'profile_id': p.id}


@app.route('/add-to-watchlist', methods=['POST'])
@login_required
def add_to_watchlist():
    """API para agregar contenido a la watchlist"""
    try:
        data = request.get_json()
        content_id = data.get('content_id')
        content_type = data.get('content_type')
        
        # Preferir perfil seleccionado en sesión, si existe
        profile_id = session.get('profile_id')
        if profile_id:
            profile = db.session.execute(text("SELECT id FROM profiles WHERE id = :pid AND user_id = :uid"),
                                         {'pid': profile_id, 'uid': current_user.id}).fetchone()
        else:
            # Obtener el perfil principal del usuario
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
            return {'success': False, 'message': 'Ya está en tu lista'}, 400
        
        # Agregar a la watchlist y devolver el id creado
        if content_type == 'movie':
            new_row = db.session.execute(text("""
                INSERT INTO watch_list (profile_id, movie_id, status, added_date)
                VALUES (:profile_id, :content_id, 'to_watch', CURRENT_DATE)
                RETURNING id
            """), {'profile_id': profile.id, 'content_id': content_id}).fetchone()
        else:
            new_row = db.session.execute(text("""
                INSERT INTO watch_list (profile_id, series_id, status, added_date)
                VALUES (:profile_id, :content_id, 'to_watch', CURRENT_DATE)
                RETURNING id
            """), {'profile_id': profile.id, 'content_id': content_id}).fetchone()

        db.session.commit()
        wid = new_row.id if new_row else None
        return {'success': True, 'message': 'Agregado a tu lista', 'watchlist_id': wid}
    
    except Exception as e:
        db.session.rollback()
        print(f"Error al agregar a watchlist: {e}")
        return {'success': False, 'message': 'Error al agregar'}, 500


@app.route('/remove-from-watchlist', methods=['POST'])
@login_required
def remove_from_watchlist():
    """API para eliminar un elemento de la watchlist por su id (watch_list.id)"""
    try:
        data = request.get_json()
        watchlist_id = data.get('watchlist_id')
        if not watchlist_id:
            return {'success': False, 'message': 'watchlist_id no proporcionado'}, 400

        # Obtener perfil principal del usuario
        profile = db.session.execute(text("""
            SELECT id FROM profiles
            WHERE user_id = :user_id
            ORDER BY is_main DESC, created_at ASC
            LIMIT 1
        """), {'user_id': current_user.id}).fetchone()

        if not profile:
            return {'success': False, 'message': 'No tienes perfiles creados'}, 400

        res = db.session.execute(text("""
            DELETE FROM watch_list
            WHERE id = :wid AND profile_id = :profile_id
        """), {'wid': watchlist_id, 'profile_id': profile.id})

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
        
        # Simulamos la reproducción desde aquí: redirigir a player
        # Determinar calidad según el plan del usuario
        plan = current_user.subscription_type or 'basic'
        quality = 'SD' if plan == 'basic' else 'HD' if plan == 'standard' else '4K'
        # obtener perfil seleccionado
        sel = None
        if session.get('profile_id'):
            sel = db.session.execute(text('SELECT profile_name FROM profiles WHERE id = :pid'), {'pid': session.get('profile_id')}).fetchone()
        profile_name = sel.profile_name if sel else None
        content = movie
        return render_template('player.html', content=content, quality=quality, profile_name=profile_name)
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
        
        # Simulamos la reproducción desde aquí: redirigir a player
        plan = current_user.subscription_type or 'basic'
        quality = 'SD' if plan == 'basic' else 'HD' if plan == 'standard' else '4K'
        sel = None
        if session.get('profile_id'):
            sel = db.session.execute(text('SELECT profile_name FROM profiles WHERE id = :pid'), {'pid': session.get('profile_id')}).fetchone()
        profile_name = sel.profile_name if sel else None
        content = series
        return render_template('player.html', content=content, quality=quality, profile_name=profile_name)
    except Exception as e:
        flash('Error al cargar detalles de la serie', 'danger')
        print(f"Error en series_detail: {e}")
        return redirect(url_for('series'))
    
# ============================================================================
#                              MAIN
# ============================================================================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)