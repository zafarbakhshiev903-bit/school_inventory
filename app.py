from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, IntegerField, DateTimeField, BooleanField, PasswordField, SubmitField, FloatField
from wtforms.validators import DataRequired, Email, NumberRange, EqualTo, Length, Optional, ValidationError
from wtforms.fields import DateTimeLocalField
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
from flask_mail import Mail, Message
import os
from dotenv import load_dotenv
import io
import pandas as pd
import logging
import sys

# ==============================================
# НАСТРОЙКА ЛОГИРОВАНИЯ
# ==============================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# Корректная обработка UTC для Python 3.11+ и < 3.11
try:
    from datetime import UTC
except ImportError:
    UTC = timezone.utc

load_dotenv()

app = Flask(__name__)

# ==============================================
# КОНФИГУРАЦИЯ ПРИЛОЖЕНИЯ
# ==============================================

# Получаем DATABASE_URL из переменных окружения Render
DATABASE_URL = os.environ.get('DATABASE_URL')

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL не установлен. Добавьте его в Environment Variables на Render.")

# Исправляем URL для PostgreSQL
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SESSION_TYPE'] = 'filesystem'

# Email конфигурация (опционально)
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME', 'noreply@school-inventory.com')

# Инициализация расширений
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Пожалуйста, войдите для доступа к этой странице.'
login_manager.login_message_category = 'info'

try:
    mail = Mail(app)
except Exception as e:
    logger.warning(f"Email configuration failed: {e}. Email features will be disabled.")
    mail = None

# ==============================================
# МОДЕЛИ БАЗЫ ДАННЫХ
# ==============================================

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)  # Увеличил до 128 для безопасности
    role = db.Column(db.String(20), nullable=False, default='teacher')
    full_name = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(50))
    phone = db.Column(db.String(20))
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC))
    is_active = db.Column(db.Boolean, default=True)

    reservations = db.relationship(
        'Reservation',
        back_populates='user',
        foreign_keys='Reservation.user_id',
        lazy=True,
        cascade='all, delete-orphan'
    )

    approvals = db.relationship(
        'Reservation',
        back_populates='approver',
        foreign_keys='Reservation.approved_by',
        lazy=True
    )

    usage_logs = db.relationship('UsageLog', backref='user', lazy=True, cascade='all, delete-orphan')
    events_created = db.relationship('Event', backref='creator', lazy=True, foreign_keys='Event.created_by')
    notification_subscriptions = db.relationship('NotificationSubscription', backref='user', lazy=True, cascade='all, delete-orphan')

class Category(db.Model):
    __tablename__ = 'categories'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    description = db.Column(db.Text)
    color = db.Column(db.String(20), default='#3B82F6')
    icon = db.Column(db.String(30), default='package')
    
    items = db.relationship('InventoryItem', backref='category', lazy=True, cascade='all, delete-orphan')

class InventoryItem(db.Model):
    __tablename__ = 'inventory_items'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    available_quantity = db.Column(db.Integer, nullable=False, default=1)
    min_quantity = db.Column(db.Integer, default=1)
    location = db.Column(db.String(100))
    condition = db.Column(db.String(20), default='good')
    purchase_date = db.Column(db.Date)
    purchase_price = db.Column(db.Float)
    barcode = db.Column(db.String(50), unique=True)
    responsible_person = db.Column(db.String(100))
    status = db.Column(db.String(20), default='available')
    is_reservable = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC))
    
    reservations = db.relationship('Reservation', backref='item', lazy=True, cascade='all, delete-orphan')
    usage_logs = db.relationship('UsageLog', backref='item', lazy=True, cascade='all, delete-orphan')

class Reservation(db.Model):
    __tablename__ = 'reservations'
    
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('inventory_items.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    start_time = db.Column(db.DateTime(timezone=True), nullable=False)
    end_time = db.Column(db.DateTime(timezone=True), nullable=False)
    purpose = db.Column(db.String(200))
    status = db.Column(db.String(20), default='pending')
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC))
    approved_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    approved_at = db.Column(db.DateTime(timezone=True))

    user = db.relationship(
        'User',
        back_populates='reservations',
        foreign_keys=[user_id]
    )
    approver = db.relationship(
        'User',
        back_populates='approvals',
        foreign_keys=[approved_by]
    )

class UsageLog(db.Model):
    __tablename__ = 'usage_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('inventory_items.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    reservation_id = db.Column(db.Integer, db.ForeignKey('reservations.id'))
    action = db.Column(db.String(20), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    timestamp = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC))
    notes = db.Column(db.Text)
    condition_before = db.Column(db.String(20))
    condition_after = db.Column(db.String(20))

class Event(db.Model):
    __tablename__ = 'events'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    event_type = db.Column(db.String(50), nullable=False)
    start_time = db.Column(db.DateTime(timezone=True), nullable=False)
    end_time = db.Column(db.DateTime(timezone=True))
    location = db.Column(db.String(100))
    target_audience = db.Column(db.String(100))
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC))
    send_notifications = db.Column(db.Boolean, default=True)
    notification_sent = db.Column(db.Boolean, default=False)

class NotificationSubscription(db.Model):
    __tablename__ = 'notification_subscriptions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    event_type = db.Column(db.String(50), nullable=False)
    target_group = db.Column(db.String(50))
    email_enabled = db.Column(db.Boolean, default=True)
    sms_enabled = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC))

# ==============================================
# АВТОМАТИЧЕСКАЯ ИНИЦИАЛИЗАЦИЯ БАЗЫ ДАННЫХ
# ==============================================

def init_database():
    """Создает таблицы и начальные данные при первом запуске"""
    try:
        logger.info("🔍 Начало инициализации базы данных...")
        
        with app.app_context():
            # Создаем все таблицы (если их нет)
            db.create_all()
            logger.info("✅ Таблицы созданы/проверены")
            
            # Создаем администратора по умолчанию (если его нет)
            admin = User.query.filter_by(email='admin@school.edu').first()
            if not admin:
                admin = User(
                    username='admin',
                    email='admin@school.edu',
                    password_hash=generate_password_hash('admin123'),
                    full_name='Администратор Системы',
                    role='admin',
                    department='Администрация',
                    is_active=True
                )
                db.session.add(admin)
                logger.info("👑 Администратор создан (admin@school.edu / admin123)")
            
            # Создаем тестовую категорию (если нет категорий)
            if Category.query.count() == 0:
                default_category = Category(
                    name='Разное',
                    description='Общая категория для предметов',
                    color='#6B7280',
                    icon='package'
                )
                db.session.add(default_category)
                logger.info("📦 Создана категория по умолчанию")
            
            # Создаем тестовый предмет (если нет предметов)
            if InventoryItem.query.count() == 0 and Category.query.count() > 0:
                category = Category.query.first()
                test_item = InventoryItem(
                    name='Тестовый предмет',
                    description='Это тестовый предмет для демонстрации',
                    category_id=category.id,
                    quantity=10,
                    available_quantity=10,
                    min_quantity=2,
                    location='Склад',
                    condition='good',
                    is_reservable=True
                )
                db.session.add(test_item)
                logger.info("📋 Создан тестовый предмет")
            
            db.session.commit()
            logger.info("🎉 Инициализация базы данных завершена успешно")
            
    except Exception as e:
        logger.error(f"❌ Ошибка при инициализации базы данных: {e}", exc_info=True)
        if 'db' in locals() and db.session:
            db.session.rollback()

# Вызываем инициализацию при запуске приложения
with app.app_context():
    init_database()

# ==============================================
# ФОРМЫ
# ==============================================

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')

class RegistrationForm(FlaskForm):
    username = StringField('Имя пользователя',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Подтвердите пароль',
                                     validators=[DataRequired(), EqualTo('password', message='Пароли должны совпадать')])
    full_name = StringField('Полное имя', validators=[DataRequired(), Length(max=100)])
    department = StringField('Отдел/Кафедра', validators=[Optional(), Length(max=50)])
    phone = StringField('Телефон', validators=[Optional(), Length(max=20)])
    submit = SubmitField('Зарегистрироваться')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Это имя занято. Выберите другое.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Этот email уже зарегистрирован.')

class InventoryForm(FlaskForm):
    name = StringField('Название', validators=[DataRequired()])
    description = TextAreaField('Описание')
    category_id = SelectField('Категория', coerce=int, validators=[DataRequired()])
    quantity = IntegerField('Количество', validators=[DataRequired(), NumberRange(min=1)])
    min_quantity = IntegerField('Минимальное количество', validators=[NumberRange(min=0)])
    location = StringField('Местоположение')
    condition = SelectField('Состояние', choices=[
        ('excellent', 'Отличное'),
        ('good', 'Хорошее'),
        ('fair', 'Удовлетворительное'),
        ('poor', 'Плохое')
    ])
    purchase_price = FloatField('Стоимость покупки', validators=[Optional(), NumberRange(min=0)])
    barcode = StringField('Штрихкод')
    responsible_person = StringField('Ответственное лицо')
    is_reservable = BooleanField('Доступно для резервирования')

class ReservationForm(FlaskForm):
    item_id = SelectField('Предмет', coerce=int, validators=[DataRequired()])
    start_time = DateTimeLocalField('Время начала', 
                                   format='%Y-%m-%dT%H:%M',
                                   validators=[DataRequired()])
    end_time = DateTimeLocalField('Время окончания', 
                                 format='%Y-%m-%dT%H:%M',
                                 validators=[DataRequired()])
    quantity = IntegerField('Количество', 
                          validators=[DataRequired(), NumberRange(min=1)],
                          default=1)
    purpose = TextAreaField('Цель использования', 
                          validators=[DataRequired(), Length(max=500)])
    notes = TextAreaField('Заметки', validators=[Optional(), Length(max=500)])

    def __init__(self, *args, **kwargs):
        super(ReservationForm, self).__init__(*args, **kwargs)
        self.item_id.choices = [(i.id, f"{i.name} (доступно: {i.available_quantity})") 
                               for i in InventoryItem.query.filter_by(is_reservable=True, status='available').all()]

    def validate_end_time(self, field):
        if self.start_time.data and field.data:
            if field.data <= self.start_time.data:
                raise ValidationError('Время окончания должно быть позже времени начала')

class EventForm(FlaskForm):
    title = StringField('Название события', validators=[DataRequired(), Length(max=200)])
    description = TextAreaField('Описание', validators=[Optional(), Length(max=1000)])
    event_type = SelectField('Тип события', choices=[
        ('meeting', 'Собрание'),
        ('excursion', 'Экскурсия'),
        ('olympiad', 'Олимпиада'),
        ('parent_meeting', 'Родительское собрание'),
        ('other', 'Другое')
    ], validators=[DataRequired()])
    start_time = DateTimeLocalField('Время начала', 
                                   format='%Y-%m-%dT%H:%M',
                                   validators=[DataRequired()])
    end_time = DateTimeLocalField('Время окончания', 
                                 format='%Y-%m-%dT%H:%M',
                                 validators=[Optional()])
    location = StringField('Место проведения', validators=[Optional(), Length(max=100)])
    target_audience = StringField('Целевая аудитория', validators=[Optional(), Length(max=100)])
    send_notifications = BooleanField('Отправить уведомления', default=True)

    def validate_end_time(self, field):
        if self.start_time.data and field.data:
            if field.data <= self.start_time.data:
                raise ValidationError('Время окончания должно быть позже времени начала')

# ==============================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ==============================================

@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except:
        return None

def create_usage_log(item_id, user_id, action, quantity=1, notes='', reservation_id=None):
    """Создает запись в логе использования"""
    try:
        log = UsageLog(
            item_id=item_id,
            user_id=user_id,
            reservation_id=reservation_id,
            action=action,
            quantity=quantity,
            notes=notes,
            timestamp=datetime.now(UTC)
        )
        db.session.add(log)
        db.session.commit()
        return True
    except Exception as e:
        logger.error(f"Error creating usage log: {e}")
        db.session.rollback()
        return False

# ==============================================
# МАРШРУТЫ (ROUTES)
# ==============================================

@app.route('/')
def index():
    """Главная страница - перенаправление на дашборд или логин"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Дашборд системы"""
    try:
        # Статистика
        total_items = db.session.query(db.func.sum(InventoryItem.quantity)).scalar() or 0
        available_items = db.session.query(db.func.sum(InventoryItem.available_quantity)).scalar() or 0
        
        low_stock_items = InventoryItem.query.filter(
            InventoryItem.available_quantity <= InventoryItem.min_quantity
        ).count()
        
        active_reservations = Reservation.query.filter(
            Reservation.status.in_(['approved', 'active'])
        ).count()
        
        # Последние действия
        recent_logs = UsageLog.query.order_by(UsageLog.timestamp.desc()).limit(5).all()
        
        # Предстоящие события
        upcoming_events = Event.query.filter(
            Event.start_time > datetime.now(UTC)
        ).order_by(Event.start_time).limit(5).all()

        # Мои активные резервирования
        my_reservations = Reservation.query.filter_by(
            user_id=current_user.id
        ).filter(
            Reservation.status.in_(['approved', 'active'])
        ).order_by(Reservation.start_time).limit(5).all()

        return render_template('dashboard.html',
                               total_items=total_items,
                               available_items=available_items,
                               low_stock_items=low_stock_items,
                               active_reservations=active_reservations,
                               recent_logs=recent_logs,
                               upcoming_events=upcoming_events,
                               my_reservations=my_reservations)
    except Exception as e:
        logger.error(f"Error in dashboard route: {e}")
        flash('Произошла ошибка при загрузке данных', 'error')
        # Возвращаем шаблон с пустыми данными
        return render_template('dashboard.html',
                               total_items=0,
                               available_items=0,
                               low_stock_items=0,
                               active_reservations=0,
                               recent_logs=[],
                               upcoming_events=[],
                               my_reservations=[])

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Страница входа в систему"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    form = LoginForm()
    
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(email=form.email.data).first()
            
            if user and user.is_active and check_password_hash(user.password_hash, form.password.data):
                login_user(user, remember=form.remember.data)
                next_page = request.args.get('next')
                flash('Вы успешно вошли в систему!', 'success')
                logger.info(f"User logged in: {user.email}")
                return redirect(next_page) if next_page else redirect(url_for('dashboard'))
            else:
                flash('Неверный email или пароль', 'danger')
                logger.warning(f"Failed login attempt for email: {form.email.data}")
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash('Произошла ошибка при входе в систему', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    """Выход из системы"""
    logout_user()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Страница регистрации"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    
    if form.validate_on_submit():
        try:
            # Проверяем, не существует ли уже пользователь
            if User.query.filter_by(username=form.username.data).first():
                flash('Это имя пользователя уже занято', 'danger')
                return render_template('register.html', form=form)
            
            if User.query.filter_by(email=form.email.data).first():
                flash('Этот email уже зарегистрирован', 'danger')
                return render_template('register.html', form=form)
            
            # Создаем нового пользователя
            hashed_password = generate_password_hash(form.password.data)
            
            user = User(
                username=form.username.data,
                email=form.email.data,
                password_hash=hashed_password,
                full_name=form.full_name.data,
                department=form.department.data or '',
                phone=form.phone.data or '',
                role='teacher',
                is_active=True
            )
            
            db.session.add(user)
            db.session.commit()
            
            flash('Ваш аккаунт успешно создан! Теперь вы можете войти.', 'success')
            logger.info(f"New user registered: {user.email}")
            
            # Создаем лог
            create_usage_log(
                item_id=None,
                user_id=user.id,
                action='registered',
                notes='Пользователь зарегистрировался в системе'
            )
            
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Registration error: {e}")
            flash(f'Ошибка при регистрации: {str(e)}', 'danger')
    
    return render_template('register.html', form=form, title='Регистрация')

@app.route('/inventory')
@login_required
def inventory():
    """Страница инвентаря"""
    try:
        search = request.args.get('search', '')
        category_id = request.args.get('category', type=int)
        status = request.args.get('status', '')
        
        query = InventoryItem.query
        
        if search:
            query = query.filter(
                InventoryItem.name.ilike(f'%{search}%') | 
                InventoryItem.description.ilike(f'%{search}%')
            )
        
        if category_id:
            query = query.filter_by(category_id=category_id)
        
        if status:
            query = query.filter_by(status=status)
        
        items = query.order_by(InventoryItem.name).all()
        categories = Category.query.order_by(Category.name).all()
        
        return render_template('inventory.html', 
                             items=items, 
                             categories=categories,
                             search=search,
                             selected_category=category_id,
                             selected_status=status)
    except Exception as e:
        logger.error(f"Error in inventory route: {e}")
        flash('Произошла ошибка при загрузке инвентаря', 'error')
        return render_template('inventory.html', items=[], categories=[])

@app.route('/inventory/add', methods=['GET', 'POST'])
@login_required
def add_inventory():
    """Добавление нового предмета в инвентарь"""
    if current_user.role not in ['admin', 'teacher']:
        flash('Недостаточно прав для добавления предметов', 'danger')
        return redirect(url_for('inventory'))
    
    form = InventoryForm()
    form.category_id.choices = [(c.id, c.name) for c in Category.query.order_by(Category.name).all()]
    
    if form.validate_on_submit():
        try:
            item = InventoryItem(
                name=form.name.data,
                description=form.description.data or '',
                category_id=form.category_id.data,
                quantity=form.quantity.data,
                available_quantity=form.quantity.data,
                min_quantity=form.min_quantity.data or 1,
                location=form.location.data or '',
                condition=form.condition.data,
                purchase_price=form.purchase_price.data,
                barcode=form.barcode.data or '',
                responsible_person=form.responsible_person.data or '',
                is_reservable=form.is_reservable.data
            )
            
            db.session.add(item)
            db.session.commit()
            
            create_usage_log(
                item_id=item.id,
                user_id=current_user.id,
                action='added',
                quantity=item.quantity,
                notes=f'Добавлен предмет: {item.name}'
            )
            
            flash(f'Предмет "{item.name}" успешно добавлен!', 'success')
            logger.info(f"Item added: {item.name} by {current_user.email}")
            
            return redirect(url_for('inventory'))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error adding inventory item: {e}")
            flash(f'Ошибка при добавлении предмета: {str(e)}', 'danger')
    
    return render_template('add_inventory.html', form=form)

@app.route('/inventory/edit/<int:item_id>', methods=['GET', 'POST'])
@login_required
def edit_inventory(item_id):
    """Редактирование предмета инвентаря"""
    item = InventoryItem.query.get_or_404(item_id)
    
    if current_user.role not in ['admin', 'teacher']:
        flash('Недостаточно прав для редактирования предметов', 'danger')
        return redirect(url_for('inventory'))
    
    form = InventoryForm(obj=item)
    form.category_id.choices = [(c.id, c.name) for c in Category.query.order_by(Category.name).all()]
    
    if form.validate_on_submit():
        try:
            old_quantity = item.quantity
            quantity_diff = form.quantity.data - old_quantity
            
            form.populate_obj(item)
            item.available_quantity += quantity_diff
            item.available_quantity = max(0, item.available_quantity)
            item.updated_at = datetime.now(UTC)
            
            db.session.commit()
            
            create_usage_log(
                item_id=item.id,
                user_id=current_user.id,
                action='updated',
                quantity=item.quantity,
                notes=f'Обновлен предмет: {item.name}'
            )
            
            flash(f'Предмет "{item.name}" успешно обновлен!', 'success')
            logger.info(f"Item updated: {item.name} by {current_user.email}")
            
            return redirect(url_for('inventory'))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error updating inventory item: {e}")
            flash(f'Ошибка при обновлении предмета: {str(e)}', 'danger')
    
    return render_template('edit_inventory.html', form=form, item=item)

@app.route('/inventory/delete/<int:item_id>', methods=['POST'])
@login_required
def delete_inventory(item_id):
    """Удаление предмета инвентаря"""
    if current_user.role != 'admin':
        flash('Недостаточно прав для удаления предметов', 'danger')
        return redirect(url_for('inventory'))
    
    try:
        item = InventoryItem.query.get_or_404(item_id)
        item_name = item.name
        
        create_usage_log(
            item_id=item_id,
            user_id=current_user.id,
            action='deleted',
            quantity=item.quantity,
            notes=f'Удален предмет: {item_name}'
        )
        
        db.session.delete(item)
        db.session.commit()
        
        flash(f'Предмет "{item_name}" успешно удален!', 'success')
        logger.info(f"Item deleted: {item_name} by {current_user.email}")
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting inventory item: {e}")
        flash(f'Ошибка при удалении предмета: {str(e)}', 'danger')
    
    return redirect(url_for('inventory'))

@app.route('/reservations')
@login_required
def reservations():
    """Страница резервирований"""
    try:
        if current_user.role == 'admin':
            # Администраторы видят все резервирования
            reservations_list = Reservation.query.order_by(Reservation.created_at.desc()).all()
        else:
            # Обычные пользователи видят только свои резервирования
            reservations_list = Reservation.query.filter_by(
                user_id=current_user.id
            ).order_by(Reservation.created_at.desc()).all()
        
        now = datetime.now(UTC)
        
        return render_template('reservations.html', 
                             reservations=reservations_list,
                             now=now)
    except Exception as e:
        logger.error(f"Error in reservations route: {e}")
        flash('Произошла ошибка при загрузке резервирований', 'error')
        return render_template('reservations.html', reservations=[])

@app.route('/reservations/add', methods=['GET', 'POST'])
@login_required
def add_reservation():
    """Создание нового резервирования"""
    form = ReservationForm()
    
    if not form.item_id.choices:
        flash('Нет доступных предметов для резервирования', 'warning')
        return redirect(url_for('reservations'))
    
    if form.validate_on_submit():
        try:
            item = InventoryItem.query.get(form.item_id.data)
            
            if not item:
                flash('Предмет не найден', 'danger')
                return render_template('add_reservation.html', form=form)
            
            if item.available_quantity < form.quantity.data:
                flash('Недостаточно доступного количества!', 'danger')
                return render_template('add_reservation.html', form=form)
            
            # Проверяем конфликты резервирования
            start_time_utc = form.start_time.data.replace(tzinfo=UTC)
            end_time_utc = form.end_time.data.replace(tzinfo=UTC)
            
            conflicts = Reservation.query.filter(
                Reservation.item_id == form.item_id.data,
                Reservation.status.in_(['approved', 'active']),
                Reservation.start_time < end_time_utc,
                Reservation.end_time > start_time_utc
            ).all()
            
            total_reserved = sum(r.quantity for r in conflicts)
            if total_reserved + form.quantity.data > item.quantity:
                flash('Конфликт резервирования! Предмет уже зарезервирован на это время.', 'danger')
                return render_template('add_reservation.html', form=form)
            
            # Создаем резервирование
            reservation = Reservation(
                item_id=form.item_id.data,
                user_id=current_user.id,
                quantity=form.quantity.data,
                start_time=start_time_utc,
                end_time=end_time_utc,
                purpose=form.purpose.data,
                notes=form.notes.data or '',
                status='approved' if current_user.role == 'admin' else 'pending'
            )
            
            if current_user.role == 'admin':
                reservation.approved_by = current_user.id
                reservation.approved_at = datetime.now(UTC)
                item.available_quantity -= form.quantity.data
            
            db.session.add(reservation)
            db.session.commit()
            
            create_usage_log(
                item_id=form.item_id.data,
                user_id=current_user.id,
                reservation_id=reservation.id,
                action='reserved',
                quantity=form.quantity.data,
                notes=f'Создано резервирование: {form.purpose.data}'
            )
            
            status_msg = 'одобрено' if current_user.role == 'admin' else 'создано и ожидает одобрения'
            flash(f'Резервирование успешно {status_msg}!', 'success')
            logger.info(f"Reservation created: {reservation.id} by {current_user.email}")
            
            return redirect(url_for('reservations'))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error creating reservation: {e}")
            flash(f'Ошибка при создании резервирования: {str(e)}', 'danger')
    
    return render_template('add_reservation.html', form=form)

@app.route('/reservations/<int:id>/approve')
@login_required
def approve_reservation(id):
    """Одобрение резервирования (только для администраторов)"""
    if current_user.role != 'admin':
        flash('Недостаточно прав!', 'danger')
        return redirect(url_for('reservations'))
    
    try:
        reservation = Reservation.query.get_or_404(id)
        item = reservation.item
        
        if reservation.status != 'pending':
            flash('Это резервирование уже обработано', 'warning')
            return redirect(url_for('reservations'))
        
        if item.available_quantity >= reservation.quantity:
            reservation.status = 'approved'
            reservation.approved_by = current_user.id
            reservation.approved_at = datetime.now(UTC)
            item.available_quantity -= reservation.quantity
            
            db.session.commit()
            
            create_usage_log(
                item_id=reservation.item_id,
                user_id=current_user.id,
                reservation_id=reservation.id,
                action='approved',
                quantity=reservation.quantity,
                notes=f'Резервирование одобрено'
            )
            
            flash('Резервирование одобрено!', 'success')
            logger.info(f"Reservation approved: {reservation.id} by {current_user.email}")
        else:
            flash('Недостаточно доступного количества!', 'danger')
            
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error approving reservation: {e}")
        flash(f'Ошибка при одобрении резервирования: {str(e)}', 'danger')
    
    return redirect(url_for('reservations'))

@app.route('/reservations/<int:id>/complete')
@login_required
def complete_reservation(id):
    """Завершение резервирования"""
    reservation = Reservation.query.get_or_404(id)
    
    # Проверяем права
    if current_user.role != 'admin' and reservation.user_id != current_user.id:
        flash('Недостаточно прав!', 'danger')
        return redirect(url_for('reservations'))
    
    try:
        if reservation.status not in ['active', 'approved']:
            flash(f'Это резервирование не может быть завершено (статус: {reservation.status})', 'warning')
            return redirect(url_for('reservations'))

        reservation.status = 'completed'
        item = reservation.item
        item.available_quantity += reservation.quantity
        
        db.session.commit()
        
        create_usage_log(
            item_id=reservation.item_id,
            user_id=current_user.id,
            reservation_id=reservation.id,
            action='completed',
            quantity=reservation.quantity,
            notes='Резервирование завершено, предмет возвращен'
        )
        
        flash('Предмет возвращен!', 'success')
        logger.info(f"Reservation completed: {reservation.id} by {current_user.email}")
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error completing reservation: {e}")
        flash(f'Ошибка при завершении резервирования: {str(e)}', 'danger')
    
    return redirect(url_for('reservations'))

@app.route('/reservations/<int:id>/cancel')
@login_required
def cancel_reservation(id):
    """Отмена резервирования"""
    reservation = Reservation.query.get_or_404(id)
    
    # Проверяем права
    if current_user.role != 'admin' and reservation.user_id != current_user.id:
        flash('Недостаточно прав!', 'danger')
        return redirect(url_for('reservations'))
    
    try:
        if reservation.status not in ['pending', 'approved', 'active']:
            flash(f'Это резервирование не может быть отменено (статус: {reservation.status})', 'warning')
            return redirect(url_for('reservations'))

        old_status = reservation.status
        reservation.status = 'cancelled'
        
        # Возвращаем количество, если резервирование было активным
        if old_status in ['approved', 'active']:
            item = reservation.item
            item.available_quantity += reservation.quantity
        
        db.session.commit()
        
        create_usage_log(
            item_id=reservation.item_id,
            user_id=current_user.id,
            reservation_id=reservation.id,
            action='cancelled',
            quantity=reservation.quantity,
            notes=f'Резервирование отменено (было: {old_status})'
        )
        
        flash('Резервирование отменено!', 'success')
        logger.info(f"Reservation cancelled: {reservation.id} by {current_user.email}")
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error cancelling reservation: {e}")
        flash(f'Ошибка при отмене резервирования: {str(e)}', 'danger')
    
    return redirect(url_for('reservations'))

@app.route('/events')
@login_required
def events():
    """Страница событий"""
    try:
        now = datetime.now(UTC)
        upcoming = Event.query.filter(
            Event.start_time > now
        ).order_by(Event.start_time).all()
        
        past = Event.query.filter(
            Event.start_time <= now
        ).order_by(Event.start_time.desc()).limit(10).all()
        
        return render_template('events.html', 
                             upcoming_events=upcoming, 
                             past_events=past)
    except Exception as e:
        logger.error(f"Error in events route: {e}")
        flash('Произошла ошибка при загрузке событий', 'error')
        return render_template('events.html', upcoming_events=[], past_events=[])

@app.route('/events/add', methods=['GET', 'POST'])
@login_required
def add_event():
    """Создание нового события"""
    if current_user.role not in ['admin', 'teacher']:
        flash('Недостаточно прав для создания событий!', 'danger')
        return redirect(url_for('events'))
    
    form = EventForm()
    
    if form.validate_on_submit():
        try:
            start_time_utc = form.start_time.data.replace(tzinfo=UTC)
            end_time_utc = form.end_time.data.replace(tzinfo=UTC) if form.end_time.data else None

            event = Event(
                title=form.title.data,
                description=form.description.data or '',
                event_type=form.event_type.data,
                start_time=start_time_utc,
                end_time=end_time_utc,
                location=form.location.data or '',
                target_audience=form.target_audience.data or '',
                created_by=current_user.id,
                send_notifications=form.send_notifications.data
            )
            
            db.session.add(event)
            db.session.commit()
            
            flash('Событие успешно создано!', 'success')
            logger.info(f"Event created: {event.title} by {current_user.email}")
            
            return redirect(url_for('events'))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error creating event: {e}")
            flash(f'Ошибка при создании события: {str(e)}', 'danger')
    
    return render_template('add_event.html', form=form)

@app.route('/reports')
@login_required
def reports():
    """Страница отчетов"""
    try:
        # Статистика использования
        usage_stats = db.session.query(
            InventoryItem.name,
            db.func.count(UsageLog.id).label('usage_count')
        ).join(UsageLog).group_by(InventoryItem.id).order_by(db.desc('usage_count')).limit(10).all()
        
        # Статистика по категориям
        category_stats = db.session.query(
            Category.name,
            db.func.count(InventoryItem.id).label('item_count'),
            db.func.sum(InventoryItem.quantity).label('total_quantity')
        ).join(InventoryItem).group_by(Category.id).all()
        
        # Предметы с низким запасом
        low_stock = InventoryItem.query.filter(
            InventoryItem.available_quantity <= InventoryItem.min_quantity
        ).all()
        
        # Активные пользователи
        active_users = db.session.query(
            User.full_name,
            db.func.count(Reservation.id).label('reservation_count')
        ).join(Reservation).group_by(User.id).order_by(db.desc('reservation_count')).limit(5).all()
        
        return render_template('reports.html', 
                             usage_stats=usage_stats,
                             category_stats=category_stats,
                             low_stock=low_stock,
                             active_users=active_users)
    except Exception as e:
        logger.error(f"Error in reports route: {e}")
        flash('Произошла ошибка при загрузке отчетов', 'error')
        return render_template('reports.html', 
                             usage_stats=[],
                             category_stats=[],
                             low_stock=[],
                             active_users=[])

# ==============================================
# МАРШРУТЫ ДЛЯ ЭКСПОРТА В EXCEL
# ==============================================

@app.route('/export/inventory')
@login_required
def export_inventory():
    """Экспорт инвентаря в Excel"""
    if current_user.role != 'admin':
        flash('Недостаточно прав для экспорта!', 'danger')
        return redirect(url_for('reports'))
    
    try:
        items = InventoryItem.query.all()
        
        data = []
        for item in items:
            data.append({
                'ID': item.id,
                'Название': item.name,
                'Описание': item.description or '',
                'Категория': item.category.name if item.category else '',
                'Количество': item.quantity,
                'Доступно': item.available_quantity,
                'Минимальное количество': item.min_quantity,
                'Местоположение': item.location or '',
                'Состояние': item.condition,
                'Дата покупки': item.purchase_date.strftime('%Y-%m-%d') if item.purchase_date else '',
                'Стоимость': item.purchase_price or 0,
                'Штрихкод': item.barcode or '',
                'Ответственный': item.responsible_person or '',
                'Статус': item.status,
                'Для резервирования': 'Да' if item.is_reservable else 'Нет',
                'Дата создания': item.created_at.strftime('%Y-%m-%d %H:%M'),
                'Дата обновления': item.updated_at.strftime('%Y-%m-%d %H:%M') if item.updated_at else ''
            })
        
        df = pd.DataFrame(data)
        
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Инвентарь', index=False)
            
            worksheet = writer.sheets['Инвентарь']
            for column in worksheet.columns:
                max_length = 0
                column_letter = column[0].column_letter
                for cell in column:
                    try:
                        if len(str(cell.value)) > max_length:
                            max_length = len(str(cell.value))
                    except:
                        pass
                adjusted_width = min(max_length + 2, 50)
                worksheet.column_dimensions[column_letter].width = adjusted_width
        
        output.seek(0)
        
        return Response(
            output,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": "attachment;filename=inventory_report.xlsx"}
        )
        
    except Exception as e:
        logger.error(f"Error exporting inventory: {e}")
        flash(f'Ошибка при экспорте: {str(e)}', 'danger')
        return redirect(url_for('reports'))

@app.route('/export/reservations')
@login_required
def export_reservations():
    """Экспорт резервирований в Excel"""
    if current_user.role != 'admin':
        flash('Недостаточно прав для экспорта!', 'danger')
        return redirect(url_for('reports'))
    
    try:
        reservations = Reservation.query.order_by(Reservation.created_at.desc()).all()
        
        data = []
        for res in reservations:
            data.append({
                'ID': res.id,
                'Предмет': res.item.name if res.item else '',
                'Пользователь': res.user.full_name if res.user else '',
                'Email пользователя': res.user.email if res.user else '',
                'Количество': res.quantity,
                'Начало': res.start_time.strftime('%Y-%m-%d %H:%M'),
                'Окончание': res.end_time.strftime('%Y-%m-%d %H:%M'),
                'Цель': res.purpose or '',
                'Статус': res.status,
                'Заметки': res.notes or '',
                'Дата создания': res.created_at.strftime('%Y-%m-%d %H:%M'),
                'Утверждено': 'Да' if res.approved_by else 'Нет',
                'Утвердил': res.approver.full_name if res.approver else '',
                'Дата утверждения': res.approved_at.strftime('%Y-%m-%d %H:%M') if res.approved_at else ''
            })
        
        df = pd.DataFrame(data)
        
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Резервирования', index=False)
            
            worksheet = writer.sheets['Резервирования']
            for column in worksheet.columns:
                max_length = 0
                column_letter = column[0].column_letter
                for cell in column:
                    try:
                        if len(str(cell.value)) > max_length:
                            max_length = len(str(cell.value))
                    except:
                        pass
                adjusted_width = min(max_length + 2, 50)
                worksheet.column_dimensions[column_letter].width = adjusted_width
        
        output.seek(0)
        
        return Response(
            output,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": "attachment;filename=reservations_report.xlsx"}
        )
        
    except Exception as e:
        logger.error(f"Error exporting reservations: {e}")
        flash(f'Ошибка при экспорте: {str(e)}', 'danger')
        return redirect(url_for('reports'))

# ==============================================
# СИСТЕМНЫЕ МАРШРУТЫ
# ==============================================

@app.route('/health')
def health():
    """Health check endpoint для Render"""
    try:
        # Проверяем подключение к базе данных
        db.session.execute('SELECT 1')
        
        # Проверяем существование основных таблиц
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        
        required_tables = ['users', 'inventory_items', 'categories']
        missing_tables = [t for t in required_tables if t not in tables]
        
        if missing_tables:
            return jsonify({
                'status': 'degraded',
                'database': 'connected',
                'message': f'Missing tables: {missing_tables}',
                'tables': tables,
                'timestamp': datetime.now(UTC).isoformat()
            }), 200
        
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'tables_count': len(tables),
            'timestamp': datetime.now(UTC).isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now(UTC).isoformat()
        }), 500

@app.errorhandler(404)
def not_found_error(error):
    """Обработка ошибки 404"""
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """Обработка ошибки 500"""
    db.session.rollback()
    logger.error(f"Internal server error: {error}")
    return render_template('500.html'), 500

# ==============================================
# ЗАПУСК ПРИЛОЖЕНИЯ
# ==============================================

if __name__ == "__main__":
    logger.info("🚀 Запуск приложения School Inventory System")
    logger.info(f"📊 Подключение к базе: {app.config['SQLALCHEMY_DATABASE_URI'][:50]}...")
    
    port = int(os.environ.get("PORT", 10000))
    logger.info(f"🌐 Запуск на порту: {port}")
    
    app.run(host="0.0.0.0", port=port, debug=False)
