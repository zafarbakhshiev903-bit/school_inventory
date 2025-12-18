from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response
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
from sqlalchemy import text
import pandas as pd

# Корректная обработка UTC для Python 3.11+ и < 3.11
try:
    from datetime import UTC
except ImportError:
    UTC = timezone.utc

load_dotenv()

app = Flask(__name__)
DATABASE_URL = os.environ.get('DATABASE_URL')

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# Email configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
mail = Mail(app)

# Database Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='teacher')  # admin, teacher, staff
    full_name = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(50))
    phone = db.Column(db.String(20))
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC))

    # Связь с резервами (тот, кто создал бронь)
    reservations = db.relationship(
        'Reservation',
        back_populates='user',
        foreign_keys='Reservation.user_id',
        lazy=True
    )

    # Связь с утверждениями (тот, кто одобрил)
    approvals = db.relationship(
        'Reservation',
        back_populates='approver',
        foreign_keys='Reservation.approved_by',
        lazy=True
    )

    usage_logs = db.relationship('UsageLog', backref='user', lazy=True)

class Category(db.Model):
    __tablename__ = 'categories'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    description = db.Column(db.Text)
    color = db.Column(db.String(20), default='#3B82F6')
    icon = db.Column(db.String(30), default='package')
    
    items = db.relationship('InventoryItem', backref='category', lazy=True)

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
    condition = db.Column(db.String(20), default='good')  # excellent, good, fair, poor
    purchase_date = db.Column(db.Date)
    purchase_price = db.Column(db.Float)
    barcode = db.Column(db.String(50), unique=True)
    responsible_person = db.Column(db.String(100))
    status = db.Column(db.String(20), default='available')  # available, maintenance, disposed
    is_reservable = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC))
    
    reservations = db.relationship('Reservation', backref='item', lazy=True)
    usage_logs = db.relationship('UsageLog', backref='item', lazy=True)

class Reservation(db.Model):
    __tablename__ = 'reservations'
    
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('inventory_items.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    start_time = db.Column(db.DateTime(timezone=True), nullable=False)
    end_time = db.Column(db.DateTime(timezone=True), nullable=False)
    purpose = db.Column(db.String(200))
    status = db.Column(db.String(20), default='pending')  # pending, approved, active, completed, cancelled
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC))
    approved_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    approved_at = db.Column(db.DateTime(timezone=True))

    # связи обратно к User
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
    action = db.Column(db.String(20), nullable=False)  # borrowed, returned, reserved, cancelled
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
    event_type = db.Column(db.String(50), nullable=False)  # meeting, excursion, olympiad, parent_meeting
    start_time = db.Column(db.DateTime(timezone=True), nullable=False)
    end_time = db.Column(db.DateTime(timezone=True))
    location = db.Column(db.String(100))
    target_audience = db.Column(db.String(100))  # all, teachers, parents, students, class_1a, etc.
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC))
    send_notifications = db.Column(db.Boolean, default=True)
    notification_sent = db.Column(db.Boolean, default=False)

class NotificationSubscription(db.Model):
    __tablename__ = 'notification_subscriptions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    event_type = db.Column(db.String(50), nullable=False)
    target_group = db.Column(db.String(50))  # all, class_1a, teachers, etc.
    email_enabled = db.Column(db.Boolean, default=True)
    sms_enabled = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC))

# Forms
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
    item_id = SelectField('Интихоби ашё', coerce=int, validators=[DataRequired()])
    start_time = DateTimeLocalField('Вақти оғоз', 
                                   format='%Y-%m-%dT%H:%M',
                                   validators=[DataRequired()])
    end_time = DateTimeLocalField('Вақти анҷом', 
                                 format='%Y-%m-%dT%H:%M',
                                 validators=[DataRequired()])
    quantity = IntegerField('Миқдор', 
                          validators=[DataRequired(), NumberRange(min=1)],
                          default=1)
    purpose = TextAreaField('Мақсад', 
                          validators=[DataRequired(), Length(max=500)])
    notes = TextAreaField('Қайдҳо', validators=[Optional(), Length(max=500)])

    def __init__(self, *args, **kwargs):
        super(ReservationForm, self).__init__(*args, **kwargs)
        self.item_id.choices = [(i.id, i.name) for i in InventoryItem.query.filter_by(is_reservable=True).all()]

    def validate_end_time(self, field):
        if self.start_time.data and field.data:
            if field.data <= self.start_time.data:
                raise ValidationError('Вақти анҷом бояд аз вақти оғоз дертар бошад')

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

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def dashboard():
    try:
        total_items = db.session.query(db.func.sum(InventoryItem.quantity)).scalar() or 0
        available_items = db.session.query(db.func.sum(InventoryItem.available_quantity)).scalar() or 0
        low_stock_items = InventoryItem.query.filter(
            InventoryItem.available_quantity <= InventoryItem.min_quantity
        ).count()
        active_reservations = Reservation.query.filter_by(status='active').count()
        
        recent_logs = UsageLog.query.order_by(UsageLog.timestamp.desc()).limit(5).all()
        
        upcoming_events = Event.query.filter(
            Event.start_time > datetime.now(UTC)
        ).order_by(Event.start_time).limit(5).all()

        return render_template('dashboard.html',
                               total_items=total_items,
                               available_items=available_items,
                               low_stock_items=low_stock_items,
                               active_reservations=active_reservations,
                               recent_logs=recent_logs,
                               upcoming_events=upcoming_events)
    except Exception as e:
        print(f"Error in dashboard route: {e}")
        flash('Произошла ошибка при загрузке данных', 'error')
        return render_template('dashboard.html',
                               total_items=0,
                               available_items=0,
                               low_stock_items=0,
                               active_reservations=0,
                               recent_logs=[],
                               upcoming_events=[])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    form = LoginForm() 
    
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('Вы успешно вошли в систему!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Вход не удался. Проверьте Email и Пароль.', 'danger')
            
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        
        user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_password,
            full_name=form.full_name.data,
            department=form.department.data,
            phone=form.phone.data,
            role='teacher'
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash('Ваш аккаунт создан! Теперь вы можете войти.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html', title='Регистрация', form=form)

@app.route('/inventory')
@login_required
def inventory():
    search = request.args.get('search', '')
    category_id = request.args.get('category', type=int)
    status = request.args.get('status', '')
    
    query = InventoryItem.query
    
    if search:
        query = query.filter(InventoryItem.name.contains(search) | 
                           InventoryItem.description.contains(search))
    if category_id:
        query = query.filter_by(category_id=category_id)
    if status:
        query = query.filter_by(status=status)
    
    items = query.all()
    categories = Category.query.all()
    
    return render_template('inventory.html', items=items, categories=categories)

@app.route('/inventory/edit/<int:item_id>', methods=['GET', 'POST'])
@login_required
def edit_inventory(item_id):
    item = InventoryItem.query.get_or_404(item_id)
    form = InventoryForm(obj=item)
    form.category_id.choices = [(c.id, c.name) for c in Category.query.all()]
    
    if form.validate_on_submit():
        old_quantity = item.quantity
        quantity_diff = form.quantity.data - old_quantity
        
        form.populate_obj(item)

        item.available_quantity += quantity_diff
        item.available_quantity = max(0, item.available_quantity)

        db.session.commit()
        
        log = UsageLog(
            item_id=item.id,
            user_id=current_user.id,
            action='updated',
            quantity=item.quantity,
            notes=f'Обновление предмета инвентаря'
        )
        db.session.add(log)
        db.session.commit()
        
        flash(f'Предмет "{item.name}" успешно обновлен! ✅', 'success')
        return redirect(url_for('inventory'))

    return render_template('edit_inventory.html', form=form, item=item)

@app.route('/inventory/add', methods=['GET', 'POST'])
@login_required
def add_inventory():
    form = InventoryForm()
    form.category_id.choices = [(c.id, c.name) for c in Category.query.all()]
    
    if form.validate_on_submit():
        item = InventoryItem(
            name=form.name.data,
            description=form.description.data,
            category_id=form.category_id.data,
            quantity=form.quantity.data,
            available_quantity=form.quantity.data,
            min_quantity=form.min_quantity.data or 1,
            location=form.location.data,
            condition=form.condition.data,
            purchase_price=form.purchase_price.data,
            barcode=form.barcode.data,
            responsible_person=form.responsible_person.data,
            is_reservable=form.is_reservable.data
        )
        db.session.add(item)
        db.session.commit()
        
        log = UsageLog(
            item_id=item.id,
            user_id=current_user.id,
            action='added',
            quantity=item.quantity,
            notes=f'Предмет добавлен в систему'
        )
        db.session.add(log)
        db.session.commit()
        
        flash('Предмет успешно добавлен!')
        return redirect(url_for('inventory'))
    
    return render_template('add_inventory.html', form=form)

@app.route('/reservations')
@login_required
def reservations():
    if current_user.role == 'admin':
        reservations = Reservation.query.order_by(Reservation.created_at.desc()).all()
    else:
        reservations = Reservation.query.filter_by(user_id=current_user.id).order_by(Reservation.created_at.desc()).all()
    
    now = datetime.now(UTC)
    
    return render_template('reservations.html', 
                         reservations=reservations,
                         now=now)

@app.route('/reservations/add', methods=['GET', 'POST'])
@login_required
def add_reservation():
    form = ReservationForm()
    form.item_id.choices = [(i.id, f"{i.name} (доступно: {i.available_quantity})") 
                            for i in InventoryItem.query.filter_by(is_reservable=True, status='available').all()]
    
    if form.validate_on_submit():
        item = InventoryItem.query.get(form.item_id.data)
        
        if item.available_quantity < form.quantity.data:
            flash('Недостаточно доступного количества!')
            return render_template('add_reservation.html', form=form)
        
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
            flash('Конфликт резервирования! Предмет уже зарезервирован на это время.')
            return render_template('add_reservation.html', form=form)
        
        reservation = Reservation(
            item_id=form.item_id.data,
            user_id=current_user.id,
            quantity=form.quantity.data,
            start_time=start_time_utc,
            end_time=end_time_utc,
            purpose=form.purpose.data,
            notes=form.notes.data,
            status='approved' if current_user.role == 'admin' else 'pending'
        )
        db.session.add(reservation)
        
        if current_user.role == 'admin':
            reservation.approved_by = current_user.id
            reservation.approved_at = datetime.now(UTC)
            item.available_quantity -= form.quantity.data
        
        db.session.commit()
        
        log = UsageLog(
            item_id=form.item_id.data,
            user_id=current_user.id,
            reservation_id=reservation.id,
            action='reserved',
            quantity=form.quantity.data,
            notes=f'Резервирование: {form.purpose.data}'
        )
        db.session.add(log)
        db.session.commit()
        
        flash('Резервирование создано!')
        return redirect(url_for('reservations'))
    
    return render_template('add_reservation.html', form=form)

@app.route('/reservations/<int:id>/approve')
@login_required
def approve_reservation(id):
    if current_user.role != 'admin':
        flash('Недостаточно прав!')
        return redirect(url_for('reservations'))
    
    reservation = Reservation.query.get_or_404(id)
    item = reservation.item
    
    if item.available_quantity >= reservation.quantity:
        reservation.status = 'approved'
        reservation.approved_by = current_user.id
        reservation.approved_at = datetime.now(UTC)
        item.available_quantity -= reservation.quantity
        
        db.session.commit()
        
        send_reservation_notification(reservation, 'approved')
        
        flash('Резервирование одобрено!')
    else:
        flash('Недостаточно доступного количества!')
    
    return redirect(url_for('reservations'))

@app.route('/reservations/<int:id>/complete')
@login_required
def complete_reservation(id):
    reservation = Reservation.query.get_or_404(id)
    
    if current_user.role != 'admin' and reservation.user_id != current_user.id:
        flash('Недостаточно прав!')
        return redirect(url_for('reservations'))
    
    if reservation.status not in ['active', 'approved']:
         flash('Это резервирование не может быть завершено (статус: {reservation.status}).')
         return redirect(url_for('reservations'))

    reservation.status = 'completed'
    item = reservation.item
    item.available_quantity += reservation.quantity
    
    db.session.commit()
    
    log = UsageLog(
        item_id=reservation.item_id,
        user_id=current_user.id,
        reservation_id=reservation.id,
        action='returned',
        quantity=reservation.quantity,
        notes='Предмет возвращен'
    )
    db.session.add(log)
    db.session.commit()
    
    flash('Предмет возвращен!')
    return redirect(url_for('reservations'))

@app.route('/events')
@login_required
def events():
    now = datetime.now(UTC)
    upcoming = Event.query.filter(Event.start_time > now).order_by(Event.start_time).all()
    past = Event.query.filter(Event.start_time <= now).order_by(Event.start_time.desc()).limit(10).all()
    
    return render_template('events.html', upcoming_events=upcoming, past_events=past)

@app.route('/events/add', methods=['GET', 'POST'])
@login_required
def add_event():
    if current_user.role not in ['admin', 'teacher']:
        flash('Недостаточно прав!')
        return redirect(url_for('events'))
    
    form = EventForm()
    
    if form.validate_on_submit():
        start_time_utc = form.start_time.data.replace(tzinfo=UTC)
        end_time_utc = form.end_time.data.replace(tzinfo=UTC) if form.end_time.data else None

        event = Event(
            title=form.title.data,
            description=form.description.data,
            event_type=form.event_type.data,
            start_time=start_time_utc,
            end_time=end_time_utc,
            location=form.location.data,
            target_audience=form.target_audience.data,
            created_by=current_user.id,
            send_notifications=form.send_notifications.data
        )
        db.session.add(event)
        db.session.commit()
        
        if form.send_notifications.data:
            send_event_notifications(event)
        
        flash('Событие создано!')
        return redirect(url_for('events'))
    
    return render_template('add_event.html', form=form)

@app.route('/reports')
@login_required
def reports():
    usage_stats = db.session.query(
        InventoryItem.name,
        db.func.count(UsageLog.id).label('usage_count')
    ).join(UsageLog).group_by(InventoryItem.id).order_by(db.desc('usage_count')).limit(10).all()
    
    category_stats = db.session.query(
        Category.name,
        db.func.count(InventoryItem.id).label('item_count'),
        db.func.sum(InventoryItem.quantity).label('total_quantity')
    ).join(InventoryItem).group_by(Category.id).all()
    
    low_stock = InventoryItem.query.filter(InventoryItem.available_quantity <= InventoryItem.min_quantity).all()
    
    return render_template('reports.html', 
                         usage_stats=usage_stats,
                         category_stats=category_stats,
                         low_stock=low_stock)

# Новые маршруты для экспорта отчетов в Excel
@app.route('/export/inventory')
@login_required
def export_inventory():
    if current_user.role != 'admin':
        flash('Недостаточно прав!', 'error')
        return redirect(url_for('reports'))
    
    try:
        # Получаем все данные инвентаря
        items = InventoryItem.query.all()
        
        # Создаем DataFrame
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
        
        # Создаем Excel файл в памяти
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Инвентарь', index=False)
            
            # Настраиваем ширину колонок
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
        
        # Возвращаем файл
        return Response(
            output,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": "attachment;filename=inventory_report.xlsx"}
        )
        
    except Exception as e:
        print(f"Error exporting inventory: {e}")
        flash(f'Ошибка при экспорте: {str(e)}', 'error')
        return redirect(url_for('reports'))

@app.route('/export/reservations')
@login_required
def export_reservations():
    if current_user.role != 'admin':
        flash('Недостаточно прав!', 'error')
        return redirect(url_for('reports'))
    
    try:
        # Получаем все резервирования
        reservations = Reservation.query.order_by(Reservation.created_at.desc()).all()
        
        # Создаем DataFrame
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
        
        # Создаем Excel файл в памяти
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Резервирования', index=False)
            
            # Настраиваем ширину колонок
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
        
        # Возвращаем файл
        return Response(
            output,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": "attachment;filename=reservations_report.xlsx"}
        )
        
    except Exception as e:
        print(f"Error exporting reservations: {e}")
        flash(f'Ошибка при экспорте: {str(e)}', 'error')
        return redirect(url_for('reports'))

@app.route('/export/usage')
@login_required
def export_usage():
    if current_user.role != 'admin':
        flash('Недостаточно прав!', 'error')
        return redirect(url_for('reports'))
    
    try:
        # Получаем все логи использования
        logs = UsageLog.query.order_by(UsageLog.timestamp.desc()).all()
        
        # Создаем DataFrame
        data = []
        for log in logs:
            data.append({
                'ID': log.id,
                'Предмет': log.item.name if log.item else '',
                'Пользователь': log.user.full_name if log.user else '',
                'Email пользователя': log.user.email if log.user else '',
                'Действие': log.action,
                'Количество': log.quantity,
                'Дата и время': log.timestamp.strftime('%Y-%m-%d %H:%M'),
                'Заметки': log.notes or '',
                'Состояние до': log.condition_before or '',
                'Состояние после': log.condition_after or '',
                'ID резервирования': log.reservation_id or ''
            })
        
        df = pd.DataFrame(data)
        
        # Создаем Excel файл в памяти
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Использование', index=False)
            
            # Настраиваем ширину колонок
            worksheet = writer.sheets['Использование']
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
        
        # Возвращаем файл
        return Response(
            output,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": "attachment;filename=usage_report.xlsx"}
        )
        
    except Exception as e:
        print(f"Error exporting usage logs: {e}")
        flash(f'Ошибка при экспорте: {str(e)}', 'error')
        return redirect(url_for('reports'))

@app.route('/export/low_stock')
@login_required
def export_low_stock():
    if current_user.role != 'admin':
        flash('Недостаточно прав!', 'error')
        return redirect(url_for('reports'))
    
    try:
        # Получаем предметы с низким запасом
        low_stock = InventoryItem.query.filter(
            InventoryItem.available_quantity <= InventoryItem.min_quantity
        ).all()
        
        # Создаем DataFrame
        data = []
        for item in low_stock:
            data.append({
                'ID': item.id,
                'Название': item.name,
                'Категория': item.category.name if item.category else '',
                'Количество': item.quantity,
                'Доступно': item.available_quantity,
                'Минимальное количество': item.min_quantity,
                'Дефицит': item.min_quantity - item.available_quantity,
                'Местоположение': item.location or '',
                'Ответственный': item.responsible_person or '',
                'Статус': item.status,
                'Дата обновления': item.updated_at.strftime('%Y-%m-%d %H:%M') if item.updated_at else ''
            })
        
        df = pd.DataFrame(data)
        
        # Создаем Excel файл в памяти
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Низкий запас', index=False)
            
            # Настраиваем ширину колонок
            worksheet = writer.sheets['Низкий запас']
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
        
        # Возвращаем файл
        return Response(
            output,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": "attachment;filename=low_stock_report.xlsx"}
        )
        
    except Exception as e:
        print(f"Error exporting low stock: {e}")
        flash(f'Ошибка при экспорте: {str(e)}', 'error')
        return redirect(url_for('reports'))

@app.route('/export/events')
@login_required
def export_events():
    if current_user.role != 'admin':
        flash('Недостаточно прав!', 'error')
        return redirect(url_for('reports'))
    
    try:
        # Получаем все события
        events = Event.query.order_by(Event.start_time.desc()).all()
        
        # Создаем DataFrame
        data = []
        for event in events:
            data.append({
                'ID': event.id,
                'Название': event.title,
                'Описание': event.description or '',
                'Тип события': event.event_type,
                'Начало': event.start_time.strftime('%Y-%m-%d %H:%M'),
                'Окончание': event.end_time.strftime('%Y-%m-%d %H:%M') if event.end_time else '',
                'Место': event.location or '',
                'Целевая аудитория': event.target_audience or '',
                'Создатель': User.query.get(event.created_by).full_name if User.query.get(event.created_by) else '',
                'Дата создания': event.created_at.strftime('%Y-%m-%d %H:%M'),
                'Уведомления отправлены': 'Да' if event.notification_sent else 'Нет'
            })
        
        df = pd.DataFrame(data)
        
        # Создаем Excel файл в памяти
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='События', index=False)
            
            # Настраиваем ширину колонок
            worksheet = writer.sheets['События']
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
        
        # Возвращаем файл
        return Response(
            output,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": "attachment;filename=events_report.xlsx"}
        )
        
    except Exception as e:
        print(f"Error exporting events: {e}")
        flash(f'Ошибка при экспорте: {str(e)}', 'error')
        return redirect(url_for('reports'))

# Utility functions
def send_reservation_notification(reservation, status):
    if not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
        print("Email configuration missing, skipping email.")
        return
    
    try:
        msg = Message(
            subject=f'Резервирование {status}',
            sender=app.config['MAIL_USERNAME'],
            recipients=[reservation.user.email]
        )
        
        local_tz = timezone(timedelta(hours=5)) 
        start_local = reservation.start_time.astimezone(local_tz).strftime('%d.%m.%Y %H:%M')
        end_local = reservation.end_time.astimezone(local_tz).strftime('%d.%m.%Y %H:%M')

        if status == 'approved':
            msg.html = f'''
<p>Ваше резервирование одобрено!</p>
<p><b>Предмет:</b> {reservation.item.name}</p>
<p><b>Количество:</b> {reservation.quantity}</p>
<p><b>Время:</b> {start_local} - {end_local} (Ваше местное время)</p>
<p><b>Цель:</b> {reservation.purpose}</p>
<p>Пожалуйста, заберите предмет в указанное время.</p>
            '''
        
        from threading import Thread
        thr = Thread(target=send_async_email, args=[app, msg])
        thr.start()

    except Exception as e:
        print(f"Error preparing email: {e}")

def send_async_email(flask_app, msg):
    """Вспомогательная функция для отправки email в потоке."""
    with flask_app.app_context():
        try:
            mail.send(msg)
        except Exception as e:
            print(f"Error sending async email: {e}")

def send_event_notifications(event):
    if not app.config['MAIL_USERNAME']:
        print("Email configuration missing, skipping event notification.")
        return
    
    users = User.query.all() 
    
    local_tz = timezone(timedelta(hours=5))
    start_local = event.start_time.astimezone(local_tz).strftime('%d.%m.%Y %H:%M')
    
    with mail.connect() as conn:
        for user in users:
            try:
                msg = Message(
                    subject=f'Новое событие: {event.title}',
                    sender=app.config['MAIL_USERNAME'],
                    recipients=[user.email]
                )
                
                msg.html = f'''
<p>Новое событие в школе!</p>
<h3>{event.title}</h3>
<p><b>Описание:</b> {event.description}</p>
<p><b>Время:</b> {start_local} (Ваше местное время)</p>
<p><b>Место:</b> {event.location}</p>
<p><b>Аудитория:</b> {event.target_audience}</p>
                '''
                conn.send(msg)
            except Exception as e:
                print(f"Error sending event email to {user.email}: {e}")

# ДОБАВЛЕНО: Требуемые зависимости для работы
# Для экспорта в Excel нужно установить: pandas, openpyxl
# pip install pandas openpyxl

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
