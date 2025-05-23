import eventlet
eventlet.monkey_patch()
from flask import Flask, render_template, redirect, url_for, flash, request, make_response
from flask_socketio import SocketIO
from threading import Thread
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from wtforms.fields import TextAreaField
from werkzeug.security import generate_password_hash, check_password_hash
from collections import defaultdict
import time
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  # Используем SQLite для простоты
socketio = SocketIO(app, cors_allowed_origins="*")
user_connections = defaultdict(set)
db = SQLAlchemy(app)
running = False

# Модель пользователя
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Модель игры
class Game(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)
    description = db.Column(db.String(200), nullable=False)
    picture = db.Column(db.String(200), nullable=False)
    code = db.Column(db.String(10000), nullable=False)
    author = db.Column(db.String(20), nullable=False)
    release = db.Column(db.String(1), nullable=False)

# Модель сессии
class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    game = db.Column(db.String(20), nullable=False)
    host = db.Column(db.String(20), nullable=False)
    players = db.Column(db.String(300), nullable=False)
    active_players = db.Column(db.String(300), nullable=False)
    active = db.Column(db.String(1), nullable=False)
    description = db.Column(db.String(100), nullable=False)

# Настройка Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Страница входа

# Загрузчик пользователя для Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Форма регистрации
class RegistrationForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Зарегистрироваться')
    # Кастомная валидация для username
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Это имя пользователя уже занято. Пожалуйста, выберите другое.')
    # Кастомная валидация для email
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Этот email уже используется. Пожалуйста, используйте другой.')

# Форма входа
class LoginForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')

# Маршрут регистрации
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('gallery'))  # Если пользователь уже авторизован, перенаправляем на главную
    theme = request.cookies.get('theme', 'light')  # Получаем тему из куки
    form = RegistrationForm()
    if form.validate_on_submit():
        # Создаем нового пользователя
        user = User(
            username=form.username.data,
            email=form.email.data,
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Ваш аккаунт успешно создан! Теперь вы можете войти.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form, theme=theme)  # Передаём тему в шаблон

# Маршрут входа
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('gallery'))  # Если пользователь уже авторизован, перенаправляем на главную
    theme = request.cookies.get('theme', 'light')  # Получаем тему из куки
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)  # Сохраняем сессию пользователя
            flash('Вы успешно вошли в систему!', 'success')
            return redirect(url_for('gallery'))
        else:
            flash('Неверный username или пароль. Пожалуйста, попробуйте снова.', 'danger')
    return render_template('login.html', form=form, theme=theme)  # Передаём тему в шаблон

# Маршрут выхода
@app.route('/logout')
@login_required  # Только для авторизованных пользователей
def logout():
    logout_user()  # Завершаем сессию
    flash('Вы вышли из системы.', 'success')
    return redirect(url_for('index'))

# Начальная страница
@app.route('/')
def index():
    theme = request.cookies.get('theme', 'light')  # Получаем тему из куки
    return render_template('index.html', theme=theme)

# Главная страница
@app.route('/gallery')
def gallery():
    username = current_user.username
    games = Game.query.filter(Game.release == 'T').all()
    games = [{key: value for key, value in item.__dict__.items() if not key.startswith('_')} for item in games]
    return render_template('gallery.html', games=games)

@app.route('/workshop')
def workshop():
    username = current_user.username
    games = Game.query.filter(Game.author == username).all()
    games = [{key: value for key, value in item.__dict__.items() if not key.startswith('_')} for item in games]
    return render_template('workshop.html', games=games)

@app.route('/search')
def search():
    username = current_user.username
    query = request.args.get('query', '')
    query = Game.query.filter(Game.name == query).all()
    if (len(query) > 0):
        query = ([{key: value for key, value in item.__dict__.items() if not key.startswith('_')} for item in query])[0]
        check = Game.query.filter(Game.name == query['name']+'_copy').all()
        if (len(check) == 0):
            game = Game(
                name=query['name']+'_copy',
                description=query['description'],
                picture=query['picture'],
                code=query['code'],
                author=username,
                release = 'F',
            )
            db.session.add(game)
            db.session.commit()
    return redirect(url_for('workshop'))

@app.route('/create')
@login_required
def create_game():
    username = current_user.username
    query = 'base game'
    query = Game.query.filter(Game.name == query).all()
    query = ([{key: value for key, value in item.__dict__.items() if not key.startswith('_')} for item in query])[0]
    r = random.randint(1,1000)
    check = Game.query.filter(Game.name == 'base game'+str(r)).all()
    if (len(check) == 0):
        game = Game(
            name='base game'+str(r),
            description=query['description'],
            picture=query['picture'],
            code=query['code'],
            author=username,
            release = 'F',
        )
        db.session.add(game)
        db.session.commit()
    return redirect(url_for('workshop'))

class GameForm(FlaskForm):
    name = StringField('Название игры', validators=[
        DataRequired(message="Поле обязательно для заполнения"),
        Length(min=3, max=100, message="Название должно быть от 3 до 100 символов")
    ])
    description = TextAreaField('Описание', validators=[
        DataRequired(message="Поле обязательно для заполнения"),
        Length(min=10, message="Описание должно быть не менее 10 символов")
    ])
    picture = TextAreaField('Постер', validators=[
        DataRequired(message="Поле обязательно для заполнения"),
        Length(min=10, message="Описание должно быть не менее 10 символов")
    ])
    submit = SubmitField('Сохранить изменения')

@app.route('/rename/<int:game_id>', methods=['GET', 'POST'])
def rename_game(game_id):
    game = Game.query.get_or_404(game_id)  # Получаем игру или возвращаем 404
    form = GameForm()
    
    if form.validate_on_submit():
        # Обновляем данные игры
        game.name = form.name.data
        game.description = form.description.data
        game.picture = form.picture.data
        db.session.commit()
        flash('Игра успешно обновлена!', 'success')
        return redirect(url_for('workshop'))
    
    # Для GET запроса заполняем форму текущими данными
    if request.method == 'GET':
        form.name.data = game.name
        form.description.data = game.description
    
    return render_template('rename.html', form=form, game_id=game_id)

@app.route('/publish/<int:game_id>')
def publish_game(game_id):
    username = current_user.username
    game = Game.query.get(game_id)
    if game:
        game.release = 'T'
        db.session.commit()
    games = Game.query.filter(Game.author == username).all()
    games = [{key: value for key, value in item.__dict__.items() if not key.startswith('_')}for item in games]
    return render_template('workshop.html', games=games)

@app.route('/edit_game/<int:game_id>')
def edit_game(game_id):
    username = current_user.username
    game = Game.query.get_or_404(game_id)
    return redirect(url_for('game_host',game=game.name))

@app.route('/sessions')
def sessions():
    username = current_user.username
    sessions = Session.query.all()
    sessions = [{key: value for key, value in item.__dict__.items() if not key.startswith('_')} for item in sessions]
    return render_template('sessions.html', sessions=sessions)

@app.route('/create_session/<int:game_id>')
@login_required
def create_session(game_id):
    username = current_user.username
    # Проверяем, есть ли уже активная сессия у пользователя
    existing_session = Session.query.filter_by(host=username, active='T').first()
    if not existing_session:
        game_name = Game.query.get_or_404(game_id)
        game_name = game_name.name
        new_session = Session(
            game = game_name,
            host=username,
            players='',
            active_players='',
            active='F',
            description = 'Играем 31 вефраля в 25:79 в viber.',
        )
        db.session.add(new_session)
        db.session.commit()
        flash('Новая сессия успешно создана!', 'success')
    else:
        flash('У вас уже есть активная сессия!', 'warning')
    # Перенаправляем на страницу сессий
    return redirect(url_for('sessions'))

@app.route('/delete_session/<int:session_id>', methods=['DELETE'])
@login_required
def delete_session(session_id):
    session = Session.query.get_or_404(session_id)
    if session.host == current_user.username:
        db.session.delete(session)
        db.session.commit()
        return '', 200
    else:
        return '', 403  # Forbidden

@app.route('/join_session/<int:session_id>')
@login_required
def join_session(session_id):
    username = current_user.username
    session = Session.query.get(session_id)
    if session:
        if (session.active == 'F'):
            if (session.host != username):
                if username not in session.players.split('%'):
                    if (session.players == ''):
                        session.players = username
                    else:
                        session.players += username
                    db.session.commit()
        else:
            return redirect(url_for('game_player', session_id=session_id))
    return redirect(url_for('sessions'))

@app.route('/start_session/<int:session_id>')
@login_required
def start_session(session_id):
    session = Session.query.get_or_404(session_id)
    if session.host == current_user.username:
        # Логика начала игры
        session.active = 'T'
        db.session.commit()
        return redirect(url_for('game_host',game=session.game))
    else:
        flash('Только хост может начать сессию!', 'warning')
        return redirect(url_for('sessions'))    

@app.route('/game_host/<game>')
def game_host(game):
    username = current_user.username
    gm = Game.query.filter(Game.name == game).first()
    return render_template('game_host.html', name=username, game_name=game, code=gm.code)

@app.route('/game_player/<int:session_id>')
def game_player(session_id):
    username = current_user.username
    session = Session.query.get_or_404(session_id)
    if session:
        if (session.active_players == ''):
            session.active_players = username
        else:
            session.active_players += '%'+username
        db.session.commit()
    socketio.emit('new_player', {'name':username, 'host':session.host})
    return render_template('game_player.html', name=username, host=session.host)

# Новый маршрут для обработки отключения игрока
@app.route('/player_disconnected', methods=['POST'])
def handle_player_disconnected_http():
    username = request.args.get('name')
    if username:
        session = Session.query.filter(Session.players.contains(username)).first()
        if session:
            active_players = session.active_players.split('%')
            if username in active_players:
                active_players.remove(username)
                session.active_players = '%'.join(active_players)
                db.session.commit()
                socketio.emit('player_list_updated', {'players': active_players})
        session = Session.query.filter(Session.host == username).first()
        if session:
            session.active = 'F'
            db.session.commit()
    return '', 200

@socketio.on('player_input')
def players_inputs(inputs):
    socketio.emit('players_update', [{'name': inputs['name'],'keys': inputs['keys']}])

@socketio.on('game_state_update')
def game_state_update(data):
    socketio.emit('players_draw', data)

@socketio.on('save_game_speed')
def handle_save_game_speed(data):
    game_name = data['game']
    new_speed = data['speed']
    # Находим игру в базе данных
    game = Game.query.filter_by(name=game_name).first()
    if game:
        # Обновляем поле code с новым значением скорости
        game.code = str(new_speed)
        db.session.commit()

def background_thread():
    """Поток для периодической отправки данных клиенту"""
    counter = 0
    while running:
        time.sleep(5)  # Отправляем сообщения каждые 3 секунды
        counter += 1
        #print(f"Отправлено обновление клиенту")

# Запуск приложения
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, host='0.0.0.0', port=5000)
