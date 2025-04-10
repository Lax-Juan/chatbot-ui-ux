import uuid
import os
from flask import Flask, render_template, redirect, url_for, request, session, jsonify
from flask_sqlalchemy import SQLAlchemy
import pymysql
import requests
import markdown
from datetime import datetime
from flask_login import (
    LoginManager, UserMixin,
    login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash

pymysql.install_as_MySQLdb()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_secret_key_123')
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost:3306/test'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Modelos
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class ChatSession(db.Model):
    __tablename__ = 'chat_sessions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False, default='Nueva conversación')
    uuid = db.Column(db.String(36), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    messages = db.relationship('ChatMessage', backref='session', lazy=True, cascade='all, delete-orphan')

class ChatMessage(db.Model):
    __tablename__ = 'chat_messages'
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('chat_sessions.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_bot = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

# Configuración Login Manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Rutas
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            return "El usuario ya existe", 400
            
        user = User(
            username=username,
            password=generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
        )
        
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if not user or not check_password_hash(user.password, password):
            return "Credenciales inválidas", 401
        
        login_user(user)
        
        # Crear nueva sesión al hacer login
        new_session = ChatSession(
            user_id=user.id,
            name=f"Conversación {datetime.now().strftime('%d/%m %H:%M')}",
            uuid=str(uuid.uuid4())
        )
        db.session.add(new_session)
        db.session.commit()
        
        session['session_id'] = new_session.uuid
        return redirect(url_for('chat'))
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('session_id', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def chat():
    sessions = ChatSession.query.filter_by(user_id=current_user.id)\
                .order_by(ChatSession.created_at.desc())\
                .all()
    return render_template('chat.html',
                         sessions=sessions,
                         current_session_id=session.get('session_id'))

# API
@app.route('/api/session', methods=['POST', 'DELETE'])
@login_required
def handle_session():
    if request.method == 'POST':
        new_session = ChatSession(
            user_id=current_user.id,
            name=f"Conversación {datetime.now().strftime('%d/%m %H:%M')}",
            uuid=str(uuid.uuid4())
        )
        db.session.add(new_session)
        db.session.commit()
        
        session['session_id'] = new_session.uuid
        return jsonify({
            'uuid': new_session.uuid,
            'name': new_session.name
        })
    
    elif request.method == 'DELETE':
        session_uuid = request.json.get('session_id')
        session_to_delete = ChatSession.query.filter_by(
            uuid=session_uuid,
            user_id=current_user.id
        ).first()
        
        if not session_to_delete:
            return jsonify({'status': 'error'}), 404
        
        db.session.delete(session_to_delete)
        db.session.commit()
        return jsonify({'status': 'success'})

@app.route('/api/chat', methods=['POST'])
@login_required
def api_chat():
    data = request.get_json()
    user_msg = data.get('message', '').strip()
    sid = session.get('session_id')
    
    if not sid or not user_msg:
        return jsonify({'response': 'Solicitud inválida'}), 400
    
    # Obtener sesión actual
    current_session = ChatSession.query.filter_by(
        uuid=sid,
        user_id=current_user.id
    ).first()
    
    if not current_session:
        return jsonify({'response': 'Sesión no encontrada'}), 404
    
    # Procesar mensaje
    bot_response = ""
    try:
        # Llamar al webhook de n8n
        resp = requests.post(
            'https://diegolightxd7.app.n8n.cloud/webhook/chatbot-ai-webhook',
            json={'session_id': sid, 'message': user_msg},
            timeout=30
        )
        resp.raise_for_status()
        result = resp.json()
        bot_response = markdown.markdown(
            result.get('output', ''),
            extensions=['nl2br']
        )
    except Exception as e:
        app.logger.error(f"Error en webhook: {str(e)}")
        bot_response = "⚠️ Error procesando tu mensaje"
    
    # Guardar mensajes en BD
    try:
        db.session.add_all([
            ChatMessage(
                session_id=current_session.id,
                content=user_msg,
                is_bot=False
            ),
            ChatMessage(
                session_id=current_session.id,
                content=bot_response,
                is_bot=True
            )
        ])
        db.session.commit()
    except Exception as e:
        app.logger.error(f"Error guardando mensajes: {str(e)}")
        db.session.rollback()
    
    return jsonify({'response': bot_response})

@app.route('/api/messages')
@login_required
def get_messages():
    session_uuid = request.args.get('session_id')
    if not session_uuid:
        return jsonify([]), 400
    
    chat_session = ChatSession.query.filter_by(
        uuid=session_uuid,
        user_id=current_user.id
    ).first()
    
    if not chat_session:
        return jsonify([]), 404
    
    messages = ChatMessage.query.filter_by(
        session_id=chat_session.id
    ).order_by(ChatMessage.timestamp.asc()).all()
    
    return jsonify([{
        'content': msg.content,
        'is_bot': msg.is_bot,
        'timestamp': msg.timestamp.isoformat()
    } for msg in messages])

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)