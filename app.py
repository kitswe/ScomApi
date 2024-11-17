from flask import Flask, request, jsonify, url_for
from flask_sqlalchemy import SQLAlchemy
import hashlib
import os
from itsdangerous import Serializer, URLSafeTimedSerializer, SignatureExpired, BadSignature

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] ='sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = ''#建议使用随机字符串
db = SQLAlchemy(app)

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# 用户模型类
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    bio = db.Column(db.String(255))  # 简介
    star = db.Column(db.Integer, default=0)  # 获得的星星
    fire = db.Column(db.Integer, default=0)  # 获得的热度
    image = db.Column(db.String(255))  # 主页图
    avatar = db.Column(db.String(255))  # 头像
    is_verified = db.Column(db.Boolean, default=False)  # 官方认证
    is_email_verified = db.Column(db.Boolean, default=False)


    def __repr__(self):
        return f'<User {self.username}>'


# 创建数据库
with app.app_context():
    db.create_all()


# 注册
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    if not username or not password or not email:
        return jsonify({'message': 'Missing Field'}), 400

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'message': 'Used Username'}), 400

    existing_email = User.query.filter_by(email=email).first()
    if existing_email:
        return jsonify({'message': 'Used Email Adress'}), 400

    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    new_user = User(username=username, password=hashed_password, email=email)
    db.session.add(new_user)
    db.session.commit()
    verification_link = generate_verification_link(new_user.id, new_user.email)

    # 发送邮件
    send_email(new_user.email, verification_link)

    return jsonify({'message': 'Register Successfully'}), 201

def generate_verification_link(user_id, email):
    token = serializer.serialize({'user_id': user_id, 'email': email})
    return url_for('verify_email', token=token, _external=True)



def send_email(to_email, link):
  #暂未完成
    print(f"发送邮件到: {to_email}，邮件内容包含验证链接: {link}")
  
# 登录
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Missing Field'}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'Username Not Found'}), 400

    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    if user.password!= hashed_password:
        return jsonify({'message': 'Password Not Correct'}), 400

    return jsonify({'message': 'Login Successfully', 'user_id': user.id}), 200


# 获取用户
@app.route('/users/<int:user_id>', methods=['GET'])
def get_user_info(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User Not Found'}), 404

    return jsonify({
        'username': user.username,
        'email': user.email,
        'bio': user.bio,
        'star': user.star,
        'fire': user.fire,
        'image': user.image,
        'avatar': user.avatar,
        'is_verified': user.is_verified,
        'is_email_verified': user.is_email_verified
    }), 200

@app.route('/verify_email/<token>', methods=['GET'])
def verify_email(token):
    try:
        data = serializer.deserialize(token, max_age=3600)  # 设置token有效期为1小时
        user_id = data['user_id']
        email = data['email']

        user = User.query.get(user_id)
        if user and user.email == email:
            user.is_email_verified = True
            db.session.commit()
            return jsonify({'message': 'Email Verify Successfully'}), 200
        else:
            return jsonify({'message': 'Email Verify Failed'}), 400
    except SignatureExpired:
        return jsonify({'message': 'Expired Link'}), 400
    except BadSignature:
        return jsonify({'message': 'Invalid Link'}), 400

if __name__ == '__main__':
    app.run(debug=True)
