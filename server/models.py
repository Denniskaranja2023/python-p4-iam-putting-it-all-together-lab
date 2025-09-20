from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'
    id= db.Column(db.Integer, primary_key=True)
    username= db.Column(db.String, unique=True, nullable=False)
    _password_hash= db.Column(db.String)
    image_url= db.Column(db.String)
    bio= db.Column(db.String)
    recipes= db.relationship('Recipe', back_populates='user')
    
    @validates('username')
    def validate_username(self, key, username):
        if not username or not username.strip():
            raise ValueError("username must be present")
        return username.strip()
    
    @hybrid_property
    def password_hash(self):
        raise AttributeError("password hashes may not be accessed")
    
    @password_hash.setter
    def password_hash(self, password):
        password_hash= bcrypt.generate_password_hash(password.encode('utf-8'))
        self._password_hash= password_hash.decode('utf-8')
    
    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password.encode('utf-8'))
        
    
class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'
    id= db.Column(db.Integer, primary_key=True)
    title= db.Column(db.String)
    instructions= db.Column(db.String)
    minutes_to_complete= db.Column(db.Integer, nullable=False)
    user_id= db.Column(db.Integer, db.ForeignKey('users.id'))
    user= db.relationship('User', back_populates='recipes')
    
    @validates('title', 'instructions')
    def validate_fields(self, key, value):
        if key == 'title':
            if not value or not value.strip():
                raise ValueError("Recipe title must be present.")
        if key == 'instructions':
            if not value or not value.strip():
                raise ValueError("Recipe instructions must be present.")
            if len(value.strip()) < 50:
                raise ValueError("Recipe instructions must be at least 50 characters long.")
        return value.strip()