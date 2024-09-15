from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    # Attributes
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)
    _password_hash = db.Column(db.String, nullable=True)  # Made nullable
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    # Relationships
    recipes = db.relationship('Recipe', backref='user', lazy=True)

    # Serialization rules
    serialize_rules = ('-recipes.user', '-_password_hash')

    # Password property
    @hybrid_property
    def password_hash(self):
        raise AttributeError('Password hashes may not be accessed.')

    @password_hash.setter
    def password_hash(self, password):
        if password:
            self._password_hash = bcrypt.generate_password_hash(password.encode('utf-8')).decode('utf-8')
        else:
            self._password_hash = None

    # Authentication method
    def authenticate(self, password):
        if self._password_hash:
            return bcrypt.check_password_hash(self._password_hash, password.encode('utf-8'))
        return False

    # Validators
    @validates('username')
    def validate_username(self, key, username):
        if not username:
            raise ValueError('Username must be present.')
        return username

class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'

    # Attributes
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # Made nullable

    # Serialization rules
    serialize_rules = ('-user.recipes',)

    # Validators
    @validates('title')
    def validate_title(self, key, title):
        if not title:
            raise ValueError('Title must be present.')
        return title

    @validates('instructions')
    def validate_instructions(self, key, instructions):
        if not instructions:
            raise ValueError('Instructions must be present.')
        if len(instructions) < 50:
            raise ValueError('Instructions must be at least 50 characters long.')
        return instructions
