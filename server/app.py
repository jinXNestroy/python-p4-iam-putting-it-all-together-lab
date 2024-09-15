#!/usr/bin/env python3

from flask import request, session, jsonify, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        try:
            data = request.get_json()

            username = data.get('username')
            password = data.get('password')
            image_url = data.get('image_url')
            bio = data.get('bio')

            user = User(
                username=username,
                image_url=image_url,
                bio=bio
            )

            user.password_hash = password
            db.session.add(user)
            db.session.commit()

            session['user_id'] = user.id

            return make_response(user.to_dict(), 201)

        except IntegrityError:
            db.session.rollback()
            return make_response({'errors': ['Username must be unique.']}, 422)
        except ValueError as e:
            return make_response({'errors': [str(e)]}, 422)

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id is not None:
            user = User.query.get(user_id)
            if user:
                return make_response(user.to_dict(), 200)
            else:
                return make_response({'error': 'User not found.'}, 401)
        else:
            return make_response({'error': 'Unauthorized.'}, 401)

class Login(Resource):
    def post(self):
        data = request.get_json()

        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id
            return make_response(user.to_dict(), 200)
        else:
            return make_response({'error': 'Invalid username or password.'}, 401)

class Logout(Resource):
    def delete(self):
        if session.get('user_id') is not None:
            session.pop('user_id', None)
            return make_response('', 204)
        else:
            return make_response({'error': 'Unauthorized.'}, 401)

class RecipeIndex(Resource):
    def get(self):
        if session.get('user_id') is not None:
            recipes = Recipe.query.all()
            recipe_list = [recipe.to_dict() for recipe in recipes]
            return make_response(recipe_list, 200)
        else:
            return make_response({'error': 'Unauthorized.'}, 401)

    def post(self):
        if session.get('user_id') is not None:
            try:
                data = request.get_json()
                title = data.get('title')
                instructions = data.get('instructions')
                minutes_to_complete = data.get('minutes_to_complete')
                user_id = session.get('user_id')

                recipe = Recipe(
                    title=title,
                    instructions=instructions,
                    minutes_to_complete=minutes_to_complete,
                    user_id=user_id
                )

                db.session.add(recipe)
                db.session.commit()
                return make_response(recipe.to_dict(), 201)
            except (ValueError, IntegrityError) as e:
                db.session.rollback()
                return make_response({'errors': [str(e)]}, 422)
        else:
            return make_response({'error': 'Unauthorized.'}, 401)

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
