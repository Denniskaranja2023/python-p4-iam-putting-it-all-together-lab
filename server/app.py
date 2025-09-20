#!/usr/bin/env python3

from flask import request, session, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe


class Signup(Resource):
    def post(self):
        data = request.get_json()

        username = data.get("username")
        password = data.get("password")
        image_url = data.get("image_url")
        bio = data.get("bio")

        try:
            # Create a new user
            new_user = User(
                username=username,
                image_url=image_url,
                bio=bio
            )
            new_user.password_hash = password  # triggers bcrypt hashing

            db.session.add(new_user)
            db.session.commit()

        except ValueError as ve:
            db.session.rollback()
            return make_response({"errors": [str(ve)]}, 422)

        except IntegrityError:
            db.session.rollback()
            return make_response({"errors": ["Username already taken."]}, 422)

        # Store user_id in the session
        session["user_id"] = new_user.id

        response = {
            "id": new_user.id,
            "username": new_user.username,
            "image_url": new_user.image_url,
            "bio": new_user.bio
        }
        return make_response(response, 201)


class CheckSession(Resource):
    def get(self):
        user_id = session.get("user_id")

        if not user_id:
            return make_response({"error": "Unauthorized"}, 401)

        user = db.session.get(User, user_id)  # modern replacement
        if not user:
            return make_response({"error": "Unauthorized"}, 401)

        response = {
            "id": user.id,
            "username": user.username,
            "image_url": user.image_url,
            "bio": user.bio
        }
        return make_response(response, 200)

class Login(Resource):
    def post(self):
        data = request.get_json()

        username = data.get("username")
        password = data.get("password")

        user = User.query.filter_by(username=username).first()

        if user and user.authenticate(password):
            session["user_id"] = user.id
            response = {
                "id": user.id,
                "username": user.username,
                "image_url": user.image_url,
                "bio": user.bio
            }
            return make_response(response, 200)

        return make_response({"error": "Invalid username or password"}, 401)


class Logout(Resource):
    def delete(self):
        if "user_id" in session and session["user_id"] is not None:
            session.pop("user_id")
            return make_response("", 204)
        else:
            return make_response({"error": "Unauthorized"}, 401)


class RecipeIndex(Resource):
    def get(self):
        user_id = session.get("user_id")
        if not user_id:
            return make_response({"error": "Unauthorized"}, 401)

        recipes = Recipe.query.filter_by(user_id=user_id).all()

        recipes_data = [
            {
                **recipe.to_dict(
                    only=("id", "title", "instructions", "minutes_to_complete"),
                    rules=("-user.recipes",)
                ),
                "user": recipe.user.to_dict(
                    only=("id", "username", "image_url", "bio")
                )
            }
            for recipe in recipes
        ]

        return make_response(recipes_data, 200)

    def post(self):
        user_id = session.get("user_id")
        if not user_id:
            return make_response({"error": "Unauthorized"}, 401)

        data = request.get_json()

        try:
            new_recipe = Recipe(
                title=data.get("title"),
                instructions=data.get("instructions"),
                minutes_to_complete=data.get("minutes_to_complete"),
                user_id=user_id
            )

            db.session.add(new_recipe)
            db.session.commit()

            recipe_data = {
                **new_recipe.to_dict(
                    only=("id", "title", "instructions", "minutes_to_complete"),
                    rules=("-user.recipes",)
                ),
                "user": new_recipe.user.to_dict(
                    only=("id", "username", "image_url", "bio")
                )
            }

            return make_response(recipe_data, 201)

        except ValueError as e:
            return make_response({"errors": [str(e)]}, 422)


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
