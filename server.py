import json
from hashlib import md5

from flask import Flask, jsonify, request
from flask.views import MethodView
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError

from models import Advertisement, Session, User
from validation import CreateUser, UpdateUser

app = Flask("app")


class HttpError(Exception):
    def __init__(self, status_code: int, message: dict | str | list):
        self.status_code = status_code
        self.message = message


@app.errorhandler(HttpError)
def error_handler(err: HttpError):
    http_response = jsonify({"status": "error", "message": err.message})
    http_response.status_code = err.status_code
    return http_response


def get_adv(adv_id: int, session: Session):
    adv = session.get(Advertisement, adv_id)
    if adv is None:
        raise HttpError(404, "Advertisement not found")
    return adv


class AdvertisementView(MethodView):
    def get(self, adv_id):
        with Session() as session:
            adv = get_adv(adv_id, session)
            return jsonify(
                {"id": adv.id, "title": adv.title, "description": adv.description}
            )

    def post(self):
        with Session() as session:
            new_adv = Advertisement(**request.json)
            session.add(new_adv)
            session.commit()
            return jsonify({"id": new_adv.id})

    def patch(self, adv_id):
        with Session() as session:
            adv = get_adv(adv_id, session)
            for key, value in request.json.items():
                setattr(adv, key, value)
            session.add(adv)
            session.commit()
            return jsonify({"status": "success"})

    def delete(self, adv_id):
        with Session() as session:
            adv = get_adv(adv_id, session)
            session.delete(adv)
            session.commit()
            return jsonify({"status": "success"})


def get_user(user_id: int, session: Session):
    user = session.get(User, user_id)
    if user is None:
        raise HttpError(404, "User not found")
    return user


def validate(json_data, validation_scheme):
    try:
        model = validation_scheme(**json_data)
        return model.dict(exclude_none=True)
    except ValidationError as err:
        error_message = json.loads(err.json())
        raise HttpError(400, error_message)


def hash_password(password: str):
    password = str(password).encode()
    password = md5(password).hexdigest()


class UserView(MethodView):
    def get(self, user_id):
        with Session() as session:
            user = get_user(user_id, session)
            return jsonify(
                {"id": user.id, "username": user.username, "email": user.email}
            )

    def post(self):
        json_data = validate(request.json, CreateUser)
        json_data["password"] = hash_password(json_data["password"])
        with Session() as session:
            new_user = User(**json_data)
            session.add(new_user)

            try:
                session.commit()
            except IntegrityError:
                raise HttpError(408, "User already exists")

            return jsonify({"id": new_user.id})

    def patch(self, user_id):
        json_data = validate(request.json, UpdateUser)
        if "password" in json_data:
            json_data["password"] = hash_password(json_data["password"])

        with Session() as session:
            user = get_user(user_id, session)
            for key, value in json_data.items():
                setattr(user, key, value)
            session.add(user)
            try:
                session.commit()
            except IntegrityError:
                raise HttpError(408, "user already exists")
            return jsonify({"status": "success"})

    def delete(self, user_id):
        with Session() as session:
            user = get_user(user_id, session)
            session.delete(user)
            session.commit()
            return jsonify({"status": "success"})


advertisement_view = AdvertisementView.as_view("advertisement")

app.add_url_rule("/advertisements/", view_func=advertisement_view, methods=["POST"])

app.add_url_rule(
    "/advertisements/<int:adv_id>/",
    view_func=advertisement_view,
    methods=["GET", "PATCH", "DELETE"],
)

user_view = UserView.as_view("user")

app.add_url_rule("/users/", view_func=user_view, methods=["POST"])

app.add_url_rule(
    "/users/<int:user_id>/", view_func=user_view, methods=["GET", "PATCH", "DELETE"]
)

if __name__ == "__main__":
    app.run()
