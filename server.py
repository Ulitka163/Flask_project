import typing
import pydantic
from flask import Flask, jsonify, request
from flask.views import MethodView
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy import Column, Integer, String, DateTime, func, create_engine, Text, ForeignKey
from flask_bcrypt import Bcrypt
from flask_httpauth import HTTPBasicAuth


class HttpError(Exception):

    def __init__(self, status_code: int, message: str | dict | list):
        self.status_code = status_code
        self.message = message


class CreateUser(pydantic.BaseModel):
    mail: str
    password: str


class PatchUser(pydantic.BaseModel):
    mail: typing.Optional[str]
    password: typing.Optional[str]


def validate(model, raw_data: dict):
    try:
        return model(**raw_data).dict()
    except pydantic.ValidationError as error:
        raise HttpError(400, error.errors())


app = Flask('app')
bcrypt = Bcrypt(app)
auth = HTTPBasicAuth()


@app.errorhandler(HttpError)
def http_error_handler(error: HttpError):
    response = jsonify({
        'status': 'error',
        'reason': error.message
    })
    response.status_code = error.status_code
    return response


PG_DSN = 'postgresql://app:12345@127.0.0.1/flask'

engine = create_engine(PG_DSN)
Session = sessionmaker(bind=engine)

Base = declarative_base()


class User(Base):

    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    mail = Column(String(32), index=True)
    password_hash = Column(String(128))
    created_at = Column(DateTime, server_default=func.now())

    def hash_password(self, password: str):
        hashed = bcrypt.generate_password_hash(password)
        self.password_hash = hashed.decode('utf-8')

    def verify_password(self, password):
        return bcrypt.check_password_hash(self.password_hash.encode('utf-8'), password)


class Advertisement(Base):

    __tablename__ = 'advertisement'

    id = Column(Integer, primary_key=True)
    header = Column(String, index=True, nullable=False)
    description = Column(Text)
    created_at = Column(DateTime, server_default=func.now())
    owner = Column(Integer, ForeignKey('users.id'))


Base.metadata.create_all(engine)


class UserView(MethodView):

    @auth.login_required
    def get(self, user_id):
        with Session() as session:
            user = get_user(session, user_id)
            return jsonify({'id': user.id, 'mail': user.mail})

    def post(self):
        validated = validate(CreateUser, request.json)

        with Session() as session:
            user = User(mail=validated['mail'])
            user.hash_password(validated['password'])
            session.add(user)
            session.commit()
            return {'id': user.id}

    @auth.login_required
    def patch(self):
        user_id = auth.current_user().id
        validated = validate(PatchUser, request.json)
        with Session() as session:
            user = get_user(session, user_id)
            if validated.get('mail'):
                user.mail = validated['mail']
            if validated.get('password'):
                user.password_hash = user.hash_password(validated['password'])
            session.add(user)
            session.commit()
            return {'status': 'success'}

    @auth.login_required
    def delete(self):
        user_id = auth.current_user().id
        with Session() as session:
            user = get_user(session, user_id)
            session.delete(user)
            session.commit()
            return {'status': 'success'}


class AdvertisementView(MethodView):

    @auth.login_required
    def get(self, adv_id):
        with Session() as session:
            advertisement = get_adv(session, adv_id)
            return jsonify({'id': advertisement.id, 'header': advertisement.header, 'created_at': advertisement.created_at})

    @auth.login_required
    def post(self):
        data = request.json
        user = auth.current_user()

        with Session() as session:
            advertisement = Advertisement(header=data['header'],
                                          description=data['description'],
                                          owner=user.id)
            session.add(advertisement)
            session.commit()
            return {'id': advertisement.id, 'header': advertisement.header, 'owner': advertisement.owner}

    @auth.login_required
    def patch(self, adv_id):
        user_id = auth.current_user().id
        with Session() as session:
            advertisement = get_adv(session, adv_id)
            if advertisement.owner == user_id:
                if request.json.get('header'):
                    advertisement.header = request.json['header']
                if request.json.get('description'):
                    advertisement.description = request.json['description']
                session.add(advertisement)
                session.commit()
                return {'status': 'success'}
            else:
                raise HttpError(404, 'you are not the ad owner')

    @auth.login_required
    def delete(self, adv_id):
        user_id = auth.current_user().id
        with Session() as session:
            advertisement = get_adv(session, adv_id)
            if advertisement.owner == user_id:
                session.delete(advertisement)
                session.commit()
                return {'status': 'success'}
            else:
                raise HttpError(404, 'you are not the ad owner')


def get_user(session: Session, user_id: int):
    user = session.query(User).get(user_id)
    if user is None:
        raise HttpError(404, 'user not found')
    return user


def get_adv(session: Session, adv_id: int):
    advertisement = session.query(Advertisement).get(adv_id)
    if advertisement is None:
        raise HttpError(404, 'advertisement not found')
    return advertisement


@auth.verify_password
def verify_password(mail, password):
    with Session() as session:
        user = session.query(User).filter_by(mail=mail).first()

        if user and user.verify_password(password):
            return user


user_view = UserView.as_view('users')
advertisement_view = AdvertisementView.as_view('adv')

app.add_url_rule('/users/', view_func=user_view, methods=['POST', 'PATCH', 'DELETE'])
app.add_url_rule('/users/<int:user_id>', view_func=user_view, methods=['GET'])

app.add_url_rule('/adv/', view_func=advertisement_view, methods=['POST'])
app.add_url_rule('/adv/<int:adv_id>', view_func=advertisement_view, methods=['GET', 'PATCH', 'DELETE'])

app.run()
