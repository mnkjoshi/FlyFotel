import os
import flask
import flask_sqlalchemy
#from flask_sqlalchemy import SQLAlchemy
import flask_praetorian
import flask_cors
#https://flask-praetorian.readthedocs.io/en/latest/quickstart.html


db = flask_sqlalchemy.SQLAlchemy()
guard = flask_praetorian.Praetorian()
cors = flask_cors.CORS()


#class Trip(db.Model):
#	id = db.Column(db.Integer, primary_key=True)
#	userID = db.relationship("User", back_populates="trips")
#	flightID = db.Column(db.Text)
#	foodID = db.Column(db.Text)
#	hotelID = db.Column(db.Text)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text, unique=True)
    password = db.Column(db.Text)
    roles = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True, server_default="true")

    @classmethod
    def lookup(cls, username):
        return cls.query.filter_by(username=username).one_or_none()

    @classmethod
    def identify(cls, id):
        return cls.query.get(id)

    @property
    def rolenames(self):
        try:
            return self.roles.split(',')
        except Exception:
            return []

    @property
    def identity(self):
        return self.id

    def is_valid(self):
        return self.is_active


# Initialize flask app for the example
app = flask.Flask(__name__)
app.debug = True
app.config['SECRET_KEY'] = 'top secret'
app.config['JWT_ACCESS_LIFESPAN'] = {'hours': 24}
app.config['JWT_REFRESH_LIFESPAN'] = {'days': 30}

guard.init_app(app, User)

# Initialize a local database for the example
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(os.getcwd(), 'database2.db')}"
db.init_app(app)

# Initializes CORS so that the api_tool can talk to the example app
cors.init_app(app)

# Add users for the example
with app.app_context():
    User.trips = db.relationship("User", back_populates="trips")
    db.create_all()
    if db.session.query(User).filter_by(username='josh').count() < 1:
        db.session.add(User(
          username='josh',
          password=guard.hash_password('batterystaple')
            ))
    db.session.commit()

# Set up some routes for the example
@app.route('/api/')
def home():
    return {"msg": "Blank Endpoint"}, 200
  
@app.route('/api/login', methods=['POST'])
def login():
    username = req.get('username', None)
    password = req.get('password', None)
    user = guard.authenticate(username, password)
    ret = {'access_token': guard.encode_jwt_token(user)}
    return ret, 200
  
@app.route('/api/refresh', methods=['POST'])
def refresh():
    print("refresh request")
    old_token = request.get_data()
    new_token = guard.refresh_jwt_token(old_token)
    ret = {'access_token': new_token}
    return ret, 200
  
  
@app.route('/api/protected')
@flask_praetorian.auth_required
def protected():
    return {'message': f'You will only see this if you are authenticated'}

@app.route('/api/saved')
@flask_praetorian.auth_required
def stored():
	#//db find the data that is stored and send it out in json
	return 0
# Run the example
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
