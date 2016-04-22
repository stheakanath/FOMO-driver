from itsdangerous import URLSafeSerializer
import hashlib
import time

from server import db
import os

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, index=True)
    email = db.Column(db.Unicode(80), default="")
    password_hash = db.Column(db.LargeBinary)
    is_facebook = db.Column(db.Boolean, default=False)
    fb_id = db.Column(db.Unicode(100), default="", index=True)
    token_hash = db.Column(db.LargeBinary)
    number = db.Column(db.Integer, default=0)
    # Is facebook
    # Email
    # List of saved songs
    # Times user requested from server
    # More metadata (ask designer)

    def generate_token(self):
        s = URLSafeSerializer(os.environ['SIGNER_SECRET'])
        info = {
            'id': self.id,
            'time': time.time(),
            'email': self.email,
            'fb_id': self.fb_id,
        }
        token = s.dumps(info)
        self.token_hash = hashlib.md5(token.encode('utf-8')).hexdigest()
        return token


    def update_number(self, num):
        self.number = num
        db.session.commit()


    @staticmethod
    def add_user(args):
        user = User()

        for key, value in args.items():
            setattr(user, key, value)

        db.session.add(user)
        db.session.commit()
        return user


    @staticmethod
    def get_data(token):
        s = URLSafeSerializer(os.environ['SIGNER_SECRET'])
        try:
            return s.loads(token)
        except BadSignature:
            # Invalid token
            return None


    @staticmethod
    def verify_token(token):
        s = URLSafeSerializer(os.environ['SIGNER_SECRET'])
        data = get_data(token)
        if data is None:
            return None
        user = User.query.get(data['id'])
        # This block is for logging out other logged in devices (also possibly more secure)
        if hashlib.md5(token.encode('utf-8')).hexdigest() != user.token_hash:
            # Token is old (someone logged in again on another device)
            return None

        return user


# class Song(Base):
    # __tablename__ = 'songs'
    # Metadata:
    #   Genre
    #   Artist
    #   Year released
    #   Song name
    #   Album name
    #   Album cover [not storing]
    #   Tag List
    #   Song itself [not storing]
    # Song feedback
    #   Amount of users disliked
    #   Amount of users liked
    #   Amount of users song shown to
    #   When was song played at, and feedback given at time
