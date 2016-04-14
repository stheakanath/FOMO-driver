from sqlalchemy import Column, Integer, String, Boolean, Text
from itsdangerous import URLSafeSerializer
import hashlib
import time

from database import Base, db_session
import config

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(80), default="")
    password_hash = Column(Text)
    is_facebook = Column(Boolean, default=False)
    fb_id = Column(String(100), default="", index=True)
    token_hash = Column(String(32))
    number = Column(Integer, default=0)
    # Is facebook
    # Email
    # List of saved songs
    # Times user requested from server
    # More metadata (ask designer)

    def generate_token(self):
        s = URLSafeSerializer(config.SIGNER_SECRET)
        info = {
            'id': self.id,
            'time': time.time(),
            'email': self.email,
            'fb_id': self.fb_id,
        }
        token = s.dumps(info)
        self.token_hash = hashlib.md5(token).hexdigest()
        return token


    def update_number(self, num):
        self.number = num
        db_session.commit()


    @staticmethod
    def add_user(args):
        user = User()

        for key, value in args.iteritems():
            setattr(user, key, value)

        db_session.add(user)
        db_session.commit()
        return user


    @staticmethod
    def get_data(token):
        s = URLSafeSerializer(config.SIGNER_SECRET)
        try:
            return s.loads(token)
        except BadSignature:
            # Invalid token
            return None


    @staticmethod
    def verify_token(token):
        s = URLSafeSerializer(config.SIGNER_SECRET)
        data = get_data(token)
        if data is None:
            return None
        user = User.query.get(data['id'])
        # This block is for logging out other logged in devices (also possibly more secure)
        if hashlib.md5(token).hexdigest() != user.token_hash:
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
