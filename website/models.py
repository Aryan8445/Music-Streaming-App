from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship


class User(db.Model, UserMixin):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    firstname = db.Column(db.String(80), nullable=False)
    lastname = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    user_type = db.Column(db.String(80), nullable=False)
    is_blacklisted = db.Column(db.Boolean, default=False)
    registration_date = db.Column(
        db.DateTime(timezone=True), default=func.now())
    songs = relationship('Song', back_populates='artist', lazy=True)
    albums = relationship('Album', back_populates='artist', lazy=True)
    ratings = relationship('Rating', back_populates='user', lazy=True)


class Song(db.Model):
    __tablename__ = 'song'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(255), nullable=False)
    artist_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    release_date = db.Column(db.Date, nullable=False)
    genre = db.Column(db.String(50), nullable=False)
    album_id = db.Column(db.Integer, db.ForeignKey('album.id'))
    file_path = db.Column(db.String(255), nullable=False)
    lyrics = db.Column(db.Text)
    upload_date = db.Column(db.DateTime(timezone=True), default=func.now())
    playlists = relationship('Playlist', secondary='playlist_songs', back_populates='songs', lazy=True)
    ratings = relationship('Rating', back_populates='song', lazy=True)
    album = db.relationship('Album',secondary='album_songs', back_populates='songs', lazy=True)
    artist = db.relationship('User', back_populates='songs', lazy=True)
    is_flagged = db.Column(db.Boolean, default=False)

class Playlist(db.Model):
    __tablename__ = 'playlist'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    title = db.Column(db.String(255), nullable=False)
    songs = relationship('Song', secondary='playlist_songs', back_populates='playlists')


class PlaylistSongs(db.Model):
    __tablename__ = 'playlist_songs'
    playlist_id = db.Column(db.Integer, db.ForeignKey('playlist.id'), primary_key=True)
    song_id = db.Column(db.Integer, db.ForeignKey('song.id'), primary_key=True)

class AlbumSongs(db.Model):
    __tablename__ = 'album_songs'
    album_id = db.Column(db.Integer, db.ForeignKey('album.id'), primary_key=True)
    song_id = db.Column(db.Integer, db.ForeignKey('song.id'), primary_key=True)

class Album(db.Model):
    __tablename__ = 'album'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(255), nullable=False)
    artist_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    artist = db.relationship('User', back_populates='albums')
    songs = relationship('Song', secondary='album_songs',back_populates='album', lazy=True)


class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    value = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    song_id = db.Column(db.Integer, db.ForeignKey('song.id'), nullable=False)
    user = db.relationship('User', back_populates='ratings')
    song = db.relationship('Song', back_populates='ratings')
