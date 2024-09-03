from flask import Blueprint, render_template, redirect, request, flash, url_for
from flask_login import current_user, login_required
from .models import *
from datetime import datetime
from . import db
from sqlalchemy import or_, desc, distinct
from werkzeug.utils import secure_filename
import os

controllers = Blueprint('controllers', __name__)

# -------------------------------------------User controllerss---------------------------------------------------------


@controllers.route('/')
def index():
    return render_template('index.html')


@controllers.route('/home')
@login_required
def home():
    recommended_songs = Song.query.order_by(
        Song.upload_date.desc()).limit(5).all()
    user_playlists = Playlist.query.filter_by(
        user_id=current_user.id).limit(4).all()
    albums = Album.query.limit(4).all()
    rock_songs = Song.query.filter_by(genre='Rock').all()
    Bhakti_songs = Song.query.filter_by(genre='Bhakti').all()
    return render_template('home.html', user=current_user, recommended_songs=recommended_songs, user_playlists=user_playlists, albums=albums, rock_songs=rock_songs, Bhakti_songs=Bhakti_songs)


@controllers.route('/recommended_songs')
@login_required
def recommended_songs():
    recommended_songs = Song.query.order_by(Song.upload_date.desc()).all()
    return render_template('recommended_songs.html', user=current_user, recommended_songs=recommended_songs)


@controllers.route('/playlist/<int:playlist_id>')
@login_required
def playlist_songs(playlist_id):
    playlist = Playlist.query.get(playlist_id)

    if playlist:
        songs = playlist.songs
    else:
        songs = []

    return render_template('playlist_songs.html', playlist=playlist, songs=songs, user=current_user)


@controllers.route('/album/<int:album_id>')
@login_required
def album_songs(album_id):
    album = Album.query.get(album_id)

    if album:
        songs = album.songs
    else:
        songs = []

    return render_template('album_songs.html', album=album, songs=songs, user=current_user)


@controllers.route('/create_playlist', methods=['GET', 'POST'])
@login_required
def create_playlist():
    songs = Song.query.all()

    if request.method == 'POST':
        songs = Song.query.all()
        title = request.form.get('playlist_name')
        selected_song_ids = request.form.getlist('song_ids[]')
        new_playlist = Playlist(title=title, user_id=current_user.id)
        db.session.add(new_playlist)
        db.session.commit()

        for song_id in selected_song_ids:
            playlist_song = PlaylistSongs(
                playlist_id=new_playlist.id, song_id=song_id)
            db.session.add(playlist_song)

        db.session.commit()

        flash('Playlist created successfully', category='success')
        return redirect(url_for('controllers.home'))

    return render_template('create_playlist.html', songs=songs, user=current_user)


@controllers.route('/add_song_to_playlist/<int:playlist_id>', methods=['GET', 'POST'])
@login_required
def add_song_to_playlist(playlist_id):
    songs = Song.query.all()
    playlist = Playlist.query.get(playlist_id)

    if request.method == 'POST':
        selected_song_ids = request.form.getlist('song_ids[]')
        for song_id in selected_song_ids:
            existing_song = PlaylistSongs.query.filter_by(
                playlist_id=playlist_id, song_id=song_id).first()
            if existing_song:
                pass
            else:
                playlist_song = PlaylistSongs(
                    playlist_id=playlist.id, song_id=song_id)
                db.session.add(playlist_song)

        db.session.commit()
        flash('Songs added successfully', category='success')
        return redirect(url_for('controllers.playlist_songs', playlist_id=playlist.id))

    return render_template('add_song_to_playlist.html', user=current_user, playlist=playlist, songs=songs)


@controllers.route('/all_playlists')
@login_required
def all_playlists():
    all_playlists = Playlist.query.filter_by(user_id=current_user.id).all()
    return render_template('all_playlists.html', user=current_user, all_playlists=all_playlists)


@controllers.route('/remove_song_from_playlist/<int:playlist_id>/<int:song_id>', methods=['GET', 'POST'])
def remove_song_from_playlist(playlist_id, song_id):
    playlist = Playlist.query.get(playlist_id)
    song = Song.query.get(song_id)
    if playlist and song:
        if song in playlist.songs:
            playlist.songs.remove(song)
            db.session.commit()
            flash('Song removed from playlist successfully', category='success')
        else:
            flash('Song is not in the playlist', category='error')
    else:
        flash('Playlist or Song not found', category='error')

    return redirect(url_for('controllers.playlist_songs', playlist_id=playlist_id))


@controllers.route('/profile')
@login_required
def profile():
    favorite_ratings = Rating.query.filter_by(
        user_id=current_user.id).order_by(Rating.value.desc()).all()
    print(type(favorite_ratings))
    return render_template('profile.html', user=current_user, favorite_ratings=favorite_ratings)


@controllers.route('/read_lyrics/<int:song_id>')
@login_required
def read_lyrics(song_id):
    song = Song.query.get(song_id)
    return render_template('read_lyrics.html', user=current_user, song=song)


@controllers.route('/play_song/<int:song_id>')
@login_required
def play_song(song_id):
    song = Song.query.get(song_id)
    return render_template('play_song.html', user=current_user, song=song)


@controllers.route('/rate_song/<int:song_id>', methods=['GET', 'POST'])
@login_required
def rate_song(song_id):
    if request.method == 'POST':
        rating_value = int(request.form.get('rating'))
        user_id = current_user.id

        rating_exist = Rating.query.filter_by(
            user_id=user_id, song_id=song_id).first()
        if rating_exist:
            rating_exist.value = rating_value
            flash('Rating Updated!', category='success')
        else:
            new_rating = Rating(value=rating_value,
                                user_id=user_id, song_id=song_id)
            db.session.add(new_rating)
            flash('Song rated Successfully', category='success')
        db.session.commit()

    return redirect(url_for('controllers.home', user=current_user))

# -------------------------------------------Creator controllers---------------------------------------------------------


@controllers.route('/creator_dashboard', methods=['GET', 'POST'])
@login_required
def creator_dashboard():
    creator_id = current_user.id
    total_songs_uploaded = Song.query.filter_by(artist_id=creator_id).count()
    total_albums = Album.query.filter_by(artist_id=creator_id).count()
    songs = Song.query.filter_by(artist_id=creator_id).all()
    all_albums = Album.query.filter_by(artist_id=current_user.id).all()
    all_ratings = Rating.query.join(Song).filter(
        Song.artist_id == creator_id).all()
    total_ratings = sum([rating.value for rating in all_ratings])
    average_rating = total_ratings / \
        len(all_ratings) if len(all_ratings) > 0 else 0

    return render_template('creator_dashboard.html', user=current_user, total_songs_uploaded=total_songs_uploaded, songs=songs, total_albums=total_albums, average_rating=average_rating, all_albums=all_albums)


@controllers.route('/add_song_to_album/<int:album_id>', methods=['GET', 'POST'])
@login_required
def add_song_to_album(album_id):

    songs = Song.query.all()
    album = Album.query.get(album_id)

    if request.method == 'POST':
        selected_song_ids = request.form.getlist('song_ids[]')
        for song_id in selected_song_ids:
            existing_song = AlbumSongs.query.filter_by(
                album_id=album_id, song_id=song_id).first()
            if existing_song:
                pass
            else:
                album_song = AlbumSongs(album_id=album.id, song_id=song_id)
                db.session.add(album_song)

        db.session.commit()
        flash('Songs added successfully', category='success')
        return redirect(url_for('controllers.album_songs', album_id=album.id))

    return render_template('add_song_to_album.html', user=current_user, album=album, songs=songs)


@controllers.route('/remove_song_from_album/<int:album_id>/<int:song_id>', methods=['GET', 'POST'])
def remove_song_from_album(album_id, song_id):
    album = Album.query.get(album_id)
    song = Song.query.get(song_id)
    if album and song:
        if song in album.songs:
            album.songs.remove(song)
            db.session.commit()
            flash('Song removed from album successfully', category='success')
        else:
            flash('Song is not in the album', category='error')
    else:
        flash('Album or Song not found', category='error')

    return redirect(url_for('controllers.album_songs', album_id=album_id))


@controllers.route('/flagged_songs')
@login_required
def flagged_songs():
    flagged_songs = Song.query.filter_by(
        is_flagged=True, artist_id=current_user.id).all()
    return render_template('flagged_songs.html', user=current_user, flagged_songs=flagged_songs)

# -------------------------------------------Admin controllers---------------------------------------------------------


@controllers.route('/admin_dashboard')
@login_required
def admin_dashboard():

    total_normal_users = User.query.filter_by(user_type='user').count()
    total_creators = User.query.filter_by(user_type='creator').count()
    total_songs = Song.query.count()
    total_albums = Album.query.count()
    total_genres = Song.query.group_by(Song.genre).count()
    top_rated_songs = (Song.query.join(Rating).group_by(Song.id).order_by(desc(func.avg(Rating.value))).limit(5).all()
    )
    return render_template('admin_dashboard.html', admin=current_user,
                           total_normal_users=total_normal_users,
                           total_creators=total_creators,
                           total_songs=total_songs,
                           total_albums=total_albums,
                           total_genres=total_genres,
                           top_rated_songs=top_rated_songs)


@controllers.route('/flag_song/<int:song_id>')
@login_required
def flag_song(song_id):
    song = Song.query.get(song_id)
    if song:
        song.is_flagged = True
        db.session.commit()
        flash('Song Flagged Successfully!', category='success')
        return redirect(url_for('controllers.all_songs'))
    else:
        flash('No such song found!', category='error')
        return redirect(url_for('controllers.all_songs'))


@controllers.route('/blacklist/<int:user_id>')
@login_required
def blacklist(user_id):
    user = User.query.get(user_id)
    if user:
        user = User.query.get(user_id)
        user.is_blacklisted = True
        db.session.commit()
        if user.user_type == 'user':
            flash('User Blacklisted Successfully!', category='success')
            return redirect(url_for('controllers.all_users'))
        else:
            flash('Creator Blacklisted Successfully!', category='success')
            return redirect(url_for('controllers.all_creators'))
    else:
        if user.user_type == 'user':
            flash('No such user found!', category='error')
            return redirect(url_for('controllers.all_users'))
        else:
            flash('No such creator found!', category='error')
            return redirect(url_for('controllers.all_creators'))


@controllers.route('/whitelist/<int:user_id>')
@login_required
def whitelist(user_id):
    user = User.query.get(user_id)
    if user:
        user = User.query.get(user_id)
        user.is_blacklisted = False
        db.session.commit()
        if user.user_type == 'user':
            flash('User Whitelisted Successfully!', category='success')
            return redirect(url_for('controllers.all_users'))
        else:
            flash('Creator Whitelisted Successfully!', category='success')
            return redirect(url_for('controllers.all_creators'))
    else:
        if user.user_type == 'user':
            flash('No such user found!', category='error')
            return redirect(url_for('controllers.all_users'))
        else:
            flash('No such creator found!', category='error')
            return redirect(url_for('controllers.all_creators'))


@controllers.route('/all_users')
@login_required
def all_users():
    all_users = User.query.filter_by(user_type='user').all()
    return render_template('all_users.html', admin=current_user, all_users=all_users)


@controllers.route('/all_creators')
@login_required
def all_creators():
    all_creators = User.query.filter_by(user_type='creator').all()
    return render_template('all_creators.html', admin=current_user, all_creators=all_creators)
# -------------------------------------------CRUD Operations---------------------------------------------------------


@controllers.route('/all_songs')
@login_required
def all_songs():
    all_songs = Song.query.all()
    return render_template('all_songs.html', admin=current_user, all_songs=all_songs)


@controllers.route('/get_song/<int:song_id>', methods=['GET'])
@login_required
def get_song(song_id):
    song = Song.query.get(song_id)
    return render_template('all_songs.html', user=current_user, song=song)


@controllers.route('/upload_song', methods=['GET', 'POST'])
@login_required
def upload_song():
    if request.method == 'POST':
        title = request.form.get('title')
        artist_id = current_user.id
        album_title = request.form.get('album')
        release_date = request.form.get('release_date')
        genre = request.form.get('genre')
        lyrics = request.form.get('lyrics')
        song_file = request.files['song_file']

        if song_file:
            filename = secure_filename(song_file.filename)
            song_file.save(os.path.join('website/static/uploads', filename))

            album = Album.query.filter_by(
                title=album_title, artist_id=artist_id).first()
            if not album:
                album = Album(title=album_title, artist_id=artist_id)
                db.session.add(album)
                db.session.commit()

            new_song = Song(
                title=title,
                artist_id=artist_id,
                release_date=datetime.strptime(
                    release_date, '%Y-%m-%d').date(),
                genre=genre,
                lyrics=lyrics,
                file_path=filename,
                album=album
            )

            current_user.user_type = 'creator'
            db.session.add(new_song)
            db.session.add(album)
            db.session.commit()
            album_song = AlbumSongs(album_id=album.id, song_id=new_song.id)
            db.session.add(album_song)
            db.session.commit()

            flash('Song uploaded successfully', category='success')
            return redirect(url_for('controllers.home'))

    return render_template('upload_song.html', user=current_user)


@controllers.route('/update_song/<int:song_id>', methods=['GET', 'POST'])
@login_required
def update_song(song_id):
    song = Song.query.get(song_id)

    if not song or song.artist_id != current_user.id:
        flash('Song not found or you are not the creator.', category='error')
        return redirect(url_for('controllers.all_songs'))

    if request.method == 'POST':
        title = request.form.get('title')
        release_date = request.form.get('release_date')
        genre = request.form.get('genre')
        lyrics = request.form.get('lyrics')

        song.title = title
        song.release_date = datetime.strptime(
            release_date, '%Y-%m-%d').date()
        song.genre = genre
        song.lyrics = lyrics
        song.is_flagged = False

        db.session.commit()
        flash('Song updated successfully', category='success')

        if current_user.user_type == 'admin':
            return redirect(url_for('controllers.all_songs'))

        return redirect(url_for('controllers.creator_dashboard'))

    return render_template('update_song.html', user=current_user, song=song)


@controllers.route('/delete_song/<int:song_id>', methods=['GET', 'POST', 'DELETE'])
@login_required
def delete_song(song_id):
    song = Song.query.get(song_id)
    user = current_user
    if song:
        if user.user_type == 'creator' or user.user_type == 'admin':
            db.session.delete(song)
            db.session.commit()
            flash('Song deleted Successfully', category='success')
            if current_user.user_type == 'admin':
                return redirect(url_for('controllers.all_songs'))

            return redirect(url_for('controllers.creator_dashboard'))
        else:
            flash('You are not authorized to delete this song.')
    else:
        flash('Song does not exist!', category='error')
        if current_user.user_type == 'admin':
            return redirect(url_for('controllers.all_songs'))

        return redirect(url_for('controllers.creator_dashboard'))


@controllers.route('/search', methods=['GET'])
def search():
    query = request.args.get('query')

    if query:
        songs = Song.query.join(User).join(Album).filter(
            or_(Song.title.ilike(f"%{query}%"),
                User.firstname.ilike(f"%{query}%"),
                User.lastname.ilike(f"%{query}%"),
                Album.title.ilike(f"%{query}%"))
        ).all()
        if not songs:
            flash('No songs or artists found for the given text.', category='error')
            return redirect(url_for('controllers.home'))
    else:
        flash('Invalid Input!', category='error')
        return redirect(url_for('controllers.home'))

    return render_template('search_results.html', user=current_user, query=query, songs=songs)
