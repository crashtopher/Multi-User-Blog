import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'fart'

# Basic Functions for Usablity and Security


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# Helper Class for other Handlers to have access to basic Handler Functions


class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

# user stuff


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# blog stuff

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)

# Post class for database


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    created_by = db.StringProperty()
    last_modified = db.DateTimeProperty(auto_now=True)
    liked_by = db.ListProperty(str)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

    def render_edit(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("edit.html", p=self)

# comment class for database


class Comment(db.Model):
    post = db.IntegerProperty()
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    created_by = db.StringProperty()

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comment.html", c=self)


class BlogFront(Handler):

    def get(self):
        posts = Post.all().order('-created')
        self.render('front.html', posts=posts, user=self.user)


class NewPost(Handler):

    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            error = "You need to be logged in to do that."
            self.render("login-form.html", error=error)

    def post(self):
        if not self.user:
            return self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(), subject=subject,
                     content=content, created_by=self.user.name)
            p.put()
            return self.redirect('/%s' % str(p.key().id()))
        else:
            error = "we need a subject and content, Friend!"
            self.render(
                "newpost.html", subject=subject, content=content, error=error)

# handlers for Blog Requests


class PostPage(Handler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        comments = Comment.all().filter(
            'post =', int(post_id)).order('created')

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post, comments=comments)


class EditPostPage(Handler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user:
            if post.created_by == self.user.name:
                if not post:
                    self.error(404)
                    return

                self.render("editlink.html", post=post)
            else:
                self.render("error.html")
        else:
            error = "You need to be logged in to do that."
            self.render("login-form.html", error=error)

    def post(self, post_id):
        subject = self.request.get('subject')
        content = self.request.get('content')

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        # Updates existing entity without deleting and recreating it
        if self.user:
            if post.created_by == self.user.name:
                if subject and content:
                    post.subject = subject
                    post.content = content
                    post.created_by = self.user.name
                    post.put()
                    return self.redirect('/%s' % str(post.key().id()))
                else:
                    error = "we need a subject and content, Friend!"
                    self.render(
                        "edit.html", subject=subject, content=content,
                        error=error)
            else:
                self.render('error.html')
        else:
            error = "You need to be logged in to do that."
            self.render("login-form.html", error=error)


class DeletePostPage(Handler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user:
            if post.created_by == self.user.name:
                if not post:
                    self.error(404)
                    return

                self.render("delete.html", post=post)
            else:
                self.render("error.html")
        else:
            error = "You need to be logged in to do that."
            self.render("login-form.html", error=error)

    def post(self, post_id):
        delete = self.request.get('delete')

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user:
            if post.created_by == self.user.name:
                if delete == 'yes':
                    post.delete()
                    return self.redirect('/welcome')
                else:
                    return self.redirect('/%s/edit' % str(post.key().id()))
            else:
                self.render('error.html')
        else:
            error = "You need to be logged in to do that."
            self.render("login-form.html", error=error)

# like system for posts


class LikePost(Handler):

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        comments = Comment.all().filter(
            'post =', int(post_id)).order('created')

        if self.user:
            if post.created_by != self.user.name:
                if self.user.name not in post.liked_by:
                    post.liked_by.append(self.user.name)
                    post.put()
                    msg = "You Totally Like This Post!"
                    return self.render('permalink.html', post=post,
                                       comments=comments, msg=msg)

                else:
                    post.liked_by.remove(self.user.name)
                    post.put()
                    msg = "You Dont Like This Post..."
                    return self.render('permalink.html', post=post,
                                       comments=comments, msg=msg)
            else:
                msg = "You're Not Allowed To Like That..."
                self.render(
                    'permalink.html', post=post, comments=comments, msg=msg)
        else:
            error = "You need to be logged in to do that."
            self.render("login-form.html", error=error)

# comment Class Handlers


class PostComment(Handler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user:
            self.render('postcomment.html', post=post)
        else:
            error = "You need to be logged in to do that."
            self.render('login-form.html', error=error)

    def post(self, post_id):
        content = self.request.get('content')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user:
            if content:
                c = Comment(
                    post=int(post_id), content=content,
                    created_by=self.user.name)
                c.put()
                return self.redirect('/%s' % str(post.key().id()))
            else:
                error = "You never wrote a comment, Buddy."
                self.render(
                    'postcomment.html', post=post.user.name, error=error)


class CommentEdit(Handler):

    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)

        if self.user:
            if comment.created_by == self.user.name:
                content = comment.content
                self.render('editcomment.html', content=content)
            else:
                self.render('error.html')
        else:
            error = "You need to be logged in to do that!"
            self.render('login-form.html', error=error)

    def post(self, comment_id):
        content = self.request.get('content')

        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)

        if self.user:
            if comment.created_by == self.user.name:
                if content:
                    comment.content = content
                    comment.put()
                    return self.redirect('/welcome')
                else:
                    error = "You need some content to do that!"
                    self.render('editcomment.html', error=error)
            else:
                self.render('error.html')
        else:
            error = "You need to be logged in to do that!"
            self.render('login-form.html', error=error)


class CommentDelete(Handler):

    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)

        if self.user:
            if comment.created_by == self.user.name:
                self.render('delcomment.html')
        else:
            self.render('error.html')

    def post(self, comment_id):
        delete = self.request.get('delete')

        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)

        if self.user:
            if comment.created_by == self.user.name:
                if delete == 'yes':
                    comment.delete()
                    self.render('success.html')
                else:
                    return self.redirect('/')

# Code alows for Users to be created and set by cookies
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(Handler):

    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username, Friend."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password, Buddy."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match, Buddy."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email, Guy."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):

    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'Sorry! That user already exists. :('
            self.render('signup.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            return self.redirect('/welcome')


class Login(Handler):

    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            return self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(Handler):

    def get(self):
        self.logout()
        self.redirect('/')

# "Welcome Page" acts as Homepage for Users to view/edit their own posts


class Unit3Welcome(Handler):

    def get(self):
        if self.user:
            posts = Post.all().filter(
                'created_by =', self.user.name).order('-created')
            self.render('welcome.html', username=self.user.name, posts=posts)
        else:
            error = "you need to be logged in to do that."
            self.render('loggin-form.html', error=error)

app = webapp2.WSGIApplication([('/', BlogFront),
                               ('/newpost', NewPost),
                               ('/([0-9]+)', PostPage),
                               ('/([0-9]+)/edit', EditPostPage),
                               ('/([0-9]+)/delete', DeletePostPage),
                               ('/([0-9]+)/like', LikePost),
                               ('/([0-9]+)/comment', PostComment),
                               ('/([0-9]+)/editcomment', CommentEdit),
                               ('/([0-9]+)/delcomment', CommentDelete),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Unit3Welcome),
                               ],
                              debug=True)
