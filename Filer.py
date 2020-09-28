#!venv/bin/python

import hashlib
import base64
import time
import gpgencryption
from os import unlink, path, getenv, listdir, mkdir, chmod, umask, urandom
from shutil import rmtree
from threading import Thread
from random import randint
from sys import stderr, exit

from flask import (
    Flask,
    render_template,
    jsonify,
    request,
    redirect,
    send_from_directory,
    g,
)
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_dropzone import Dropzone
from flask_babel import Babel, _, refresh
from argparse import ArgumentParser
from werkzeug.utils import secure_filename

app = Flask(__name__)
### start of config
app.config["SECRET_KEY"] = getenv("SECRET_KEY", None)
# app.jinja_env.trim_blocks = True
# app.jinja_env.lstrip_blocks = True


app.config["DROPZONE_ALLOWED_FILE_CUSTOM"] = True
app.config["DROPZONE_ALLOWED_FILE_TYPE"] = ""
app.config["DROPZONE_SERVE_LOCAL"] = True
app.config["DROPZONE_ENABLE_CSRF"] = True
app.config["DROPZONE_TIMEOUT"] = 600000
app.config["WTF_CSRF_SSL_STRICT"] = False # Disable looking at referrer

app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = 'Strict'

app.config["ORGANIZATION"] = getenv("ORGANIZATION", "Kanzlei Hubrig")
app.config["TITLE"] = "Filer"
app.config["LANGUAGES"] = ["en", "de"]

filettl = int(getenv("FILER_FILETTL", 10))  # file lifetime in days
support_public_docs = True

gpg_enable_upload_encryption = True  # encrypt customer-uploaded data via GPG
gpg_recipient_fprint = None
gpg_key_server = "keys.openpgp.org"

basedir = getenv("FILER_BASEDIR", "./Daten")
publicdir = getenv("FILER_PUBLICDIR", "Public")
documentsdir = getenv("FILER_DOCUMENTSDIR", "Dokumente")
clientsdir = getenv("FILER_CLIENTSSDIR", "Mandanten")
gpg_home_dir = path.join(basedir, "gpghome")

### end of config

csrf = CSRFProtect(app)
dropzone = Dropzone(app)
babel = Babel(app)


nonce = base64.b64encode(urandom(64)).decode("utf8")
default_http_header = {
    "Content-Security-Policy": f"default-src 'self'; img-src 'self' data:; script-src 'self' 'nonce-{nonce}'",
    "X-Frame-Options": "SAMEORIGIN",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy" : "no-referrer"
}


def update_dropzone_message():
    app.config["DROPZONE_DEFAULT_MESSAGE"] = _(
        "Ziehe die Dateien hier hin, um sie hochzuladen oder klicken Sie zur Auswahl."
    )


#### ADMIN FACING DIRECTORY LISTS ####
####
####
@app.route("/admin", methods=["GET"])
def admin():

    update_dropzone_message()
    url_root = request.url_root.replace("http://", "https://", 1)
    users = listdir(path.join(basedir, clientsdir))
    return (
        render_template(
            "admin.html",
            users=users,
            tree=make_tree(basedir, publicdir),
            url_root=url_root,
            documentsdir=documentsdir,
            support_public_docs=support_public_docs,
            nonce=nonce,
            organization=app.config["ORGANIZATION"],
            title=app.config["TITLE"],
        ),
        200,
        default_http_header,
    )


@app.route("/admin/" + documentsdir + "/<user>", methods=["GET"])
def admin_dokumente(user):
    update_dropzone_message()
    return (
        render_template(
            "mandant.html",
            admin="admin/",
            user=secure_filename(user),
            tree=make_tree(basedir, path.join(documentsdir, secure_filename(user))),
            documentsdir=documentsdir,
            support_public_docs=support_public_docs,
            nonce=nonce,
            organization=app.config["ORGANIZATION"],
            title=app.config["TITLE"],
        ),
        200,
        default_http_header,
    )


#
# API
#


@app.route("/admin/del-user/<user>", methods=["POST"])
def admin_deluser(user):
    method = request.form.get("_method", "POST")
    if method == "DELETE":
        rmtree(path.join(basedir, documentsdir, secure_filename(user)))
        unlink(path.join(basedir, clientsdir, secure_filename(user)))
    return redirect("/admin")


@app.route("/admin/new-user", methods=["POST"])
def admin_newuser():
    password = request.form.get("password", "")
    user = request.form.get("user", "")
    if not password or not user:
        return "Username or password missing", 400
    directory = secure_filename(user)

    salt = urandom(4)
    sha = hashlib.sha1(password.encode("utf-8"))
    sha.update(salt)

    digest_salt_b64 = base64.b64encode(sha.digest() + salt)
    tagged_digest_salt = "{{SSHA}}{}".format(digest_salt_b64.decode("ascii"))

    try:
        make_dir(path.join(basedir, documentsdir, directory))
        with open(
            path.join(basedir, clientsdir, directory), "w+", encoding="utf-8"
        ) as htpasswd:
            htpasswd.write("{}:{}\n".format(secure_filename(user), tagged_digest_salt))

    except OSError as error:
        return "Couldn't create user scope", 500
    return redirect("/admin")


#### USER FACING DIRECTORY LIST ####
####
####
@app.route("/" + documentsdir + "/<user>", methods=["GET"])
def mandant(user):
    update_dropzone_message()
    return (
        render_template(
            "mandant.html",
            admin="",
            user=secure_filename(user),
            tree=make_tree(basedir, path.join(documentsdir, secure_filename(user))),
            documentsdir=documentsdir,
            support_public_docs=support_public_docs,
            nonce=nonce,
            organization=app.config["ORGANIZATION"],
            title=app.config["TITLE"],
        ),
        200,
        default_http_header,
    )


#### UPLOAD FILE ROUTES ####
####
####


@app.route("/" + documentsdir + "/<user>", methods=["POST"])
def upload_mandant_as_mandant(user):
    return _upload_mandant(
        user,
        encrypt=(gpg_enable_upload_encryption and gpg_recipient_fprint is not None),
    )


@app.route("/admin/" + documentsdir + "/<user>", methods=["POST"])
def upload_mandant_as_admin(user):
    return _upload_mandant(user)


@app.route("/admin", methods=["POST"])
def upload_admin():
    return _upload_mandant()


def _upload_mandant(user=None, encrypt=False):
    for key, f in request.files.items():
        if key.startswith("file"):
            filename = secure_filename(f.filename)
            if user:
                username = secure_filename(user)
                pathname = path.join(basedir, documentsdir, username, filename)

                if encrypt:
                    pathname += ".gpg"
                    enc = gpgencryption.GPGEncryption(gpg_home_dir, gpg_key_server)
                    enc.encrypt_fh(gpg_recipient_fprint, f, pathname)  # no signing

                else:
                    f.save(pathname)
            else:
                f.save(path.join(basedir, publicdir, filename))
    return "upload template"


# handle CSRF error
@app.errorhandler(CSRFError)
def csrf_error(e):
    return e.description, 400


#### DELETE FILE ROUTES ####
####
####
@app.route("/" + documentsdir + "/<user>/<path:filename>", methods=["POST"])
def delete_file_mandant(user, filename):
    method = request.form.get("_method", "POST")
    if method == "DELETE":
        unlink(
            path.join(
                basedir, documentsdir, secure_filename(user), secure_filename(filename)
            )
        )
    return redirect("/" + documentsdir + "/" + secure_filename(user))


@app.route("/admin/" + documentsdir + "/<user>/<path:filename>", methods=["POST"])
def delete_file_mandant_admin(user, filename):
    method = request.form.get("_method", "POST")
    if method == "DELETE":
        unlink(
            path.join(
                basedir, documentsdir, secure_filename(user), secure_filename(filename)
            )
        )
    return redirect("/admin/" + documentsdir + "/" + secure_filename(user))


@app.route("/admin/" + publicdir + "/<path:filename>", methods=["POST"])
def delete_file_admin(filename):
    method = request.form.get("_method", "POST")
    if method == "DELETE":
        unlink(path.join(basedir, publicdir, secure_filename(filename)))
    return redirect("/admin")


#### SERVE FILES RULES ####
####
####
@app.route("/admin/" + documentsdir + "/<user>/<path:filename>", methods=["GET"])
@app.route("/" + documentsdir + "/<user>/<path:filename>", methods=["GET"])
def custom_static(user, filename):
    return send_from_directory(
        path.join(basedir, documentsdir), path.join(user, filename)
    )


@app.route("/" + publicdir + "/<path:filename>")
def custom_static_public(filename):
    return send_from_directory(path.join(basedir, publicdir), filename)


def make_tree(rel, pathname, clean_expired=True):
    tree = dict(name=pathname, download=path.basename(pathname), children=[])
    try:
        lst = listdir(path.join(rel, pathname))
    except OSError:
        pass  # ignore errors
    else:
        for name in lst:
            fn = path.join(pathname, name)
            if path.isdir(path.join(rel, fn)):
                tree["children"].append(make_tree(rel, fn, clean_expired))
            else:
                ttl = filettl - int(
                    (time.time() - path.getmtime(path.join(rel, fn))) / (24 * 3600)
                )
                if clean_expired and ttl < 0:
                    unlink(path.join(rel, fn))
                else:
                    tree["children"].append(dict(name=fn, download=name, ttl=ttl))
    return tree


# Start a cleaner thread that will trigger make_tree's side effect of
# wiping old files
def cleaner_thread():
    while True:
        make_tree(basedir, documentsdir)
        # sleep for 6h plus jitter
        time.sleep(21600 + randint(1, 1800))


def make_dir(dir_name):
    if not path.exists(dir_name):
        mkdir(dir_name)
        chmod(dir_name, 0o700)


@babel.localeselector
def get_locale():
    if not g.get("lang_code", None):
        g.lang_code = request.accept_languages.best_match(app.config["LANGUAGES"])
    return g.lang_code


# Main program

umask(0o177)

thread = Thread(target=cleaner_thread, args=())
thread.daemon = True
thread.start()

# Ensure all working directories are there
try:
    for datadir in (
        basedir,
        path.join(basedir, documentsdir),
        path.join(basedir, clientsdir),
        path.join(basedir, publicdir),
    ):
        make_dir(datadir)
except:
    stderr.write("Error: Basedir not accessible\n")
    exit(1)

if app.config["SECRET_KEY"] is None:
    stderr.write("Error: Flask secret key is not set.\n")
    exit(1)

# download GPG key if enabled
if gpg_enable_upload_encryption and gpg_recipient_fprint is not None:
    enc = gpgencryption.GPGEncryption(gpg_home_dir, gpg_key_server)
    enc.download_key(gpg_recipient_fprint)


if __name__ == "__main__":
    parser = ArgumentParser(description="Filer")
    parser.add_argument(
        "-H",
        "--host",
        help="Hostname of the Flask app " + "[default %s]" % "127.0.0.1",
        default="127.0.0.1",
    )
    parser.add_argument(
        "-P",
        "--port",
        help="Port for the Flask app " + "[default %s]" % "5000",
        default="5000",
    )

    args = parser.parse_args()

    app.run(host=args.host, port=int(args.port))
