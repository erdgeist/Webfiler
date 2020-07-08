#!venv/bin/python

import hashlib
import base64
import time
from os import unlink, path, getenv, listdir, mkdir, urandom
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
)
from flask_dropzone import Dropzone
from argparse import ArgumentParser
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["SECRET_KEY"] = "You should change this value!"
# app.jinja_env.trim_blocks = True
# app.jinja_env.lstrip_blocks = True

app.config["PREFERRED_URL_SCHEME"] = "https"
app.config["DROPZONE_SERVE_LOCAL"] = True
app.config["DROPZONE_MAX_FILE_SIZE"] = 128
app.config["DROPZONE_UPLOAD_MULTIPLE"] = True
app.config["DROPZONE_PARALLEL_UPLOADS"] = 10

app.config["DROPZONE_ALLOWED_FILE_CUSTOM"] = True
app.config["DROPZONE_ALLOWED_FILE_TYPE"] = ""

app.config[
    "DROPZONE_DEFAULT_MESSAGE"
] = "Ziehe die Dateien hier hin, um sie hochzuladen oder klicken Sie zur Auswahl."

dropzone = Dropzone(app)

basedir = getenv("FILER_BASEDIR", "./Daten")
publicdir = getenv("FILER_PUBLICDIR", "Public")
documentsdir = getenv("FILER_DOCUMENTSDIR", "Dokumente")
clientsdir = getenv("FILER_CLIENTSSDIR", "Mandanten")

filettl = int(getenv("FILER_FILETTL", 10))

#### ADMIN FACING DIRECTORY LISTS ####
####
####
@app.route("/admin", methods=["GET"])
def admin():
    url_root = request.url_root.replace("http://", "https://", 1)
    users = listdir(path.join(basedir, clientsdir))
    return render_template(
        "admin.html",
        users=users,
        tree=make_tree(basedir, publicdir, False),
        url_root=url_root,
        documentsdir=documentsdir,
    )


@app.route("/admin/" + documentsdir + "/<user>", methods=["GET"])
def admin_dokumente(user):
    return render_template(
        "mandant.html",
        admin="admin/",
        user=user,
        tree=make_tree(basedir, path.join(documentsdir, user)),
        documentsdir=documentsdir,
    )


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
        if not path.exists(path.join(basedir, documentsdir, directory)):
            mkdir(path.join(basedir, documentsdir, directory))
        with open(
            path.join(basedir, clientsdir, directory), "w+", encoding="utf-8"
        ) as htpasswd:
            htpasswd.write("{}:{}\n".format(user, tagged_digest_salt))
    except OSError as error:
        return "Couldn't create user scope", 500
    return redirect("/admin")


#### USER FACING DIRECTORY LIST ####
####
####
@app.route("/" + documentsdir + "/<user>", methods=["GET"])
def mandant(user):
    return render_template(
        "mandant.html",
        admin="",
        user=user,
        tree=make_tree(basedir, path.join(documentsdir, user)),
        documentsdir=documentsdir,
    )


#### UPLOAD FILE ROUTES ####
####
####
@app.route("/" + documentsdir + "/<user>", methods=["POST"])
@app.route("/admin/" + documentsdir + "/<user>", methods=["POST"])
def upload_mandant(user):
    for key, f in request.files.items():
        if key.startswith("file"):
            username = secure_filename(user)
            filename = secure_filename(f.filename)
            f.save(path.join(basedir, documentsdir, username, filename))
    return "upload template"


@app.route("/admin", methods=["POST"])
def upload_admin():
    for key, f in request.files.items():
        if key.startswith("file"):
            filename = secure_filename(f.filename)
            f.save(path.join(basedir, publicdir, filename))
    return "upload template"


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
    return redirect("/" + documentsdir + "/" + user)


@app.route("/admin/" + documentsdir + "/<user>/<path:filename>", methods=["POST"])
def delete_file_mandant_admin(user, filename):
    method = request.form.get("_method", "POST")
    if method == "DELETE":
        unlink(
            path.join(
                basedir, documentsdir, secure_filename(user), secure_filename(filename)
            )
        )
    return redirect("/admin/" + documentsdir + "/" + user)


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


def make_tree(rel, pathname, clean_expired = True):
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
        if not path.exists(datadir):
            mkdir(datadir)
except:
    stderr.write("Error: Basedir not accessible\n")
    exit(1)

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
