from flask import Blueprint, render_template

bp = Blueprint("main", __name__)


# @bp.before_request
# def before_request_callback():


@bp.route("/", methods=["GET"])
def index():
    return render_template("pages/index.jinja")
