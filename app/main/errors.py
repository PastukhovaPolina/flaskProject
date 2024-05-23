from flask import render_template
from . import main


@main.errorhandler(500)
def internal_server_error(error):
    """Handle internal server error (500)."""
    return render_template("error.html"), 500


@main.route("/error")
def raise_error():
    """Route to intentionally raise an internal server error."""
    raise Exception("Error 500: Internal Server Error")
