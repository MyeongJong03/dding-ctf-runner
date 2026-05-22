from flask import Flask, request

app = Flask(__name__)


@app.route("/upload", methods=["POST"])
def upload():
    filename = request.files["file"].filename
    return eval(request.form.get("expr", "0"))
