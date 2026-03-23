from flask import Flask, request

app = Flask(__name__)

@app.route("/")
def home():
    name = request.args.get("name")

    # XSS vulnerability
    return "<h1>Hello " + name + "</h1>"

if __name__ == "__main__":
    app.run()
