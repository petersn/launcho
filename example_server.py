import sys
import os
sys.path.append("/home/snp/.local/lib/python3.10/site-packages")
from flask import Flask

app = Flask(__name__)

version = sys.argv[1]

@app.route("/api")
def api():
    return "My version: %s\n" % version

@app.route("/health")
def health():
    return "ok"

if __name__ == "__main__":
    port = int(os.environ["SERVICE_PORT_SV1"])
    print("Starting server on port %d" % port)
    app.run("localhost", port=port)
