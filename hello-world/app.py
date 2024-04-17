from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route('/', methods=['GET'])
def home():
    return 'Hello World!', 200


@app.route('/callback', methods=['GET', 'POST'])
def callback():
    payload = request.headers.get('x-jwt-payload', None)
    tenant_id = request.headers.get('X-tenant-id', None)
    return jsonify({"X-tenant-id": tenant_id, "jwt-payload": payload}), 200


if __name__ == '__main__':
    app.run(debug=True)
