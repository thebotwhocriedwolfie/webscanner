from flask import Flask, request, jsonify

app = Flask(__name__)

#Test db
users = [
    {"id": 1, "name": "admin"},
    {"id": 2, "name": "john"}
]

@app.route("/")
def home():
    return """
    <h1>Vulnerable Test Site!!!</h1>
    <ul>
        <li><a href="/search?q=test">Search</a></li>
        <li><a href="/user?id=1">User Lookup</a></li>
        <li><a href="/admin">Admin Panel</a></li>
        <li><a href="/config">Config</a></li>
    </ul>
    """

#Reflected XSS
@app.route("/search")
def search():
    query = request.args.get("q", "")
    return f"<h2>You searched for: {query}</h2>"

#Simulated SQL Injection
@app.route("/user")
def get_user():
    user_id = request.args.get("id", "")
    
    #intentionally unsafe query 
    query = f"SELECT * FROM users WHERE id = {user_id}"
    
    return f"Executing query: {query}"

#Sensitive info exposure
@app.route("/config")
def config():
    return jsonify({
        "db_host": "localhost",
        "db_user": "root",
        "db_password": "root123",
        "api_key": "SUPER_SECRET_KEY"
    })

# hidden admin panel
@app.route("/admin")
def admin():
    return "<h1>Admin Panel - Confidential</h1>"

if __name__ == "__main__":
    app.run(debug=True, port=5000)
