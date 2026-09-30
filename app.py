"""
Flask test harness for Glassworm / sentinel.

Serves a handful of fake GraphQL endpoints so you can test:
  - detect_graphql()            -> hits /graphql and /api/graphql
  - gobuster filtering          -> one URL contains "graphql", one "api"
  - introspection_check()       -> /graphql returns a full schema
  - error paths                 -> 404 / 500 / non-JSON endpoints

Run:
    pip install flask
    python app.py
Then:
    ./sentinel ./output            # see scan.rs::graphql_scanning
    ./sentinel --gobuster ./output # after running gobuster -> ./output/gobuster.txt
"""

import json
import os
from flask import Flask, request, Response, jsonify

app = Flask(__name__)

HERE = os.path.dirname(os.path.abspath(__file__))


# ----------------------------------------------------------------------
# Load the same payloads Glassworm ships with, if they're present.
# ----------------------------------------------------------------------
def _load(name: str) -> dict:
    for candidate in (
        os.path.join(HERE, "glassworm", "graphql", name),
        os.path.join(HERE, "..", "glassworm", "graphql", name),
        name,
    ):
        if os.path.isfile(candidate):
            with open(candidate, "r", encoding="utf-8") as fh:
                return json.load(fh)
    return {}


INTROSPECTION = _load("introspection.json")   # the big query
UNI = _load("uni.json")                       # the small probe


# ----------------------------------------------------------------------
# A complete, realistic-looking introspection *response*.
# This is what scan.rs -> introspection_check() will parse and analyze.
# ----------------------------------------------------------------------
FULL_SCHEMA_RESPONSE = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "subscriptionType": None,
            "types": [
                {
                    "kind": "OBJECT",
                    "name": "Query",
                    "description": "Root query",
                    "fields": [
                        {
                            "name": "user",
                            "description": "Fetch a user",
                            "args": [
                                {"name": "id", "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "ID"}}}
                            ],
                            "type": {"kind": "OBJECT", "name": "User"},
                            "isDeprecated": False,
                            "defaultValue": None,
                        },
                        {
                            "name": "users",
                            "description": "List all users",
                            "args": [],
                            "type": {"kind": "LIST", "ofType": {"kind": "OBJECT", "name": "User"}},
                            "isDeprecated": False,
                            "defaultValue": None,
                        },
                        {
                            "name": "apiKey",
                            "description": "Returns the caller's API key",
                            "args": [],
                            "type": {"kind": "SCALAR", "name": "String"},
                            "isDeprecated": False,
                            "defaultValue": None,
                        },
                    ],
                    "interfaces": [],
                },
                {
                    "kind": "OBJECT",
                    "name": "User",
                    "description": "A user record",
                    "fields": [
                        {"name": "id", "args": [], "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "ID"}}, "isDeprecated": False},
                        {"name": "email", "args": [], "type": {"kind": "SCALAR", "name": "String"}, "isDeprecated": False},
                        {"name": "passwordHash", "args": [], "type": {"kind": "SCALAR", "name": "String"}, "isDeprecated": True},
                        {"name": "creditCard", "args": [], "type": {"kind": "SCALAR", "name": "String"}, "isDeprecated": False},
                        {"name": "friends", "args": [], "type": {"kind": "LIST", "ofType": {"kind": "OBJECT", "name": "User"}}, "isDeprecated": False},
                    ],
                    "interfaces": [],
                },
                {
                    "kind": "OBJECT",
                    "name": "Mutation",
                    "description": "Root mutation",
                    "fields": [
                        {"name": "createUser", "args": [
                            {"name": "input", "type": {"kind": "INPUT_OBJECT", "name": "UserInput"}}
                        ], "type": {"kind": "OBJECT", "name": "User"}, "isDeprecated": False},
                    ],
                    "interfaces": [],
                },
                {
                    "kind": "INPUT_OBJECT",
                    "name": "UserInput",
                    "description": None,
                    "inputFields": [
                        {"name": "email", "type": {"kind": "SCALAR", "name": "String"}, "defaultValue": None},
                        {"name": "password", "type": {"kind": "SCALAR", "name": "String"}, "defaultValue": None},
                    ],
                },
                {
                    "kind": "ENUM",
                    "name": "Role",
                    "description": None,
                    "enumValues": [
                        {"name": "ADMIN", "isDeprecated": False},
                        {"name": "USER", "isDeprecated": False},
                        {"name": "LEGACY", "isDeprecated": True},
                    ],
                },
                {
                    "kind": "SCALAR",
                    "name": "DateTime",
                    "description": None,
                    "specifiedByURL": "https://scalars.graphql.org/andimarek/date-time",
                },
                # Built-ins: should be filtered out by build_schema_data().
                {"kind": "SCALAR", "name": "String", "description": None},
                {"kind": "SCALAR", "name": "Int", "description": None},
                {"kind": "SCALAR", "name": "Boolean", "description": None},
                {"kind": "SCALAR", "name": "Float", "description": None},
                {"kind": "SCALAR", "name": "ID", "description": None},
                {"kind": "OBJECT", "name": "__Type", "description": None, "fields": [], "interfaces": []},
            ],
            "directives": [
                {"name": "include", "args": [{"name": "if", "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "Boolean"}}}]},
                {"name": "skip", "args": [{"name": "if", "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "Boolean"}}}]},
            ],
        }
    }
}


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def _looks_like_introspection(body: bytes) -> bool:
    """Does the POST body ask for __schema / introspection?"""
    try:
        text = body.decode("utf-8", errors="ignore")
    except Exception:
        return False
    return "__schema" in text or "__type" in text or "IntrospectionQuery" in text


def _graphql_like_response() -> Response:
    return Response(json.dumps(FULL_SCHEMA_RESPONSE), mimetype="application/json")


# ----------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------

@app.route("/graphql", methods=["POST", "GET"])
def graphql_main():
    """The 'real' endpoint: full introspection."""
    if request.method == "GET":
        return "GraphQL endpoint. POST your query.", 200
    body = request.get_data()
    if _looks_like_introspection(body) or body == b"":
        return _graphql_like_response()
    # Non-introspection query -> minimal, but still GraphQL-shaped.
    return jsonify({"data": {"__typename": "Query"}}), 200


@app.route("/api/graphql", methods=["POST"])
def graphql_api():
    """Second GraphQL endpoint — both 'api' and 'graphql' in the path,
    so gobuster filtering will keep it."""
    return _graphql_like_response()


@app.route("/api/v1/users", methods=["POST", "GET"])
def api_only():
    """Has 'api' but is NOT GraphQL. Response must NOT contain the
    detection keywords, otherwise detect_graphql() will falsely flag it."""
    return jsonify({"users": [{"id": 1, "name": "alice"}]}), 200


@app.route("/graphql-broken", methods=["POST"])
def graphql_broken():
    """GraphQL-looking path, but returns 500 — detection should skip it."""
    return jsonify({"errors": [{"message": "internal error"}]}), 500


@app.route("/graphql-html", methods=["POST"])
def graphql_html():
    """GraphQL-looking path, but returns HTML (no JSON body)."""
    return Response("<html><body>not graphql</body></html>", mimetype="text/html"), 200


@app.route("/graphql-slow", methods=["POST"])
def graphql_slow():
    """Triggers the client timeout path if you set the timeout low."""
    import time
    time.sleep(35)
    return _graphql_like_response()


@app.route("/", methods=["GET"])
def index():
    return (
        "<h1>Glassworm test harness</h1>"
        "<ul>"
        "<li>POST /graphql           -> full introspection</li>"
        "<li>POST /api/graphql       -> full introspection</li>"
        "<li>POST /api/v1/users      -> decoy (no GraphQL)</li>"
        "<li>POST /graphql-broken    -> 500</li>"
        "<li>POST /graphql-html      -> HTML, not JSON</li>"
        "<li>POST /graphql-slow      -> sleeps 35s</li>"
        "</ul>"
    )


if __name__ == "__main__":
    # Run on plain HTTP so http.rs can hit it directly.
    # Use 127.0.0.1, not localhost, to avoid IPv6 resolution surprises.
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)