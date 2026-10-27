from flask import Flask, request
from flask_cors import CORS

from .routes.backup_codes import bp as backup_codes_bp
from .routes.settings import bp as settings_bp
from .routes.verification import bp as verification_bp


def create_app():
    app = Flask(__name__)
    CORS(
        app,
        supports_credentials=True,
        origins=["http://localhost:4200", "http://localhost:4201"],
    )
    app.register_blueprint(settings_bp)
    app.register_blueprint(verification_bp)
    app.register_blueprint(backup_codes_bp)

    @app.before_request
    def debug_request():
        print(
            f"[DEBUG] -> {request.method} {request.path} endpoint={request.endpoint}",
            flush=True,
        )

    @app.after_request
    def debug_response(response):
        print(
            f"[DEBUG] <- {request.method} {request.path} status={response.status_code}",
            flush=True,
        )
        return response

    return app
