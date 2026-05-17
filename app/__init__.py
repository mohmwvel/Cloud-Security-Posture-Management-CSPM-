from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os

# Initialize Limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
)

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'default-dev-key')
    
    limiter.init_app(app)
    
    # Register blueprints/routes
    from .routes import main_bp
    app.register_blueprint(main_bp)
    
    return app
