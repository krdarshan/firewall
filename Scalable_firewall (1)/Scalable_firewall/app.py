from flask import Flask
from src.hybrid_waf.routes.main import main_bp
from src.hybrid_waf.routes.proxy import proxy_bp  # Import proxy Blueprint

app = Flask(__name__)

# Register blueprints
app.register_blueprint(main_bp)
app.register_blueprint(proxy_bp)

if __name__ == '__main__':
    # Listen on all network interfaces (0.0.0.0) to accept connections from other devices on the network
    app.run(host='0.0.0.0', port=5000, debug=True)
