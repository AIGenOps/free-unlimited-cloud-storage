import os

bind = f"0.0.0.0:{os.getenv('PORT', '443')}"
workers = int(os.getenv("GUNICORN_WORKERS", "1"))
threads = int(os.getenv("GUNICORN_THREADS", "8"))
timeout = int(os.getenv("GUNICORN_TIMEOUT", "120"))
keepalive = 5
accesslog = "-"
errorlog = "-"
loglevel = os.getenv("LOGGING_LEVEL", "info").lower()

enable_ssl = os.getenv("ENABLE_SSL", "True").upper() == "TRUE"
if enable_ssl and os.path.exists("certs/cert.pem") and os.path.exists("certs/key.pem"):
    certfile = "certs/cert.pem"
    keyfile = "certs/key.pem"
