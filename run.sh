mkdir -p certs
if [ ! -f certs/cert.pem ]; then
    openssl genrsa -out certs/key.pem 2048
    openssl req -new -key certs/key.pem -out certs/csr.pem -batch
    openssl x509 -req -days 365 -in certs/csr.pem -signkey certs/key.pem -out certs/cert.pem
fi
exec gunicorn -c gunicorn.conf.py bot:app


