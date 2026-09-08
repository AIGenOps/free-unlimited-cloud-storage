FROM python:3.10-slim

RUN apt-get update && apt-get install -y openssl curl && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /svc/certs /svc/schema
WORKDIR /svc

COPY requirements.txt /svc/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY static/ /svc/static/
COPY utils/ /svc/utils/
COPY templates/ /svc/templates/
COPY certs/ /svc/certs/
COPY bot.py /svc/bot.py
COPY core.py /svc/core.py
COPY auth.py /svc/auth.py
COPY gunicorn.conf.py /svc/gunicorn.conf.py
COPY schema/ /svc/schema/
COPY run.sh /svc/run.sh

EXPOSE 443 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -k -f https://localhost:443/login || curl -f http://localhost:443/login || exit 1

CMD [ "bash", "run.sh"]


