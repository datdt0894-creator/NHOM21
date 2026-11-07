FROM python:3.12.16-alpine3.23

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

WORKDIR /app

# Cai dat zlib da co ban sua bao mat
RUN apk add --no-cache zlib=1.4-r0

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Tao user khong co quyen root
RUN addgroup -S app && \
    adduser -S -D -H -u 10001 -G app appuser

USER 10001

EXPOSE 5000

HEALTHCHECK --interval=30s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:5000/health')" || exit 1

CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:app"]
