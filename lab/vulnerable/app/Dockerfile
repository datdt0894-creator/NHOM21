# [SEED-07] Dockerfile yếu: base cũ, chạy root, ADD, EXPOSE 22, secret trong ENV, không HEALTHCHECK
FROM python:3.8
ENV DB_PASSWORD=admin123
WORKDIR /app
ADD . /app
RUN pip install -r requirements.txt
EXPOSE 22 5000
CMD ["python", "app.py"]
