FROM python:3.8-slim-buster

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

COPY . .

CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:app", "--access-logfile", "-"]
#CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:app", "--access-logfile", "-", "--keyfile=nginx/cert.pem", "--certfile=nginx/key.pem"]
# FROM python:3.8-slim-buster

# WORKDIR /app

# COPY requirements.txt .
# RUN pip install -r requirements.txt

# COPY app.py .

# CMD ["python", "app.py"]
