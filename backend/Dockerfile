FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app/backend

WORKDIR /app/backend
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY backend /app/backend

CMD ["sh", "-c", "python manage.py migrate --noinput && gunicorn edupki.wsgi:application --bind 0.0.0.0:8000"]

