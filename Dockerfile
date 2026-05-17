FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y curl

COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

RUN mkdir -p /app/data

EXPOSE 5000
EXPOSE 5001
