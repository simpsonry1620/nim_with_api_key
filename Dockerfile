FROM python:3.9-slim

# Install debugging tools
RUN apt-get update && apt-get install -y curl iputils-ping

# Install SQLite
RUN apt-get update && apt-get install -y sqlite3

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

EXPOSE 8000
CMD ["uvicorn", "app.app:app", "--host", "0.0.0.0", "--port", "8000"]

