FROM python:3.9-slim

WORKDIR /app

COPY htb.py .
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8501

CMD ["streamlit", "run", "htb.py", "--server.port=8501", "--server.address=0.0.0.0"]
