FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt && playwright install --with-deps chromium
COPY xss_sentinel ./xss_sentinel
COPY static ./static
COPY templates ./templates

EXPOSE 8000
CMD ["uvicorn", "xss_sentinel.main:app", "--host", "0.0.0.0", "--port", "8000"]
