# Self-hosted PhishGuard detonation sandbox.
# Built on Microsoft's Playwright image, which already includes a browser.
FROM mcr.microsoft.com/playwright/python:v1.44.0-jammy

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY sandbox_server.py .

EXPOSE 9000
CMD ["uvicorn", "sandbox_server:app", "--host", "0.0.0.0", "--port", "9000"]
