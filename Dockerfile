# PhishGuard backend + web UI in one container.
# Build:  docker build -t phishguard .
# Run:    docker run -p 8000:8000 phishguard   (then open http://localhost:8000/)
FROM python:3.11-slim

WORKDIR /app

# Install Python dependencies first (better build caching).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code and the web page.
COPY src/ ./src/
COPY web/ ./web/

# Build the dataset and train the model at image-build time, so the trained
# model is baked into the image and the app is ready to serve immediately.
RUN python src/make_dataset.py && python src/train.py

# Optional API keys for live link reputation / detonation (leave blank to skip).
ENV VIRUSTOTAL_API_KEY=""
ENV URLSCAN_API_KEY=""

EXPOSE 8000
# Use the platform-provided $PORT if set (e.g. on Render), else default to 8000.
CMD ["sh", "-c", "uvicorn src.api:app --host 0.0.0.0 --port ${PORT:-8000}"]
