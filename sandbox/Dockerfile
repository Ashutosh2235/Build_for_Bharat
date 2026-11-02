# Isolated link sandbox. Playwright image tag must match the pip playwright version.
FROM mcr.microsoft.com/playwright/python:v1.64.1-noble
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 SCREEN_DIR=/screens
WORKDIR /srv
COPY sandbox/requirements.txt .
RUN pip install -r requirements.txt
COPY sandbox/server.py sandbox/page_analysis.py ./
# pwuser ships with the Playwright image (non-root)
RUN mkdir -p /screens && chown pwuser /screens
USER pwuser
EXPOSE 8100
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8100"]
