FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    fastapi==0.115.0 \
    uvicorn==0.32.0 \
    presidio-analyzer==2.2.354 \
    spacy==3.8.3

RUN python -m spacy download en_core_web_lg

COPY app.py .
CMD ["uvicorn","app:app","--host","0.0.0.0","--port","8001"]
