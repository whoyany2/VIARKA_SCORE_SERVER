FROM python:3.12-slim

WORKDIR /app
COPY server.py /app/server.py

ENV PORT=8765
ENV VIARKA_SCORE_DB=/data/viarka_score.db
ENV VIARKA_SCORE_HOST=0.0.0.0

EXPOSE 8765
CMD ["python", "server.py"]
