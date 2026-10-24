FROM python:3.13-slim
WORKDIR /app
COPY . /app
ENV PYTHONUNBUFFERED=1
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health',timeout=3).status==200 else 1)"
CMD ["python3", "server.py", "--port", "8000"]
