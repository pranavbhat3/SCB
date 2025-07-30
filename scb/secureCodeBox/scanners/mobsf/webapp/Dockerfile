FROM python:3.10-slim
WORKDIR /app
COPY . .
RUN pip install fastapi uvicorn boto3 kubernetes jinja2 python-multipart
EXPOSE 8088
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8088"]