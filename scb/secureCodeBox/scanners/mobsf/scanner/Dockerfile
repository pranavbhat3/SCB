FROM python:3.10-slim
WORKDIR /app
COPY mobsf_wrapper.py .
RUN pip install boto3 requests
ENTRYPOINT ["python", "/app/mobsf_wrapper.py"]
