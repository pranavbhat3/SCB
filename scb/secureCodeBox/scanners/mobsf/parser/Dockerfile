FROM python:3.9-slim

WORKDIR /app

COPY mobsf_parser.py ./

RUN pip install boto3 requests

RUN adduser --disabled-password --gecos '' --uid 1000 appuser \
    && chown -R 1000 /app
USER 1000

ENTRYPOINT ["python", "./mobsf_parser.py"]