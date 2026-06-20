FROM python:3.12-slim

ADD https://example.com/release/app.tar.gz /opt/app/

COPY . /opt/app
RUN pip install --no-cache-dir -r /opt/app/requirements.txt

USER root

CMD ["python", "/opt/app/main.py"]
