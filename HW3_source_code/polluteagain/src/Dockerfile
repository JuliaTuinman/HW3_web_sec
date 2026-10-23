FROM python:3.9-slim

RUN /usr/sbin/useradd --no-create-home -u 1337 user

COPY ./ /home/user/

RUN chown -R 1337 /home/user/*
WORKDIR /home/user/
RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "app.py"]