FROM python:3.9-slim

WORKDIR /app
COPY ./requirements.txt ./

RUN pip install -r requirements.txt

COPY ./main.py ./app.py
COPY ./settings.py ./settings.py
COPY ./templates ./templates
COPY ./static ./static

ENTRYPOINT [ "python3" ]
CMD [ "app.py" ]
