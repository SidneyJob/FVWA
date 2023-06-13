FROM ubuntu

RUN mkdir /app
RUN apt update -y && apt install python3 -y && apt install python3-pip -y
WORKDIR /app

COPY ./requirements.txt /app/requirements.txt

RUN python3 -m pip install -r requirements.txt
COPY ./main.py /app/app.py
COPY ./settings.py /app/settings.py

COPY ./templates /app/templates
COPY ./static /app/static


ENTRYPOINT [ "python3" ]
CMD [ "app.py" ]
