# FlaskApp

# RU

## О проекте
Уязвимое веб-приложение, чтобы любой желающий мог попрактиковаться в разных уязвимостях и отточить свои навыки.


## Авторы
Данная лаборатория была сделала двумя русскими энтузиастами:
[cherepawwka] (https://t.me/CherepawwkaChannel)
[SidneyJob] (https://t.me/SidneyJobChannel)


## Описание
Приложение содержит 11 заданий на следующие темы:
[1-3] Brute force
[4] Fuzzing
[5] SQLI
[6] SSTI
[7] JWT
[8] IDOR
[9] XXE
[10] XSS
[11] Бонусное задание — генерация Debugger PIN (при создании вдохновлялись исследованем [SidneyJob](https://t.me/SidneyJobChannel), опубликованным на [Habr](https://habr.com/ru/articles/738238/))


## Установка
```bash
git clone https://github.com/SidneyJob/FlaskApp.git
cd FlaskApp
sudo docker build . -t flaskapp
sudo docker run --rm --name FlaskLab -it -p 8080:5001 flaskapp
```

Готово! Теперь лабаратория запущена у вас по адресу http://127.0.0.1:8080


# EN

## About project
Vulnerable web application to hone your web application security skills.


## Authors
This laboratory was made by Russian enthusiasts:
[cherepawwka](https://t.me/CherepawwkaChannel)
[SidneyJob](https://t.me/SidneyJobChannel)


## Description
Application contains 11 tasks on the following topics:
[1-3] Brute force
[4] Fuzzing
[5] SQLI
[6] SSTI
[7] JWT
[8] IDOR
[9] XXE
[10] XSS
[11] Bonus task - generation of Debugger PIN (inspired by the research of one of the authors @SidneyJobChannel, published on [Habr](https://habr.com/ru/articles/738238/))

## Installation
```bash
git clone https://github.com/SidneyJob/FlaskApp.git
cd FlaskApp
sudo docker build . -t flaskapp
sudo docker run --rm --name FlaskLab -it -p 8080:5001 flaskapp
```

Done! Now the laboratory is running at http://127.0.0.1:8080