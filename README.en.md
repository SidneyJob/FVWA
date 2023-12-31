# FVWA (Flask Vulnerable Web Application)

## About project
![Title](./static/logo.jpg)
Vulnerable web application to hone your web application security skills.


## Authors
This laboratory was made by Russian enthusiasts:
- [cherepawwka](https://t.me/CherepawwkaChannel)
- [SidneyJob](https://t.me/SidneyJobChannel)


## Description
Application contains 11 tasks on the following topics:
- [1-3] Brute force
- [4] Fuzzing
- [5] SQLI
- [6] SSTI
- [7] JWT
- [8] IDOR
- [9] XXE
- [10] XSS
- [11] Bonus task - generation of Debugger PIN (inspired by the research of one of the authors @SidneyJobChannel, published on [Habr](https://habr.com/ru/articles/738238/))

## Installation
```bash
git clone https://github.com/SidneyJob/FVWA.git
cd FVWA
sudo docker build . -t fvwa
sudo docker run -d --rm --name FVWA -it -p 8080:5001 fvwa
```

**Done! Now the laboratory is running at http://127.0.0.1:8080**
