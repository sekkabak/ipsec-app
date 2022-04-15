# ipsec-app
IPsec DEMONSTRATION as emulation project

# How to install for devs
## 1. npm
$ npm install
## 2. python virtual env
$ python3 -m venv venv<br>
## 3. activate venv
(windows) .\env\Scripts\activate<br>
(linux) source env/bin/activate<br>
## 4. install python libs
$ pip install -r requirements.txt

# How to run
npm start

# How its working (step by step)
## Testing network setup
![network](schemat.png)
---
TODO (https://www.ciscopress.com/articles/article.asp?p=25474&seqNum=7)

1. HOST1 wants to send message or file to HOST2
2. Transceiver1 see that the transmission is "interesting" so it initializes IKE between Transceiver1 and Transceiver2
3. (IKE phase 1)
   1. checks if other peer(Transceiver2) is authenticated via for example "pre shared key"
   2. via diffie hellman it creates secure tunnel to exchange keys for phase 2
4. (IKE phase 2)
   1. Negotiates IPSec parameters protected by an existing tunnel
   2. Establishes IPSec security associations:
      1. Material for keys for encryption and authentication
      2. The algorithms that can be used
      3. The identities of the endpoints
5. Working IPsec tunnel
6. Tunnel Termination