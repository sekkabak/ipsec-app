#!/bin/bash

python -m venv ./ipsecpython/venv
chmod +x ./ipsecpython/venv/bin/activate
./ipsecpython/venv/bin/activate
pip install -r ./ipsecpython/requirements.txt
