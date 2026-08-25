#!/usr/bin/env bash
set -e

python -m pip install --upgrade pip
python -m pip install --no-cache-dir dlib-bin==19.24.6
python -m pip install --no-cache-dir --no-deps face-recognition==1.3.0
python -m pip install --no-cache-dir -r requirements-render.txt
