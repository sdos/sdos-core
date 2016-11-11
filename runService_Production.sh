#!/bin/bash

gunicorn --config=config_gunicorn.py mcm.sdos.service:app