# AMKUSHscanner
# Scanner Bot

A simple Python script that implements various network scanning functionalities and can be deployed as a Telegram bot.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Usage](#usage)
  - [VPS Deployment](#vps-deployment)
  - [Termux Deployment](#termux-deployment)
  - [GithHub Actions](#github-actions)
- [Contributing](#contributing)

## Features

- IP address scanner (CIDR/multi CIDR)
- CIDR reverse IP lookup
- TLS scanner (default port 443)
- File.txt scanner
- Proxy scanner
- Domain extractor with scanner
- Custom port scanning
- Payload maker for HTTP proxies (SSH payload)

## Requirements

- Python 3.8+
- Scapy
- Requests
- Python-Telegram-Bot

## Usage

### VPS Deployment

...

### Termux Deployment

...

### GitHub Actions

To automate the deployment process, you can set up GitHub Actions workflows. Create a new file `.github/workflows/deploy.yml` in your repository with the following content:

```yaml
name: Deploy Scanner Bot

on:
  push:
    branches: [ main ]

jobs:
  build:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v2

      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: 3.8

      - name: Install dependencies
        run: |
          pip install scapy requests python-telegram-bot

      - name: Deploy bot
        run: |
          python scanner_bot.py
