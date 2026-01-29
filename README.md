# Fully Legal OSINT API (FLOA)

A clean, public and **fully legal** OSINT API.

## Features
- IP OSINT
- Email OSINT
- Username OSINT
- Wi-Fi OSINT (WiGLE)
- Leak & paste search
- Google dork helper
- Hash info
- Cache system
- Provider-based rate limits
- Owner key (unlimited)

## Install
```bash
git clone https://github.com/arascoskun0/FLOA.git
cd FLOA
pip install -r requirements.txt
```

## Run
```bash
export WIGLE_USER="your_user"
export WIGLE_TOKEN="your_token"
uvicorn floa:app --host 0.0.0.0 --port 8000
```

## Legal Notice
This project uses **only public OSINT sources**.
No rate-limit bypass, scraping, sniffing or exploitation.
