
# Phishing Website Detection - Next Level

Includes:
- Rule-based phishing URL analysis
- Better UI with red/yellow/green states, animated risk bar, loader
- WHOIS lookup
- SSL certificate check
- Optional Google Safe Browsing hook
- Chrome extension starter

## Run
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

## Chrome extension
Load the `extension/` folder from `chrome://extensions` using **Load unpacked**.

## Safe Browsing API
Add your API key in `detector/reputation.py` if you want that check enabled.
