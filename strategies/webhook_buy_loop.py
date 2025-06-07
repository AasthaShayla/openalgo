"""Simple example to send a BUY signal via webhook every 10 seconds.

Replace `host_url`, `webhook_id`, and `symbol` with your actual OpenAlgo
server address, the webhook ID from your strategy, and the configured
symbol name.
"""

import time
import requests

HOST_URL = "http://127.0.0.1:5000"  # OpenAlgo server base URL
WEBHOOK_ID = "your-webhook-id"      # Replace with your webhook ID
SYMBOL = "NIFTY"                    # Replace with the symbol you configured

WEBHOOK_URL = f"{HOST_URL}/strategy/webhook/{WEBHOOK_ID}"


def send_buy_order():
    payload = {"symbol": SYMBOL, "action": "BUY"}
    try:
        resp = requests.post(WEBHOOK_URL, json=payload, timeout=5)
        print("Status:", resp.status_code, resp.text)
    except requests.exceptions.RequestException as exc:
        print("Error sending request:", exc)


if __name__ == "__main__":
    print("Sending buy order every 10 seconds... Press Ctrl+C to stop.")
    while True:
        send_buy_order()
        time.sleep(10)
