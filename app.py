# -*- coding: utf-8 -*-
"""
Created on Thurs Jan  1 2:46:47 2025

@author: IAN CARTER KULANI
"""

import requests
from flask import Flask, render_template, request, jsonify
import re

app = Flask(__name__)

# Phishing detection using Google Safe Browsing API
API_KEY = "YOUR_GOOGLE_SAFE_BROWSING_API_KEY"  # You need to create a Google API key for Safe Browsing

# Function to check URL using Google Safe Browsing API
def check_phishing_url(url):
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + API_KEY
    body = {
        "client": {
            "clientId": "your_client_id",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "urlInfo": {
                "url": url
            }
        }
    }

    try:
        response = requests.post(endpoint, json=body)
        response_data = response.json()

        if "matches" in response_data:
            return True  # Phishing detected
        else:
            return False  # No phishing detected

    except requests.exceptions.RequestException as e:
        print(f"Error while making request: {e}")
        return False

# Function to detect suspicious patterns in the URL (heuristics)
def heuristic_check(url):
    # Check for suspicious keywords in the domain
    suspicious_keywords = ["login", "secure", "update", "account", "verify", "paypal", "bank"]
    if any(keyword in url.lower() for keyword in suspicious_keywords):
        return True  # Potential phishing detected
    return False

@app.route('/')
def index():
    return render_template('Phish-Detector.html')

@app.route('/check_url', methods=['POST'])
def check_url():
    url = request.form['url']
    
    # First, check using Google Safe Browsing API
    is_phishing = check_phishing_url(url)

    # Second, check using heuristic methods
    if not is_phishing:
        is_phishing = heuristic_check(url)

    return jsonify({"url": url, "is_phishing": is_phishing})

if __name__ == "__main__":
    app.run(debug=True)