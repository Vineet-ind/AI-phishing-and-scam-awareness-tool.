"""Local, explainable scam-message checker."""

import re
from urllib.parse import urlparse

from flask import Flask, jsonify, render_template, request

MAX_MESSAGE_LENGTH = 10_000

SIGNALS = (
    (
        "urgency",
        22,
        "Pressure to act now",
        "Scammers create urgency so you have less time to verify the request.",
        re.compile(r"\b(?:urgent|immediately|act now|within \d+ hours?|expires? today|final notice|account (?:is )?suspended)\b", re.I),
    ),
    (
        "credentials",
        26,
        "Request for sensitive information",
        "Legitimate organizations should not ask you to share passwords, PINs, or one-time codes in a message.",
        re.compile(r"\b(?:password|passcode|one[- ]time (?:code|password)|\botp\b|login credentials|verify your (?:account|identity))\b", re.I),
    ),
    (
        "payment",
        24,
        "Unusual payment or money request",
        "Gift cards, cryptocurrency, wire transfers, or unexpected fees are common scam payment methods.",
        re.compile(r"\b(?:gift cards?|crypto(?:currency)?|bitcoin|wire transfer|pay (?:a )?(?:fee|fine|customs)|payment required|send money|bank transfer)\b", re.I),
    ),
    (
        "impersonation",
        17,
        "Possible authority impersonation",
        "The message invokes a trusted institution or authority. Verify it using contact details you find independently.",
        re.compile(r"\b(?:your bank|tax (?:office|refund)|police department|government agency|tech support|delivery company|microsoft support|account security team)\b", re.I),
    ),
    (
        "secrecy",
        15,
        "Request to keep it secret",
        "A demand for secrecy can be used to stop you checking with someone you trust.",
        re.compile(r"\b(?:keep (?:this|it) (?:a )?secret|do not tell anyone|don't tell anyone|confidential transfer)\b", re.I),
    ),
)

URL_PATTERN = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.I)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly"}


def link_looks_suspicious(message: str) -> bool:
    for raw_url in URL_PATTERN.findall(message):
        url = raw_url.rstrip(".,!?);]")
        parsed = urlparse(url if "://" in url else f"https://{url}")
        host = (parsed.hostname or "").lower()
        if (
            host in SHORTENERS
            or "@" in parsed.netloc
            or host.startswith("xn--")
            or re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host)
        ):
            return True
    return False


def analyze_message(message: str) -> dict:
    findings = [
        {"id": key, "title": title, "explanation": explanation}
        for key, _weight, title, explanation, pattern in SIGNALS
        if pattern.search(message)
    ]
    score = sum(weight for key, weight, *_ in SIGNALS if any(f["id"] == key for f in findings))

    if link_looks_suspicious(message):
        findings.append({
            "id": "link",
            "title": "Link may hide its destination",
            "explanation": "Shortened, numeric, or unusual links can conceal a misleading website. Do not open it; visit the official site yourself.",
        })
        score += 20

    score = min(score, 100)
    level = "high" if score >= 55 else "caution" if score >= 20 else "low"
    return {
        "score": score,
        "level": level,
        "label": {"high": "High risk", "caution": "Use caution", "low": "No strong signals found"}[level],
        "findings": findings,
        "advice": (
            "Do not reply, pay, or open links. Contact the organization through its official app or a number you already trust."
            if level == "high"
            else "Pause before responding. Independently verify the sender and destination using an official channel."
            if level == "caution"
            else "This checker found few common warning signs, but that does not prove the message is genuine. Verify unexpected requests."
        ),
    }


def create_app():
    app = Flask(__name__)

    @app.get("/")
    def home():
        return render_template("index.html")

    @app.post("/api/analyze")
    def analyze():
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or not isinstance(data.get("message"), str):
            return jsonify(error="Send a JSON object with a message string."), 400
        message = data["message"].strip()
        if not message:
            return jsonify(error="Paste a message to check."), 400
        if len(message) > MAX_MESSAGE_LENGTH:
            return jsonify(error=f"Messages must be {MAX_MESSAGE_LENGTH:,} characters or fewer."), 400
        return jsonify(analyze_message(message))

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
