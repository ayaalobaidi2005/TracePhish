# TracePhish

### Email Threat Investigation Tool

TracePhish is a Python-based email investigation tool designed to
identify suspicious indicators in potentially malicious emails.

## Features

- Email address extraction
- URL and domain extraction
- Suspicious keyword detection
- Unsolicited money-offer detection
- Preliminary risk scoring
- Low, Medium, and High risk classification
- Interactive Streamlit dashboard

## Technology Stack

- Python
- Streamlit
- Regular Expressions (Regex)
- Rule-based detection

## Risk Scoring

The tool uses a preliminary rule-based scoring system.

- Ordinary suspicious phrase: +10
- Unsolicited money offer: +20
- Extracted URL: +10

The score is capped at 100.

## Disclaimer

TracePhish is an educational cybersecurity project.
Its risk score is a preliminary heuristic and does not
represent a verified probability of phishing.

A low score does not guarantee that an email is safe.