

import re #regular expression library, helps with finding patterns in text
import streamlit as st #importing libraries
from pathlib import Path
LOGO_PATH = Path(__file__).parent / "tracephish-logo.png"

# Common phishing-related keywords
SUSPICIOUS_KEYWORDS = [
    "urgent",
    "verify your account",
    "password",
    "suspended",
    "account locked",
    "click here",
    "confirm your identity",
    "payment failed",
    "unusual activity",
    "immediately",
    "congratulations",
    "free gift",
    "Limited time offer",
    "winner",
    "claim your prize",
    "click the link",
    "send money",
    "wire transfer",
    "gift card",
    "bank details",
    "update your payment",
    "payment overdue",
    "limited time offer",
    "act now",
    "exclusive offer",
    "verify your identity",
    "confirm your account",
    "security alert",
    "unusual login",
    "password expires",
    "your account will be closed",
    "avoid suspension",
    "unauthorized access",
    "account verification",
    "reset your password",
    "birth certificate",
     "special offer",
                                        ]


def extract_email_addresses(email_text):
    """Extract email addresses from the email text."""

    pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

    addresses = re.findall(pattern, email_text)

    return addresses


def extract_urls(email_text):
    """Extract URLs and bare domains from email text."""

    pattern = r"""(?i)(?<!@)\b(?:https?://|www\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?:/[^\s<>"']*)?"""

    urls = re.findall(pattern, email_text)

    # Remove punctuation at the end of extracted links
    urls = [url.rstrip(".,;:!?)]}") for url in urls]

    return urls


def detect_suspicious_keywords(email_text):
    """Find suspicious keywords and potential money-bait messages."""

    email_text = email_text.lower()

    detected_keywords = []

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in email_text:
            detected_keywords.append(keyword)

    # Detect unexpected money offers
    money_offer_pattern = (
        r"\b(?:do you want|do u want)\s+"
        r"\$?\s*\d+(?:[.,]\d+)?\s*(?:k|thousand)?\b"
    )

    if re.search(money_offer_pattern, email_text):
        detected_keywords.append("unsolicited money offer")

    return detected_keywords


def analyze_email(email_text):
    """Analyze an email and calculate a preliminary risk score."""

    email_addresses = extract_email_addresses(email_text)
    urls = extract_urls(email_text)
    suspicious_keywords = detect_suspicious_keywords(email_text)

    # Calculate preliminary risk score
    risk_score = 0

    # Give extra weight to unsolicited money offers
    for keyword in suspicious_keywords:
        if keyword == "unsolicited money offer":
            risk_score += 20
        else:
            risk_score += 10

    # Add points for extracted URLs
    risk_score += len(urls) * 10

    # Keep score between 0 and 100
    risk_score = min(risk_score, 100)

    # Determine risk classification
    if risk_score >= 60:
        risk_level = "High"
    elif risk_score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "email_addresses": email_addresses,
        "urls": urls,
        "suspicious_keywords": suspicious_keywords,
        "risk_score": risk_score,
        "risk_level": risk_level,
    }
# -------------------------------
# TracePhish - User Interface
# -------------------------------

st.set_page_config(
    page_title="TracePhish | Email Investigation",
    page_icon=str(LOGO_PATH),
    layout="wide"
)

# Custom dashboard styling
st.markdown("""
<style>

.results-jump {
    display: inline-block;
    background-color: #101B2D;
    color: #F4F6FA !important;
    border: 1px solid #34445F;
    padding: 12px 20px;
    border-radius: 8px;
    text-decoration: none !important;
    font-weight: 600;
    margin: 12px 0 20px 0;
}

.results-jump:hover {
    background-color: #263752;
    border-color: #AAB8CC;
}


.stApp {
    background-color: #080D18;
    color: #F4F6FA;
}

[data-testid="stHeader"] {
    background: transparent;
}

[data-testid="stSidebar"] {
    background-color: #0D1627;
}

.block-container {
    max-width: 1450px;
    padding-top: 2rem;
    padding-bottom: 3rem;
}

h1, h2, h3, p, label {
    color: #F4F6FA;
}

[data-testid="stTextArea"] textarea {
    background-color: #101B2D;
    color: #F4F6FA;
    border: 1px solid #34445F;
    border-radius: 10px;
}

.stButton > button {
    background-color: #DCE6F5 !important;
    color: #080D18 !important;
    border: 1px solid #DCE6F5;
    border-radius: 8px;
    font-weight: 700;
    min-height: 48px;
}

.stButton > button p {
    color: #080D18 !important;
    font-weight: 700;
}

.stButton > button:hover {
    background-color: #FFFFFF !important;
    color: #080D18 !important;
    border-color: #FFFFFF;
}

.stButton > button:hover p {
    color: #080D18 !important;
}

[data-testid="stMetric"] {
    background-color: #101B2D;
    border: 1px solid #263752;
    border-radius: 10px;
    padding: 18px;
}

[data-testid="stMetricLabel"] {
    color: #AAB8CC;
}

[data-testid="stMetricValue"] {
    color: #FFFFFF;
}

hr {
    border-color: #263752;
}
</style>
""", unsafe_allow_html=True)


# Dashboard header


# Dashboard header
header_logo, header_title = st.columns([1, 6])

with header_logo:
    st.image(str(LOGO_PATH), width=100)
with header_title:
    st.title("TracePhish")
    st.caption("EMAIL THREAT INVESTIGATION WORKBENCH")

st.divider()


# Main dashboard layout
left_panel, right_panel = st.columns([2.5, 1])


# Email investigation panel
with left_panel:

    st.subheader("Email Investigation")

    st.write(
        "Submit suspicious email content for indicator "
        "extraction and preliminary risk assessment."
    )

    email_text = st.text_area(
        "EMAIL CONTENT",
        height=280,
        placeholder="Paste the suspicious email content here..."
    )

    analyze_button = st.button(
        "Run Investigation",
        use_container_width=True
    )


# Information panel
with right_panel:

    st.subheader("Investigation Overview")

    st.markdown("**Detection Engine**")
    st.write("Rule-based indicator detection")

    st.markdown("**Risk Assessment**")
    st.write("Preliminary score from 0 to 100")

    st.markdown("**Scoring Criteria**")
    st.write("Suspicious phrase: +10")
    st.write("Extracted URL: +5")

    st.markdown("**Risk Classification**")
    st.write("Low: 0–29")
    st.write("Medium: 30–59")
    st.write("High: 60–100")


# Analysis results
if analyze_button:

    if email_text.strip():

        results = analyze_email(email_text)

        st.markdown(
            """
            <a href="#investigation-results" class="results-jump">
                ↓ &nbsp; Jump to Investigation Results
            </a>
            """,
            unsafe_allow_html=True
        )

        st.divider()
        st.header("Investigation Results", anchor="investigation-results")
        score_col, level_col, keyword_col, url_col = st.columns(4)

        score_col.metric(
            "Risk Score",
            f'{results["risk_score"]}/100'
        )

        level_col.metric(
            "Risk Classification",
            results["risk_level"]
        )

        keyword_col.metric(
            "Suspicious Phrases",
            len(results["suspicious_keywords"])
        )

        url_col.metric(
            "Extracted URLs",
            len(results["urls"])
        )

        st.progress(results["risk_score"] / 100)

        st.subheader("Extracted Indicators")

        email_col, link_col = st.columns(2)

        with email_col:
            st.markdown("**Email Addresses**")

            if results["email_addresses"]:
                for address in results["email_addresses"]:
                    st.code(address)
            else:
                st.write("No email addresses detected.")

        with link_col:
            st.markdown("**URLs**")

            if results["urls"]:
                for url in results["urls"]:
                    st.code(url)
            else:
                st.write("No URLs detected.")

        st.subheader("Suspicious Phrases")

        if results["suspicious_keywords"]:
            for keyword in results["suspicious_keywords"]:
                st.write(f"• {keyword}")
        else:
            st.write("No suspicious phrases detected.")

        st.caption(
            "Note: This score is a preliminary heuristic, "
            "not a verified probability of phishing."
        )

    else:
        st.warning("Please paste email content before running an investigation.")

st.markdown("""
<style>
.footer {
    margin-top: 60px;
    padding: 22px 10px;
    border-top: 1px solid #263449;
    text-align: center;
    color: #94A3B8;
    font-size: 12px;
}
.footer strong {
    color: #FFFFFF;
    font-size: 14px;
}
</style>

<div class="footer">
    <strong>TracePhish</strong><br>
    EMAIL THREAT INVESTIGATION TOOL<br><br>
    © 2026 Aya Al Obaidi. All rights reserved.<br>
    Designed and developed by Aya Al Obaidi.
</div>
""", unsafe_allow_html=True)
