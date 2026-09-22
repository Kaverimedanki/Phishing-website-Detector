from flask import Flask, render_template, request
import joblib
import re
from urllib.parse import urlparse

app = Flask(__name__)

# Load trained ML model
model = joblib.load("phishing_model.pkl")


def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    features = []

    # 1. having_IP_Address
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    features.append(-1 if re.match(ip_pattern, domain) else 1)

    # 2. URL_Length
    if len(url) < 54:
        features.append(1)
    elif len(url) <= 75:
        features.append(0)
    else:
        features.append(-1)

    # 3. Shortining_Service
    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "t.co",
        "ow.ly",
        "is.gd"
    ]

    features.append(
        -1 if any(x in domain for x in shorteners) else 1
    )

    # 4. having_At_Symbol
    features.append(-1 if "@" in url else 1)

    # 5. double_slash_redirecting
    features.append(-1 if "//" in url[7:] else 1)

    # 6. Prefix_Suffix
    features.append(-1 if "-" in domain else 1)

    # 7. having_Sub_Domain
    dots = domain.count(".")

    if dots == 1:
        features.append(1)
    elif dots == 2:
        features.append(0)
    else:
        features.append(-1)

    # 8. SSLfinal_State
    features.append(1 if url.startswith("https://") else -1)

    # Remaining dataset features
    features += [0] * (30 - len(features))

    return features


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/check", methods=["POST"])
def check_url():

    url = request.form.get("url", "").strip()

    # Basic suspicious pattern detection
    suspicious = False

    # @ symbol
    if "@" in url:
        suspicious = True

    # IP address instead of domain
    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        suspicious = True

    # URL shorteners
    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd"
    ]

    if any(x in url.lower() for x in shorteners):
        suspicious = True

    # Very long URL
    if len(url) > 100:
        suspicious = True

    # Too many subdomains
    try:
        domain = urlparse(url).netloc
        if domain.count(".") > 3:
            suspicious = True
    except:
        pass

    # ML prediction
    features = extract_features(url)
    prediction = model.predict([features])[0]

    # Final result
    if suspicious or prediction == -1:
        result = "⚠️ Suspicious URL"
        message = (
            "The URL contains patterns commonly associated "
            "with suspicious websites."
        )
    else:
        result = "✅ URL Looks Safe"
        message = (
            "No suspicious pattern was detected by "
            "the current detector."
        )

    return f"""
    <!DOCTYPE html>
    <html>
    <head>

        <title>Scan Result</title>

        <style>

            body {{
                font-family: Arial, sans-serif;
                background: #f4f7fb;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                margin: 0;
            }}

            .card {{
                background: white;
                width: 500px;
                padding: 40px;
                border-radius: 15px;
                text-align: center;
                box-shadow: 0 8px 25px rgba(0,0,0,0.12);
            }}

            h1 {{
                margin-bottom: 20px;
            }}

            .url {{
                word-break: break-all;
                background: #f1f5f9;
                padding: 12px;
                border-radius: 8px;
            }}

            .message {{
                color: #555;
                margin: 20px 0;
                line-height: 1.5;
            }}

            a {{
                display: inline-block;
                padding: 12px 25px;
                background: #2563eb;
                color: white;
                text-decoration: none;
                border-radius: 8px;
            }}

            a:hover {{
                background: #1d4ed8;
            }}

        </style>

    </head>

    <body>

        <div class="card">

            <h1>{result}</h1>

            <p class="url">
                <b>URL:</b> {url}
            </p>

            <p class="message">
                {message}
            </p>

            <a href="/">
                Check Another URL
            </a>

        </div>

    </body>
    </html>
    """


if __name__ == "__main__":
    app.run(debug=True)