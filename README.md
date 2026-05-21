# Phishing URL Detection Tool

A beginner-friendly Python cybersecurity project that analyzes URLs and detects possible phishing risk using rule-based checks.

This project does not use machine learning. It extracts simple URL-based features and calculates a risk score based on common phishing indicators.

## Features

- Checks URL length
- Checks whether HTTPS is used
- Detects the `@` symbol in URLs
- Detects hyphens in domains
- Detects IP addresses used instead of domain names
- Calculates domain length
- Counts dots in the full URL
- Finds suspicious words such as `login`, `verify`, `account`, and `secure`
- Detects known URL shortening services
- Calculates a risk score and risk level
- Tests sample URLs from a CSV file

## Technologies Used

- Python 3
- `urllib.parse`
- `re`
- `csv`
- `pathlib`

Only Python standard library modules are used.

## Project Structure

```text
phishing-url-detector/
├── features.py
├── detector.py
├── app.py
├── test_urls.csv
├── requirements.txt
└── README.md
```

## How To Run

1. Open a terminal.
2. Go to the project folder:

```bash
cd phishing-url-detector
```

3. Run the application:

```bash
python3 app.py
```

## Example Usage

```text
Phishing URL Detection Tool
==============================
1. Analyze a single URL
2. Test URLs from CSV
3. Exit
Choose an option (1-3): 1

Enter a URL to analyze: http://secure-login-paypal.com
```

## Example Output

```text
Analysis Result
----------------------------------------
URL: http://secure-login-paypal.com
Risk Score: 7
Risk Level: High Risk

Reasons:
- HTTPS is not used
- Suspicious words found: login, secure, paypal
- Hyphen is used in the domain

Extracted Features:
- Url Length: 30
- Uses Https: False
- Has At Symbol: False
- Has Hyphen In Domain: True
- Is Ip Address: False
- Domain Length: 23
- Dot Count: 1
- Suspicious Words: ['login', 'secure', 'paypal']
- Is Shortened Url: False
```

## Risk Scoring

The tool adds points for risky indicators:

- No HTTPS: +2
- IP address used instead of domain: +3
- `@` symbol exists: +3
- URL length greater than 75: +2
- 1 suspicious word found: +2
- 2 suspicious words found: +3
- 3 or more suspicious words found: +4
- More than 3 dots: +1
- Hyphen in domain: +1
- Known shortened URL service: +2
- Domain length greater than 30: +1

Risk levels:

- 0-2: Low Risk
- 3-5: Medium Risk
- 6 or more: High Risk

## Limitations

- This is a rule-based educational project.
- It does not use machine learning.
- It cannot detect every phishing website.
- It can produce false positives for safe websites.
- It can produce false negatives for phishing websites.
- It should not be used as a real-world security product.

## Future Improvements

- Add more URL-based features
- Improve IP address validation
- Add domain age checks using external APIs
- Add a simple web interface with Flask
- Export analysis results to a CSV file
- Add automated unit tests

## CV Description

Developed a rule-based phishing URL detection tool using Python. Extracted URL-based features such as HTTPS usage, IP address detection, suspicious keywords, special characters and URL length. Implemented a risk scoring system and tested the tool using CSV-based sample data.
