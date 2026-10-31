"""
Synthetic & Realistic Email Dataset Generator for Phishing Detection.
"""
import csv, os, random
from typing import List, Dict

PHISHING_TEMPLATES = [
    {
        "subject": "URGENT: Your {brand} Account Has Been Suspended! Verify Immediately",
        "sender": "security-alert@{spoof_domain}",
        "body": "Dear Customer, We detected unauthorized login attempts on your {brand} account. Your account has been temporarily locked! Click here immediately to verify your identity: {url} . Failure to complete verification within 24 hours will result in permanent closure."
    },
    {
        "subject": "Action Required: Confirm your banking PIN & OTP to avoid block",
        "sender": "admin-update@{spoof_domain}",
        "body": "ALERT! Your netbanking profile requires mandatory KYC update today. Please login at {url} and enter your password and OTP to keep your credit card active."
    }
]

SAFE_TEMPLATES = [
    {
        "subject": "Weekly Engineering Standup Notes & Sprint Roadmap",
        "sender": "priya.sharma@company-tech.com",
        "body": "Hi team, Here are the meeting notes from today's sprint planning session. Unit test coverage is now at 92%. Please review pull requests on https://github.com/org/project before Friday."
    },
    {
        "subject": "Project Milestone Update: Q3 Analytics Dashboard",
        "sender": "rahul.verma@enterprise-analytics.in",
        "body": "Hello everyone, The updated Q3 revenue analytics charts have been uploaded to our shared workspace. View documentation at https://docs.python.org/3/ for reference."
    }
]

BRANDS = ["PayPal", "Amazon", "Netflix", "HDFC Bank", "Microsoft 365"]
SPOOF_DOMAINS = ["secure-login-verify.xyz", "account-update-portal.top", "paypa1-security.ru"]
MALICIOUS_URLS = ["http://192.168.45.12/login/verify.php", "http://bit.ly/3xYz99Urgent", "http://secure-verify-account.xyz/auth"]

def generate_dataset(num_samples: int = 500, seed: int = 42) -> List[Dict[str, str]]:
    random.seed(seed)
    dataset = []
    half = num_samples // 2
    for i in range(half):
        tpl = random.choice(PHISHING_TEMPLATES)
        brand = random.choice(BRANDS)
        spoof_domain = random.choice(SPOOF_DOMAINS)
        url = random.choice(MALICIOUS_URLS)
        subject = tpl["subject"].format(brand=brand)
        sender = tpl["sender"].format(spoof_domain=spoof_domain)
        body = tpl["body"].format(brand=brand, url=url)
        dataset.append({"email_id": f"EML-{1000+i}", "sender": sender, "subject": subject, "body": body, "label": "Phishing"})

    for i in range(num_samples - half):
        tpl = random.choice(SAFE_TEMPLATES)
        dataset.append({"email_id": f"EML-{1000+half+i}", "sender": tpl["sender"], "subject": tpl["subject"], "body": tpl["body"], "label": "Safe"})

    random.shuffle(dataset)
    return dataset

def save_dataset_csv(filepath: str, num_samples: int = 500) -> str:
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    rows = generate_dataset(num_samples=num_samples)
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["email_id", "sender", "subject", "body", "label"])
        writer.writeheader()
        writer.writerows(rows)
    return filepath

if __name__ == "__main__":
    save_dataset_csv(os.path.join("data", "emails_dataset.csv"), 500)
