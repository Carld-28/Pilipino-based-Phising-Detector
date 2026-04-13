import sys
import os

# Add the parent directory to sys.path to import detectors
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set encoding for better handling of symbols in Windows terminal
import io
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Import detectors directly to avoid dependency issues with voice_detector
import importlib.util

def import_module_from_path(module_name, file_path):
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
url_detector_mod = import_module_from_path("url_detector", os.path.join(base_dir, "detectors", "url_detector.py"))
message_detector_mod = import_module_from_path("message_detector", os.path.join(base_dir, "detectors", "message_detector.py"))

URLDetector = url_detector_mod.URLDetector
MessageDetector = message_detector_mod.MessageDetector

def test_urls():
    detector = URLDetector()
    urls = [
        "https://gcash.com/login",      # Legit
        "http://gc4sh.com/login",       # Typo
        "https://gcash.com/ver1fy",     # Legit domain, suspicious path
        "https://maya.ph",              # Legit
        "https://bdo.com.ph",           # Legit
        "http://gcash-verify.net/login", # User reported issue
        "https://bdo-verify.com",       # Typo
        "https://gcash.com.security-update.io/login" # Subdomain mimicry
    ]

    print("\n--- URL TESTING ---")
    for url in urls:
        result = detector.analyze(url)
        print(f"URL: {url}")
        print(f"  Score: {result['risk_score']}")
        print(f"  Level: {result['risk_level']}")
        print(f"  Is Phishing: {result['is_phishing']}")
        print(f"  Explanation: {result['explanation']}")
        print("-" * 20)

def test_messages():
    detector = MessageDetector()
    messages = [
        "URGENT: Your GCash account is locked. Click here: https://gcash.com/login", # Legit link
        "URGENT: Your GCash account is locked. Click here: https://gc4sh.com/login", # Phishing link
        "Please visit our official site: https://maya.ph for updates.", # Legit
    ]

    print("\n--- MESSAGE TESTING ---")
    for msg in messages:
        result = detector.analyze(msg)
        print(f"Message: {msg[:50]}...")
        print(f"  Score: {result['risk_score']}")
        print(f"  Level: {result['risk_level']}")
        print(f"  Is Phishing: {result['is_phishing']}")
        print(f"  Explanation: {result['explanation']}")
        print("-" * 20)

if __name__ == "__main__":
    test_urls()
    test_messages()
