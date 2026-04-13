import re
from urllib.parse import urlparse
from datetime import datetime
import difflib

class URLDetector:
    """Detects phishing URLs using various heuristics, whitelists, and typosquatting detection"""
    
    def __init__(self):
        # Official domains provided by the user
        self.OFFICIAL_DOMAINS = [
            "gcash.com", "maya.ph", "bdo.com.ph", "bpi.com.ph", 
            "unionbankph.com", "metrobank.com.ph", "gotyme.com.ph", 
            "seabank.ph", "grab.com", "shopee.ph", "coins.ph", 
            "landbank.com", "rcbc.com", "tonikbank.com", "uno.bank", "paypal.com"
        ]
        
        # Extract brand keywords from official domains (e.g., "gcash", "maya", "bdo")
        self.OFFICIAL_BRANDS = [d.split('.')[0] for d in self.OFFICIAL_DOMAINS]
        
        # Suspicious keywords that often appear in phishing paths
        self.suspicious_keywords = ["verify", "confirm", "update", "validate", "urgent", "secure", "account", "billing", "login", "signin"]

    def analyze(self, url: str) -> dict:
        """Analyze URL for phishing indicators"""
        threats = []
        risk_score = 0.0
        
        try:
            parsed = urlparse(url if "://" in url else f"http://{url}")
            domain = parsed.netloc.lower()
            if not domain and parsed.path:
                domain = parsed.path.split('/')[0]
            
            domain = domain.split(':')[0]
            
            # --- 1. Whitelist Check (Priority) ---
            is_whitelisted = domain in self.OFFICIAL_DOMAINS or any(domain.endswith(f".{d}") for d in self.OFFICIAL_DOMAINS)
            
            if is_whitelisted:
                path_threats = self._check_path_anomalies(parsed.path)
                if path_threats:
                    threats.extend(path_threats)
                    risk_score = 0.45
                    risk_level = "MEDIUM"
                else:
                    return {
                        "is_phishing": False,
                        "risk_score": 0.0,
                        "risk_level": "LOW",
                        "threats": ["Verified Official Domain"],
                        "explanation": f"✓ TRUSTED: This is an official website for {domain}. It is safe to visit."
                    }
            else:
                # --- 2. Brand Impersonation Check (CRITICAL FIX) ---
                # Check if any official brand name is used in a non-whitelisted domain
                for brand in self.OFFICIAL_BRANDS:
                    if brand in domain:
                        threats.append(f"Impersonates official brand: {brand}")
                        risk_score += 0.85
                        break
                
                # --- 3. Typosquatting / Look-alike Check ---
                typo_result = self._check_typosquatting(domain)
                if typo_result:
                    threats.append(f"Look-alike domain detected (similar to {typo_result})")
                    risk_score += 0.95

            # --- 4. Protocol Check ---
            if not parsed.scheme or parsed.scheme != "https":
                if not is_whitelisted:
                    threats.append("Uses insecure protocol (non-HTTPS)")
                    risk_score += 0.2 # Increased penalty for insecure protocol on non-white domains
            
            # --- 5. IP Address Check ---
            if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
                threats.append("Uses IP address instead of domain name")
                risk_score += 0.3
            
            # --- 6. Keyword Analysis ---
            url_lower = url.lower()
            hit_count = 0
            for keyword in self.suspicious_keywords:
                if keyword in url_lower:
                    count = url_lower.count(keyword)
                    hit_count += count
                    if not is_whitelisted:
                        risk_score += 0.15 * count # Increased keyword penalty
            
            if hit_count >= 2 and not is_whitelisted:
                threats.append("High suspicious keyword density")
                risk_score += 0.25
            
            # --- 7. Multiple Subdomains & Unusual TLDs ---
            subdomain_count = domain.count('.')
            if subdomain_count > 3:
                threats.append("Excessive subdomains")
                risk_score += 0.2
            
            if any(domain.endswith(tld) for tld in ['.net', '.xyz', '.biz', '.top', '.info', '.online']):
                if not is_whitelisted:
                    threats.append("Uses unusual top-level domain for financial service")
                    risk_score += 0.15

            # Risk level determination
            risk_score = min(risk_score, 1.0)
            if risk_score >= 0.7:
                risk_level = "HIGH"
                is_phishing = True
            elif risk_score >= 0.4:
                risk_level = "MEDIUM"
                is_phishing = False
            else:
                risk_level = "LOW"
                is_phishing = False
            
            explanation = self._generate_explanation(threats, risk_level)
            
            return {
                "is_phishing": is_phishing,
                "risk_score": round(risk_score, 2),
                "risk_level": risk_level,
                "threats": threats if threats else ["No obvious threats detected"],
                "explanation": explanation
            }
        except Exception as e:
            return {
                "is_phishing": False,
                "risk_score": 0.0,
                "risk_level": "ERROR",
                "threats": [f"Error analyzing URL: {str(e)}"],
                "explanation": "Unable to fully analyze this URL. Please verify the format."
            }
    
    def _check_typosquatting(self, domain: str) -> str:
        """Checks if the domain is a typo of an official domain"""
        # Remove TLD for comparison
        domain_parts = domain.split('.')
        main_part = domain_parts[-2] if len(domain_parts) >= 2 else domain_parts[0]
        
        for official in self.OFFICIAL_DOMAINS:
            off_parts = official.split('.')
            off_main = off_parts[0]
            
            # If it's a very close match but NOT the same
            if domain != official:
                similarity = difflib.SequenceMatcher(None, main_part, off_main).ratio()
                if similarity >= 0.8: # Very high similarity (e.g., gcash vs gc4sh is 0.8)
                    return official
        return None

    def _check_path_anomalies(self, path: str) -> list:
        """Checks for leetspeak or suspicious typos in the path"""
        threats = []
        path_lower = path.lower()
        
        # Leetspeak patterns
        leetspeak = {
            'v3rify': 'verify', 'ver1fy': 'verify', 'v3r1fy': 'verify',
            'l0gin': 'login', 'l0g1n': 'login', '5ignin': 'signin',
            '4ccount': 'account', 'updat3': 'update'
        }
        
        for typo, real in leetspeak.items():
            if typo in path_lower:
                threats.append(f"Suspicious path typo detected: '{typo}' instead of '{real}'")
        
        return threats
    
    def _generate_explanation(self, threats: list, risk_level: str) -> str:
        if not threats:
            return "This URL appears to be legitimate based on current analysis."
        
        threat_summary = ", ".join(threats[:2])
        if len(threats) > 2:
            threat_summary += f", and {len(threats)-2} more issue(s)"
        
        if risk_level == "HIGH":
            return f"⚠️ HIGH RISK: {threat_summary}. Avoid this link at all costs."
        elif risk_level == "MEDIUM":
            return f"⚠️ CAUTION: {threat_summary}. This looks suspicious but may be a mistake. Verify carefully."
        else:
            return f"✓ LOW RISK: {threat_summary} detected, but the domain seems generally safe."
