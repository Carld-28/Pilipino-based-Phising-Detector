import re
from urllib.parse import urlparse
from datetime import datetime
import requests

class URLDetector:
    """Detects phishing URLs using various heuristics"""
    
    def __init__(self):
        self.ph_banks = ["bdo", "bpi", "metrobank", "maybank", "security bank", "pnb", "ucpb"]
        # Added Maya to services
        self.ph_services = ["gcash", "paymaya", "maya", "grabpay", "coins.ph", "lbc", "cebuana", "remitly"]
        # Added "login" and "signin" to keywords
        self.suspicious_keywords = ["verify", "confirm", "update", "validate", "urgent", "secure", "account", "billing", "login", "signin"]
        
    def analyze(self, url: str) -> dict:
        """Analyze URL for phishing indicators"""
        threats = []
        risk_score = 0.0
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            url_lower = url.lower()
            
            # 1. Check for missing protocol
            if not parsed.scheme:
                threats.append("Missing HTTPS protocol")
                risk_score += 0.15
            elif parsed.scheme != "https":
                threats.append("Uses non-HTTPS protocol")
                risk_score += 0.2
            
            # 2. Check for IP address instead of domain
            if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
                threats.append("Uses IP address instead of domain name")
                risk_score += 0.25
            
            # 3. Check for PH financial service mimicry (CRITICAL FIX)
            if self._check_ph_impersonation(url):
                threats.append("Impersonates Philippine financial service")
                risk_score += 0.50 # Increased weight to push towards HIGH
            
            # 4. Check for homoglyph attacks
            if self._check_homoglyph(domain):
                threats.append("Suspicious domain similar to known banks/services")
                risk_score += 0.3
            
            # 5. Check for suspicious keywords & keyword stacking
            hit_count = 0
            for keyword in self.suspicious_keywords:
                if keyword in url_lower:
                    count = url_lower.count(keyword)
                    hit_count += count
                    risk_score += 0.05 * count
            
            if hit_count >= 2:
                threats.append("Suspicious keyword stacking detected")
                risk_score += 0.15
            
            # 6. Check for suspicious subdomains
            subdomain_count = domain.count('.')
            if subdomain_count > 2:
                threats.append("Multiple subdomains (unusual for legitimate sites)")
                risk_score += 0.1
            
            # 7. Check for obfuscation
            if '%' in url or any(char in url for char in ['@', '&amp;']):
                threats.append("URL contains suspicious encoding or characters")
                risk_score += 0.12
            
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
                "explanation": "Unable to analyze this URL. Please verify the format."
            }
    
    def _check_homoglyph(self, domain: str) -> bool:
        for service in self.ph_banks + self.ph_services:
            if service in domain:
                if domain != service and not domain.endswith(f".{service}.com") and not domain.endswith(f".{service}.ph"):
                    return True
        return False
    
    def _check_ph_impersonation(self, url: str) -> bool:
        """Improved check for brand names in subdomains or hyphenated strings"""
        url_lower = url.lower()
        domain = urlparse(url).netloc.lower()

        # Official roots for major services
        official_roots = {
            "gcash": "gcash.com",
            "maya": "maya.ph",
            "paymaya": "maya.ph",
            "bpi": "bpi.com.ph",
            "bdo": "bdo.com.ph"
        }

        for service in self.ph_banks + self.ph_services:
            if service in url_lower:
                official = official_roots.get(service)
                # If service name exists but the host isn't the official domain
                if official and official not in domain:
                    return True
                # Catch service name in subdomains or with hyphens
                if f"{service}." in domain or f"{service}-" in domain or f"-{service}" in domain:
                    if official and domain != official:
                        return True
        return False
    
    def _generate_explanation(self, threats: list, risk_level: str) -> str:
        if not threats:
            return "This URL appears to be legitimate based on structural analysis."
        
        threat_summary = ", ".join(threats[:2])
        if len(threats) > 2:
            threat_summary += f", and {len(threats)-2} more issue(s)"
        
        if risk_level == "HIGH":
            return f"⚠️ HIGH RISK: {threat_summary}. Do not click this link."
        elif risk_level == "MEDIUM":
            return f"⚠️ CAUTION: {threat_summary}. Verify the source before clicking."
        else:
            return f"✓ LOW RISK: {threat_summary} detected, but the URL appears generally safe."
