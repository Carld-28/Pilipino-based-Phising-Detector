import re
from collections import Counter
from urllib.parse import urlparse

class MessageDetector:
    """Detects phishing patterns in messages with trust bonuses for official links"""
    
    def __init__(self):
        # Official domains for trust bonus
        self.OFFICIAL_DOMAINS = [
            "gcash.com", "maya.ph", "bdo.com.ph", "bpi.com.ph", 
            "unionbankph.com", "metrobank.com.ph", "gotyme.com.ph", 
            "seabank.ph", "grab.com", "shopee.ph", "coins.ph", 
            "landbank.com", "rcbc.com", "tonikbank.com", "uno.bank", "paypal.com"
        ]
        
        # Phishing indicators
        self.urgency_keywords = [
            "urgent", "immediately", "asap", "verify", "confirm", "validate", 
            "update now", "action required", "act now", "limited time", "final notice"
        ]
        
        self.phishing_patterns = [
            r"click (here|link|below|now)",
            r"verify (your|account|identity|information)",
            r"confirm (your|account|password|pin)",
            r"update (your|account|payment|billing)",
            r"suspicious (activity|access|login)",
            r"unauthorized (transaction|access|login)",
            r"account (locked|suspended|disabled|compromised)",
            r"(reset|change) your (password|pin)",
        ]
        
        self.financial_threats = [
            "money", "payment", "transaction", "transfer", "balance", 
            "card", "account", "bank", "cash", "withdraw", "deposit", "loan"
        ]
        
    def analyze(self, message: str) -> dict:
        """Analyze message for phishing indicators"""
        threats = []
        risk_score = 0.0
        trust_bonus = 0.0
        
        message_lower = message.lower()
        
        # 1. Check for links and apply trust bonus if official
        links = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', message)
        if links:
            threats.append(f"Contains {len(links)} link(s)")
            
            official_link_found = False
            for link in links:
                try:
                    domain = urlparse(link).netloc.lower().split(':')[0]
                    if domain in self.OFFICIAL_DOMAINS or any(domain.endswith(f".{d}") for d in self.OFFICIAL_DOMAINS):
                        official_link_found = True
                        break
                except:
                    continue
            
            if official_link_found:
                trust_bonus += 0.6 # Significant bonus for having a real link
            else:
                risk_score += len(links) * 0.2 # Penalty for non-official links
        
        # 2. Check for urgency language
        urgency_count = sum(1 for keyword in self.urgency_keywords if keyword in message_lower)
        if urgency_count > 0:
            threats.append(f"Uses urgent language ({urgency_count} instances)")
            risk_score += min(urgency_count * 0.2, 0.5)
        
        # 3. Check for phishing patterns
        pattern_matches = 0
        for pattern in self.phishing_patterns:
            if re.search(pattern, message_lower):
                pattern_matches += 1
                risk_score += 0.25
        
        if pattern_matches > 0:
            threats.append("Contains suspicious phishing patterns")
        
        # 4. Check for financial threats combined with urgency
        financial_count = sum(1 for threat in self.financial_threats if threat in message_lower)
        if financial_count > 0 and urgency_count > 0:
            threats.append("Combines financial language with urgency")
            risk_score += 0.3
        
        # 5. Check for all caps
        caps_words = len(re.findall(r'\b[A-Z]{3,}\b', message))
        if caps_words > 2:
            threats.append("Excessive use of capital letters")
            risk_score += 0.1
        
        # Calculate Final Score
        final_score = max(0.0, risk_score - trust_bonus)
        final_score = min(final_score, 1.0)
        
        # Risk level determination
        if final_score >= 0.7:
            risk_level = "HIGH"
            is_phishing = True
        elif final_score >= 0.4:
            risk_level = "MEDIUM"
            is_phishing = False
        else:
            risk_level = "LOW"
            is_phishing = False
        
        explanation = self._generate_explanation(threats, risk_level, final_score, trust_bonus > 0)
        
        return {
            "is_phishing": is_phishing,
            "risk_score": round(final_score, 2),
            "risk_level": risk_level,
            "threats": threats if threats else ["No obvious phishing indicators"],
            "explanation": explanation
        }
    
    def _generate_explanation(self, threats: list, risk_level: str, score: float, has_trust: bool) -> str:
        """Generate human-readable explanation with trust bonus context"""
        if not threats:
            return "This message appears legitimate."
        
        threat_summary = threats[0]
        if len(threats) > 1:
            threat_summary += f" and {len(threats)-1} more warning(s)"
        
        if has_trust and score < 0.5:
            return f"✓ VERIFIED LINK: Although this message {threat_summary}, it contains a verified link to an official service. It is likely safe."

        if risk_level == "HIGH":
            return f"⚠️ HIGH RISK: {threat_summary}. This looks like a phishing attempt. Even with official links, be extremely careful."
        elif risk_level == "MEDIUM":
            return f"⚠️ CAUTION: {threat_summary}. Be cautious and verify the sender independently."
        else:
            return f"✓ LOW RISK: {threat_summary}, but appears generally safe."
