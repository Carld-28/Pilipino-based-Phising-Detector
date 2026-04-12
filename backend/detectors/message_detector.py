import re
from collections import Counter

class MessageDetector:
    """Detects phishing patterns in messages using NLP and keyword analysis"""
    
    def __init__(self):
        # Philippine financial institutions and services
        self.ph_banks = ["bdo", "bpi", "metrobank", "maybank", "security bank", "pnb", "ucpb", "landbank"]
        self.ph_services = ["gcash", "paymaya", "grabpay", "coins.ph", "lbc", "cebuana", "western union", "remitly"]
        
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
        
        message_lower = message.lower()
        
        # Check for urgency language
        urgency_count = sum(1 for keyword in self.urgency_keywords if keyword in message_lower)
        if urgency_count > 0:
            threats.append(f"Uses urgent language ({urgency_count} instances)")
            risk_score += min(urgency_count * 0.15, 0.4)
        
        # Check for phishing patterns
        pattern_matches = []
        for pattern in self.phishing_patterns:
            if re.search(pattern, message_lower):
                pattern_matches.append(pattern)
                risk_score += 0.2
        
        if pattern_matches:
            threats.append("Contains suspicious phishing patterns")
        
        # Check for financial threats combined with urgency
        financial_count = sum(1 for threat in self.financial_threats if threat in message_lower)
        if financial_count > 0 and urgency_count > 0:
            threats.append("Combines financial language with urgency")
            risk_score += 0.25
        
        # Check for impersonation attempts
        if self._check_impersonation(message_lower):
            threats.append("Impersonates legitimate institution")
            risk_score += 0.3
        
        # Check for suspicious links
        link_count = len(re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', message))
        if link_count > 0:
            threats.append(f"Contains {link_count} link(s)")
            risk_score += link_count * 0.15
        
        # Check for all caps (often used in scam messages)
        caps_words = len(re.findall(r'\b[A-Z]{3,}\b', message))
        if caps_words > 2:
            threats.append("Excessive use of capital letters")
            risk_score += 0.08
        
        # Check for poor grammar/spelling patterns (common in phishing)
        spelling_issues = self._check_spelling_issues(message_lower)
        if spelling_issues:
            threats.append("Contains spelling or grammar errors")
            risk_score += 0.1
        
        # Check for suspicious requests
        if self._has_suspicious_request(message_lower):
            threats.append("Requests personal or financial information")
            risk_score += 0.35
        
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
            "threats": threats if threats else ["No obvious phishing indicators"],
            "explanation": explanation
        }
    
    def _check_impersonation(self, message: str) -> bool:
        """Check if message impersonates legitimate institution"""
        impersonation_phrases = [
            r"this is (from|from the) (bdo|bpi|gcash|paymaya)",
            r"official (bdo|bpi|gcash|paymaya|bank)",
            r"(bdo|bpi|gcash|paymaya|bank) (account|security|team|support)",
        ]
        
        for phrase in impersonation_phrases:
            if re.search(phrase, message):
                return True
        
        return False
    
    def _check_spelling_issues(self, message: str) -> bool:
        """Check for common phishing spelling patterns"""
        issues = [
            r"\b(pasword|passwod|passowrd)\b",  # password misspellings
            r"\b(acount|acunt|accunt)\b",  # account misspellings
            r"\b(verivy|verify)\b",  # verify misspellings
            r"\b(clcik|clck|clik)\b",  # click misspellings
        ]
        
        for issue in issues:
            if re.search(issue, message):
                return True
        
        return False
    
    def _has_suspicious_request(self, message: str) -> bool:
        """Check for requests for sensitive information"""
        suspicious_requests = [
            r"(send|provide|share|give).?(password|pin|otp|code|cvv|card)",
            r"(confirm|verify).?(password|pin|account|identity|personal)",
            r"(update|change).?(account|password|payment method)",
            r"(click|visit|open).?(link|attachment)",
        ]
        
        for request in suspicious_requests:
            if re.search(request, message):
                return True
        
        return False
    
    def _generate_explanation(self, threats: list, risk_level: str) -> str:
        """Generate human-readable explanation"""
        if not threats:
            return "This message appears legitimate."
        
        threat_summary = threats[0]
        if len(threats) > 1:
            threat_summary += f" and {len(threats)-1} more warning(s)"
        
        if risk_level == "HIGH":
            return f"⚠️ HIGH RISK: {threat_summary}. This looks like a phishing attempt. Do not click links or share information."
        elif risk_level == "MEDIUM":
            return f"⚠️ CAUTION: {threat_summary}. Be cautious and verify the sender independently."
        else:
            return f"✓ LOW RISK: {threat_summary}, but appears safe to interact with."
