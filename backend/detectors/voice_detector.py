import speech_recognition as sr
from io import BytesIO
import re
import whisper

class VoiceDetector:
    """Detects phishing patterns in voice/audio messages"""
    
    def __init__(self):
        self.recognizer = sr.Recognizer()
        self.message_detector = None  # Will import message detector logic
        
        self.voice_phishing_indicators = [
            "press", "enter", "account number", "verify", "confirm",
            "security code", "otp", "pin", "password", "urgent"
        ]
        
        print("⚙️ Loading Offline Whisper Model at startup...")
        self.whisper_model = whisper.load_model("base")
        print("✅ Whisper model loaded successfully!")
    
    def analyze(self, audio_content: bytes) -> dict:
        """Analyze audio for phishing indicators"""
        threats = []
        risk_score = 0.0
        
        try:
            import tempfile
            import os
            
            # Write audio bytes to a temporary file for Whisper
            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as temp_audio:
                temp_audio.write(audio_content)
                temp_path = temp_audio.name
                
            try:
                # Add bundled ffmpeg to PATH if available (fixes Windows ffmpeg missing issues)
                try:
                    import imageio_ffmpeg
                    ffmpeg_dir = os.path.dirname(imageio_ffmpeg.get_ffmpeg_exe())
                    if ffmpeg_dir not in os.environ.get("PATH", ""):
                        os.environ["PATH"] = ffmpeg_dir + os.pathsep + os.environ.get("PATH", "")
                except ImportError:
                    pass

                print("🎙️ Sending audio to Whisper for local transcription...")
                result = self.whisper_model.transcribe(temp_path, language="tl")
                transcript = result["text"].strip()
                print(f"🎯 WHISPER TRANSCRIPT HEARD: '{transcript}'")
                
                transcript_lower = transcript.lower()
            except Exception as e:
                print(f"WHISPER ERROR: {e}")
                return {
                    "is_phishing": False,
                    "risk_score": 0.0,
                    "risk_level": "ERROR",
                    "threats": [f"Whisper transcription failed: {str(e)}"],
                    "explanation": "Unable to transcribe audio."
                }
            finally:
                if os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except:
                        pass
            
            # Check for suspicious voice patterns
            if self._is_robocall(transcript):
                threats.append("Appears to be automated/robocall")
                risk_score += 0.3
            
            # Check for urgency language
            urgency_keywords = [
                "urgent", "immediately", "right away", "asap", "now", "arrest", "warrant", "suspended", "locked", "compromised", "police", "illegal", "unauthorized",
                "ngayon na", "bilisan", "huli", "pulis", "makukulong", "aresto", "korte", "isuspinde", "na-hack", "madali", "emergency", "isara", "blocked", "na-block", "warning", "dead-line", "deadline"
            ]
            urgency_count = sum(1 for keyword in urgency_keywords if keyword in transcript_lower)
            if urgency_count > 0:
                threats.append(f"Uses urgent or threatening language")
                risk_score += urgency_count * 0.3
            
            # Check for requests for sensitive info
            sensitive_requests = [
                r"(account|card|social|bank|credit|atm)\s*(number|details|info|numero)",
                r"(enter|provide|give|tell|share|verify|confirm|ibigay|isend|sabihin|ilagay|kumpirmahin).{0,30}(pin|password|otp|code|cvv)",
                r"(confirm|verify|validate).{0,30}(account|identity|details)",
                r"(your\s+pin|your\s+password|your\s+otp|iyong\s+pin|yung\s+otp|yung\s+pin|iyong\s+password)",
            ]
            
            for pattern in sensitive_requests:
                if re.search(pattern, transcript_lower):
                    threats.append("Requests sensitive information")
                    risk_score += 0.6
            
            # Check for bank/financial impersonation
            financial_mentions = ["bank", "bdo", "bpi", "gcash", "paymaya", "maya", "atm", "card", "credit", "debit", "wallet", "crypto", "bitcoin", "paypal", "landbank", "unionbank", "metrobank", "security bank", "rcbc", "finance", "payout", "remittance", "prize", "nanalo", "jackpot"]
            financial_count = sum(1 for mention in financial_mentions if mention in transcript_lower)
            
            if financial_count > 0:
                threats.append(f"Mentions financial institution/service")
                risk_score += financial_count * 0.25
            
            # Check for press number prompts
            if self._has_press_prompts(transcript_lower):
                threats.append("Contains 'press' or number entry prompts")
                risk_score += 0.4
            
            # Check for unusual phrasing (common in scam calls)
            if self._check_unnatural_speech(transcript):
                threats.append("Contains unnatural or scripted phrasing")
                risk_score += 0.3
            
            # Risk level determination
            risk_score = min(risk_score, 1.0)
            if risk_score >= 0.6:  # Lowered threshold slightly to catch more vishing
                risk_level = "HIGH"
                is_phishing = True
            elif risk_score >= 0.3:
                risk_level = "MEDIUM"
                is_phishing = False
            else:
                risk_level = "LOW"
                is_phishing = False
            
            explanation = self._generate_explanation(threats, risk_level, transcript)
            
            return {
                "is_phishing": is_phishing,
                "risk_score": round(risk_score, 2),
                "risk_level": risk_level,
                "threats": threats if threats else ["No obvious threats detected"],
                "explanation": explanation,
                "transcript": transcript[:500]  # Include partial transcript for reference
            }
        except Exception as e:
            return {
                "is_phishing": False,
                "risk_score": 0.0,
                "risk_level": "ERROR",
                "threats": [f"Error analyzing audio: {str(e)}"],
                "explanation": "Unable to analyze this audio. Please try again."
            }
    
    def _is_robocall(self, transcript: str) -> bool:
        """Detect if call appears to be automated"""
        robocall_indicators = [
            "press", "enter", "digit", "menu", "option",
            "automated", "recording", "please listen",
            "pindutin", "ilagay", "pakinggan", "makinig"
        ]
        return any(indicator in transcript.lower() for indicator in robocall_indicators)
    
    def _has_press_prompts(self, transcript: str) -> bool:
        """Check for prompt to press numbers"""
        patterns = [
            r"press\s+\d",
            r"enter\s+\d",
            r"dial\s+\d",
            r"type\s+\d",
            r"(pindutin|press)\s+(one|two|three|four|five|six|seven|eight|nine|zero|isa|dalawa|tatlo|apat|lima|anim|pito|walo|siyam|wala)",
            r"press\s+the\s+(one|two|three|four|five|six|seven|eight|nine|zero)",
            r"press\s+(star|pound)"
        ]
        return any(re.search(pattern, transcript.lower()) for pattern in patterns)
    
    def _check_unnatural_speech(self, transcript: str) -> bool:
        """Check for scripted or unnatural phrasing"""
        unnatural_phrases = [
            "this is a call from",
            "this is to inform you",
            "please be advised",
            "as per our records",
            "attention please",
            "final notice",
            "legal action",
            "under your name",
            "ito ay mula sa",
            "tawag mula sa",
            "ipagbigay alam",
            "huling babala"
        ]
        return any(phrase in transcript.lower() for phrase in unnatural_phrases)
    
    def _generate_explanation(self, threats: list, risk_level: str, transcript: str) -> str:
        """Generate human-readable explanation"""
        if not threats:
            return f"This call appears legitimate. Transcript: {transcript[:100]}..."
        
        threat_summary = threats[0]
        
        if risk_level == "HIGH":
            return f"⚠️ HIGH RISK: {threat_summary}. This appears to be a phishing call. Hang up immediately and do not provide any personal information."
        elif risk_level == "MEDIUM":
            return f"⚠️ CAUTION: {threat_summary}. Be cautious with this call. Verify the caller's identity independently before sharing information."
        else:
            return f"✓ LOW RISK: {threat_summary}, but the call appears safe."
