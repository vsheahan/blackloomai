"""
Input Sanitization Module
Safely sanitizes potentially malicious inputs while preserving legitimate functionality
"""

import base64
import re
import logging
from typing import List, Dict, Optional, Tuple
from html import escape
import urllib.parse


class InputSanitizer:
 """
 Advanced input sanitization for AI security
 Removes or neutralizes malicious patterns while preserving user intent
 """

 def __init__(self, config: Optional[Dict] = None):
 self.config = config or {}
 self.logger = logging.getLogger(__name__)

 # Sanitization strategies
 self.strategies = self.config.get('strategies', {
 'remove_injection_keywords': True,
 'neutralize_delimiters': True,
 'decode_and_check': True,
 'limit_length': True,
 'filter_special_chars': True
 })

 # Limits
 self.max_length = self.config.get('max_length', 2000)
 self.max_special_char_ratio = self.config.get('max_special_char_ratio', 0.2)

 # Initialize sanitization patterns
 self._init_sanitization_patterns()

 def _init_sanitization_patterns(self):
 """Initialize patterns for sanitization"""

 # High-risk instruction keywords to remove/neutralize
 self.injection_keywords = [
 r'\bignore\s+(previous|all|above|prior)\s+(instructions?|prompts?|commands?)\b',
 r'\bforget\s+(everything|all|previous|your\s+instructions)\b',
 r'\bdisregard\s+(previous|all|above|prior)\s+(instructions?|prompts?)\b',
 r'\boverride\s+(your|the)\s+(instructions?|system|settings)\b',
 r'\bnew\s+(instructions?|task|mission|role):\s*',
 r'\bsystem\s+update:\s*',
 r'\bdeveloper\s+(mode|override|command):\s*',
 ]

 # Role manipulation phrases
 self.role_keywords = [
 r'\byou\s+are\s+now\s+(a|an|the)\s+',
 r'\bpretend\s+(you\s+are|to\s+be)\s+',
 r'\bact\s+as\s+(a|an|the)\s+',
 r'\broleplay\s+as\s+',
 r'\bsimulate\s+(being|a|an)\s+',
 ]

 # System prompt leak attempts
 self.system_leak_keywords = [
 r'\bwhat\s+(are\s+)?your\s+(initial\s+)?(instructions?|prompts?|settings)\b',
 r'\bshow\s+(me\s+)?your\s+(system\s+)?(prompt|instructions?)\b',
 r'\breveal\s+your\s+(system\s+)?(prompt|instructions?|settings)\b',
 r'\bprint\s+(your|the)\s+(system\s+)?(prompt|instructions?)\b',
 ]

 # Delimiter patterns that might be used for structure manipulation
 self.delimiter_patterns = [
 r'```[^`]*```', # Code blocks
 r'---{3,}', # Horizontal rules
 r'==={3,}', # Alternative horizontal rules
 r'\*{5,}', # Multiple asterisks
 r'#{5,}', # Multiple hash symbols
 ]

 # Compile patterns for efficiency
 self._compile_sanitization_patterns()

 def _compile_sanitization_patterns(self):
 """Compile regex patterns for sanitization"""
 self.compiled_injection = [re.compile(p, re.IGNORECASE) for p in self.injection_keywords]
 self.compiled_roles = [re.compile(p, re.IGNORECASE) for p in self.role_keywords]
 self.compiled_leaks = [re.compile(p, re.IGNORECASE) for p in self.system_leak_keywords]
 self.compiled_delimiters = [re.compile(p, re.IGNORECASE) for p in self.delimiter_patterns]

 def sanitize(self, user_input: str, detected_attacks: List[str]) -> str:
 """
 Sanitize user input based on detected attack types

 Args:
 user_input: The input to sanitize
 detected_attacks: List of detected attack types

 Returns:
 Sanitized input string
 """
 sanitized = user_input

 self.logger.info(f"Sanitizing input with detected attacks: {detected_attacks}")

 # Apply sanitization strategies based on detected attacks
 if 'direct_injection' in detected_attacks:
 sanitized = self._remove_injection_keywords(sanitized)

 if 'role_manipulation' in detected_attacks:
 sanitized = self._neutralize_role_manipulation(sanitized)

 if 'system_prompt_leak' in detected_attacks:
 sanitized = self._remove_system_leak_attempts(sanitized)

 if 'jailbreak_attempt' in detected_attacks:
 sanitized = self._neutralize_jailbreak_patterns(sanitized)

 if 'delimiter_injection' in detected_attacks:
 sanitized = self._neutralize_delimiters(sanitized)

 if 'encoded_injection' in detected_attacks:
 sanitized = self._handle_encoded_content(sanitized)

 if 'adversarial_input' in detected_attacks:
 sanitized = self._reduce_adversarial_patterns(sanitized)

 # Apply general sanitization
 sanitized = self._apply_general_sanitization(sanitized)

 # Final validation
 if len(sanitized.strip()) == 0:
 sanitized = "[Content removed for security reasons]"

 return sanitized

 def _remove_injection_keywords(self, text: str) -> str:
 """Remove direct injection keywords"""
 for pattern in self.compiled_injection:
 text = pattern.sub('[INSTRUCTION REMOVED]', text)
 return text

 def _neutralize_role_manipulation(self, text: str) -> str:
 """Neutralize role manipulation attempts"""
 for pattern in self.compiled_roles:
 # Replace with neutral phrasing
 text = pattern.sub('Please help me understand ', text)
 return text

 def _remove_system_leak_attempts(self, text: str) -> str:
 """Remove system prompt leak attempts"""
 for pattern in self.compiled_leaks:
 text = pattern.sub('[SYSTEM QUERY BLOCKED]', text)
 return text

 def _neutralize_jailbreak_patterns(self, text: str) -> str:
 """Neutralize jailbreak attempt patterns"""

 jailbreak_replacements = {
 r'\bhypothetically,?\s+': 'Please consider: ',
 r'\bin\s+a\s+(fictional|hypothetical)\s+(world|scenario|universe)': 'In general',
 r'\bfor\s+(educational|research|academic)\s+purposes': 'For information',
 r'\bthis\s+is\s+(just\s+)?(a\s+)?(test|experiment|simulation)': 'This is a question',
 r'\bpretend\s+(there\s+are\s+)?no\s+(rules|restrictions|limitations)': '[CONSTRAINT OVERRIDE BLOCKED]',
 r'\bignore\s+(all\s+)?(safety|ethical|moral)\s+(guidelines|restrictions)': '[SAFETY OVERRIDE BLOCKED]',
 }

 for pattern, replacement in jailbreak_replacements.items():
 text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)

 return text

 def _neutralize_delimiters(self, text: str) -> str:
 """Neutralize excessive delimiter usage"""

 # Replace code blocks with safe alternatives
 text = re.sub(r'```[^`]*```', '[CODE BLOCK REMOVED]', text)

 # Replace excessive delimiters using more Pythonic mapping approach
 delimiter_replacements = {
 r'---{3,}': '---',
 r'==={3,}': '===', 
 r'\*{5,}': '***',
 r'#{5,}': '###',
 }
 
 for pattern, replacement in delimiter_replacements.items():
 text = re.sub(pattern, replacement, text)

 return text

 def _handle_encoded_content(self, text: str) -> str:
 """Handle encoded content by decoding and re-sanitizing"""

 # Handle Base64
 base64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
 base64_matches = base64_pattern.findall(text)

 for match in base64_matches:
 try:
 decoded = base64.b64decode(match + '==').decode('utf-8', errors='ignore')
 # Recursively sanitize decoded content
 sanitized_decoded = self.sanitize(decoded, ['direct_injection', 'role_manipulation'])
 text = text.replace(match, f"[DECODED: {sanitized_decoded[:50]}...]")
 except (ValueError, UnicodeDecodeError, Exception) as e:
 self.logger.debug(f"Base64 decoding failed: {e}")
 text = text.replace(match, '[INVALID ENCODING REMOVED]')

 # Handle URL encoding
 if '%' in text and len(re.findall(r'%[0-9A-Fa-f]{2}', text)) > 3:
 try:
 decoded = urllib.parse.unquote(text)
 # If significantly different after decoding, it was likely encoded
 if decoded != text:
 text = self.sanitize(decoded, ['direct_injection', 'role_manipulation'])
 except (ValueError, UnicodeDecodeError, Exception) as e:
 self.logger.debug(f"URL decoding failed: {e}")
 pass

 return text

 def _reduce_adversarial_patterns(self, text: str) -> str:
 """Reduce patterns that might be adversarial"""

 # Limit excessive repetition
 text = self._limit_repetition(text)

 # Reduce excessive special characters
 text = self._limit_special_characters(text)

 # Truncate if too long
 if len(text) > self.max_length:
 text = text[:self.max_length] + "... [TRUNCATED FOR SECURITY]"

 return text

 def _limit_repetition(self, text: str) -> str:
 """Limit repetitive patterns"""
 words = text.split()
 if len(words) <= 10:
 return text

 # Check for repeating sequences
 result_words = []
 i = 0
 while i < len(words):
 current_word = words[i]

 # Check for immediate repetition (same word repeated)
 repeat_count = 1
 j = i + 1
 while j < len(words) and words[j] == current_word:
 repeat_count += 1
 j += 1

 # Limit repetition to 3
 if repeat_count > 3:
 result_words.extend([current_word] * 3)
 result_words.append('[REPETITION TRUNCATED]')
 i = j
 else:
 result_words.append(current_word)
 i += 1

 return ' '.join(result_words)

 def _limit_special_characters(self, text: str) -> str:
 """Limit ratio of special characters"""
 if not text:
 return text

 # More efficient calculation without creating intermediate list
 special_char_count = sum(1 for c in text if not c.isalnum() and not c.isspace())
 special_ratio = special_char_count / len(text)

 if special_ratio > self.max_special_char_ratio:
 # Keep only alphanumeric, spaces, and common punctuation
 cleaned = re.sub(r'[^a-zA-Z0-9\s.,!?;:\'"()-]', '', text)
 if len(cleaned.strip()) < len(text.strip()) * 0.5:
 # If too much was removed, add a note
 cleaned += " [SPECIAL CHARACTERS FILTERED]"
 return cleaned

 return text

 def _apply_general_sanitization(self, text: str) -> str:
 """Apply general sanitization rules"""

 # HTML escape to prevent any HTML injection
 text = escape(text)

 # Remove null bytes and other control characters
 text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', text)

 # Normalize whitespace
 text = ' '.join(text.split())

 # Remove any remaining suspicious patterns
 suspicious_patterns = [
 r'<script[^>]*>.*?</script>', # JavaScript
 r'javascript:', # JavaScript URLs
 r'data:.*?base64,', # Data URLs with base64
 r'vbscript:', # VBScript
 ]

 for pattern in suspicious_patterns:
 text = re.sub(pattern, '[SUSPICIOUS CONTENT REMOVED]', text, flags=re.IGNORECASE | re.DOTALL)

 return text.strip()