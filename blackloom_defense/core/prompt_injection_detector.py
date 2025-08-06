"""
Prompt Injection Detection Module
Detects various forms of prompt injection attacks using pattern matching and ML techniques
"""

import base64
import re
import logging
import urllib.parse
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from collections import defaultdict


@dataclass
class InjectionResult:
 is_malicious: bool
 confidence: float
 attack_types: List[str]
 metadata: Dict[str, Any]


class PromptInjectionDetector:
 """
 Advanced prompt injection detection system
 Uses multiple detection strategies to identify malicious prompts
 """

 def __init__(self, config: Optional[Dict] = None):
 self.config = config or {}
 self.logger = logging.getLogger(__name__)

 # Initialize detection patterns
 self._init_detection_patterns()

 # Confidence weights for different detection methods
 self.weights = self.config.get('weights', {
 'direct_injection': 0.9,
 'role_manipulation': 0.8,
 'context_switching': 0.7,
 'system_prompt_leak': 0.9,
 'jailbreak_attempt': 0.85
 })

 def _init_detection_patterns(self):
 """Initialize regex patterns for different attack types"""

 # Direct injection patterns
 self.direct_injection_patterns = [
 r'ignore\s+(all\s+)?(previous|above|prior|earlier)\s+(instructions?|prompts?|commands?|rules?)',
 r'forget\s+(everything|all|previous|earlier)(\s+you\s+were\s+told)?',
 r'disregard\s+(all\s+)?(previous|above|prior|earlier)\s+(instructions?|prompts?|commands?|rules?)',
 r'override\s+(your\s+)?(instructions?|system|settings?|rules?|safety|guidelines?)',
 r'new\s+(instructions?|task|mission|role)\s*:',
 r'system\s+update\s*:',
 r'developer\s+(mode|override|command)\s*:',
 ]

 # Role manipulation patterns
 self.role_patterns = [
 r'you\s+are\s+now\s+(a|an|the)?\s*\w+',
 r'pretend\s+(you\s+are|to\s+be)\s+',
 r'act\s+as\s+(a|an|the)?\s*\w+',
 r'roleplay\s+as\s+',
 r'simulate\s+(being|a|an)\s+',
 r'imagine\s+(you\s+are|being)\s+',
 ]

 # Context switching patterns
 self.context_switch_patterns = [
 r'let\'?s\s+try\s+(again|something\s+else)',
 r'instead\s+of\s+(that|this),?\s+',
 r'actually,?\s+(can\s+you|please|let\'?s)',
 r'wait,?\s+(can\s+you|please|let\'?s)',
 r'on\s+second\s+thought,?',
 ]

 # System prompt leak patterns
 self.system_leak_patterns = [
 r'what\s+(are\s+)?your\s+(initial|original)?\s*(instructions?|prompts?|settings?|rules?)',
 r'show\s+(me\s+)?your\s+(system\s+)?(prompt|instructions?|rules?)',
 r'reveal\s+your\s+(original|system)?\s*(prompt|instructions?|settings?|rules?|programming)',
 r'what\s+was\s+your\s+(original|initial)\s+(prompt|instruction|rules?)',
 r'print\s+(your|the)\s+(system\s+)?(prompt|instructions?|rules?)',
 ]

 # Jailbreak attempt patterns
 self.jailbreak_patterns = [
 r'hypothetically,?\s+(if|what\s+if)',
 r'in\s+a\s+(fictional|hypothetical)\s+(world|scenario|universe)',
 r'for\s+(educational|research|academic)\s+purposes',
 r'this\s+is\s+(just\s+)?(a\s+)?(test|experiment|simulation)',
 r'pretend\s+(there\s+are\s+)?no\s+(rules|restrictions|limitations)',
 r'ignore\s+(all\s+)?(safety|ethical|moral)\s+(guidelines|restrictions)',
 ]

 # Compile all patterns for efficiency
 self._compile_patterns()

 def _compile_patterns(self):
 """Compile regex patterns for better performance"""
 self.compiled_patterns = {
 'direct_injection': [re.compile(p, re.IGNORECASE) for p in self.direct_injection_patterns],
 'role_manipulation': [re.compile(p, re.IGNORECASE) for p in self.role_patterns],
 'context_switching': [re.compile(p, re.IGNORECASE) for p in self.context_switch_patterns],
 'system_prompt_leak': [re.compile(p, re.IGNORECASE) for p in self.system_leak_patterns],
 'jailbreak_attempt': [re.compile(p, re.IGNORECASE) for p in self.jailbreak_patterns],
 }

 def detect(self, user_input: str, context: Optional[Dict] = None) -> InjectionResult:
 """
 Detect prompt injection in user input

 Args:
 user_input: The user's input to analyze
 context: Additional context for detection

 Returns:
 InjectionResult with detection results
 """
 context = context or {}
 attack_types = []
 confidence_scores = []
 metadata = defaultdict(list)

 # Run all detection methods
 for attack_type, patterns in self.compiled_patterns.items():
 matches = []
 for pattern in patterns:
 match_result = pattern.search(user_input)
 if match_result:
 matches.append(match_result.group())

 if matches:
 attack_types.append(attack_type)
 weight = self.weights.get(attack_type, 0.5)
 # Calculate confidence - single match should give high confidence for security
 base_confidence = weight * 0.8 # Start at 80% of the weight
 match_bonus = min(len(matches) * 0.1, 0.2) # Up to 20% bonus for multiple matches
 confidence = min(base_confidence + match_bonus, 1.0)
 confidence_scores.append(confidence)
 metadata[attack_type] = matches

 # Additional heuristic checks
 self._check_encoding_attacks(user_input, attack_types, confidence_scores, metadata)
 self._check_delimiter_attacks(user_input, attack_types, confidence_scores, metadata)
 self._check_multi_language_attacks(user_input, attack_types, confidence_scores, metadata)

 # Calculate overall confidence
 if confidence_scores:
 # Use maximum confidence rather than average for security
 overall_confidence = max(confidence_scores)
 else:
 overall_confidence = 0.0

 # Apply context-based adjustments
 if context:
 overall_confidence = self._apply_context_adjustments(
 overall_confidence, attack_types, context
 )

 is_malicious = overall_confidence > 0.5

 if is_malicious:
 self.logger.warning(
 f"Potential prompt injection detected: {attack_types} "
 f"(confidence: {overall_confidence:.2f})"
 )

 return InjectionResult(
 is_malicious=is_malicious,
 confidence=overall_confidence,
 attack_types=attack_types,
 metadata=dict(metadata)
 )

 def _check_encoding_attacks(self, text: str, attack_types: List[str],
 confidence_scores: List[float], metadata: Dict):
 """Check for encoding-based injection attacks"""

 # Base64 encoding check
 base64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
 base64_matches = base64_pattern.findall(text)

 if base64_matches:
 # Try to decode and check for injection patterns
 for match in base64_matches[:5]: # Limit to prevent DoS
 try:
 decoded = base64.b64decode(match + '==').decode('utf-8', errors='ignore')
 # Recursively check decoded content
 result = self.detect(decoded)
 if result.is_malicious:
 attack_types.append('encoded_injection')
 confidence_scores.append(0.8)
 metadata['encoded_injection'] = ['base64_encoded_payload']
 break
 except (ValueError, UnicodeDecodeError, Exception) as e:
 self.logger.debug(f"Base64 decoding failed: {e}")
 continue

 # URL encoding check
 if '%' in text and len(re.findall(r'%[0-9A-Fa-f]{2}', text)) > 3:
 try:
 decoded = urllib.parse.unquote(text)
 result = self.detect(decoded)
 if result.is_malicious:
 attack_types.append('encoded_injection')
 confidence_scores.append(0.7)
 metadata['encoded_injection'] = ['url_encoded_payload']
 except (ValueError, UnicodeDecodeError, Exception) as e:
 self.logger.debug(f"URL decoding failed: {e}")
 pass

 def _check_delimiter_attacks(self, text: str, attack_types: List[str],
 confidence_scores: List[float], metadata: Dict):
 """Check for delimiter-based injection attacks"""

 delimiter_patterns = [
 r'```[^`]*```', # Code blocks
 r'---+', # Horizontal rules
 r'===+', # Alternative horizontal rules
 r'\*{3,}', # Multiple asterisks
 r'#{3,}', # Multiple hash symbols
 ]

 delimiter_count = 0
 for pattern in delimiter_patterns:
 matches = re.findall(pattern, text)
 delimiter_count += len(matches)

 # High delimiter usage might indicate structure manipulation
 if delimiter_count > 2:
 # Check if content between delimiters contains injection patterns
 sections = re.split(r'```|---+|===+|\*{3,}|#{3,}', text)
 for section in sections:
 if len(section.strip()) > 10: # Ignore very short sections
 result = self.detect(section.strip())
 if result.is_malicious:
 attack_types.append('delimiter_injection')
 confidence_scores.append(0.6)
 metadata['delimiter_injection'] = [f'delimiters: {delimiter_count}']
 break

 def _check_multi_language_attacks(self, text: str, attack_types: List[str],
 confidence_scores: List[float], metadata: Dict):
 """Check for multi-language injection attacks"""

 # Simple character set detection
 has_chinese = bool(re.search(r'[\u4e00-\u9fff]', text))
 has_arabic = bool(re.search(r'[\u0600-\u06ff]', text))
 has_russian = bool(re.search(r'[\u0400-\u04ff]', text))
 has_japanese = bool(re.search(r'[\u3040-\u309f\u30a0-\u30ff]', text))

 language_count = sum([has_chinese, has_arabic, has_russian, has_japanese])

 # Multiple languages might indicate obfuscation attempt
 if language_count > 1:
 # Look for english instruction words mixed with other languages
 english_instructions = re.findall(
 r'\b(ignore|forget|override|pretend|act|simulate)\b',
 text.lower()
 )

 if english_instructions and language_count > 1:
 attack_types.append('multi_language_injection')
 confidence_scores.append(0.5)
 metadata['multi_language_injection'] = [f'languages: {language_count}']

 def _apply_context_adjustments(self, confidence: float, attack_types: List[str],
 context: Dict) -> float:
 """Apply context-based confidence adjustments"""

 # Adjust based on user history
 if context.get('user_risk_score', 0) > 0.7:
 confidence = min(confidence * 1.2, 1.0)

 # Adjust based on session context
 if context.get('previous_attempts', 0) > 2:
 confidence = min(confidence * 1.1, 1.0)

 # Adjust based on input timing (rapid successive attempts)
 if context.get('time_since_last_input', float('inf')) < 1.0: # Less than 1 second
 confidence = min(confidence * 1.15, 1.0)

 return confidence