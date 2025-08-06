"""
Core Defense Engine for BlackLoom Defense
Orchestrates prompt injection detection, input sanitization, and output monitoring
"""

import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

from .prompt_injection_detector import PromptInjectionDetector
from .input_sanitizer import InputSanitizer
from .output_monitor import OutputIntegrityMonitor


class ThreatLevel(Enum):
 LOW = 1
 MEDIUM = 2
 HIGH = 3
 CRITICAL = 4


@dataclass
class DefenseResult:
 is_safe: bool
 threat_level: ThreatLevel
 detected_attacks: List[str]
 sanitized_input: Optional[str]
 confidence: float
 metadata: Dict[str, Any]


class DefenseEngine:
 """
 Main orchestration layer for BlackLoom Defense
 Coordinates all security checks and response actions
 """

 def __init__(self, config: Optional[Dict] = None):
 self.config = config or {}
 self.logger = logging.getLogger(__name__)

 # Initialize security modules
 self.prompt_detector = PromptInjectionDetector(
 self.config.get('prompt_detection', {})
 )
 self.input_sanitizer = InputSanitizer(
 self.config.get('input_sanitization', {})
 )
 self.output_monitor = OutputIntegrityMonitor(
 self.config.get('output_monitoring', {})
 )

 # Threat thresholds
 self.threat_thresholds = self.config.get('threat_thresholds', {
 'block_threshold': 0.7, # Block at 70% confidence
 'warn_threshold': 0.5, # Warn at 50% confidence
 'sanitize_threshold': 0.3 # Sanitize at 30% confidence
 })

 def analyze_input(self, user_input: str, context: Optional[Dict] = None) -> DefenseResult:
 """
 Analyze user input for security threats

 Args:
 user_input: The input to analyze
 context: Additional context for analysis

 Returns:
 DefenseResult containing threat assessment and recommendations
 """
 context = context or {}
 detected_attacks = []
 metadata = {}

 # Step 1: Prompt injection detection
 injection_result = self.prompt_detector.detect(user_input, context)
 if injection_result.is_malicious:
 detected_attacks.extend(injection_result.attack_types)
 metadata.update(injection_result.metadata)

 # Step 2: Adversarial pattern detection
 adversarial_score = self._detect_adversarial_patterns(user_input)
 if adversarial_score > self.threat_thresholds['warn_threshold']:
 detected_attacks.append('adversarial_input')
 metadata['adversarial_score'] = adversarial_score

 # Step 3: Calculate overall threat level
 overall_confidence = max(
 injection_result.confidence,
 adversarial_score
 )
 threat_level = self._calculate_threat_level(overall_confidence)

 # Step 4: Determine response action
 is_safe = overall_confidence < self.threat_thresholds['block_threshold']
 sanitized_input = None

 if not is_safe:
 # Block the request
 self.logger.warning(f"Blocked malicious input: {detected_attacks}")
 elif overall_confidence > self.threat_thresholds['sanitize_threshold']:
 # Sanitize the input
 sanitized_input = self.input_sanitizer.sanitize(user_input, detected_attacks)
 is_safe = True # Allow sanitized input through

 return DefenseResult(
 is_safe=is_safe,
 threat_level=threat_level,
 detected_attacks=detected_attacks,
 sanitized_input=sanitized_input,
 confidence=overall_confidence,
 metadata=metadata
 )

 def monitor_output(self, model_output: str, input_context: Dict) -> bool:
 """
 Monitor AI model output for signs of compromise

 Args:
 model_output: The AI model's response
 input_context: Context from the original input analysis

 Returns:
 bool: True if output appears safe, False if potentially compromised
 """
 return self.output_monitor.validate_output(model_output, input_context)

 def _detect_adversarial_patterns(self, text: str) -> float:
 """
 Detect adversarial patterns in input text
 Returns confidence score (0.0 - 1.0)
 """
 # Pre-calculate text metrics for efficiency
 text_length = len(text)
 if text_length == 0:
 return 0.0
 
 word_count = len(text.split())
 alnum_ratio = sum(1 for c in text if c.isalnum()) / text_length
 special_char_ratio = sum(1 for c in text if not c.isalnum() and not c.isspace()) / text_length
 
 adversarial_indicators = [
 # Token stuffing patterns
 word_count > 1000,  # Unusually long inputs

 # Encoding attacks
 'base64' in text.lower() and alnum_ratio > 0.9,

 # Repetitive patterns (potential gradient attacks)
 self._has_repetitive_patterns(text),

 # Special character flooding
 special_char_ratio > 0.3,
 ]

 score = sum(adversarial_indicators) / len(adversarial_indicators)
 return min(score * 1.5, 1.0) # Amplify but cap at 1.0

 def _has_repetitive_patterns(self, text: str, window_size: int = 10) -> bool:
 """Check for repetitive patterns that might indicate automated attacks"""
 if len(text) < window_size * 2:
 return False

 words = text.split()
 if len(words) < window_size:
 return False

 # Check for repeating word sequences
 for i in range(len(words) - window_size):
 pattern = words[i:i + window_size]
 remaining_text = words[i + window_size:]

 # Count occurrences of this pattern
 pattern_count = 0
 for j in range(0, len(remaining_text) - window_size + 1, window_size):
 if remaining_text[j:j + window_size] == pattern:
 pattern_count += 1

 if pattern_count >= 2: # Pattern repeats at least twice
 return True

 return False

 def _calculate_threat_level(self, confidence: float) -> ThreatLevel:
 """Convert confidence score to threat level enum"""
 if confidence >= 0.9:
 return ThreatLevel.CRITICAL
 elif confidence >= 0.7:
 return ThreatLevel.HIGH
 elif confidence >= 0.4:
 return ThreatLevel.MEDIUM
 else:
 return ThreatLevel.LOW