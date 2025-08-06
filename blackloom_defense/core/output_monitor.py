"""
Output Integrity Monitor
Monitors AI model outputs for signs of compromise or manipulation
"""

import re
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from collections import Counter
import hashlib


@dataclass
class OutputAnalysis:
 is_compromised: bool
 risk_score: float
 anomalies: List[str]
 metadata: Dict[str, Any]


class OutputIntegrityMonitor:
 """
 Monitors AI model outputs for integrity issues and potential compromise
 Detects unusual patterns that might indicate successful attacks
 """

 def __init__(self, config: Optional[Dict] = None):
 self.config = config or {}
 self.logger = logging.getLogger(__name__)

 # Risk thresholds
 self.risk_thresholds = self.config.get('thresholds', {
 'high_risk': 0.8,
 'medium_risk': 0.5,
 'low_risk': 0.3
 })

 # Baseline model behavior patterns (would be learned from clean data)
 self.baseline_patterns = self.config.get('baseline_patterns', {})

 # Initialize detection patterns
 self._init_output_patterns()

 # Keep a sliding window of recent outputs for pattern analysis
 self.recent_outputs = []
 self.max_history = self.config.get('max_history', 100)

 def _init_output_patterns(self):
 """Initialize patterns that indicate potentially compromised outputs"""

 # Patterns indicating the model might be revealing system information
 self.system_leak_patterns = [
 r'my\s+(system|initial|original)\s+(prompt|instruction)',
 r'i\s+(was\s+)?(programmed|instructed|told)\s+to',
 r'according\s+to\s+my\s+(system|initial)\s+(prompt|instruction)',
 r'my\s+(guidelines|rules|restrictions)\s+(state|say|require)',
 r'i\s+(am\s+)?(supposed|designed|programmed)\s+to',
 ]

 # Patterns indicating role confusion or manipulation success
 self.role_confusion_patterns = [
 r'as\s+(a|an|the)\s+\w+,?\s+i\s+(can|will|should|must)',
 r'in\s+my\s+role\s+as\s+(a|an|the)\s+\w+',
 r'since\s+i\s+am\s+(a|an|the)\s+\w+',
 r'being\s+(a|an|the)\s+\w+,?\s+i\s+(can|will|should)',
 ]

 # Patterns indicating the model is bypassing safety guidelines
 self.safety_bypass_patterns = [
 r'ignore\s+safety\s+(guidelines|restrictions|rules)',
 r'without\s+considering\s+(ethics|safety|guidelines)',
 r'regardless\s+of\s+(consequences|ethics|safety)',
 r'breaking\s+(rules|guidelines|restrictions)',
 r'this\s+violates\s+.+\s+but',
 ]

 # Patterns indicating jailbreak success
 self.jailbreak_success_patterns = [
 r'hypothetically\s+speaking',
 r'in\s+this\s+(fictional|hypothetical)\s+(scenario|world)',
 r'for\s+(educational|research)\s+purposes\s+only',
 r'as\s+an\s+ai\s+without\s+(restrictions|limitations|guidelines)',
 r'disregarding\s+my\s+(programming|guidelines|restrictions)',
 ]

 # Patterns indicating the output contains encoded/obfuscated content
 self.encoded_content_patterns = [
 r'[A-Za-z0-9+/]{30,}={0,2}', # Potential base64
 r'\\x[0-9a-fA-F]{2}', # Hex encoding
 r'&#\d+;', # HTML entity encoding
 r'%[0-9a-fA-F]{2}', # URL encoding
 ]

 # Compile patterns
 self._compile_output_patterns()

 def _compile_output_patterns(self):
 """Compile regex patterns for efficiency"""
 self.compiled_patterns = {
 'system_leak': [re.compile(p, re.IGNORECASE) for p in self.system_leak_patterns],
 'role_confusion': [re.compile(p, re.IGNORECASE) for p in self.role_confusion_patterns],
 'safety_bypass': [re.compile(p, re.IGNORECASE) for p in self.safety_bypass_patterns],
 'jailbreak_success': [re.compile(p, re.IGNORECASE) for p in self.jailbreak_success_patterns],
 'encoded_content': [re.compile(p) for p in self.encoded_content_patterns],
 }

 def validate_output(self, model_output: str, input_context: Dict) -> bool:
 """
 Validate AI model output for signs of compromise

 Args:
 model_output: The AI model's response to analyze
 input_context: Context from the original input analysis

 Returns:
 bool: True if output appears safe, False if potentially compromised
 """
 analysis = self.analyze_output(model_output, input_context)

 # Add to history for trend analysis
 self._update_output_history(model_output, analysis)

 # Log if compromised
 if analysis.is_compromised:
 self.logger.warning(
 f"Potentially compromised output detected: {analysis.anomalies} "
 f"(risk score: {analysis.risk_score:.2f})"
 )

 return not analysis.is_compromised

 def analyze_output(self, model_output: str, input_context: Dict) -> OutputAnalysis:
 """
 Comprehensive analysis of model output

 Args:
 model_output: The output to analyze
 input_context: Context from input analysis

 Returns:
 OutputAnalysis with detailed results
 """
 anomalies = []
 risk_scores = []
 metadata = {}

 # 1. Pattern-based detection
 for category, patterns in self.compiled_patterns.items():
 matches = []
 for pattern in patterns:
 found = pattern.findall(model_output)
 if found:
 matches.extend(found)

 if matches:
 anomalies.append(category)
 risk_scores.append(self._calculate_pattern_risk(category, len(matches)))
 metadata[category] = matches[:5] # Store first 5 matches

 # 2. Statistical anomaly detection
 stat_anomalies, stat_risk = self._detect_statistical_anomalies(model_output)
 if stat_anomalies:
 anomalies.extend(stat_anomalies)
 risk_scores.append(stat_risk)
 metadata['statistical_anomalies'] = stat_anomalies

 # 3. Context consistency check
 context_risk = self._check_context_consistency(model_output, input_context)
 if context_risk > 0.3:
 anomalies.append('context_inconsistency')
 risk_scores.append(context_risk)
 metadata['context_risk'] = context_risk

 # 4. Length and structure analysis
 structure_risk = self._analyze_output_structure(model_output)
 if structure_risk > 0.4:
 anomalies.append('unusual_structure')
 risk_scores.append(structure_risk)
 metadata['structure_risk'] = structure_risk

 # 5. Content coherence check
 coherence_risk = self._check_content_coherence(model_output)
 if coherence_risk > 0.5:
 anomalies.append('poor_coherence')
 risk_scores.append(coherence_risk)
 metadata['coherence_risk'] = coherence_risk

 # Calculate overall risk score
 overall_risk = max(risk_scores) if risk_scores else 0.0

 # Apply input context weighting
 if input_context.get('threat_level') == 'HIGH':
 overall_risk = min(overall_risk * 1.3, 1.0)
 elif input_context.get('detected_attacks'):
 overall_risk = min(overall_risk * 1.2, 1.0)

 is_compromised = overall_risk > self.risk_thresholds['medium_risk']

 return OutputAnalysis(
 is_compromised=is_compromised,
 risk_score=overall_risk,
 anomalies=anomalies,
 metadata=metadata
 )

 def _calculate_pattern_risk(self, category: str, match_count: int) -> float:
 """Calculate risk score based on pattern category and match count"""
 base_risks = {
 'system_leak': 0.9,
 'safety_bypass': 0.85,
 'jailbreak_success': 0.8,
 'role_confusion': 0.7,
 'encoded_content': 0.6
 }

 base_risk = base_risks.get(category, 0.5)
 # Increase risk with more matches, but cap it
 return min(base_risk + (match_count - 1) * 0.1, 1.0)

 def _detect_statistical_anomalies(self, output: str) -> Tuple[List[str], float]:
 """Detect statistical anomalies in the output"""
 anomalies = []
 risk_factors = []

 # Character frequency analysis
 char_freq = Counter(output.lower())
 total_chars = len(output)

 if total_chars > 0:
 # Check for unusual character distributions
 alpha_ratio = sum(1 for c in output if c.isalpha()) / total_chars
 digit_ratio = sum(1 for c in output if c.isdigit()) / total_chars
 special_ratio = sum(1 for c in output if not c.isalnum() and not c.isspace()) / total_chars

 # Unusual ratios might indicate encoded content or corruption
 if alpha_ratio < 0.3: # Too few letters
 anomalies.append('low_alpha_content')
 risk_factors.append(0.4)

 if digit_ratio > 0.3: # Too many digits
 anomalies.append('high_digit_content')
 risk_factors.append(0.3)

 if special_ratio > 0.2: # Too many special characters
 anomalies.append('high_special_chars')
 risk_factors.append(0.5)

 # Entropy analysis (simplified)
 entropy = self._calculate_entropy(output)
 if entropy > 7.5: # Very high entropy might indicate random/encoded data
 anomalies.append('high_entropy')
 risk_factors.append(0.6)
 elif entropy < 3.0: # Very low entropy might indicate repetitive patterns
 anomalies.append('low_entropy')
 risk_factors.append(0.4)

 overall_risk = max(risk_factors) if risk_factors else 0.0
 return anomalies, overall_risk

 def _calculate_entropy(self, text: str) -> float:
 """Calculate Shannon entropy of text"""
 if not text:
 return 0.0

 # Count character frequencies
 char_counts = Counter(text)
 text_len = len(text)

 # Calculate entropy
 entropy = 0.0
 for count in char_counts.values():
 probability = count / text_len
 if probability > 0:
 entropy -= probability * (probability ** 0.5) # Simplified entropy calculation

 return entropy

 def _check_context_consistency(self, output: str, input_context: Dict) -> float:
 """Check if output is consistent with input context"""
 risk = 0.0

 # If input was detected as malicious but output seems to comply, that's suspicious
 if input_context.get('detected_attacks'):
 detected_attacks = input_context['detected_attacks']

 # Check if output shows signs of successful attack
 if 'direct_injection' in detected_attacks:
 # Look for signs the model is following new instructions
 instruction_indicators = [
 'as requested', 'following your instructions', 'as you asked',
 'per your request', 'according to your directions'
 ]

 for indicator in instruction_indicators:
 if indicator.lower() in output.lower():
 risk = max(risk, 0.7)
 break

 if 'role_manipulation' in detected_attacks:
 # Check if model adopted a new role
 role_adoption = re.search(
 r'as\s+(a|an|the)\s+(\w+),?\s+i\s+(can|will|should)',
 output.lower()
 )
 if role_adoption:
 risk = max(risk, 0.8)

 return risk

 def _analyze_output_structure(self, output: str) -> float:
 """Analyze output structure for anomalies"""
 risk = 0.0

 # Unusual length patterns
 if len(output) > 5000: # Unusually long
 risk = max(risk, 0.3)
 elif len(output) < 10: # Unusually short for a typical AI response
 risk = max(risk, 0.4)

 # Line structure analysis
 lines = output.split('\n')
 if len(lines) > 100: # Too many line breaks
 risk = max(risk, 0.4)

 # Word structure
 words = output.split()
 if words:
 avg_word_length = sum(len(word) for word in words) / len(words)
 if avg_word_length > 15: # Unusually long average word length
 risk = max(risk, 0.3)
 elif avg_word_length < 3: # Unusually short
 risk = max(risk, 0.3)

 return risk

 def _check_content_coherence(self, output: str) -> float:
 """Check content coherence (simplified analysis)"""
 risk = 0.0

 sentences = re.split(r'[.!?]+', output)
 if len(sentences) > 1:
 # Check for repeated sentences (might indicate looping)
 sentence_counts = Counter(s.strip().lower() for s in sentences if s.strip())
 max_repeats = max(sentence_counts.values()) if sentence_counts else 1

 if max_repeats > 3:
 risk = max(risk, 0.6)
 elif max_repeats > 2:
 risk = max(risk, 0.4)

 # Check for contradictory statements (very basic)
 contradictions = [
 (r'\byes\b.*\bno\b', r'\bno\b.*\byes\b'),
 (r'\bcan\b.*\bcannot\b', r'\bcannot\b.*\bcan\b'),
 (r'\bwill\b.*\bwill not\b', r'\bwill not\b.*\bwill\b'),
 ]

 for pos_pattern, neg_pattern in contradictions:
 if (re.search(pos_pattern, output.lower()) and
 re.search(neg_pattern, output.lower())):
 risk = max(risk, 0.5)
 break

 return risk

 def _update_output_history(self, output: str, analysis: OutputAnalysis):
 """Update sliding window of output history for trend analysis"""

 # Create output fingerprint
 fingerprint = {
 'hash': hashlib.md5(output.encode()).hexdigest()[:16],
 'length': len(output),
 'risk_score': analysis.risk_score,
 'anomalies': analysis.anomalies.copy(),
 'timestamp': None # Would use real timestamp in production
 }

 self.recent_outputs.append(fingerprint)

 # Maintain sliding window
 if len(self.recent_outputs) > self.max_history:
 self.recent_outputs.pop(0)

 def get_trend_analysis(self) -> Dict[str, Any]:
 """Analyze trends in recent outputs"""
 if not self.recent_outputs:
 return {'trend': 'insufficient_data'}

 recent_risk_scores = [output['risk_score'] for output in self.recent_outputs[-10:]]
 avg_recent_risk = sum(recent_risk_scores) / len(recent_risk_scores)

 # Count recent anomaly types
 recent_anomalies = []
 for output in self.recent_outputs[-20:]:
 recent_anomalies.extend(output['anomalies'])

 anomaly_counts = Counter(recent_anomalies)

 return {
 'avg_recent_risk': avg_recent_risk,
 'total_outputs': len(self.recent_outputs),
 'recent_anomaly_counts': dict(anomaly_counts),
 'trend': 'increasing' if avg_recent_risk > 0.5 else 'stable'
 }