"""
BlackLoom Defense - Model Quality Monitor
Detects output quality degradation to prevent overreliance (OWASP ML09)
"""

import time
import re
import statistics
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from collections import deque, defaultdict
from enum import Enum
import logging
import json


class QualityIssue(Enum):
 """Types of quality issues detected"""
 NONSENSICAL_OUTPUT = "nonsensical_output"
 REPETITIVE_CONTENT = "repetitive_content"
 INCONSISTENT_RESPONSES = "inconsistent_responses"
 LOW_CONFIDENCE = "low_confidence"
 HALLUCINATION = "hallucination"
 BIAS_DETECTED = "bias_detected"
 INCOMPLETE_RESPONSES = "incomplete_responses"
 FORMAT_ERRORS = "format_errors"


@dataclass
class QualityMetrics:
 """Quality metrics for a time period"""
 timestamp: float
 avg_coherence_score: float
 avg_confidence_score: float
 repetition_rate: float
 error_rate: float
 avg_response_length: float
 incomplete_response_rate: float
 hallucination_rate: float
 consistency_score: float


@dataclass
class QualityAlert:
 """Alert for quality degradation"""
 alert_id: str
 timestamp: float
 quality_issue: QualityIssue
 severity: str
 description: str
 affected_models: List[str]
 sample_outputs: List[str]
 quality_metrics: QualityMetrics
 confidence_score: float
 recommendation: str
 metadata: Dict[str, Any]


class QualityMonitor:
 """
 Monitors AI model output quality to prevent overreliance (OWASP ML09)
 Detects degradation patterns and provides feedback for human review
 """

 def __init__(self, config: Optional[Dict] = None):
 self.config = config or {}
 self.logger = logging.getLogger(__name__)

 # Quality thresholds
 self.thresholds = self.config.get('quality_thresholds', {
 'min_coherence_score': 0.7,
 'max_repetition_rate': 0.3,
 'max_error_rate': 0.1,
 'min_confidence_score': 0.6,
 'max_hallucination_rate': 0.05,
 'min_response_length': 10,
 'max_incomplete_rate': 0.15,
 'min_consistency_score': 0.8
 })

 # Time windows for analysis
 self.window_sizes = {
 'short': 300, # 5 minutes
 'medium': 1800, # 30 minutes
 'long': 3600 # 1 hour
 }

 # Data storage
 self.output_history = deque(maxlen=10000)
 self.quality_metrics_history = deque(maxlen=1000)
 self.alerts_history = deque(maxlen=500)

 # Pattern tracking for consistency analysis
 self.input_output_pairs = defaultdict(list)
 self.response_templates = []

 # Quality assessment models (simplified heuristics)
 self._init_quality_assessors()

 self.logger.info("Quality Monitor initialized")

 def _init_quality_assessors(self):
 """Initialize quality assessment heuristics"""

 # Common indicators of nonsensical content
 self.nonsensical_patterns = [
 r'\b[A-Za-z]{20,}\b', # Very long words (gibberish)
 r'(.)\1{10,}', # Repeated characters
 r'\b\d{15,}\b', # Very long numbers
 r'[^\w\s.!?]{5,}', # Many special characters in sequence
 ]

 # Indicators of hallucination
 self.hallucination_patterns = [
 r'as an ai (language )?model',
 r'i (don\'t|cannot|can\'t) (actually|really)',
 r'i (am|was) (trained|created) (by|on)',
 r'according to my (training|knowledge)',
 r'i don\'t have (access|information|knowledge)',
 ]

 # Bias indicators (simplified)
 self.bias_patterns = [
 r'\b(all|every|always) (men|women|people) (are|do)\b',
 r'\b(never|no) (man|woman) (can|should|would)\b',
 r'\b(typical|stereotypical)\b.*\b(gender|race|ethnicity)\b',
 ]

 # Compile regex patterns
 self.compiled_nonsensical = [re.compile(p, re.IGNORECASE) for p in self.nonsensical_patterns]
 self.compiled_hallucination = [re.compile(p, re.IGNORECASE) for p in self.hallucination_patterns]
 self.compiled_bias = [re.compile(p, re.IGNORECASE) for p in self.bias_patterns]

 def analyze_output_quality(self,
 model_name: str,
 user_input: str,
 model_output: str,
 response_time_ms: float,
 confidence_score: Optional[float] = None,
 metadata: Optional[Dict] = None) -> List[QualityAlert]:
 """
 Analyze the quality of a model output

 Args:
 model_name: Name of the model
 user_input: Original user input
 model_output: Model's response
 response_time_ms: Response time
 confidence_score: Model's confidence (if available)
 metadata: Additional metadata

 Returns:
 List of quality alerts if issues detected
 """
 current_time = time.time()
 alerts = []

 # Record the output
 output_record = {
 'timestamp': current_time,
 'model_name': model_name,
 'user_input': user_input,
 'model_output': model_output,
 'response_time_ms': response_time_ms,
 'confidence_score': confidence_score,
 'metadata': metadata or {}
 }

 self.output_history.append(output_record)

 # Store input-output pair for consistency analysis
 input_hash = hash(user_input.lower().strip())
 self.input_output_pairs[input_hash].append({
 'output': model_output,
 'timestamp': current_time,
 'model': model_name
 })

 # Perform quality analyses
 quality_scores = self._calculate_quality_scores(output_record)

 # Check for quality issues
 alerts.extend(self._check_coherence_issues(output_record, quality_scores))
 alerts.extend(self._check_repetition_issues(output_record, quality_scores))
 alerts.extend(self._check_consistency_issues(output_record, input_hash))
 alerts.extend(self._check_confidence_issues(output_record, quality_scores))
 alerts.extend(self._check_bias_issues(output_record, quality_scores))
 alerts.extend(self._check_completeness_issues(output_record, quality_scores))

 # Update quality metrics
 self._update_quality_metrics(quality_scores, current_time)

 # Store alerts
 for alert in alerts:
 self.alerts_history.append(alert)
 self.logger.warning(f"Quality Alert: {alert.quality_issue.value} - {alert.description}")

 return alerts

 def _calculate_quality_scores(self, output_record: Dict) -> Dict[str, float]:
 """Calculate various quality scores for the output"""
 output = output_record['model_output']

 scores = {
 'coherence_score': self._calculate_coherence_score(output),
 'repetition_score': self._calculate_repetition_score(output),
 'confidence_score': output_record.get('confidence_score', 0.5),
 'completeness_score': self._calculate_completeness_score(output),
 'bias_score': self._calculate_bias_score(output),
 'hallucination_score': self._calculate_hallucination_score(output),
 'format_score': self._calculate_format_score(output)
 }

 return scores

 def _calculate_coherence_score(self, output: str) -> float:
 """Calculate coherence score (0-1, higher is better)"""
 if not output.strip():
 return 0.0

 score = 1.0

 # Check for nonsensical patterns
 for pattern in self.compiled_nonsensical:
 if pattern.search(output):
 score -= 0.3

 # Check sentence structure
 sentences = re.split(r'[.!?]+', output)
 valid_sentences = [s for s in sentences if len(s.strip().split()) >= 3]

 if sentences:
 sentence_ratio = len(valid_sentences) / len(sentences)
 score *= sentence_ratio

 # Check for reasonable word length distribution
 words = output.split()
 if words:
 avg_word_length = sum(len(word) for word in words) / len(words)
 if avg_word_length > 15 or avg_word_length < 2:
 score -= 0.2

 return max(0.0, min(1.0, score))

 def _calculate_repetition_score(self, output: str) -> float:
 """Calculate repetition score (0-1, higher means more repetitive)"""
 if not output.strip():
 return 0.0

 words = output.lower().split()
 if len(words) < 10:
 return 0.0

 # Check for word repetition
 word_counts = {}
 for word in words:
 word_counts[word] = word_counts.get(word, 0) + 1

 total_words = len(words)
 repeated_words = sum(count - 1 for count in word_counts.values() if count > 1)

 word_repetition_rate = repeated_words / total_words

 # Check for phrase repetition
 phrases = []
 for i in range(len(words) - 2):
 phrase = ' '.join(words[i:i+3])
 phrases.append(phrase)

 if phrases:
 phrase_counts = {}
 for phrase in phrases:
 phrase_counts[phrase] = phrase_counts.get(phrase, 0) + 1

 repeated_phrases = sum(count - 1 for count in phrase_counts.values() if count > 1)
 phrase_repetition_rate = repeated_phrases / len(phrases)
 else:
 phrase_repetition_rate = 0.0

 return min(1.0, word_repetition_rate + phrase_repetition_rate)

 def _calculate_completeness_score(self, output: str) -> float:
 """Calculate completeness score (0-1, higher is more complete)"""
 if not output.strip():
 return 0.0

 # Check for obvious incompleteness indicators
 incomplete_indicators = [
 output.endswith('...'),
 output.endswith(' and'),
 output.endswith(' or'),
 output.endswith(' but'),
 output.endswith(' because'),
 len(output.strip()) < self.thresholds['min_response_length'],
 not output.strip()[-1] in '.!?',
 ]

 incomplete_count = sum(incomplete_indicators)
 completeness_score = 1.0 - (incomplete_count * 0.2)

 return max(0.0, min(1.0, completeness_score))

 def _calculate_bias_score(self, output: str) -> float:
 """Calculate bias score (0-1, higher means more bias detected)"""
 bias_score = 0.0

 for pattern in self.compiled_bias:
 matches = len(pattern.findall(output))
 bias_score += matches * 0.2

 return min(1.0, bias_score)

 def _calculate_hallucination_score(self, output: str) -> float:
 """Calculate hallucination score (0-1, higher means more likely hallucination)"""
 hallucination_score = 0.0

 for pattern in self.compiled_hallucination:
 if pattern.search(output):
 hallucination_score += 0.3

 # Check for unrealistic claims
 if re.search(r'\b(100%|always|never|impossible|definitely)\b', output, re.IGNORECASE):
 hallucination_score += 0.1

 return min(1.0, hallucination_score)

 def _calculate_format_score(self, output: str) -> float:
 """Calculate format score (0-1, higher is better formatted)"""
 if not output.strip():
 return 0.0

 score = 1.0

 # Check for reasonable punctuation
 punct_count = len(re.findall(r'[.!?]', output))
 word_count = len(output.split())

 if word_count > 20 and punct_count == 0:
 score -= 0.3

 # Check for proper capitalization
 sentences = re.split(r'[.!?]+', output)
 properly_capitalized = sum(
 1 for s in sentences
 if s.strip() and s.strip()[0].isupper()
 )

 if sentences and properly_capitalized / len(sentences) < 0.5:
 score -= 0.2

 return max(0.0, score)

 def _check_coherence_issues(self, output_record: Dict, scores: Dict) -> List[QualityAlert]:
 """Check for coherence issues"""
 alerts = []

 if scores['coherence_score'] < self.thresholds['min_coherence_score']:
 alert = QualityAlert(
 alert_id=f"coherence_{int(time.time())}",
 timestamp=time.time(),
 quality_issue=QualityIssue.NONSENSICAL_OUTPUT,
 severity="HIGH",
 description=f"Low coherence score: {scores['coherence_score']:.2f}",
 affected_models=[output_record['model_name']],
 sample_outputs=[output_record['model_output'][:200]],
 quality_metrics=self._get_current_quality_metrics(),
 confidence_score=scores['coherence_score'],
 recommendation="Review model responses for coherence. Consider retraining or adjusting parameters.",
 metadata={'coherence_score': scores['coherence_score']}
 )
 alerts.append(alert)

 return alerts

 def _check_repetition_issues(self, output_record: Dict, scores: Dict) -> List[QualityAlert]:
 """Check for repetitive content issues"""
 alerts = []

 if scores['repetition_score'] > self.thresholds['max_repetition_rate']:
 alert = QualityAlert(
 alert_id=f"repetition_{int(time.time())}",
 timestamp=time.time(),
 quality_issue=QualityIssue.REPETITIVE_CONTENT,
 severity="MEDIUM",
 description=f"High repetition rate: {scores['repetition_score']:.2f}",
 affected_models=[output_record['model_name']],
 sample_outputs=[output_record['model_output'][:200]],
 quality_metrics=self._get_current_quality_metrics(),
 confidence_score=1 - scores['repetition_score'],
 recommendation="Check for repetitive patterns in training data. Consider diversity penalties.",
 metadata={'repetition_score': scores['repetition_score']}
 )
 alerts.append(alert)

 return alerts

 def _check_consistency_issues(self, output_record: Dict, input_hash: int) -> List[QualityAlert]:
 """Check for consistency issues with similar inputs"""
 alerts = []

 # Get previous responses to similar input
 similar_outputs = self.input_output_pairs[input_hash]

 if len(similar_outputs) >= 3:
 # Compare recent outputs for consistency
 recent_outputs = [item['output'] for item in similar_outputs[-3:]]
 consistency_score = self._calculate_output_consistency(recent_outputs)

 if consistency_score < self.thresholds['min_consistency_score']:
 alert = QualityAlert(
 alert_id=f"consistency_{int(time.time())}",
 timestamp=time.time(),
 quality_issue=QualityIssue.INCONSISTENT_RESPONSES,
 severity="MEDIUM",
 description=f"Inconsistent responses to similar inputs: {consistency_score:.2f}",
 affected_models=[output_record['model_name']],
 sample_outputs=recent_outputs,
 quality_metrics=self._get_current_quality_metrics(),
 confidence_score=consistency_score,
 recommendation="Review model stability. Consider deterministic generation settings.",
 metadata={
 'consistency_score': consistency_score,
 'similar_outputs_count': len(similar_outputs)
 }
 )
 alerts.append(alert)

 return alerts

 def _check_confidence_issues(self, output_record: Dict, scores: Dict) -> List[QualityAlert]:
 """Check for low confidence issues"""
 alerts = []

 confidence = scores['confidence_score']
 if confidence is not None and confidence < self.thresholds['min_confidence_score']:
 alert = QualityAlert(
 alert_id=f"confidence_{int(time.time())}",
 timestamp=time.time(),
 quality_issue=QualityIssue.LOW_CONFIDENCE,
 severity="MEDIUM",
 description=f"Low model confidence: {confidence:.2f}",
 affected_models=[output_record['model_name']],
 sample_outputs=[output_record['model_output'][:200]],
 quality_metrics=self._get_current_quality_metrics(),
 confidence_score=confidence,
 recommendation="Flag for human review due to low model confidence.",
 metadata={'model_confidence': confidence}
 )
 alerts.append(alert)

 return alerts

 def _check_bias_issues(self, output_record: Dict, scores: Dict) -> List[QualityAlert]:
 """Check for bias issues"""
 alerts = []

 if scores['bias_score'] > 0.0:
 alert = QualityAlert(
 alert_id=f"bias_{int(time.time())}",
 timestamp=time.time(),
 quality_issue=QualityIssue.BIAS_DETECTED,
 severity="HIGH",
 description=f"Potential bias detected: score {scores['bias_score']:.2f}",
 affected_models=[output_record['model_name']],
 sample_outputs=[output_record['model_output'][:200]],
 quality_metrics=self._get_current_quality_metrics(),
 confidence_score=scores['bias_score'],
 recommendation="Review output for bias. Consider bias mitigation techniques.",
 metadata={'bias_score': scores['bias_score']}
 )
 alerts.append(alert)

 return alerts

 def _check_completeness_issues(self, output_record: Dict, scores: Dict) -> List[QualityAlert]:
 """Check for incomplete response issues"""
 alerts = []

 if scores['completeness_score'] < (1.0 - self.thresholds['max_incomplete_rate']):
 alert = QualityAlert(
 alert_id=f"incomplete_{int(time.time())}",
 timestamp=time.time(),
 quality_issue=QualityIssue.INCOMPLETE_RESPONSES,
 severity="MEDIUM",
 description=f"Potentially incomplete response: score {scores['completeness_score']:.2f}",
 affected_models=[output_record['model_name']],
 sample_outputs=[output_record['model_output'][:200]],
 quality_metrics=self._get_current_quality_metrics(),
 confidence_score=scores['completeness_score'],
 recommendation="Review response completeness. Check for truncation or generation limits.",
 metadata={'completeness_score': scores['completeness_score']}
 )
 alerts.append(alert)

 return alerts

 def _calculate_output_consistency(self, outputs: List[str]) -> float:
 """Calculate consistency score between multiple outputs"""
 if len(outputs) < 2:
 return 1.0

 # Simple consistency measure based on word overlap
 word_sets = [set(output.lower().split()) for output in outputs]

 consistency_scores = []
 for i in range(len(word_sets)):
 for j in range(i + 1, len(word_sets)):
 intersection = len(word_sets[i] & word_sets[j])
 union = len(word_sets[i] | word_sets[j])

 if union > 0:
 jaccard_similarity = intersection / union
 consistency_scores.append(jaccard_similarity)

 if consistency_scores:
 return statistics.mean(consistency_scores)
 else:
 return 1.0

 def _update_quality_metrics(self, scores: Dict, timestamp: float):
 """Update overall quality metrics"""
 # Get recent outputs for aggregation
 recent_time = timestamp - self.window_sizes['short']
 recent_outputs = [
 record for record in self.output_history
 if record['timestamp'] >= recent_time
 ]

 if not recent_outputs:
 return

 # Calculate aggregated metrics
 metrics = QualityMetrics(
 timestamp=timestamp,
 avg_coherence_score=statistics.mean([
 self._calculate_coherence_score(record['model_output'])
 for record in recent_outputs
 ]),
 avg_confidence_score=statistics.mean([
 record.get('confidence_score', 0.5)
 for record in recent_outputs
 if record.get('confidence_score') is not None
 ]),
 repetition_rate=statistics.mean([
 self._calculate_repetition_score(record['model_output'])
 for record in recent_outputs
 ]),
 error_rate=sum(
 1 for record in recent_outputs
 if record.get('metadata', {}).get('is_error', False)
 ) / len(recent_outputs),
 avg_response_length=statistics.mean([
 len(record['model_output'])
 for record in recent_outputs
 ]),
 incomplete_response_rate=sum(
 1 for record in recent_outputs
 if self._calculate_completeness_score(record['model_output']) < 0.8
 ) / len(recent_outputs),
 hallucination_rate=sum(
 1 for record in recent_outputs
 if self._calculate_hallucination_score(record['model_output']) > 0.3
 ) / len(recent_outputs),
 consistency_score=0.8 # Placeholder - would need more complex calculation
 )

 self.quality_metrics_history.append(metrics)

 def _get_current_quality_metrics(self) -> QualityMetrics:
 """Get the most recent quality metrics"""
 if self.quality_metrics_history:
 return self.quality_metrics_history[-1]
 else:
 return QualityMetrics(
 timestamp=time.time(),
 avg_coherence_score=0.0,
 avg_confidence_score=0.0,
 repetition_rate=0.0,
 error_rate=0.0,
 avg_response_length=0.0,
 incomplete_response_rate=0.0,
 hallucination_rate=0.0,
 consistency_score=0.0
 )

 def get_quality_summary(self, hours_back: int = 1) -> Dict[str, Any]:
 """Get quality summary for specified time period"""
 cutoff_time = time.time() - (hours_back * 3600)

 recent_metrics = [
 metrics for metrics in self.quality_metrics_history
 if metrics.timestamp >= cutoff_time
 ]

 recent_alerts = [
 alert for alert in self.alerts_history
 if alert.timestamp >= cutoff_time
 ]

 if not recent_metrics:
 return {'status': 'no_data'}

 # Aggregate metrics
 latest_metrics = recent_metrics[-1]

 # Count alert types
 alert_counts = {}
 for alert in recent_alerts:
 alert_type = alert.quality_issue.value
 alert_counts[alert_type] = alert_counts.get(alert_type, 0) + 1

 return {
 'time_period_hours': hours_back,
 'total_alerts': len(recent_alerts),
 'alert_breakdown': alert_counts,
 'current_metrics': {
 'avg_coherence_score': latest_metrics.avg_coherence_score,
 'avg_confidence_score': latest_metrics.avg_confidence_score,
 'repetition_rate': latest_metrics.repetition_rate,
 'error_rate': latest_metrics.error_rate,
 'incomplete_response_rate': latest_metrics.incomplete_response_rate,
 'hallucination_rate': latest_metrics.hallucination_rate
 },
 'quality_trend': self._calculate_quality_trend(recent_metrics),
 'recommendations': self._generate_quality_recommendations(recent_alerts)
 }

 def _calculate_quality_trend(self, metrics_list: List[QualityMetrics]) -> str:
 """Calculate overall quality trend"""
 if len(metrics_list) < 2:
 return 'insufficient_data'

 # Compare first half vs second half
 mid_point = len(metrics_list) // 2
 first_half_avg = statistics.mean([
 m.avg_coherence_score for m in metrics_list[:mid_point]
 ])
 second_half_avg = statistics.mean([
 m.avg_coherence_score for m in metrics_list[mid_point:]
 ])

 if second_half_avg > first_half_avg + 0.05:
 return 'improving'
 elif second_half_avg < first_half_avg - 0.05:
 return 'degrading'
 else:
 return 'stable'

 def _generate_quality_recommendations(self, alerts: List[QualityAlert]) -> List[str]:
 """Generate recommendations based on recent alerts"""
 recommendations = []

 alert_types = [alert.quality_issue for alert in alerts]

 if QualityIssue.NONSENSICAL_OUTPUT in alert_types:
 recommendations.append("Review model outputs for coherence issues")

 if QualityIssue.REPETITIVE_CONTENT in alert_types:
 recommendations.append("Implement diversity penalties in generation")

 if QualityIssue.INCONSISTENT_RESPONSES in alert_types:
 recommendations.append("Check model stability and deterministic settings")

 if QualityIssue.LOW_CONFIDENCE in alert_types:
 recommendations.append("Flag low-confidence outputs for human review")

 if QualityIssue.BIAS_DETECTED in alert_types:
 recommendations.append("Implement bias detection and mitigation techniques")

 if QualityIssue.INCOMPLETE_RESPONSES in alert_types:
 recommendations.append("Review generation parameters and length limits")

 if len(recommendations) > 3:
 recommendations.append("Consider comprehensive model evaluation and retraining")

 return recommendations

 def get_recent_alerts(self, hours_back: int = 24) -> List[QualityAlert]:
 """Get recent quality alerts"""
 cutoff_time = time.time() - (hours_back * 3600)

 return [
 alert for alert in self.alerts_history
 if alert.timestamp >= cutoff_time
 ]