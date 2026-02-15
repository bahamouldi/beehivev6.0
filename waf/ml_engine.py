"""
BeeWAF Advanced ML Engine
=========================
Inspired by Cloudflare's WAF ML system with multiple models:

1. IsolationForest - Unsupervised anomaly detection
2. RandomForestClassifier - Supervised attack classification (WAF Attack Score)
3. GradientBoostingClassifier - Attack probability scoring (similar to Bot Score)

The ensemble uses weighted voting for final decision.
"""

import os
import csv
import json
import pickle
import re
import math
import logging
from typing import List, Dict, Any, Tuple, Optional
from urllib.parse import unquote, urlparse, parse_qs
from collections import Counter

import numpy as np

try:
    from sklearn.ensemble import (
        IsolationForest,
        RandomForestClassifier,
        GradientBoostingClassifier,
        VotingClassifier
    )
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import (
        classification_report,
        confusion_matrix,
        accuracy_score,
        precision_score,
        recall_score,
        f1_score,
        roc_auc_score
    )
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

try:
    import joblib
except ImportError:
    joblib = None

log = logging.getLogger("beewaf.ml_engine")

# ==================== FEATURE EXTRACTION ====================

# Attack pattern keywords for feature extraction
SQL_KEYWORDS = [
    'select', 'union', 'insert', 'update', 'delete', 'drop', 'where',
    'from', 'table', 'database', 'exec', 'execute', 'xp_', 'sp_',
    'waitfor', 'delay', 'benchmark', 'sleep', 'having', 'group by',
    'order by', 'null', 'and', 'or', 'like', 'in', 'between'
]

XSS_KEYWORDS = [
    'script', 'javascript', 'onerror', 'onload', 'onclick', 'onmouseover',
    'alert', 'confirm', 'prompt', 'eval', 'document', 'cookie', 'window',
    'location', 'innerhtml', 'outerhtml', 'fromcharcode', 'string.fromcharcode'
]

CMD_KEYWORDS = [
    'cat', 'ls', 'dir', 'whoami', 'id', 'pwd', 'wget', 'curl', 'nc',
    'bash', 'sh', 'cmd', 'powershell', 'ping', 'nslookup', 'chmod',
    'chown', 'rm', 'mv', 'cp', 'echo', 'printf', 'system', 'exec'
]

PATH_KEYWORDS = [
    '..', 'etc/passwd', 'etc/shadow', 'windows/system32', 'boot.ini',
    'proc/self', 'var/log', 'tmp/', 'dev/null'
]

SSRF_KEYWORDS = [
    'localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254', 'metadata',
    '10.0.0', '192.168.', '172.16.', 'file://', 'gopher://', 'dict://'
]

# Special characters weights
DANGEROUS_CHARS = {
    "'": 3, '"': 2, '<': 3, '>': 3, '&': 1, '|': 2, ';': 3,
    '`': 3, '$': 2, '(': 2, ')': 2, '{': 2, '}': 2, '[': 1,
    ']': 1, '\\': 2, '/': 1, '%': 1, '#': 2, '!': 1, '=': 1,
    '\x00': 5, '\n': 2, '\r': 2, '\t': 1
}


class FeatureExtractor:
    """
    Advanced feature extraction for HTTP requests.
    Extracts 35+ features for ML models.
    """
    
    def __init__(self):
        self.feature_names = [
            # Length features (6)
            'url_length', 'path_length', 'query_length', 'body_length',
            'header_count', 'cookie_length',
            # Character distribution features (8)
            'special_char_count', 'special_char_ratio', 'dangerous_char_score',
            'uppercase_ratio', 'digit_ratio', 'non_ascii_count',
            'max_char_repeat', 'entropy',
            # Keyword features (5)
            'sql_keyword_count', 'xss_keyword_count', 'cmd_keyword_count',
            'path_traversal_count', 'ssrf_keyword_count',
            # Encoding features (4)
            'url_encoding_count', 'double_encoding_count',
            'hex_encoding_count', 'unicode_encoding_count',
            # Structural features (7)
            'param_count', 'nested_bracket_depth', 'comment_patterns',
            'null_byte_count', 'whitespace_anomaly', 'method_encoded',
            'suspicious_extension',
            # NEW: Context features (5)
            'has_valid_tld', 'path_depth', 'query_key_anomaly',
            'body_is_json', 'mixed_case_keywords'
        ]
    
    def extract_features(self, url: str, body: str, headers: Dict[str, str], 
                        method: str = 'GET') -> np.ndarray:
        """Extract all features from a request."""
        # Combine all input for analysis
        full_text = f"{url} {body}"
        decoded_text = self._safe_decode(full_text)
        
        features = []
        
        # === Length features ===
        parsed_url = urlparse(url) if url else urlparse('')
        features.append(len(url) if url else 0)  # url_length
        features.append(len(parsed_url.path))  # path_length
        features.append(len(parsed_url.query))  # query_length
        features.append(len(body) if body else 0)  # body_length
        features.append(len(headers) if headers else 0)  # header_count
        features.append(len(headers.get('cookie', '') if headers else ''))  # cookie_length
        
        # === Character distribution features ===
        features.append(self._count_special_chars(decoded_text))  # special_char_count
        features.append(self._special_char_ratio(decoded_text))  # special_char_ratio
        features.append(self._dangerous_char_score(decoded_text))  # dangerous_char_score
        features.append(self._uppercase_ratio(decoded_text))  # uppercase_ratio
        features.append(self._digit_ratio(decoded_text))  # digit_ratio
        features.append(self._count_non_ascii(decoded_text))  # non_ascii_count
        features.append(self._max_char_repeat(decoded_text))  # max_char_repeat
        features.append(self._calculate_entropy(decoded_text))  # entropy
        
        # === Keyword features ===
        lower_text = decoded_text.lower()
        features.append(self._count_keywords(lower_text, SQL_KEYWORDS))  # sql_keyword_count
        features.append(self._count_keywords(lower_text, XSS_KEYWORDS))  # xss_keyword_count
        features.append(self._count_keywords(lower_text, CMD_KEYWORDS))  # cmd_keyword_count
        features.append(self._count_keywords(lower_text, PATH_KEYWORDS))  # path_traversal_count
        features.append(self._count_keywords(lower_text, SSRF_KEYWORDS))  # ssrf_keyword_count
        
        # === Encoding features ===
        features.append(self._count_url_encoding(full_text))  # url_encoding_count
        features.append(self._count_double_encoding(full_text))  # double_encoding_count
        features.append(self._count_hex_encoding(full_text))  # hex_encoding_count
        features.append(self._count_unicode_encoding(full_text))  # unicode_encoding_count
        
        # === Structural features ===
        features.append(self._count_params(url, body))  # param_count
        features.append(self._nested_bracket_depth(decoded_text))  # nested_bracket_depth
        features.append(self._count_comment_patterns(decoded_text))  # comment_patterns
        features.append(decoded_text.count('\x00'))  # null_byte_count
        features.append(self._whitespace_anomaly(decoded_text))  # whitespace_anomaly
        features.append(1 if '%' in method else 0)  # method_encoded
        features.append(self._suspicious_extension(url))  # suspicious_extension
        
        # === NEW: Context features ===
        features.append(self._has_valid_tld(url))  # has_valid_tld
        features.append(self._path_depth(url))  # path_depth
        features.append(self._query_key_anomaly(url))  # query_key_anomaly
        features.append(self._body_is_json(body))  # body_is_json
        features.append(self._mixed_case_keywords(decoded_text))  # mixed_case_keywords
        
        return np.array(features, dtype=np.float32)
    
    def _safe_decode(self, text: str) -> str:
        """Safely decode URL-encoded text."""
        if not text:
            return ''
        try:
            # Try double decoding to catch double-encoded attacks
            decoded = unquote(unquote(text))
            return decoded
        except Exception:
            return text
    
    def _count_special_chars(self, text: str) -> int:
        """Count special characters."""
        return sum(1 for c in text if not c.isalnum() and not c.isspace())
    
    def _special_char_ratio(self, text: str) -> float:
        """Calculate ratio of special characters."""
        if not text:
            return 0.0
        special = sum(1 for c in text if not c.isalnum() and not c.isspace())
        return special / len(text)
    
    def _dangerous_char_score(self, text: str) -> float:
        """Calculate weighted score for dangerous characters."""
        return sum(DANGEROUS_CHARS.get(c, 0) for c in text)
    
    def _uppercase_ratio(self, text: str) -> float:
        """Calculate ratio of uppercase characters."""
        if not text:
            return 0.0
        alpha = sum(1 for c in text if c.isalpha())
        if alpha == 0:
            return 0.0
        upper = sum(1 for c in text if c.isupper())
        return upper / alpha
    
    def _digit_ratio(self, text: str) -> float:
        """Calculate ratio of digits."""
        if not text:
            return 0.0
        return sum(1 for c in text if c.isdigit()) / len(text)
    
    def _count_non_ascii(self, text: str) -> int:
        """Count non-ASCII characters."""
        return sum(1 for c in text if ord(c) > 127)
    
    def _max_char_repeat(self, text: str) -> int:
        """Find maximum consecutive character repetition."""
        if not text:
            return 0
        max_repeat = 1
        current = 1
        for i in range(1, len(text)):
            if text[i] == text[i-1]:
                current += 1
                max_repeat = max(max_repeat, current)
            else:
                current = 1
        return max_repeat
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of the text."""
        if not text:
            return 0.0
        counter = Counter(text)
        length = len(text)
        entropy = 0.0
        for count in counter.values():
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy
    
    def _count_keywords(self, text: str, keywords: List[str]) -> int:
        """Count keyword occurrences."""
        return sum(text.count(kw) for kw in keywords)
    
    def _count_url_encoding(self, text: str) -> int:
        """Count URL-encoded sequences."""
        return len(re.findall(r'%[0-9a-fA-F]{2}', text))
    
    def _count_double_encoding(self, text: str) -> int:
        """Count double-encoded sequences."""
        return len(re.findall(r'%25[0-9a-fA-F]{2}', text))
    
    def _count_hex_encoding(self, text: str) -> int:
        """Count hex-encoded sequences (0x...)."""
        return len(re.findall(r'0x[0-9a-fA-F]+', text))
    
    def _count_unicode_encoding(self, text: str) -> int:
        """Count unicode escape sequences."""
        return len(re.findall(r'\\u[0-9a-fA-F]{4}|&#x?[0-9a-fA-F]+;?', text))
    
    def _count_params(self, url: str, body: str) -> int:
        """Count total parameters."""
        count = 0
        if url:
            parsed = urlparse(url)
            count += len(parse_qs(parsed.query))
        if body:
            # Count & separated params
            count += body.count('&') + 1 if '=' in body else 0
        return count
    
    def _nested_bracket_depth(self, text: str) -> int:
        """Calculate maximum nested bracket depth."""
        max_depth = 0
        depth = 0
        for c in text:
            if c in '([{<':
                depth += 1
                max_depth = max(max_depth, depth)
            elif c in ')]}>':
                depth = max(0, depth - 1)
        return max_depth
    
    def _count_comment_patterns(self, text: str) -> int:
        """Count SQL/code comment patterns."""
        patterns = ['--', '/*', '*/', '#', '//', '<!--', '-->']
        return sum(text.count(p) for p in patterns)
    
    def _whitespace_anomaly(self, text: str) -> int:
        """Detect unusual whitespace patterns."""
        anomalies = 0
        # Multiple consecutive spaces
        anomalies += len(re.findall(r' {3,}', text))
        # Tab characters in URL/params
        anomalies += text.count('\t')
        # Newlines in unexpected places
        anomalies += text.count('\n') + text.count('\r')
        return anomalies
    
    def _suspicious_extension(self, url: str) -> int:
        """Check for suspicious file extensions."""
        if not url:
            return 0
        suspicious = ['.php', '.asp', '.aspx', '.jsp', '.cgi', '.pl', '.py',
                     '.sh', '.bash', '.exe', '.dll', '.bat', '.cmd', '.ps1',
                     '.bak', '.old', '.tmp', '.swp', '.config', '.env']
        url_lower = url.lower()
        return sum(1 for ext in suspicious if ext in url_lower)
    
    def _has_valid_tld(self, url: str) -> int:
        """Check if URL has a valid-looking TLD (indicates normal request)."""
        if not url:
            return 0
        valid_tlds = ['.com', '.org', '.net', '.edu', '.gov', '.io', '.co',
                     '.html', '.htm', '.jsp', '.php', '.asp', '.aspx']
        url_lower = url.lower()
        return 1 if any(tld in url_lower for tld in valid_tlds) else 0
    
    def _path_depth(self, url: str) -> int:
        """Count path depth (number of / in path)."""
        if not url:
            return 0
        parsed = urlparse(url)
        return parsed.path.count('/')
    
    def _query_key_anomaly(self, url: str) -> int:
        """Check for anomalous query parameter names."""
        if not url:
            return 0
        parsed = urlparse(url)
        query = parsed.query
        # Count params with very short or suspicious names
        anomalies = 0
        params = parse_qs(query)
        for key in params:
            if len(key) == 1 and key not in ['q', 'p', 'n', 's', 't', 'v', 'r']:
                anomalies += 1
            if any(c in key for c in "'\"<>;"):
                anomalies += 2
        return anomalies
    
    def _body_is_json(self, body: str) -> int:
        """Check if body looks like valid JSON (indicates normal API request)."""
        if not body:
            return 0
        body = body.strip()
        if (body.startswith('{') and body.endswith('}')) or \
           (body.startswith('[') and body.endswith(']')):
            try:
                json.loads(body)
                return 1
            except:
                return 0
        return 0
    
    def _mixed_case_keywords(self, text: str) -> int:
        """Count SQL/XSS keywords with mixed case (evasion attempt)."""
        if not text:
            return 0
        keywords = ['select', 'union', 'script', 'alert', 'onerror', 'onload']
        count = 0
        for kw in keywords:
            # Find keyword ignoring case
            idx = text.lower().find(kw)
            if idx != -1:
                # Check if it has mixed case in original
                found = text[idx:idx+len(kw)]
                if found != kw and found != kw.upper():
                    count += 1
        return count


# ==================== ML MODELS ====================

class BeeWAFMLEngine:
    """
    Advanced ML Engine with multiple models for attack detection.
    Similar to Cloudflare's approach with ensemble learning.
    """
    
    def __init__(self):
        self.feature_extractor = FeatureExtractor()
        self.scaler = StandardScaler() if SKLEARN_AVAILABLE else None
        
        # Model 1: Isolation Forest (Unsupervised Anomaly Detection)
        self.isolation_forest = None
        
        # Model 2: Random Forest (Supervised Classification - WAF Attack Score)
        self.random_forest = None
        
        # Model 3: Gradient Boosting (Probability Scoring - similar to Bot Score)
        self.gradient_boosting = None
        
        # Ensemble weights (tunable) - prioritize supervised models
        self.weights = {
            'isolation_forest': 0.1,  # Lower weight - less reliable
            'random_forest': 0.45,     # High weight - best for classification
            'gradient_boosting': 0.45  # High weight - best for scoring
        }
        
        # Thresholds - higher threshold = less false positives
        self.attack_threshold = 0.6  # Increased from 0.5 for fewer false positives
        
        # Training stats
        self.is_trained = False
        self.training_stats = {}
    
    def train(self, X: np.ndarray, y: np.ndarray, 
              test_size: float = 0.2) -> Dict[str, Any]:
        """
        Train all models on labeled data.
        
        Args:
            X: Feature matrix
            y: Labels (0=normal, 1=attack)
            test_size: Fraction for test set
            
        Returns:
            Training statistics and metrics
        """
        if not SKLEARN_AVAILABLE:
            return {'ok': False, 'error': 'sklearn not available'}
        
        log.info(f"Training ML models on {len(X)} samples...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        results = {}
        
        # Train Model 1: Isolation Forest
        log.info("Training Isolation Forest...")
        self.isolation_forest = IsolationForest(
            n_estimators=200,
            contamination=float(np.mean(y)),  # Based on actual attack ratio
            max_samples='auto',
            max_features=1.0,
            bootstrap=False,
            random_state=42,
            n_jobs=-1
        )
        self.isolation_forest.fit(X_train_scaled)
        
        # Evaluate IF
        if_pred = self.isolation_forest.predict(X_test_scaled)
        if_pred_binary = np.where(if_pred == -1, 1, 0)  # -1 is anomaly
        results['isolation_forest'] = {
            'accuracy': accuracy_score(y_test, if_pred_binary),
            'precision': precision_score(y_test, if_pred_binary, zero_division=0),
            'recall': recall_score(y_test, if_pred_binary, zero_division=0),
            'f1': f1_score(y_test, if_pred_binary, zero_division=0)
        }
        
        # Train Model 2: Random Forest
        log.info("Training Random Forest Classifier...")
        self.random_forest = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            max_features='sqrt',
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        )
        self.random_forest.fit(X_train_scaled, y_train)
        
        # Evaluate RF
        rf_pred = self.random_forest.predict(X_test_scaled)
        rf_proba = self.random_forest.predict_proba(X_test_scaled)[:, 1]
        results['random_forest'] = {
            'accuracy': accuracy_score(y_test, rf_pred),
            'precision': precision_score(y_test, rf_pred, zero_division=0),
            'recall': recall_score(y_test, rf_pred, zero_division=0),
            'f1': f1_score(y_test, rf_pred, zero_division=0),
            'roc_auc': roc_auc_score(y_test, rf_proba)
        }
        
        # Train Model 3: Gradient Boosting
        log.info("Training Gradient Boosting Classifier...")
        self.gradient_boosting = GradientBoostingClassifier(
            n_estimators=150,
            max_depth=8,
            learning_rate=0.1,
            min_samples_split=5,
            min_samples_leaf=2,
            subsample=0.8,
            random_state=42
        )
        self.gradient_boosting.fit(X_train_scaled, y_train)
        
        # Evaluate GB
        gb_pred = self.gradient_boosting.predict(X_test_scaled)
        gb_proba = self.gradient_boosting.predict_proba(X_test_scaled)[:, 1]
        results['gradient_boosting'] = {
            'accuracy': accuracy_score(y_test, gb_pred),
            'precision': precision_score(y_test, gb_pred, zero_division=0),
            'recall': recall_score(y_test, gb_pred, zero_division=0),
            'f1': f1_score(y_test, gb_pred, zero_division=0),
            'roc_auc': roc_auc_score(y_test, gb_proba)
        }
        
        # Ensemble evaluation
        ensemble_proba = self._ensemble_predict_proba(X_test_scaled)
        ensemble_pred = (ensemble_proba >= self.attack_threshold).astype(int)
        results['ensemble'] = {
            'accuracy': accuracy_score(y_test, ensemble_pred),
            'precision': precision_score(y_test, ensemble_pred, zero_division=0),
            'recall': recall_score(y_test, ensemble_pred, zero_division=0),
            'f1': f1_score(y_test, ensemble_pred, zero_division=0),
            'roc_auc': roc_auc_score(y_test, ensemble_proba)
        }
        
        # Feature importance from Random Forest
        feature_importance = dict(zip(
            self.feature_extractor.feature_names,
            self.random_forest.feature_importances_
        ))
        top_features = sorted(
            feature_importance.items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:10]
        
        self.is_trained = True
        self.training_stats = {
            'ok': True,
            'samples_total': len(X),
            'samples_train': len(X_train),
            'samples_test': len(X_test),
            'attack_ratio': float(np.mean(y)),
            'models': results,
            'top_features': top_features,
            'confusion_matrix': confusion_matrix(y_test, ensemble_pred).tolist()
        }
        
        log.info(f"Training complete. Ensemble F1: {results['ensemble']['f1']:.4f}")
        
        return self.training_stats
    
    def _ensemble_predict_proba(self, X_scaled: np.ndarray) -> np.ndarray:
        """Get weighted ensemble probability."""
        proba = np.zeros(len(X_scaled))
        
        # Isolation Forest contribution
        if self.isolation_forest is not None:
            if_scores = -self.isolation_forest.decision_function(X_scaled)
            if_proba = (if_scores - if_scores.min()) / (if_scores.max() - if_scores.min() + 1e-10)
            proba += self.weights['isolation_forest'] * if_proba
        
        # Random Forest contribution
        if self.random_forest is not None:
            rf_proba = self.random_forest.predict_proba(X_scaled)[:, 1]
            proba += self.weights['random_forest'] * rf_proba
        
        # Gradient Boosting contribution
        if self.gradient_boosting is not None:
            gb_proba = self.gradient_boosting.predict_proba(X_scaled)[:, 1]
            proba += self.weights['gradient_boosting'] * gb_proba
        
        return proba
    
    def predict(self, url: str, body: str, headers: Dict[str, str],
                method: str = 'GET') -> Dict[str, Any]:
        """
        Predict if a request is an attack.
        
        Returns:
            Dict with:
            - is_attack: bool
            - attack_score: float (0-1 probability)
            - model_scores: individual model scores
            - attack_type: predicted attack type (if available)
        """
        if not self.is_trained:
            return {
                'is_attack': False,
                'attack_score': 0.0,
                'model_scores': {},
                'reason': 'model_not_trained'
            }
        
        # Quick check for obviously safe requests (reduces false positives)
        if self._is_obviously_safe(url, body, method):
            return {
                'is_attack': False,
                'attack_score': 0.0,
                'model_scores': {'quick_check': 'safe'},
                'attack_type': None
            }
        
        # Extract features
        features = self.feature_extractor.extract_features(url, body, headers, method)
        features_scaled = self.scaler.transform([features])
        
        # Get individual model scores
        model_scores = {}
        
        # Isolation Forest
        if_score = -self.isolation_forest.decision_function(features_scaled)[0]
        if_normalized = (if_score + 0.5) / 1.0  # Normalize roughly to 0-1
        if_normalized = max(0, min(1, if_normalized))
        model_scores['isolation_forest'] = float(if_normalized)
        
        # Random Forest
        rf_proba = self.random_forest.predict_proba(features_scaled)[0][1]
        model_scores['random_forest'] = float(rf_proba)
        
        # Gradient Boosting
        gb_proba = self.gradient_boosting.predict_proba(features_scaled)[0][1]
        model_scores['gradient_boosting'] = float(gb_proba)
        
        # Ensemble score
        attack_score = self._ensemble_predict_proba(features_scaled)[0]
        attack_score = max(0, min(1, attack_score))  # Clamp to 0-1
        
        # Determine attack type based on features
        attack_type = self._determine_attack_type(features)
        
        return {
            'is_attack': attack_score >= self.attack_threshold,
            'attack_score': float(attack_score),
            'model_scores': model_scores,
            'attack_type': attack_type if attack_score >= self.attack_threshold else None
        }
    
    def _is_obviously_safe(self, url: str, body: str, method: str) -> bool:
        """
        Quick check to identify obviously safe requests.
        This helps reduce false positives on simple, normal requests.
        """
        # Check body for valid JSON FIRST (API requests are usually safe)
        # JSON uses " which would otherwise be flagged as dangerous
        if body:
            body_stripped = body.strip()
            if body_stripped.startswith('{') and body_stripped.endswith('}'):
                try:
                    parsed = json.loads(body_stripped)
                    # Valid JSON - check it doesn't contain attack patterns in values
                    json_str = json.dumps(parsed).lower()
                    attack_keywords = ['script', 'alert', 'onerror', 'union', 'select', 
                                      '../', '/etc/', 'exec', 'cmd', 'drop', 'insert']
                    if not any(kw in json_str for kw in attack_keywords):
                        return True
                except:
                    pass
            elif body_stripped.startswith('[') and body_stripped.endswith(']'):
                try:
                    parsed = json.loads(body_stripped)
                    json_str = json.dumps(parsed).lower()
                    attack_keywords = ['script', 'alert', 'onerror', 'union', 'select', 
                                      '../', '/etc/', 'exec', 'cmd', 'drop', 'insert']
                    if not any(kw in json_str for kw in attack_keywords):
                        return True
                except:
                    pass
        
        # Check form-urlencoded body — standard form submissions
        if body:
            import urllib.parse as _up
            body_stripped = body.strip()
            # Form-encoded: key=value&key2=value2 (no angle brackets, backticks, etc.)
            if '=' in body_stripped and not any(c in body_stripped for c in '<>`|;'):
                try:
                    params = _up.parse_qs(body_stripped, keep_blank_values=True)
                    if params:  # Successfully parsed as form data
                        all_values = ' '.join(v for vals in params.values() for v in vals)
                        form_attacks = ['<script', 'alert(', 'onerror', 'union select',
                                       '../', '/etc/', 'exec(', '; cat', '| cat',
                                       'drop table', 'insert into']
                        if not any(kw in all_values.lower() for kw in form_attacks):
                            return True
                except:
                    pass
        
        # URL-decode combined for accurate dangerous pattern check
        import urllib.parse
        combined_raw = (url + ' ' + body).lower()
        combined = urllib.parse.unquote(combined_raw).lower()
        
        # Dangerous characters/patterns that should always be analyzed
        # Note: & is excluded because it's used in form-urlencoded data
        # Note: " is excluded because it's checked in JSON handling above
        dangerous_patterns = [
            '<', '>', ';', '|', '$(', '${', '`', '\\',
            '--', '/*', '*/', '%00', '%0a', '%0d', '%0D', '%0A',
            'onerror', 'onload', 'onclick', 'oninput', 'onfocus',
            'xp_', 'sp_', 'bash', 'powershell',
            '../', '..\\', '/etc/', '/proc/', '/var/', 'c:\\', 'windows\\system32',
            'javascript:', 'data:', 'vbscript:', 'file://',
            'waitfor', 'benchmark', 'sleep(', 'pg_sleep'
        ]
        
        # Words that must be checked with word boundaries AND attack context to avoid FPs
        # e.g., "script writing course" is safe, "<script>" is not
        # e.g., "alert system monitoring" is safe, "alert(1)" is not
        import re as _re
        dangerous_words = ['script', 'alert', 'iframe', 'object', 'embed', 'svg', 'onmouseover']
        dangerous_word_contexts = {
            'script': [r'<\s*script', r'script\s*>', r'script\s*\(', r'/script'],
            'alert': [r'alert\s*\(', r'alert\s*`', r'<[^>]*alert'],
        }
        for word, contexts in dangerous_word_contexts.items():
            if word in combined and _re.search(r'\b' + word + r'\b', combined):
                # Word found — only flag if attack context present
                for ctx_pat in contexts:
                    if _re.search(ctx_pat, combined):
                        return False
                # No attack context → word is used naturally, continue checking
        
        # SQL keywords only dangerous if combined with SQL syntax context
        sql_context_patterns = [
            ('select', [' from ', ' * ', '@@', ' top ', ' distinct ', ' all ']),
            ('union', [' select', ' all ']),
            ('insert', [' into ']),
            ('update', [' set ']),
            ('delete', [' from ']),
            ('drop', [' table', ' database', ' column', ' index', ' view', ' schema']),
            ('exec', ['(', 'ute ']),
            ('cmd', ['.exe', '/c ', ' /c', ' &&', ' ||', 'shell']),
            ('truncate', [' table']),
        ]
        
        # If any dangerous pattern found, analyze with ML
        for pattern in dangerous_patterns:
            if pattern in combined:
                return False
        
        # Check dangerous words with word boundaries (avoid FPs like "description" → "script")
        for word in dangerous_words:
            if word in combined and _re.search(r'\b' + word + r'\b', combined):
                return False
        
        # Check SQL keywords — only flag if SQL syntax context present
        for keyword, contexts in sql_context_patterns:
            if keyword in combined:
                for ctx in contexts:
                    if ctx in combined:
                        return False
        
        # Check for single quotes in attack context (not just apostrophes)
        if "'" in combined:
            # Apostrophes in SQL context: ' OR, ' AND, '=', '; --, '1'='1
            import re
            if re.search(r"'(?:\s*(?:or|and|=|;|--|union|select|\d+\s*=))", combined):
                return False
        
        # Safe extensions for static resources
        safe_extensions = ['.html', '.htm', '.css', '.js', '.png', '.jpg', 
                         '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2',
                         '.ttf', '.eot', '.map']
        
        url_lower = url.lower()
        for ext in safe_extensions:
            if url_lower.endswith(ext):
                return True
        
        # Simple paths without query params or with simple params
        if '?' not in url:
            # No query string - likely safe if path is simple
            if len(url) < 150 and url.count('/') <= 8:
                return True
        else:
            # Has query string - check if params look safe
            query = url.split('?', 1)[1] if '?' in url else ''
            # Simple alphanumeric params are safe (include % for URL encoding)
            # Include , (field lists) and : (titles, time values) - dangerous uses like
            # javascript: and data: are already caught by dangerous_patterns above
            # Include # (C# searches), () for natural language, [] for arrays
            # International chars (> 127) are safe — Arabic, Chinese, etc.
            if all(c.isalnum() or c in '=&_-+.%,:#()[]@!~' or ord(c) > 127 for c in query):
                if len(query) < 200:
                    return True
            # URL-decode and re-check — encoded +, =, &, ', % are normal
            query_decoded = urllib.parse.unquote_plus(query)
            safe_decoded = all(c.isalnum() or c in "=&_-+.%,:#()[]@!~ '" or ord(c) > 127 for c in query_decoded)
            if safe_decoded and len(query_decoded) < 300:
                # Even with apostrophes, if no SQL context → safe
                if "'" not in query_decoded:
                    return True
                # Has apostrophe — safe only if it looks like a name (O'Reilly, McDonald's)
                # Parse query values to check apostrophes in param values, not raw string
                parsed_params = urllib.parse.parse_qs(query, keep_blank_values=True)
                all_values_text = ' '.join(v for vals in parsed_params.values() for v in vals)
                words_with_apos = [w for w in all_values_text.split() if "'" in w]
                all_name_like = all(
                    len(w) < 20 and w.replace("'", "").isalpha() 
                    for w in words_with_apos
                )
                if all_name_like:
                    return True
        
        return False
    
    def _determine_attack_type(self, features: np.ndarray) -> str:
        """Determine likely attack type based on feature values."""
        # Feature indices based on FeatureExtractor
        sql_idx = 14  # sql_keyword_count
        xss_idx = 15  # xss_keyword_count
        cmd_idx = 16  # cmd_keyword_count
        path_idx = 17  # path_traversal_count
        ssrf_idx = 18  # ssrf_keyword_count
        
        scores = {
            'sqli': features[sql_idx],
            'xss': features[xss_idx],
            'cmdi': features[cmd_idx],
            'path_traversal': features[path_idx],
            'ssrf': features[ssrf_idx]
        }
        
        max_type = max(scores, key=scores.get)
        if scores[max_type] > 0:
            return max_type
        
        # Check other indicators
        if features[6] > 20:  # High special char count
            return 'injection'
        if features[8] > 50:  # High dangerous char score
            return 'suspicious'
        
        return 'anomaly'
    
    def save(self, path: str) -> bool:
        """Save all models to disk."""
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            data = {
                'scaler': self.scaler,
                'isolation_forest': self.isolation_forest,
                'random_forest': self.random_forest,
                'gradient_boosting': self.gradient_boosting,
                'weights': self.weights,
                'attack_threshold': self.attack_threshold,
                'is_trained': self.is_trained,
                'training_stats': self.training_stats
            }
            if joblib is not None:
                joblib.dump(data, path)
            else:
                with open(path, 'wb') as f:
                    pickle.dump(data, f)
            log.info(f"Models saved to {path}")
            return True
        except Exception as e:
            log.error(f"Failed to save models: {e}")
            return False
    
    def load(self, path: str) -> bool:
        """Load all models from disk."""
        if not os.path.exists(path):
            return False
        try:
            if joblib is not None:
                data = joblib.load(path)
            else:
                with open(path, 'rb') as f:
                    data = pickle.load(f)
            
            self.scaler = data.get('scaler')
            self.isolation_forest = data.get('isolation_forest')
            self.random_forest = data.get('random_forest')
            self.gradient_boosting = data.get('gradient_boosting')
            self.weights = data.get('weights', self.weights)
            self.attack_threshold = data.get('attack_threshold', 0.6)
            self.is_trained = data.get('is_trained', False)
            self.training_stats = data.get('training_stats', {})
            
            log.info(f"Models loaded from {path}")
            return True
        except Exception as e:
            log.error(f"Failed to load models: {e}")
            return False


# ==================== DATA LOADERS ====================

class CSICDataLoader:
    """Load and parse CSIC 2010 dataset."""
    
    def __init__(self, feature_extractor: FeatureExtractor):
        self.feature_extractor = feature_extractor
    
    def load(self, csv_path: str) -> Tuple[np.ndarray, np.ndarray]:
        """
        Load CSIC dataset and extract features.
        
        Returns:
            X: Feature matrix
            y: Labels (0=normal, 1=attack)
        """
        X = []
        y = []
        
        with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                try:
                    # Get classification (first column might be unnamed)
                    classification = row.get('', row.get('classification', '')).strip()
                    if not classification:
                        # Try first column
                        first_key = list(row.keys())[0]
                        classification = row[first_key].strip()
                    
                    # Determine label
                    if 'normal' in classification.lower():
                        label = 0
                    elif 'anomalous' in classification.lower():
                        label = 1
                    else:
                        continue  # Skip unknown
                    
                    # Extract URL
                    url = row.get('URL', '')
                    
                    # Extract body/content
                    body = row.get('content', '')
                    
                    # Extract method
                    method = row.get('Method', 'GET')
                    
                    # Build headers dict
                    headers = {}
                    for key in ['User-Agent', 'Accept', 'Accept-encoding', 
                               'Accept-charset', 'cookie', 'content-type']:
                        if key in row and row[key]:
                            headers[key.lower()] = row[key]
                    
                    # Extract features
                    features = self.feature_extractor.extract_features(
                        url, body, headers, method
                    )
                    
                    X.append(features)
                    y.append(label)
                    
                except Exception as e:
                    continue  # Skip problematic rows
        
        return np.array(X), np.array(y)


# ==================== GLOBAL INSTANCE ====================

_global_engine = BeeWAFMLEngine()


def get_engine() -> BeeWAFMLEngine:
    """Get the global ML engine instance."""
    return _global_engine


def train_from_csic(csv_path: str, save_path: str = None) -> Dict[str, Any]:
    """
    Train the ML engine from CSIC dataset.
    
    Args:
        csv_path: Path to CSIC CSV file
        save_path: Path to save trained models
        
    Returns:
        Training statistics
    """
    engine = get_engine()
    loader = CSICDataLoader(engine.feature_extractor)
    
    log.info(f"Loading CSIC data from {csv_path}...")
    X, y = loader.load(csv_path)
    
    if len(X) == 0:
        return {'ok': False, 'error': 'No data loaded'}
    
    log.info(f"Loaded {len(X)} samples ({np.sum(y)} attacks, {len(y) - np.sum(y)} normal)")
    
    # Train
    stats = engine.train(X, y)
    
    # Save if path provided
    if save_path and stats.get('ok'):
        engine.save(save_path)
    
    return stats


def load_engine(path: str) -> bool:
    """Load the ML engine from disk."""
    return _global_engine.load(path)


def predict_request(url: str, body: str, headers: Dict[str, str],
                   method: str = 'GET') -> Dict[str, Any]:
    """
    Predict if a request is an attack using the global engine.
    
    Returns prediction dict with:
    - is_attack: bool
    - attack_score: float (0-1)
    - model_scores: dict of individual model scores
    - attack_type: predicted attack type
    """
    return _global_engine.predict(url, body, headers, method)


def is_attack(url: str, body: str, headers: Dict[str, str]) -> bool:
    """Simple interface for WAF middleware - returns True if attack detected."""
    result = predict_request(url, body, headers)
    return result.get('is_attack', False)


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='BeeWAF ML Engine')
    parser.add_argument('--train', help='Path to CSIC CSV file for training')
    parser.add_argument('--save', help='Path to save trained models', 
                       default='models/ml_engine.pkl')
    parser.add_argument('--load', help='Path to load trained models')
    parser.add_argument('--test', help='Test URL to predict')
    
    args = parser.parse_args()
    
    logging.basicConfig(level=logging.INFO)
    
    if args.train:
        stats = train_from_csic(args.train, args.save)
        print(json.dumps(stats, indent=2, default=str))
    
    elif args.load:
        if load_engine(args.load):
            print("Models loaded successfully")
            if args.test:
                result = predict_request(args.test, '', {})
                print(json.dumps(result, indent=2))
        else:
            print("Failed to load models")
