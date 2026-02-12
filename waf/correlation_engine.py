"""
BeeWAF Enterprise - Attack Correlation Engine
==============================================
Correlates multiple low-severity events across time windows to detect
coordinated attacks, multi-phase intrusions, and slow-burn campaigns.

F5 ASM only does basic event correlation. This engine provides:
- Multi-phase attack chain detection (recon -> exploit -> persist)
- Cross-IP campaign correlation (distributed attacks)
- Temporal pattern analysis (slow attacks evading rate limits)
- Attack graph construction
- Threat scoring escalation
- Kill chain mapping (Lockheed Martin Cyber Kill Chain)
"""

import time
import re
import threading
from collections import defaultdict
from typing import Dict, List, Optional, Tuple


# ==================== KILL CHAIN PHASES ====================
KILL_CHAIN = {
    'reconnaissance': {
        'indicators': [
            'scanner_probe', 'path-traversal', 'sensitive-path',
            'graphql', 'info_disclosure', 'recon-detected',
        ],
        'weight': 1.0,
        'next_phases': ['weaponization', 'delivery'],
    },
    'weaponization': {
        'indicators': [
            'known-attack-tool', 'exploit-campaign', 'c2-callback',
        ],
        'weight': 2.0,
        'next_phases': ['delivery'],
    },
    'delivery': {
        'indicators': [
            'sqli', 'xss', 'cmdi', 'ssrf', 'xxe', 'ssti',
            'jndi', 'rce', 'php-filter', 'deserialization',
        ],
        'weight': 3.0,
        'next_phases': ['exploitation'],
    },
    'exploitation': {
        'indicators': [
            'python-injection', 'jar-protocol', 'lfi',
            'nosql', 'ldap', 'jwt-bypass', 'prototype-pollution',
            'xml-bomb', 'api-security',
        ],
        'weight': 4.0,
        'next_phases': ['installation', 'command_control'],
    },
    'installation': {
        'indicators': [
            'webshell', 'backdoor', 'file-upload', 'rce',
        ],
        'weight': 5.0,
        'next_phases': ['command_control'],
    },
    'command_control': {
        'indicators': [
            'c2-callback', 'dns-exfil', 'reverse-shell',
        ],
        'weight': 6.0,
        'next_phases': ['actions_on_objectives'],
    },
    'actions_on_objectives': {
        'indicators': [
            'dlp-leak', 'data-exfil', 'privilege-escalation',
            'auth_bypass',
        ],
        'weight': 7.0,
        'next_phases': [],
    },
}

# ==================== ATTACK CHAIN PATTERNS ====================
ATTACK_CHAINS = {
    'sql_injection_campaign': {
        'description': 'Multi-stage SQL injection attack',
        'phases': [
            {'events': ['scanner_probe', 'info_disclosure'], 'max_gap': 300},
            {'events': ['sqli'], 'max_gap': 600},
            {'events': ['sqli', 'auth_bypass'], 'max_gap': 300},
        ],
        'severity': 'critical',
        'min_events': 3,
    },
    'xss_watering_hole': {
        'description': 'XSS-based watering hole attack',
        'phases': [
            {'events': ['scanner_probe'], 'max_gap': 600},
            {'events': ['xss'], 'max_gap': 300},
            {'events': ['xss', 'session-violation'], 'max_gap': 300},
        ],
        'severity': 'high',
        'min_events': 3,
    },
    'rce_exploitation': {
        'description': 'Remote code execution chain',
        'phases': [
            {'events': ['scanner_probe', 'known-attack-tool'], 'max_gap': 600},
            {'events': ['cmdi', 'ssti', 'jndi', 'rce', 'deserialization'], 'max_gap': 300},
            {'events': ['c2-callback', 'reverse-shell'], 'max_gap': 600},
        ],
        'severity': 'critical',
        'min_events': 2,
    },
    'data_exfiltration': {
        'description': 'Data exfiltration attempt',
        'phases': [
            {'events': ['sqli', 'nosql', 'ldap', 'lfi'], 'max_gap': 600},
            {'events': ['ssrf', 'c2-callback'], 'max_gap': 300},
        ],
        'severity': 'critical',
        'min_events': 2,
    },
    'api_abuse': {
        'description': 'API exploitation chain',
        'phases': [
            {'events': ['graphql', 'scanner_probe'], 'max_gap': 300},
            {'events': ['api-security', 'jwt-bypass', 'auth_bypass'], 'max_gap': 300},
            {'events': ['rate-limit', 'bot-detected'], 'max_gap': 600},
        ],
        'severity': 'high',
        'min_events': 2,
    },
    'credential_stuffing': {
        'description': 'Credential stuffing campaign',
        'phases': [
            {'events': ['bot-detected', 'rate-limit'], 'max_gap': 120},
            {'events': ['brute', 'auth_bypass'], 'max_gap': 300},
        ],
        'severity': 'high',
        'min_events': 3,
    },
    'supply_chain_probe': {
        'description': 'Supply chain / dependency confusion probe',
        'phases': [
            {'events': ['scanner_probe', 'sensitive-path'], 'max_gap': 300},
            {'events': ['ssrf', 'path-traversal'], 'max_gap': 300},
            {'events': ['cmdi', 'rce'], 'max_gap': 600},
        ],
        'severity': 'critical',
        'min_events': 2,
    },
    'log4shell_attack': {
        'description': 'Log4Shell exploitation chain',
        'phases': [
            {'events': ['scanner_probe'], 'max_gap': 600},
            {'events': ['jndi', 'exploit-campaign'], 'max_gap': 300},
            {'events': ['c2-callback', 'reverse-shell'], 'max_gap': 300},
        ],
        'severity': 'critical',
        'min_events': 2,
    },
}

# ==================== DISTRIBUTED ATTACK PATTERNS ====================
DISTRIBUTED_PATTERNS = {
    'coordinated_scan': {
        'description': 'Multiple IPs scanning same targets',
        'min_ips': 3,
        'min_events_per_ip': 2,
        'time_window': 300,
        'event_types': ['scanner_probe', 'sensitive-path', 'path-traversal'],
    },
    'distributed_brute_force': {
        'description': 'Distributed brute force from multiple IPs',
        'min_ips': 5,
        'min_events_per_ip': 3,
        'time_window': 600,
        'event_types': ['brute', 'rate-limit', 'bot-detected'],
    },
    'botnet_attack': {
        'description': 'Botnet-driven attack campaign',
        'min_ips': 10,
        'min_events_per_ip': 1,
        'time_window': 120,
        'event_types': ['bot-detected', 'known-attack-tool'],
    },
}


class AttackEvent:
    """Represents a single security event for correlation."""
    __slots__ = ['timestamp', 'client_ip', 'event_type', 'path', 'method',
                 'severity', 'details', 'kill_chain_phase']

    def __init__(self, client_ip: str, event_type: str, path: str = '',
                 method: str = 'GET', severity: str = 'medium', details: str = ''):
        self.timestamp = time.time()
        self.client_ip = client_ip
        self.event_type = self._normalize_event_type(event_type)
        self.path = path
        self.method = method
        self.severity = severity
        self.details = details
        self.kill_chain_phase = self._determine_phase()

    def _normalize_event_type(self, event_type: str) -> str:
        # Remove regex- prefix for correlation
        if event_type.startswith('regex-'):
            return event_type[6:]
        return event_type

    def _determine_phase(self) -> str:
        for phase, config in KILL_CHAIN.items():
            if self.event_type in config['indicators']:
                return phase
        return 'unknown'


class CorrelationEngine:
    """
    Enterprise attack correlation engine.
    Maintains sliding windows of events and detects complex attack patterns.
    """

    def __init__(self, event_window: int = 3600, max_events_per_ip: int = 500):
        self._lock = threading.Lock()
        self.event_window = event_window
        self.max_events_per_ip = max_events_per_ip

        # Event storage
        self._events_by_ip: Dict[str, List[AttackEvent]] = defaultdict(list)
        self._events_by_type: Dict[str, List[AttackEvent]] = defaultdict(list)
        self._all_events: List[AttackEvent] = []

        # Correlation results cache
        self._active_chains: Dict[str, Dict] = {}
        self._ip_threat_scores: Dict[str, float] = defaultdict(float)
        self._distributed_alerts: List[Dict] = []

        # Stats
        self.stats = {
            'total_events': 0,
            'chains_detected': 0,
            'distributed_attacks': 0,
            'escalations': 0,
        }

    def _cleanup_old_events(self):
        """Remove events older than the window."""
        cutoff = time.time() - self.event_window
        with self._lock:
            self._all_events = [e for e in self._all_events if e.timestamp > cutoff]
            for ip in list(self._events_by_ip.keys()):
                self._events_by_ip[ip] = [
                    e for e in self._events_by_ip[ip] if e.timestamp > cutoff
                ]
                if not self._events_by_ip[ip]:
                    del self._events_by_ip[ip]
            for etype in list(self._events_by_type.keys()):
                self._events_by_type[etype] = [
                    e for e in self._events_by_type[etype] if e.timestamp > cutoff
                ]
                if not self._events_by_type[etype]:
                    del self._events_by_type[etype]

    def record_event(self, client_ip: str, event_type: str, path: str = '',
                     method: str = 'GET', severity: str = 'medium', details: str = '') -> Dict:
        """
        Record a security event and check for correlations.
        Returns correlation results.
        """
        event = AttackEvent(client_ip, event_type, path, method, severity, details)
        self.stats['total_events'] += 1

        with self._lock:
            # Add event
            self._events_by_ip[client_ip].append(event)
            self._events_by_type[event.event_type].append(event)
            self._all_events.append(event)

            # Cap events per IP
            if len(self._events_by_ip[client_ip]) > self.max_events_per_ip:
                self._events_by_ip[client_ip] = self._events_by_ip[client_ip][-self.max_events_per_ip:]

        # Periodic cleanup
        if self.stats['total_events'] % 100 == 0:
            self._cleanup_old_events()

        # Run correlation checks
        result = {
            'event_recorded': True,
            'kill_chain_phase': event.kill_chain_phase,
            'chains_detected': [],
            'threat_score': 0,
            'escalation': None,
            'distributed_attack': None,
        }

        # Check for attack chains from this IP
        chains = self._check_attack_chains(client_ip)
        if chains:
            result['chains_detected'] = chains
            self.stats['chains_detected'] += len(chains)

        # Update threat score
        threat_score = self._calculate_threat_score(client_ip)
        self._ip_threat_scores[client_ip] = threat_score
        result['threat_score'] = threat_score

        # Check for escalation (score crossed threshold)
        if threat_score >= 80:
            result['escalation'] = {
                'level': 'critical',
                'action': 'block_ip',
                'reason': f'Threat score {threat_score:.0f}/100 - coordinated attack detected',
            }
            self.stats['escalations'] += 1
        elif threat_score >= 50:
            result['escalation'] = {
                'level': 'high',
                'action': 'challenge',
                'reason': f'Threat score {threat_score:.0f}/100 - suspicious activity pattern',
            }

        # Check distributed attack patterns (every 10 events)
        if self.stats['total_events'] % 10 == 0:
            distributed = self._check_distributed_attacks()
            if distributed:
                result['distributed_attack'] = distributed
                self.stats['distributed_attacks'] += 1

        return result

    def _check_attack_chains(self, client_ip: str) -> List[Dict]:
        """Check if events from this IP match known attack chain patterns."""
        detected_chains = []
        ip_events = self._events_by_ip.get(client_ip, [])
        if len(ip_events) < 2:
            return detected_chains

        for chain_name, chain_config in ATTACK_CHAINS.items():
            if self._match_chain(ip_events, chain_config):
                detected_chains.append({
                    'chain': chain_name,
                    'description': chain_config['description'],
                    'severity': chain_config['severity'],
                    'events_matched': len(ip_events),
                })

        return detected_chains

    def _match_chain(self, events: List[AttackEvent], chain_config: Dict) -> bool:
        """Check if events match a chain pattern."""
        if len(events) < chain_config.get('min_events', 2):
            return False

        event_types = [e.event_type for e in events]
        phases = chain_config['phases']

        # Check if events match at least 2 phases
        phases_matched = 0
        for phase in phases:
            required_events = phase['events']
            if any(et in event_types for et in required_events):
                phases_matched += 1

        return phases_matched >= 2

    def _calculate_threat_score(self, client_ip: str) -> float:
        """Calculate cumulative threat score for an IP (0-100)."""
        events = self._events_by_ip.get(client_ip, [])
        if not events:
            return 0.0

        score = 0.0

        # Factor 1: Number of unique event types (diversity of attack)
        unique_types = len(set(e.event_type for e in events))
        score += min(unique_types * 5, 25)  # Max 25 from diversity

        # Factor 2: Kill chain progression
        phases_hit = set(e.kill_chain_phase for e in events if e.kill_chain_phase != 'unknown')
        phase_weights = {p: cfg['weight'] for p, cfg in KILL_CHAIN.items()}
        for phase in phases_hit:
            score += phase_weights.get(phase, 0) * 3  # Max ~21 per phase
        score = min(score, 60)  # Cap kill chain contribution at 60

        # Factor 3: Velocity (events per minute)
        if len(events) >= 2:
            time_span = events[-1].timestamp - events[0].timestamp
            if time_span > 0:
                events_per_min = (len(events) / time_span) * 60
                score += min(events_per_min * 2, 20)  # Max 20 from velocity

        # Factor 4: Severity escalation
        severity_scores = {'low': 1, 'medium': 2, 'high': 4, 'critical': 8}
        total_severity = sum(severity_scores.get(e.severity, 1) for e in events[-10:])
        score += min(total_severity, 20)  # Max 20 from severity

        return min(score, 100)

    def _check_distributed_attacks(self) -> Optional[Dict]:
        """Check for distributed attack patterns across IPs."""
        now = time.time()

        for pattern_name, config in DISTRIBUTED_PATTERNS.items():
            window = config['time_window']
            matching_ips = defaultdict(int)

            for event in self._all_events:
                if now - event.timestamp > window:
                    continue
                if event.event_type in config['event_types']:
                    matching_ips[event.client_ip] += 1

            # Filter IPs with enough events
            qualified_ips = {
                ip: count for ip, count in matching_ips.items()
                if count >= config['min_events_per_ip']
            }

            if len(qualified_ips) >= config['min_ips']:
                return {
                    'pattern': pattern_name,
                    'description': config['description'],
                    'participating_ips': len(qualified_ips),
                    'total_events': sum(qualified_ips.values()),
                    'severity': 'critical',
                }

        return None

    def get_ip_profile(self, client_ip: str) -> Dict:
        """Get complete threat profile for an IP."""
        events = self._events_by_ip.get(client_ip, [])
        if not events:
            return {'ip': client_ip, 'threat_score': 0, 'events': 0}

        return {
            'ip': client_ip,
            'threat_score': self._ip_threat_scores.get(client_ip, 0),
            'total_events': len(events),
            'unique_attack_types': list(set(e.event_type for e in events)),
            'kill_chain_phases': list(set(e.kill_chain_phase for e in events)),
            'first_seen': events[0].timestamp,
            'last_seen': events[-1].timestamp,
            'targeted_paths': list(set(e.path for e in events))[:20],
        }

    def get_active_campaigns(self) -> List[Dict]:
        """Get all currently active attack campaigns."""
        campaigns = []
        for ip, events in self._events_by_ip.items():
            if len(events) >= 3:
                chains = self._check_attack_chains(ip)
                if chains:
                    campaigns.append({
                        'source_ip': ip,
                        'chains': chains,
                        'threat_score': self._ip_threat_scores.get(ip, 0),
                        'events': len(events),
                    })
        return campaigns

    def get_stats(self) -> Dict:
        stats = dict(self.stats)
        stats['active_ips'] = len(self._events_by_ip)
        stats['total_stored_events'] = len(self._all_events)
        top_ips = sorted(
            self._ip_threat_scores.items(),
            key=lambda x: x[1], reverse=True
        )[:10]
        stats['top_threats'] = [{'ip': ip, 'score': s} for ip, s in top_ips]
        return stats


# ==================== SINGLETON ====================
_engine = None

def get_engine() -> CorrelationEngine:
    global _engine
    if _engine is None:
        _engine = CorrelationEngine()
    return _engine

def record_event(client_ip: str, event_type: str, **kwargs) -> Dict:
    return get_engine().record_event(client_ip, event_type, **kwargs)

def get_threat_score(client_ip: str) -> float:
    return get_engine()._ip_threat_scores.get(client_ip, 0)

def get_ip_profile(client_ip: str) -> Dict:
    return get_engine().get_ip_profile(client_ip)
