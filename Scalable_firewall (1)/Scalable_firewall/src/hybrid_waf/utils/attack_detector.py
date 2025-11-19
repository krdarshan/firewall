import time
from collections import defaultdict, deque
from datetime import datetime, timedelta

# In-memory store for tracking attacker behavior
ATTACKER_PROFILES = defaultdict(lambda: {
    'request_count': 0,
    'requests': deque(maxlen=100),  # Keep last 100 requests
    'blocked_count': 0,
    'last_seen': None,
    'attack_patterns': [],
    'suspected_attack': False
})

ATTACK_THRESHOLD_REQUESTS = 5  # Number of malicious requests to flag as attacker
TIME_WINDOW_SECONDS = 60  # Time window for rate limiting
RATE_LIMIT_THRESHOLD = 10  # Max requests per minute per IP

def is_rate_limit_exceeded(ip: str) -> bool:
    """
    Check if an IP has exceeded the request rate limit.
    """
    profile = ATTACKER_PROFILES[ip]
    current_time = time.time()
    
    # Clean old requests outside the time window
    while profile['requests'] and (current_time - profile['requests'][0]) > TIME_WINDOW_SECONDS:
        profile['requests'].popleft()
    
    # Add current request
    profile['requests'].append(current_time)
    
    return len(profile['requests']) > RATE_LIMIT_THRESHOLD

def flag_malicious_request(ip: str, attack_type: str, payload: str) -> dict:
    """
    Track and flag malicious requests from an IP.
    Returns attacker profile if flagged as confirmed attacker.
    """
    profile = ATTACKER_PROFILES[ip]
    profile['request_count'] += 1
    profile['blocked_count'] += 1
    profile['last_seen'] = datetime.now().isoformat()
    
    # Add attack pattern
    pattern = {
        'type': attack_type,
        'payload': payload[:50],  # Store first 50 chars
        'timestamp': datetime.now().isoformat()
    }
    profile['attack_patterns'].append(pattern)
    
    # Flag as suspected attacker if threshold exceeded
    if profile['blocked_count'] >= ATTACK_THRESHOLD_REQUESTS:
        profile['suspected_attack'] = True
    
    return profile

def get_attack_severity(ip: str) -> str:
    """
    Determine the severity of an attacker based on their profile.
    Returns: 'low', 'medium', 'high', 'critical'
    """
    profile = ATTACKER_PROFILES[ip]
    blocked_count = profile['blocked_count']
    
    if blocked_count >= 20:
        return 'critical'
    elif blocked_count >= 10:
        return 'high'
    elif blocked_count >= 5:
        return 'medium'
    else:
        return 'low'

def is_known_attacker(ip: str) -> bool:
    """
    Check if IP is a known/suspected attacker.
    """
    return ATTACKER_PROFILES[ip]['suspected_attack']

def get_attacker_profile(ip: str) -> dict:
    """
    Get the complete profile of an IP address.
    """
    profile = ATTACKER_PROFILES[ip]
    return {
        'ip': ip,
        'total_requests': profile['request_count'],
        'blocked_requests': profile['blocked_count'],
        'last_seen': profile['last_seen'],
        'severity': get_attack_severity(ip),
        'is_known_attacker': profile['suspected_attack'],
        'attack_patterns': profile['attack_patterns'][-10:],  # Last 10 patterns
        'total_patterns': len(profile['attack_patterns'])
    }

def get_all_attackers() -> list:
    """
    Get list of all known/suspected attackers.
    """
    attackers = []
    for ip, profile in ATTACKER_PROFILES.items():
        if profile['suspected_attack']:
            attackers.append(get_attacker_profile(ip))
    
    # Sort by severity and blocked count
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    attackers.sort(key=lambda x: (severity_order[x['severity']], -x['blocked_requests']))
    
    return attackers
