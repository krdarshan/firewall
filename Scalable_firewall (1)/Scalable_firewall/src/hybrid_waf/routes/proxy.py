from flask import Blueprint, request, jsonify
from src.hybrid_waf.utils.signature_checker import check_signature
from src.hybrid_waf.utils.attack_detector import (
    is_rate_limit_exceeded, flag_malicious_request, 
    is_known_attacker, get_attacker_profile, get_all_attackers
)
import logging

# Create a dedicated logger for WAF detections
waf_logger = logging.getLogger('waf_detections')
waf_logger.setLevel(logging.INFO)

# Create file handler
fh = logging.FileHandler('logs/detections.log')
fh.setLevel(logging.INFO)

# Create formatter (include IP address in log)
formatter = logging.Formatter('%(asctime)s - IP: %(ip)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
fh.setFormatter(formatter)

# Add the handler to the logger
waf_logger.addHandler(fh)

# Create a separate logger for blocked IPs
ip_logger = logging.getLogger('blocked_ips')
ip_logger.setLevel(logging.INFO)

# Create file handler for IPs
ip_fh = logging.FileHandler('logs/blocked_ips.log')
ip_fh.setLevel(logging.INFO)

# Create formatter for IP log
ip_formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
ip_fh.setFormatter(ip_formatter)

# Add the handler to the IP logger
ip_logger.addHandler(ip_fh)

def get_client_ip():
    """
    Extract client IP address from request.
    Handles X-Forwarded-For header (for proxied requests) and direct remote_addr.
    """
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

proxy_bp = Blueprint('proxy', __name__)

@proxy_bp.route('/check_request', methods=['POST'])
def check_request():
    data = request.get_json()
    
    user_input = data.get("user_request", "")
    uri = data.get("uri", user_input)
    get_data = data.get("get_data", "")
    post_data = data.get("post_data", "")
    client_ip = get_client_ip()
    
    log_extra = {'ip': client_ip}
    
    # --- Rate Limit Check ---
    if is_rate_limit_exceeded(client_ip):
        waf_logger.info(f"RATE_LIMIT_EXCEEDED - {user_input}", extra=log_extra)
        ip_logger.info(f"RATE_LIMIT - {client_ip} - Excessive requests detected")
        flag_malicious_request(client_ip, "rate_limit", user_input)
        return jsonify({
            "status": "malicious",
            "message": "Rate limit exceeded. Too many requests. Access temporarily blocked.🚫"
        }), 429

    # --- Protected Sites Check ---
    PROTECTED_SITES = [
        "gamechanger100199.wixsite.com/shopping",
        "https://gamechanger100199.wixsite.com/shopping",
        "http://gamechanger100199.wixsite.com/shopping"
    ]

    # Look for any indication the request is targeting the protected site(s).
    # Accepts `target_site`, `host`, `referer`, `uri`, and raw `user_request` fields from the caller.
    target_fields = " ".join([
        str(data.get("target_site", "")),
        str(data.get("host", "")),
        str(data.get("referer", "")),
        str(uri),
        str(user_input)
    ]).lower()

    for protected in PROTECTED_SITES:
        if protected in target_fields:
            waf_logger.info(f"{user_input} - malicious(protected_target:{protected})", extra=log_extra)
            ip_logger.info(f"BLOCKED - {client_ip} - Reason: Protected site target ({protected}) - Request: {user_input}")
            flag_malicious_request(client_ip, "protected_target", user_input)
            
            attacker_profile = get_attacker_profile(client_ip)
            return jsonify({
                "status": "malicious",
                "message": f"Blocked: Target is protected site ({protected}). Access Denied.",
                "attacker_profile": attacker_profile if is_known_attacker(client_ip) else None
            }), 403
    
    # --- Step 1: Signature-Based Detection ---
    signature_result = check_signature(user_input)
    
    if signature_result == "valid":
        waf_logger.info(f"{user_input} - valid", extra=log_extra)
        return jsonify({
            "status": "valid",
            "message": "All Clear! Your request passed our security checks with flying colors.✨"
        })

    if signature_result == "malicious":
        waf_logger.info(f"{user_input} - malicious(signature)", extra=log_extra)
        ip_logger.info(f"BLOCKED - {client_ip} - Reason: Malicious signature detected - Request: {user_input}")
        flag_malicious_request(client_ip, "malicious_signature", user_input)
        
        attacker_profile = get_attacker_profile(client_ip)
        return jsonify({
            "status": "malicious",
            "message": "Critical Alert! Malicious pattern detected in your request.<br>Access Denied!🔒",
            "attacker_profile": attacker_profile if is_known_attacker(client_ip) else None
        })
    
    # --- Step 2: ML-Based Anomaly Detection (Only for obfuscated requests) ---
    if signature_result == "obfuscated":
        from src.hybrid_waf.utils.preprocessor import extract_features
        from src.hybrid_waf.utils.ml_checker import check_ml_prediction
        
        features = extract_features(uri, get_data, post_data)
        prediction = check_ml_prediction(features)
        
        final_status = "malicious" if prediction == 1 else "valid"
        
        waf_logger.info(f"{user_input} - malicious(ML)" if prediction == 1 else f"{user_input} - valid", extra=log_extra)
        
        if final_status == "malicious":
            ip_logger.info(f"BLOCKED - {client_ip} - Reason: ML anomaly detected - Request: {user_input}")
            flag_malicious_request(client_ip, "ml_anomaly", user_input)
            
            attacker_profile = get_attacker_profile(client_ip)
            return jsonify({
                "status": "obfuscated",
                "ml_verdict": "🚨 Threat Confirmed! AI Defense System Blocked Suspicious Activity.🔒",
                "message": "Suspicious Pattern Detected - Engaging Advanced AI Analysis...",
                "features": features,
                "attacker_profile": attacker_profile if is_known_attacker(client_ip) else None
            })
            
        return jsonify({
            "status": "obfuscated",
            "ml_verdict": "✅ Advanced AI Scan Complete: Request Verified Safe ✨",
            "message": "Suspicious Pattern Detected - Engaging Advanced AI Analysis...",
            "features": features
        })

@proxy_bp.route('/attackers', methods=['GET'])
def get_attackers():
    """
    Get list of all detected attackers and their profiles.
    """
    attackers = get_all_attackers()
    return jsonify({
        "total_attackers": len(attackers),
        "attackers": attackers
    })

@proxy_bp.route('/attacker/<ip>', methods=['GET'])
def get_attacker_info(ip):
    """
    Get detailed profile of a specific attacker IP.
    """
    profile = get_attacker_profile(ip)
    return jsonify(profile)