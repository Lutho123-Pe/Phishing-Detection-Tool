import re
import email
import validators
import tldextract
import os
import json
from datetime import datetime
import webbrowser

# EXPANDED PHISHING KEYWORDS LIST (100+ keywords)
PHISHING_KEYWORDS = [
    # Urgency/Scarcity keywords
    "urgent", "immediately", "asap", "now", "instant", "right away",
    "limited time", "time sensitive", "expire", "expiring", "deadline",
    "today only", "final notice", "last chance", "act now",
    
    # Account-related keywords  
    "account", "password", "login", "credentials", "username",
    "verify", "verify account", "confirm", "validation", "validate",
    "suspended", "locked", "restricted", "deactivated", "terminated",
    "compromised", "hacked", "breach", "unauthorized", "suspicious",
    
    # Security threats
    "security", "security alert", "security issue", "security threat",
    "malware", "virus", "infected", "hack", "hacker", "cyber",
    "phishing", "fraud", "scam", "spoof", "spoofed", "fake",
    
    # Financial keywords
    "payment", "invoice", "billing", "charge", "transaction",
    "refund", "rebate", "prize", "winner", "won", "lottery",
    "inheritance", "funds", "money", "cash", "reward",
    "credit card", "bank", "paypal", "venmo", "bitcoin",
    "crypto", "cryptocurrency", "wallet",
    
    # Action/Click keywords
    "click", "click here", "click below", "click link", "tap here",
    "press here", "download", "install", "open", "view", "access",
    "unsubscribe", "opt-out", "remove", "stop", "cancel",
    
    # Identity/Personal info
    "social security", "ssn", "id", "identification", "identity",
    "personal", "private", "confidential", "sensitive",
    "date of birth", "dob", "address", "phone", "mobile",
    
    # Legal/Official sounding
    "legal", "court", "summons", "warrant", "police", "fbi",
    "irs", "tax", "government", "official", "authority",
    "compliance", "regulation", "required", "mandatory",
    
    # Emotional manipulation
    "important", "critical", "vital", "essential", "crucial",
    "emergency", "alert", "warning", "attention", "notice",
    "congratulations", "you won", "you've been selected",
    "exclusive", "special offer", "free", "bonus", "gift",
    
    # File/Attachment keywords
    "attachment", "document", "file", "invoice", "receipt",
    "statement", "bill", "form", "application",
    
    # Verification/Confirmation
    "update", "update information", "update account", "update details",
    "renew", "reactivate", "restore", "recover", "reset",
    "change", "modify", "correct", "fix", "repair",
    
    # Company names (commonly spoofed)
    "amazon", "paypal", "microsoft", "apple", "google",
    "netflix", "facebook", "instagram", "twitter", "linkedin",
    "bankofamerica", "chase", "wellsfargo", "citibank",
    "irs", "social security", "medicare", "fedex", "ups", "usps"
]

def get_email_body(msg):
    """Extract text body from email (handles multipart emails)"""
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            
            # Skip attachments
            if "attachment" in content_disposition:
                continue
                
            if content_type in ["text/plain", "text/html"]:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body += payload.decode('utf-8', errors='ignore')
                except:
                    try:
                        body += str(part.get_payload())
                    except:
                        pass
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode('utf-8', errors='ignore')
        except:
            body = str(msg.get_payload())
    return body

def check_keywords(text):
    """Check for phishing keywords and return with counts"""
    found_keywords = {}
    text_lower = text.lower()
    
    for kw in PHISHING_KEYWORDS:
        kw_lower = kw.lower()
        # Count occurrences
        count = text_lower.count(kw_lower)
        if count > 0:
            found_keywords[kw] = count
    
    return found_keywords

def extract_urls(text):
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w .?=%&_#:;,-]*'
    return re.findall(url_pattern, text)

def check_url_suspicion(url):
    try:
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"
        
        # Suspicious indicators
        if "-" in domain:
            return True, "Contains hyphen in domain"
        if len(extracted.domain) > 25:
            return True, "Domain name too long"
        if not validators.domain(domain):
            return True, "Invalid domain format"
            
        suspicious_tlds = ['.xyz', '.top', '.club', '.info', '.biz', '.tk', '.ml', '.ga', '.cf', '.gq']
        if any(extracted.suffix.endswith(tld) for tld in suspicious_tlds):
            return True, f"Suspicious TLD: {extracted.suffix}"
            
        # Check for IP address URLs
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.search(ip_pattern, url):
            return True, "Uses IP address instead of domain"
            
        return False, "Appears legitimate"
    except:
        return True, "Unable to parse URL"

def check_auth_headers(headers):
    results = {"SPF": "fail", "DKIM": "fail", "DMARC": "fail"}
    
    header_dict = {k.lower(): v for k, v in dict(headers).items()}
    
    spf = header_dict.get('received-spf', '')
    if 'pass' in spf.lower():
        results["SPF"] = "pass"
    
    dkim = header_dict.get('dkim-signature', '')
    auth_results = header_dict.get('authentication-results', '')
    
    if dkim or 'dkim=pass' in auth_results.lower():
        results["DKIM"] = "pass"
    
    if 'dmarc=pass' in auth_results.lower():
        results["DMARC"] = "pass"
    
    return results

def calculate_risk(keyword_hits, suspicious_urls, auth):
    score = 0
    
    # Calculate keyword score based on count and severity
    total_keyword_count = sum(keyword_hits.values())
    score += min(total_keyword_count * 8, 50)  # Max 50 points for keywords
    
    # URLs: 15 points each suspicious URL
    score += suspicious_urls * 15
    
    # Authentication failures
    if auth["SPF"] == "fail": 
        score += 10
    if auth["DKIM"] == "fail": 
        score += 15
    if auth["DMARC"] == "fail": 
        score += 20
    
    return min(score, 100)

def generate_html_report(data):
    """Generate an HTML report with the detection results"""
    
    # Determine risk level and color
    if data['score'] >= 70:
        risk_level = "HIGH RISK"
        risk_color = "#dc3545"  # Red
        risk_icon = "⚠️ 🔴"
        risk_description = "Very likely phishing - Take immediate action!"
    elif data['score'] >= 40:
        risk_level = "MEDIUM RISK"
        risk_color = "#ffc107"  # Yellow
        risk_icon = "⚠️ 🟡"
        risk_description = "Suspicious - Proceed with caution!"
    else:
        risk_level = "LOW RISK"
        risk_color = "#28a745"  # Green
        risk_icon = "✅ 🟢"
        risk_description = "Likely legitimate - Still verify if unsure"
    
    # Authentication status with colors
    auth_status = ""
    for key, value in data['auth_results'].items():
        color = "#28a745" if value == "pass" else "#dc3545"
        auth_status += f"""
        <div class="auth-item">
            <span class="auth-key">{key}:</span>
            <span class="auth-value" style="color: {color}; font-weight: bold;">{value.upper()}</span>
        </div>
        """
    
    # Keywords list with counts
    keywords_list = ""
    if data['keyword_hits']:
        sorted_keywords = sorted(data['keyword_hits'].items(), key=lambda x: x[1], reverse=True)
        for kw, count in sorted_keywords[:15]:  # Show top 15 keywords
            badge_color = "danger" if count > 2 else "warning" if count > 1 else "info"
            keywords_list += f'<span class="badge bg-{badge_color} m-1">{kw} ({count})</span> '
        if len(data['keyword_hits']) > 15:
            keywords_list += f'<br><small class="text-muted">... and {len(data["keyword_hits"]) - 15} more keywords</small>'
    else:
        keywords_list = '<span class="text-success">✅ No suspicious keywords found</span>'
    
    # Keywords by category for better visualization
    keyword_categories = {
        "Urgency": 0, "Account": 0, "Security": 0, 
        "Financial": 0, "Action": 0, "Personal": 0
    }
    
    # Categorize found keywords
    urgency_words = ["urgent", "immediately", "asap", "now", "instant", "limited time"]
    account_words = ["account", "password", "login", "verify", "suspended"]
    security_words = ["security", "alert", "hacked", "compromised", "breach"]
    financial_words = ["payment", "invoice", "prize", "winner", "money", "bank"]
    action_words = ["click", "download", "open", "access"]
    personal_words = ["social security", "ssn", "personal", "private"]
    
    for kw in data['keyword_hits']:
        kw_lower = kw.lower()
        if any(word in kw_lower for word in urgency_words):
            keyword_categories["Urgency"] += data['keyword_hits'][kw]
        elif any(word in kw_lower for word in account_words):
            keyword_categories["Account"] += data['keyword_hits'][kw]
        elif any(word in kw_lower for word in security_words):
            keyword_categories["Security"] += data['keyword_hits'][kw]
        elif any(word in kw_lower for word in financial_words):
            keyword_categories["Financial"] += data['keyword_hits'][kw]
        elif any(word in kw_lower for word in action_words):
            keyword_categories["Action"] += data['keyword_hits'][kw]
        elif any(word in kw_lower for word in personal_words):
            keyword_categories["Personal"] += data['keyword_hits'][kw]
    
    # Categories visualization
    categories_html = ""
    for category, count in keyword_categories.items():
        if count > 0:
            categories_html += f'''
            <div class="col-md-2">
                <div class="category-box">
                    <div class="category-name">{category}</div>
                    <div class="category-count">{count}</div>
                </div>
            </div>
            '''
    
    # URLs list
    urls_list = ""
    for i, url in enumerate(data['urls'][:10], 1):
        is_suspicious, reason = check_url_suspicion(url)
        status_icon = "❌" if is_suspicious else "✅"
        status_class = "text-danger" if is_suspicious else "text-success"
        urls_list += f"""
        <tr>
            <td>{i}</td>
            <td style="word-break: break-all; font-family: monospace; font-size: 0.9rem;">{url[:80]}{'...' if len(url) > 80 else ''}</td>
            <td class="{status_class}">{status_icon} {'Suspicious' if is_suspicious else 'Clean'}</td>
            <td><small>{reason}</small></td>
        </tr>
        """
    
    # HTML template
    html_template = f'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Phishing Detection Report - {data['filename']}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        body {{
            background-color: #f8f9fa;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }}
        .report-header {{
            background: linear-gradient(135deg, {risk_color} 0%, #764ba2 100%);
            color: white;
            padding: 2rem;
            border-radius: 10px 10px 0 0;
            margin-bottom: 2rem;
        }}
        .risk-score {{
            font-size: 4rem;
            font-weight: bold;
            color: {risk_color};
        }}
        .risk-level {{
            background-color: {risk_color};
            color: white;
            padding: 10px 20px;
            border-radius: 50px;
            display: inline-block;
            font-weight: bold;
            font-size: 1.2rem;
        }}
        .section-card {{
            background: white;
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            border-left: 5px solid {risk_color};
        }}
        .badge {{
            margin: 2px;
            padding: 5px 10px;
            font-size: 0.85rem;
        }}
        .auth-item {{
            display: inline-block;
            margin: 0 15px 10px 0;
            padding: 10px 15px;
            background: #f8f9fa;
            border-radius: 5px;
            min-width: 120px;
        }}
        .auth-key {{
            display: block;
            font-weight: bold;
            color: #6c757d;
        }}
        .auth-value {{
            display: block;
            font-size: 1.2rem;
        }}
        .summary-box {{
            text-align: center;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 10px;
            margin: 10px;
        }}
        .summary-number {{
            font-size: 2.5rem;
            font-weight: bold;
        }}
        .category-box {{
            text-align: center;
            padding: 15px;
            background: #e9ecef;
            border-radius: 8px;
            margin: 5px;
        }}
        .category-name {{
            font-size: 0.9rem;
            color: #6c757d;
        }}
        .category-count {{
            font-size: 1.5rem;
            font-weight: bold;
            color: {risk_color};
        }}
        .footer {{
            margin-top: 2rem;
            padding: 1rem;
            text-align: center;
            color: #6c757d;
            font-size: 0.9rem;
        }}
        table {{
            font-size: 0.9rem;
        }}
        th {{
            background-color: #f8f9fa !important;
        }}
        .progress {{
            height: 25px;
            margin: 10px 0;
        }}
        .progress-bar {{
            font-weight: bold;
        }}
        .keyword-category {{
            margin-bottom: 1rem;
        }}
        .keyword-item {{
            background: #f8f9fa;
            padding: 8px 12px;
            margin: 3px;
            border-radius: 5px;
            display: inline-block;
            font-size: 0.9rem;
        }}
    </style>
</head>
<body>
    <div class="container mt-4 mb-4">
        <!-- Header -->
        <div class="report-header text-center">
            <h1><i class="fas fa-shield-alt"></i> Phishing Email Detection Report</h1>
            <p class="lead">Analysis generated on {data['timestamp']}</p>
            <div class="mt-3">
                <span class="risk-level">{risk_icon} {risk_level}</span>
            </div>
        </div>
        
        <!-- Main Risk Summary -->
        <div class="section-card">
            <div class="row align-items-center">
                <div class="col-md-6 text-center">
                    <div class="risk-score">{data['score']}/100</div>
                    <p class="mt-2" style="color: {risk_color}; font-weight: bold; font-size: 1.2rem;">
                        {risk_description}
                    </p>
                    
                    <!-- Risk Progress Bar -->
                    <div class="progress mt-3">
                        <div class="progress-bar" role="progressbar" 
                             style="width: {data['score']}%; background-color: {risk_color};" 
                             aria-valuenow="{data['score']}" aria-valuemin="0" aria-valuemax="100">
                            {data['score']}% Risk Level
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <h4><i class="fas fa-file-alt"></i> File Information</h4>
                    <p><strong>Filename:</strong> {data['filename']}</p>
                    <p><strong>Analysis Time:</strong> {data['timestamp']}</p>
                    <p><strong>Overall Verdict:</strong> 
                        <span style="color: {risk_color}; font-weight: bold;">
                            {risk_icon} {risk_level} - {risk_description}
                        </span>
                    </p>
                </div>
            </div>
        </div>
        
        <!-- Summary Stats -->
        <div class="row">
            <div class="col-md-3">
                <div class="summary-box">
                    <div class="summary-number" style="color: #dc3545;">{sum(data['keyword_hits'].values())}</div>
                    <div>Keyword Matches</div>
                    <small>{len(data['keyword_hits'])} unique keywords</small>
                </div>
            </div>
            <div class="col-md-3">
                <div class="summary-box">
                    <div class="summary-number" style="color: #17a2b8;">{len(data['urls'])}</div>
                    <div>URLs Found</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="summary-box">
                    <div class="summary-number" style="color: #ffc107;">{data['suspicious_urls']}</div>
                    <div>Suspicious URLs</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="summary-box">
                    <div class="summary-number" style="color: #28a745;">{sum(1 for v in data['auth_results'].values() if v == 'pass')}/3</div>
                    <div>Passed Authentications</div>
                </div>
            </div>
        </div>
        
        <!-- Keyword Categories -->
        <div class="section-card">
            <h4><i class="fas fa-tags"></i> Keyword Categories Detected</h4>
            <div class="row mt-3">
                {categories_html if categories_html else '<div class="col-12 text-center text-muted">No keyword categories detected</div>'}
            </div>
        </div>
        
        <!-- Keywords Section -->
        <div class="section-card">
            <h4><i class="fas fa-keywords"></i> Suspicious Keywords Found ({len(data['keyword_hits'])}/{len(PHISHING_KEYWORDS)})</h4>
            <div class="mt-3">
                {keywords_list}
            </div>
            <div class="mt-3">
                <small class="text-muted">
                    <i class="fas fa-info-circle"></i> The system monitors {len(PHISHING_KEYWORDS)} known phishing keywords. 
                    Red badges indicate multiple occurrences.
                </small>
            </div>
        </div>
        
        <!-- Authentication Section -->
        <div class="section-card">
            <h4><i class="fas fa-user-shield"></i> Email Authentication Results</h4>
            <div class="mt-3">
                {auth_status}
            </div>
            <p class="mt-3 text-muted">
                <small><i class="fas fa-info-circle"></i> SPF, DKIM, and DMARC are email authentication methods that help prevent spoofing. 
                Missing or failed authentication increases phishing risk.</small>
            </p>
        </div>
        
        <!-- URLs Section -->
        <div class="section-card">
            <h4><i class="fas fa-link"></i> URLs Analysis</h4>
            <div class="table-responsive mt-3">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>URL</th>
                            <th>Status</th>
                            <th>Reason</th>
                        </tr>
                    </thead>
                    <tbody>
                        {urls_list if urls_list else '<tr><td colspan="4" class="text-center text-muted">No URLs found in email</td></tr>'}
                    </tbody>
                </table>
            </div>
            <p class="mt-3 text-muted">
                <small><i class="fas fa-info-circle"></i> Showing {min(10, len(data['urls']))} of {len(data['urls'])} URLs found</small>
            </p>
        </div>
        
        <!-- Score Breakdown -->
        <div class="section-card">
            <h4><i class="fas fa-chart-pie"></i> Risk Score Breakdown</h4>
            <div class="mt-3">
                <p><strong>Keywords:</strong> {sum(data['keyword_hits'].values())} matches × 8 = <strong>{min(sum(data['keyword_hits'].values()) * 8, 50)} points</strong> (max 50)</p>
                <p><strong>Suspicious URLs:</strong> {data['suspicious_urls']} × 15 = <strong>{data['suspicious_urls'] * 15} points</strong></p>
                <p><strong>Authentication Failures:</strong> 
                    SPF({10 if data['auth_results']['SPF'] == 'fail' else 0}) + 
                    DKIM({15 if data['auth_results']['DKIM'] == 'fail' else 0}) + 
                    DMARC({20 if data['auth_results']['DMARC'] == 'fail' else 0}) = 
                    <strong>{(10 if data['auth_results']['SPF'] == 'fail' else 0) + (15 if data['auth_results']['DKIM'] == 'fail' else 0) + (20 if data['auth_results']['DMARC'] == 'fail' else 0)} points</strong>
                </p>
                <hr>
                <p class="lead"><strong>Total Risk Score:</strong> <span style="color: {risk_color}; font-size: 1.5rem;">{data['score']}/100</span></p>
                
                <!-- Risk Level Guide -->
                <div class="alert alert-light mt-3">
                    <h6><i class="fas fa-info-circle"></i> Risk Level Guide:</h6>
                    <p><span style="color: #28a745; font-weight: bold;">0-39: LOW RISK</span> - Email appears legitimate</p>
                    <p><span style="color: #ffc107; font-weight: bold;">40-69: MEDIUM RISK</span> - Suspicious, needs verification</p>
                    <p><span style="color: #dc3545; font-weight: bold;">70-100: HIGH RISK</span> - Likely phishing, take action</p>
                </div>
            </div>
        </div>
        
        <!-- Recommendations -->
        <div class="section-card" style="border-left: 5px solid {risk_color};">
            <h4><i class="fas fa-lightbulb"></i> Recommendations</h4>
            {"<div class='alert alert-danger'><h5><i class='fas fa-exclamation-triangle'></i> CRITICAL ACTION REQUIRED</h5><p>This email shows strong signs of phishing. Take these actions immediately:</p><ul><li><strong>DO NOT</strong> click any links or download attachments</li><li><strong>DO NOT</strong> reply or provide any personal information</li><li>Delete this email immediately</li><li>If it claims to be from a company you use, contact them through their official website (not via links in the email)</li><li>Report this email as phishing to your email provider</li><li>Consider changing passwords if you've interacted with similar emails</li></ul></div>" if data['score'] >= 70 else 
             "<div class='alert alert-warning'><h5><i class='fas fa-exclamation-circle'></i> PROCEED WITH CAUTION</h5><p>This email shows suspicious characteristics. Recommended actions:</p><ul><li>Verify the sender's email address carefully</li><li>Hover over links to see actual URLs before clicking</li><li>Contact the alleged sender through official channels to verify</li><li>Don't provide sensitive information via email</li><li>Check for spelling and grammar errors</li><li>Look for generic greetings (e.g., 'Dear Customer' instead of your name)</li></ul></div>" if data['score'] >= 40 else
             "<div class='alert alert-success'><h5><i class='fas fa-check-circle'></i> LIKELY LEGITIMATE</h5><p>This email appears legitimate based on our analysis. Still recommended:</p><ul><li>Always verify sender identity for sensitive communications</li><li>Be cautious with unexpected attachments</li><li>Look for proper email authentication (SPF/DKIM/DMARC)</li><li>Report anything that seems unusual</li><li>When in doubt, contact the sender through other channels</li></ul></div>"}
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <hr>
            <p>
                <i class="fas fa-shield-alt"></i> Generated by Phishing Email Detector v2.0<br>
                <small>This report analyzed {len(PHISHING_KEYWORDS)} phishing keywords. Report is for informational purposes only. Always exercise caution with emails.</small>
            </p>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
'''
    
    return html_template

def save_html_report(html_content, filename):
    """Save HTML report to file"""
    # Create reports directory if it doesn't exist
    reports_dir = "reports"
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
    
    report_filename = os.path.join(reports_dir, f"report_{os.path.splitext(filename)[0]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
    
    with open(report_filename, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return report_filename

def run_detection(email_file, generate_html=True, open_in_browser=True):
    try:
        with open(email_file, "r", encoding="utf-8", errors='ignore') as f:
            msg = email.message_from_file(f)
        
        body = get_email_body(msg)
        
        keyword_hits = check_keywords(body)
        urls = extract_urls(body)
        
        # Check each URL and count suspicious ones
        suspicious_urls = 0
        for url in urls:
            is_suspicious, _ = check_url_suspicion(url)
            if is_suspicious:
                suspicious_urls += 1
        
        auth_results = check_auth_headers(msg)
        score = calculate_risk(keyword_hits, suspicious_urls, auth_results)
        
        # Prepare data for report
        report_data = {
            'filename': os.path.basename(email_file),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'keyword_hits': keyword_hits,
            'urls': urls,
            'suspicious_urls': suspicious_urls,
            'auth_results': auth_results,
            'score': score
        }
        
        # Console output
        print("\n" + "="*60)
        print("PHISHING DETECTION REPORT")
        print("="*60)
        print(f"File: {report_data['filename']}")
        print(f"Time: {report_data['timestamp']}")
        print("-"*60)
        print(f"Keywords found: {len(keyword_hits)} unique, {sum(keyword_hits.values())} total")
        if keyword_hits:
            print("Top keywords:")
            sorted_kw = sorted(keyword_hits.items(), key=lambda x: x[1], reverse=True)[:5]
            for kw, count in sorted_kw:
                print(f"  - {kw}: {count} occurrence(s)")
        print(f"URLs found: {len(urls)}")
        print(f"Suspicious URLs: {suspicious_urls}")
        print(f"Authentication: {auth_results}")
        print("-"*60)
        print(f"RISK SCORE: {score}/100")
        
        if score >= 70:
            print("🔴 HIGH RISK — Likely phishing email!")
        elif score >= 40:
            print("🟡 MEDIUM RISK — Suspicious, review carefully")
        else:
            print("🟢 LOW RISK — Probably legitimate")
        print("="*60)
        
        # Generate HTML report
        if generate_html:
            html_content = generate_html_report(report_data)
            html_filename = save_html_report(html_content, os.path.basename(email_file))
            print(f"\n📊 HTML report generated: {html_filename}")
            
            if open_in_browser:
                print("Opening report in web browser...")
                webbrowser.open(f'file://{os.path.abspath(html_filename)}')
        
        return report_data
        
    except Exception as e:
        print(f"Error processing email: {str(e)}")
        return None

if __name__ == "__main__":
    print("📧 Phishing Email Detector with 100+ Keywords")
    print("-" * 40)
    print(f"Monitoring {len(PHISHING_KEYWORDS)} phishing keywords")
    
    file_path = input("\nEnter path to email file (.eml): ").strip()
    
    # Handle drag-and-drop quotes
    if file_path.startswith('"') and file_path.endswith('"'):
        file_path = file_path[1:-1]
    
    if not os.path.exists(file_path):
        print(f"\n❌ Error: File not found: {file_path}")
        print("Please check the path and try again.")
    else:
        # Ask about HTML report
        generate_html = input("\nGenerate HTML report? (y/n, default=y): ").strip().lower()
        if generate_html == '' or generate_html == 'y':
            open_browser = input("Open report in browser after generation? (y/n, default=y): ").strip().lower()
            open_in_browser = open_browser == '' or open_browser == 'y'
            run_detection(file_path, generate_html=True, open_in_browser=open_in_browser)
        else:
            run_detection(file_path, generate_html=False)
    
    input("\nPress Enter to exit...")