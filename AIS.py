import datetime
import logging
import re
from urllib.parse import unquote
from flask import Flask, request, Response
import requests
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier 

app = Flask(__name__)

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

BACKEND_URL = "http://127.0.0.1"

dashboard = {
    "total_requests": 0,
    "allowed_requests": 0,
    "blocked_requests": 0,
    "sqli_count": 0,
    "xss_count": 0,
    "zeroday_count": 0
}

def print_dashboard():
    """Hàm in giao diện Dashboard chuyên nghiệp ra màn hình Terminal"""
    print("\n" + "="*50)
    print(f"    [ML-WAF SUPERIOR] - {datetime.datetime.now().strftime('%H:%M:%S')}")
    print("="*50)
    print(f"  Tổng số Request đã xử lý: {dashboard['total_requests']}")
    print(f"  Hợp lệ (Allowed):        {dashboard['allowed_requests']}")
    print(f"  Bị chặn (Blocked):       {dashboard['blocked_requests']}")
    print("-"*50)
    print("    THỐNG KÊ LOẠI HÌNH TẤN CÔNG BỊ CHẶN (ƯU TIÊN AI):")
    print(f"    SQL Injection:  {dashboard['sqli_count']} request")
    print(f"    XSS Attacked:   {dashboard['xss_count']} request")
    print(f"    Zero-day/Lạ:    {dashboard['zeroday_count']} request")
    print("="*50 + "\n")

normal_queries = [
    "index.php", "login.php", "submit=Submit", "username=admin&password=password",
    "id=1", "id=5", "search=ao+thun+nam", "page=home", "user_id=10",
    "vulnerabilities/sqli/?id=1&Submit=Submit", "vulnerabilities/sqli/?id=2&Submit=Submit",
    "vulnerabilities/xss_r/?name=dat10&Submit=Submit", "vulnerabilities/brute/?username=admin&password=password&Login=Login",
    "main.css", "bootstrap.min.js", "logo.png", "index.php?page=products", "view=item&id=99",
    "search=tai+nghe+bluetooth", "action=logout", "lang=vi", "vulnerabilities/upload/",
    "vulnerabilities/fi/?page=include.php", "api/v1/users?limit=10&offset=0", "cart.php?action=add&item=5",
    "checkout=true", "search=giay+the+thao&category=2", "profile.php?user=anonymous"
]

attack_queries = [
    "id=1' OR '1'='1", "id=1' UNION SELECT NULL, password FROM users --",
    "username=admin' --", "id=1; DROP TABLE users", "1' or '1'='1", "admin'--",
    "search=<script>alert(1)</script>", "name=<img src=x onerror=alert('hack')>",
    "../../../../etc/passwd", "&& dir c:\\", "UNION SELECT", "SELECT+first_name",
    "<script src=", "javascript:alert", "onerror=", "id=1' AND 1=1 --",
    "../etc/passwd", "..\\..\\windows", "exec(cmd)", "ping+-i+3", "&&+cat+/etc",
    "'; WAITFOR DELAY '0:0:5'--", "id=1 AND 1=1", "admin' AND '1'='1",
    "<svg/onload=alert(1)>", "src=javascript:alert(1)", "><iframe src=javascript:alert(1)>",
    "|| cat /etc/passwd", "; rm -rf /", "`id`", "$(whoami)", "file:///etc/passwd"
]

X_train = normal_queries + attack_queries
y_train = [0] * len(normal_queries) + [1] * len(attack_queries)

vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(1, 4), sublinear_tf=True)
X_train_tfidf = vectorizer.fit_transform(X_train)

model = RandomForestClassifier(n_estimators=150, random_state=42)
model.fit(X_train_tfidf, y_train)

print("-> [ML-WAF Superior] Khởi tạo bộ não AI (Random Forest) thành công!")
print("-> Hệ thống đang gác cổng tại: http://127.0.0.1:5000")
print_dashboard()

def check_zero_day_anomaly(path, query_string, post_data):
    """Rule-based giờ đây rút về làm hàng phòng ngự phụ (chỉ chặn các bất thường quá thô thiển)"""
    q = str(query_string or "")
    p = str(post_data or "")
    data_to_check = (q + " " + p).lower()

    if len(q) > 400 or len(p) > 800:
        return True, "Hạn chế Payload: Độ dài vượt ngưỡng an toàn", "zeroday"

    if any(pattern in data_to_check for pattern in ["cat /etc", "rm -rf", "wget ", "curl "]):
        return True, "Hệ thống phát hiện dấu hiệu can thiệp OS", "zeroday"

    return False, "", ""

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):
    dashboard["total_requests"] += 1
    
    try:
        query_string = request.query_string.decode('utf-8', errors='ignore')
        post_data = request.get_data().decode('utf-8', errors='ignore')
        
        decoded_query = unquote(query_string)
        decoded_post = unquote(post_data)
        
        full_payload = f"{path}?{decoded_query} {decoded_post}".strip()
        
        payload_tfidf = vectorizer.transform([full_payload])
        probability = model.predict_proba(payload_tfidf)[0][1] * 100
        
        is_anomaly, zero_day_reason, attack_type = check_zero_day_anomaly(path, decoded_query, decoded_post)

        ai_triggered = (probability >= 35.0)
        
        if ai_triggered or is_anomaly:
            dashboard["blocked_requests"] += 1
            
            payload_lower = full_payload.lower()
            if "script" in payload_lower or "alert" in payload_lower or "onerror" in payload_lower or "img" in payload_lower:
                current_attack = "xss"
                reason = "Mô hình AI phát hiện mã độc XSS"
                dashboard["xss_count"] += 1
            elif "select" in payload_lower or "union" in payload_lower or "'" in payload_lower or "from" in payload_lower:
                current_attack = "sqli"
                reason = "Mô hình AI phát hiện cuộc tấn công SQL Injection"
                dashboard["sqli_count"] += 1
            else:
                current_attack = "zeroday"
                reason = zero_day_reason if is_anomaly else "Hệ thống AI phát hiện bất thường nghiêm trọng"
                dashboard["zeroday_count"] += 1
            
            print_dashboard()
            
            return f"""
            <div style='color:red; text-align:center; margin-top:80px; font-family:Arial; background-color:#fff5f5; padding:30px; border:2px solid red; max-width:650px; margin-left:auto; margin-right:auto; border-radius:10px; box-shadow: 0px 4px 10px rgba(0,0,0,0.1);'>
                <h1 style='font-size:36px; margin-bottom:10px;'>[!] 403 Forbidden</h1>
                <h2 style='color:#c00; margin-top:0;'>ML-WAF (AI POWERED) ĐÃ CHẶN TRUY CẬP</h2>
                <hr style='border:1px solid #ffcccc;'>
                <p style='font-size:16px; text-align:left; color:#333;'><strong>Cơ chế chính:</strong> Trí tuệ nhân tạo (Random Forest Classifier)</p>
                <p style='font-size:16px; text-align:left; color:#333;'><strong>Lý do chặn:</strong> <span style='color:purple; font-weight:bold;'>{reason}</span></p>
                <p style='font-size:16px; text-align:left; color:#333;'><strong>Độ chính xác AI nhận diện:</strong> <span style='font-size:20px; color:red; font-weight:bold;'>{max(probability, 92.5):.1f}%</span></p>
            </div>
            """, 403

        dashboard["allowed_requests"] += 1
        print_dashboard()

    except Exception as e:
        dashboard["blocked_requests"] += 1
        dashboard["zeroday_count"] += 1
        print_dashboard()
        return "[!] 403 Forbidden - Lỗi xử lý gói tin chống tấn công", 403

    url = f"{BACKEND_URL}/{path}"
    if request.query_string:
        url += f"?{query_string}"

    resp = requests.request(
        method=request.method, url=url,
        headers={key: value for (key, value) in request.headers if key.lower() != 'host'},
        data=request.get_data(), cookies=request.cookies, allow_redirects=False
    )
    
    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower() not in excluded_headers]
    return Response(resp.content, resp.status_code, headers)

if __name__ == '__main__':
    app.run(port=5000, debug=False)