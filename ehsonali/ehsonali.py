from flask import Flask, render_template, request
import whois
import socket
import ssl
from datetime import datetime

app = Flask(__name__)

# Maxfiylik testi savollari
QUESTIONS = [
    {"id": "p_type", "text": "Parolingiz murakkabligi qanday?", "options": [
        {"val": "strong", "text": "Harf, raqam va belgilar bor", "points": 25},
        {"val": "weak", "text": "Faqat ismim yoki tug'ilgan yilim", "points": 0}
    ]},
    {"id": "2fa", "text": "Ikki bosqichli autentifikatsiya (2FA) yoqilganmi?", "options": [
        {"val": "yes", "text": "Ha, SMS yoki ilova orqali", "points": 35},
        {"val": "no", "text": "Yo'q, faqat parol", "points": 0}
    ]},
    {"id": "privacy", "text": "Profilingiz hamma uchun ochiqmi?", "options": [
        {"val": "contacts", "text": "Faqat kontaktlarim ko'ra oladi", "points": 20},
        {"val": "all", "text": "Hamma uchun ochiq", "points": 5}
    ]},
    {"id": "apps", "text": "Profilingizga uchinchi tomon ilovalari ulanganmi?", "options": [
        {"val": "no", "text": "Yo'q, hammasini o'chirganman", "points": 20},
        {"val": "yes", "text": "Ha, har xil o'yin va testlar", "points": 0}
    ]}
]

@app.route('/')
def index():
    return render_template('index.html', questions=QUESTIONS)

@app.route('/analyze', methods=['POST'])
def analyze():
    # 1. URL tahlili (HTTPS, SSL, WHOIS) qismi
    target_url = request.form.get('url_input')
    url_results = {}
    
    if target_url:
        domain = target_url.replace("https://", "").replace("http://", "").split('/')[0]
        
        # HTTPS tekshiruvi
        url_results['https'] = "Mavjud ✅" if target_url.startswith("https://") else "Mavjud emas ❌"
        
        # SSL tekshiruvi
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    url_results['ssl'] = "Sertifikat xavfsiz ✅"
        except:
            url_results['ssl'] = "Sertifikatda xato yoki topilmadi ❌"
            
        # WHOIS tekshiruvi
        try:
            w = whois.whois(domain)
            url_results['domain_age'] = str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date)
        except:
            url_results['domain_age'] = "Aniqlab bo'lmadi"

    # 2. Maxfiylik testi tahlili
    score = 0
    recs = []
    
    if request.form.get('p_type') == 'weak': recs.append("Parolni murakkabroq qiling.")
    else: score += 25
    
    if request.form.get('2fa') == 'no': recs.append("Ikki bosqichli himoyani (2FA) yoqing.")
    else: score += 35
    
    if request.form.get('privacy') == 'all': recs.append("Profilni begonalar uchun yoping.")
    else: score += 20
    
    if request.form.get('apps') == 'no': score += 20
    else: recs.append("Shubhali ilovalarni profilingizdan uzing.")

    return render_template('result.html', score=score, recs=recs, url_res=url_results, domain=domain if target_url else None)

if __name__ == '__main__':
    app.run(debug=True)