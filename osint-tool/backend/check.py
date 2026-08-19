import urllib.request, json, os
from dotenv import load_dotenv
load_dotenv('.env')
print("Key starts with:", os.getenv("GROQ_API_KEY")[:4] if os.getenv("GROQ_API_KEY") else "None")
try:
    req = urllib.request.Request('https://api.groq.com/openai/v1/models', headers={'Authorization': 'Bearer ' + os.getenv('GROQ_API_KEY'), 'User-Agent': 'Mozilla/5.0'})
    resp = urllib.request.urlopen(req)
    data = json.loads(resp.read().decode('utf-8'))
    print("Models:", [m['id'] for m in data['data']])
except Exception as e:
    print(e.read().decode('utf-8'))
