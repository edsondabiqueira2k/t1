import base64
import json
import time
import threading
import random
import sys

import qrcode
import requests
import websocket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

# SUA LISTA DE PROXYS
PROXY_LIST = [
    "45.89.111.139:1082",
    "132.226.229.220:1080",
    "144.91.82.219:9050",
    "38.190.100.168:999",
    "159.203.133.128:9056",
    "177.93.45.11:999",
    "158.172.153.36:999",
    "159.65.181.194:9056",
    "103.150.255.104:46902",
    "188.253.125.38:28798",
    "103.155.190.134:1080",
    "131.222.252.102:8080",
    "202.150.141.98:3128",
    "195.26.243.76:3128",
    "88.119.139.237:53281",
    "129.153.197.111:3128",
    "38.76.150.55:1080",
    "193.233.129.235:1080",
    "5.189.152.154:8080",
    "103.39.51.156:1080",
    "174.138.64.121:9051",
    "103.138.185.81:83",
    "103.227.187.23:8080",
    "179.1.182.20:999",
    "37.44.238.2:57167",
    "144.124.233.244:9015",
    "91.107.122.209:1080",
    "188.227.140.181:8080",
    "185.128.240.2:3128",
    "128.14.92.89:22891",
    "43.153.71.188:9050",
    "149.104.68.53:1080",
    "58.187.104.56:1092",
    "36.249.58.80:1082",
    "157.66.36.57:69",
    "150.136.163.51:80",
    "129.146.127.232:3128",
    "8.210.49.13:7777",
    "199.66.157.41:8080",
    "79.106.165.246:8989",
    "103.177.235.194:84",
    "94.131.118.129:1082",
    "223.25.110.216:3125",
    "102.68.128.217:8080",
    "148.251.86.68:16379",
    "38.191.219.62:999",
    "113.160.204.60:8080",
    "38.194.246.34:999",
    "5.75.168.247:8053",
    "103.168.254.26:1111",
    "5.104.174.199:23500",
    "103.119.63.144:8080",
    "137.184.58.163:9050",
    "80.75.169.234:8080",
    "192.9.241.51:26568",
    "94.131.118.39:1082",
    "68.183.52.128:9167",
    "140.82.35.234:44444",
    "154.12.94.120:1080",
    "38.7.195.55:999",
    "45.55.159.111:9067",
    "159.203.133.128:9054",
    "130.49.218.108:1080",
    "159.203.133.128:9058",
    "36.64.157.154:8080",
    "5.102.109.41:999",
    "176.126.70.111:16379",
    "45.55.159.111:9053",
    "103.155.168.90:8299",
    "58.229.240.204:9050",
    "142.93.195.158:80",
    "5.75.168.247:8053",
    "5.75.168.247:8027",
    "38.224.221.34:999",
    "45.89.111.179:1081",
    "38.199.26.21:999",
    "14.225.240.23:8562",
    "174.104.115.21:80",
    "64.112.125.154:9051",
    "165.227.211.170:9051",
    "5.75.168.247:8048",
    "138.199.25.13:3903",
    "45.55.159.111:9067",
    "129.150.53.35:3128",
    "51.15.117.209:3128",
    "103.247.82.203:8085",
    "89.43.135.182:8085",
    "157.66.36.170:8080",
    "177.44.182.128:8088",
    "72.11.144.141:8080",
    "45.172.142.34:999",
    "159.203.167.231:9059",
    "179.1.113.113:999",
    "103.152.238.179:1080",
    "188.165.199.207:80",
    "103.20.88.50:8080",
    "103.184.54.7:8080",
    "103.143.39.97:1111",
    "45.55.159.111:9059",
    "190.60.55.61:8080",
    "193.43.149.85:8080",
    "190.217.17.10:999",
    "147.231.163.133:80",
    "200.24.130.148:999",
    "95.129.101.73:80",
]

# Forçar flush do output
sys.stdout.reconfigure(line_buffering=True)

print("starting...", flush=True)
print(f"📋 Carregados {len(PROXY_LIST)} proxies", flush=True)

def test_proxy(host, port):
    """Testa se o proxy HTTP está funcionando"""
    try:
        proxy_url = f"http://{host}:{port}"
        proxies = {"http": proxy_url, "https": proxy_url}
        r = requests.get("https://httpbin.org/ip", proxies=proxies, timeout=5)
        if r.status_code == 200:
            print(f"✅ Proxy funcionando: {host}:{port} -> IP: {r.json()['origin']}", flush=True)
            return True
    except:
        pass
    return False

# Testar proxies e encontrar um funcionando
selected_proxy = None
print("🔍 Testando proxies HTTP...", flush=True)

# Embaralhar a lista
random.shuffle(PROXY_LIST)

for proxy_str in PROXY_LIST[:100]:  # Testa até 100 proxies
    try:
        host, port = proxy_str.split(":")
        port = int(port)
        
        if test_proxy(host, port):
            selected_proxy = {"host": host, "port": port}
            break
    except:
        continue

if not selected_proxy:
    print("⚠️ Nenhum proxy funcionou, continuando sem proxy...", flush=True)
else:
    print(f"🎯 Proxy selecionado: {selected_proxy['host']}:{selected_proxy['port']}", flush=True)

# Gerar par de chaves RSA
key = RSA.generate(2048)
private_key = key
public_key = key.publickey()

def export_public_key():
    return base64.b64encode(public_key.export_key(format='DER')).decode()

def decrypt_payload(encrypted_payload: str) -> str:
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    decrypted = cipher.decrypt(base64.b64decode(encrypted_payload))
    return decrypted.decode()

def handle_nonce(encrypted_nonce: str, ws):
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    decrypted = cipher.decrypt(base64.b64decode(encrypted_nonce))
    nonce = base64.urlsafe_b64encode(decrypted).rstrip(b'=').decode()
    
    ws.send(json.dumps({
        "op": "nonce_proof",
        "nonce": nonce
    }))

def heartbeat_thread(ws, interval):
    def heartbeat():
        while True:
            time.sleep(interval / 1000)
            ws.send(json.dumps({"op": "heartbeat"}))
            print("💓 Heartbeat", flush=True)
    
    thread = threading.Thread(target=heartbeat)
    thread.daemon = True
    thread.start()

def on_message(ws, message):
    packet = json.loads(message)
    print(f"📨 {packet.get('op')}", flush=True)
    
    op = packet.get("op")
    
    if op == "hello":
        interval = packet["heartbeat_interval"]
        heartbeat_thread(ws, interval)
        
        ws.send(json.dumps({
            "op": "init",
            "encoded_public_key": export_public_key()
        }))
        print("🔑 Chave pública enviada", flush=True)
    
    elif op == "nonce_proof":
        handle_nonce(packet["encrypted_nonce"], ws)
    
    elif op == "pending_remote_init":
        url = f"https://discord.com/ra/{packet['fingerprint']}"
        print(f"\n📱 QR CODE URL: {url}", flush=True)
        
        qr = qrcode.QRCode()
        qr.add_data(url)
        qr.print_ascii(invert=True)
        print("\n🔍 Escaneie o QR Code acima!\n", flush=True)
    
    elif op == "pending_ticket":
        payload = decrypt_payload(packet["encrypted_user_payload"])
        print(f"👤 Usuário: {payload}", flush=True)
    
    elif op == "pending_login":
        ticket = packet["ticket"]
        print(f"🎫 Ticket: {ticket[:50]}...", flush=True)
        
        # Fazer requisição via proxy (se tiver)
        session = requests.Session()
        
        if selected_proxy:
            proxy_url = f"http://{selected_proxy['host']}:{selected_proxy['port']}"
            session.proxies.update({"http": proxy_url, "https": proxy_url})
            print(f"🔄 Usando proxy para requisição: {selected_proxy['host']}:{selected_proxy['port']}", flush=True)
        
        try:
            response = session.post(
                "https://discord.com/api/v9/users/@me/remote-auth/login",
                json={"ticket": ticket},
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
                token = cipher.decrypt(base64.b64decode(data["encrypted_token"])).decode()
                print(f"\n{'='*60}", flush=True)
                print(f"✅ TOKEN: {token}", flush=True)
                print(f"{'='*60}\n", flush=True)
                
                with open("token.txt", "w") as f:
                    f.write(token)
                print("💾 Token salvo em token.txt", flush=True)
            else:
                print(f"❌ Erro: {response.status_code}", flush=True)
                print(response.json(), flush=True)
        except Exception as e:
            print(f"❌ Erro na requisição: {e}", flush=True)
        
        ws.close()

def on_error(ws, error):
    print(f"❌ Erro WebSocket: {error}", flush=True)

def on_close(ws, close_status_code, close_msg):
    print(f"🔌 Conexão fechada", flush=True)

def on_open(ws):
    print("✅ WebSocket conectado!", flush=True)

def main():
    ws_url = "wss://remote-auth-gateway.discord.gg/?v=2"
    
    print(f"🌐 Conectando WebSocket...", flush=True)
    
    ws = websocket.WebSocketApp(
        ws_url,
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close,
        header={
            "Origin": "https://discord.com",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
    )
    
    websocket.enableTrace(False)
    ws.run_forever()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n🛑 Parado pelo usuário", flush=True)
    except Exception as e:
        print(f"❌ Erro fatal: {e}", flush=True)
