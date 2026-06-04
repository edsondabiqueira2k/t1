import asyncio
import base64
import json
import time
import threading
from typing import Optional

import qrcode
import requests
import websocket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

print("starting...")

# Gerar par de chaves RSA
key = RSA.generate(2048)
private_key = key
public_key = key.publickey()

def export_public_key():
    """Exporta a chave pública no formato SPKI DER base64"""
    return base64.b64encode(public_key.export_key(format='DER')).decode()

def decrypt_payload(encrypted_payload: str) -> str:
    """Descriptografa o payload usando a chave privada"""
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    decrypted = cipher.decrypt(base64.b64decode(encrypted_payload))
    return decrypted.decode()

def handle_nonce(encrypted_nonce: str, ws):
    """Processa o nonce recebido"""
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    decrypted = cipher.decrypt(base64.b64decode(encrypted_nonce))
    nonce = base64.urlsafe_b64encode(decrypted).rstrip(b'=').decode()
    
    ws.send(json.dumps({
        "op": "nonce_proof",
        "nonce": nonce
    }))

def heartbeat_thread(ws, interval):
    """Thread para enviar heartbeats periódicos"""
    def heartbeat():
        while True:
            time.sleep(interval / 1000)  # converter ms para segundos
            ws.send(json.dumps({"op": "heartbeat"}))
    
    thread = threading.Thread(target=heartbeat)
    thread.daemon = True
    thread.start()

def on_message(ws, message):
    """Processa as mensagens recebidas do WebSocket"""
    packet = json.loads(message)
    print(packet)
    
    op = packet.get("op")
    
    if op == "hello":
        # Iniciar heartbeat
        interval = packet["heartbeat_interval"]
        heartbeat_thread(ws, interval)
        
        # Enviar chave pública
        ws.send(json.dumps({
            "op": "init",
            "encoded_public_key": export_public_key()
        }))
    
    elif op == "nonce_proof":
        handle_nonce(packet["encrypted_nonce"], ws)
    
    elif op == "pending_remote_init":
        url = f"https://discord.com/ra/{packet['fingerprint']}"
        print(url)
        
        # Gerar QR Code no terminal
        qr = qrcode.QRCode()
        qr.add_data(url)
        qr.print_ascii(invert=True)
    
    elif op == "pending_ticket":
        payload = decrypt_payload(packet["encrypted_user_payload"])
        print(payload)
    
    elif op == "pending_login":
        ticket = packet["ticket"]
        print("TICKET", ticket)
        
        # Fazer requisição para obter o token
        response = requests.post(
            "https://discord.com/api/v9/users/@me/remote-auth/login",
            json={"ticket": ticket},
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        )
        
        if response.status_code == 200:
            data = response.json()
            cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
            token = cipher.decrypt(base64.b64decode(data["encrypted_token"])).decode()
            print(f"\n{'='*50}")
            print(f"TOKEN: {token}")
            print(f"{'='*50}\n")
        else:
            print(f"Erro: {response.status_code}")
            print(response.json())
        
        ws.close()

def on_error(ws, error):
    print(f"Erro: {error}")

def on_close(ws, close_status_code, close_msg):
    print("Conexão fechada")

def on_open(ws):
    print("OPEN")

def main():
    # Configurar WebSocket
    ws_url = "wss://remote-auth-gateway.discord.gg/?v=2"
    
    websocket.enableTrace(False)
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
    
    # Executar WebSocket (bloqueante)
    ws.run_forever()

if __name__ == "__main__":
    main()
