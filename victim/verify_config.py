import base64
import re
import os

try:
    with open("installer.py", "r") as f:
        content = f.read()
    
    match = re.search(r'PAYLOAD_B64 = "(.*?)"', content, re.DOTALL)
    if match:
        b64_str = match.group(1)
        decoded = base64.b64decode(b64_str).decode('utf-8')
        
        # Check C2 URL
        c2_match = re.search(r'C2_SERVER_URL = "(.*?)"', decoded)
        if c2_match:
            print(f"FOUND_C2_URL: {c2_match.group(1)}")
        else:
            print("C2 URL not found in payload.")
            
    else:
        print("Payload B64 not found in installer.py")
except Exception as e:
    print(f"Error: {e}")
