import os
import hashlib

def calculate_sha256(file_path):
    if not os.path.isfile(file_path):
        return("error: file path does not exists")
    
    with open(file_path, "rb") as file:
        content = file.read()

    result = hashlib.sha256(content).hexdigest()

    return result