import json
import os
import shutil

# 1. Define where drafts are and where published contracts go
SOURCE_DIR = "ocsf_normalizer/src/contracts/schemas/"
REGISTRY_DIR = "shared_registry/v1/"

def publish(filename):
    source_path = os.path.join(SOURCE_DIR, filename)
    destination_path = os.path.join(REGISTRY_DIR, filename)
    
    # Check if the file actually exists
    if not os.path.exists(source_path):
        print(f"[-] Error: Contract draft '{filename}' not found in source directory.")
        return
        
    try:
        # Validate that the file is proper JSON before publishing
        with open(source_path, 'r') as file:
            json.load(file)
            
        # Ensure the registry directory exists
        os.makedirs(REGISTRY_DIR, exist_ok=True)
        
        # Copy file to publish it
        shutil.copy2(source_path, destination_path)
        print(f"[+] Success! '{filename}' has been officially published to the registry.")
        
    except json.JSONDecodeError:
        print(f"[-] Critical: '{filename}' contains invalid JSON formatting. Publishing aborted.")

if __name__ == "__main__":
    # When your friend drops a file like 'windows_auth.json' in the folder, 
    # you just type its name here to publish it!
    publish("windows_auth.json")