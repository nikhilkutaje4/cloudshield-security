import urllib.request
import os

def download_nsl_kdd():
    """Download NSL-KDD dataset from GitHub mirror"""
    
    os.makedirs('ids/data', exist_ok=True)
    
    files = {
        'KDDTrain+.txt': 'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt',
        'KDDTest+.txt': 'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt'
    }
    
    for filename, url in files.items():
        filepath = os.path.join('ids/data', filename)
        
        if os.path.exists(filepath):
            print(f"[✓] {filename} already exists")
            continue
        
        print(f"[↓] Downloading {filename}...")
        try:
            urllib.request.urlretrieve(url, filepath)
            size_mb = os.path.getsize(filepath) / (1024 * 1024)
            print(f"[✓] Downloaded {filename} ({size_mb:.2f} MB)")
        except Exception as e:
            print(f"[✗] Failed to download {filename}: {e}")
            return False
    
    print("\n[✓] Dataset ready!")
    return True

if __name__ == '__main__':
    download_nsl_kdd()