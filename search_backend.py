import os
import re

search_dir = r'c:\Users\USER\Pictures\Sasons_ERP'

for root, _, files in os.walk(search_dir):
    if '.venv' in root: continue
    for file in files:
        if file.endswith('.py'):
            path = os.path.join(root, file)
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
                if 'purchase-orders' in content or '/api/po' in content or '100' in content or 'Garment specification' in content or 'In House' in content:
                    print(f'Found in {path}')
