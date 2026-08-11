import re
with open('App.py', 'r', encoding='utf-8') as f:
    text = f.read()

for pattern in ['In House', 'Garment specification', 'Default', "'M'"]:
    if pattern in text:
        print(f'{pattern} found in App.py')
        for m in re.finditer(re.escape(pattern), text):
            print(text[max(0, m.start()-50):min(len(text), m.start()+50)])
