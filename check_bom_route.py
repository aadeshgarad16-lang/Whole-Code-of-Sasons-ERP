import re
with open('c:\\Users\\USER\\Pictures\\Sasons_ERP\\App.py', 'r', encoding='utf-8') as f:
    text = f.read()

m = re.search(r'@app\.route\([\'\"]/api/bom(?:-calculations)?/.*?(?=@app\.route|if __name__)', text, flags=re.DOTALL)
if m:
    print('Found route:', m.group(0)[:1500])
else:
    print('Route not found')
