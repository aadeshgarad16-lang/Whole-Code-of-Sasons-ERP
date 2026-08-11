import re
with open('App.py', 'r', encoding='utf-8') as f:
    text = f.read()

m = re.search(r'@app\.route\([\'\"]/purchase_orders/details/<string:po_number>\'(?:.*?)def (.*?)(?=@app\.route|if __name__)', text, flags=re.DOTALL)
if m:
    print('Route found, chars 2000 to 4000:')
    print(m.group(0)[2000:4000])
