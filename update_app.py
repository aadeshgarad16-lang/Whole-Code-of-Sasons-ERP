import re
with open('App.py', 'r', encoding='utf-8') as f:
    text = f.read()

old_logic = """        # CORE FIX: If the specification row is missing a quantity, 
        # pull the quantity or pieces directly from the parent purchase order!
        fallback_qty = po_data.get('total_pieces') or po_data.get('quantity') or 100 # DO NOT fallback to total_value
        
        for spec in specs:
            if not spec.get('quantity') or spec['quantity'] == 0:
                spec['quantity'] = fallback_qty  # Force the 0 to become the real order size!"""

new_logic = """        # CORE FIX: If the specification row is missing a quantity, 
        # pull the quantity or pieces directly from the parent purchase order!
        fallback_qty = po_data.get('total_pieces') or po_data.get('quantity') or None
        
        for spec in specs:
            if not spec.get('quantity') or spec['quantity'] == 0:
                spec['quantity'] = fallback_qty  # Allow None instead of 100"""

text = text.replace(old_logic, new_logic)

with open('App.py', 'w', encoding='utf-8') as f:
    f.write(text)

print('App.py updated')
