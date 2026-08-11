from Main import get_db_connection

conn = get_db_connection()
cur = conn.cursor(dictionary=True)

# Check customers table columns
cur.execute("SHOW COLUMNS FROM customers")
cust_cols = [r['Field'] for r in cur.fetchall()]
print("customers columns:", cust_cols)

# Check bom_done count
cur.execute("SELECT COUNT(*) as cnt FROM bom_done")
print("bom_done rows:", cur.fetchone())

# Check POs at Inventory Check stage
cur.execute("SELECT po_number, stage FROM purchase_orders WHERE LOWER(stage) LIKE '%inventory%'")
print("Inventory stage POs:", cur.fetchall())

# Try the fallback query
try:
    customer_name_col = 'customer_name' if 'customer_name' in cust_cols else cust_cols[1] if len(cust_cols) > 1 else 'customer_id'
    query = f"""
        SELECT DISTINCT po.po_number, 
               COALESCE(c.{customer_name_col}, po.contact_person, 'Customer') AS customer_name
        FROM purchase_orders po
        LEFT JOIN customers c ON po.customer_id = c.customer_id
        WHERE LOWER(TRIM(po.stage)) = 'inventory check'
    """
    cur.execute(query)
    rows = cur.fetchall()
    print(f"Fallback query results ({len(rows)}):", rows)
except Exception as e:
    print("Fallback query error:", e)

cur.close()
conn.close()
