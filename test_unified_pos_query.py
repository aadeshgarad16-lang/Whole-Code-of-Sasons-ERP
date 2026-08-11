from Main import get_db_connection

conn = get_db_connection()
cur = conn.cursor(dictionary=True)

# Test the new unified query
query = """
SELECT 
    po.po_number,
    COALESCE(c.customer_name, po.contact_person, bd.customer_name, 'Unknown Customer') AS customer_name,
    po.stage,
    po.created_at,
    CASE WHEN bd.po_number IS NOT NULL THEN 1 ELSE 0 END AS has_bom_calculated
FROM purchase_orders po
LEFT JOIN customers c ON po.customer_id = c.customer_id
LEFT JOIN (
    SELECT DISTINCT po_number, MAX(customer_name) AS customer_name
    FROM bom_done
    GROUP BY po_number
) bd ON TRIM(po.po_number) = TRIM(bd.po_number)
WHERE po.stage IN (
    'Inventory Check', 'Material Allocation', 'Procurement',
    'Material Release', 'Production', 'Quality & Packing', 'Dispatched'
)
OR bd.po_number IS NOT NULL
ORDER BY po.created_at DESC
"""

cur.execute(query)
rows = cur.fetchall()
print(f"Total rows: {len(rows)}")
for r in rows:
    print(r)

cur.close()
conn.close()
