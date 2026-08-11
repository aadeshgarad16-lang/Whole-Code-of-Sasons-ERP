import main
conn = main.get_db_connection()
c = conn.cursor()
c.execute("UPDATE store_materials SET is_deleted = 1 WHERE hsn_code LIKE '%960621%' OR material_name LIKE '%Metal Buttons%'")
c.execute("UPDATE store_garments SET is_deleted = 1 WHERE hsn_code LIKE '%960621%'")
conn.commit()
print("Deleted rows:", c.rowcount)
