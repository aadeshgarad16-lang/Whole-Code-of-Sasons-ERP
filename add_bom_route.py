import re
with open('c:\\Users\\USER\\Pictures\\Sasons_ERP\\App.py', 'r', encoding='utf-8') as f:
    text = f.read()

new_route = """@app.route('/api/bom-calculations/<identifier>', methods=['GET'])
def get_bom_calculations(identifier):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        # Query garment_bom_calculations table by po_number, garment_name, or garment_id
        sql = '''
            SELECT 
                id,
                material_inventory,
                brand,
                selected_sizes,
                per_piece_qty,
                total_qty,
                per_unit_price,
                final_price,
                wastage_margin
            FROM garment_bom_calculations
            WHERE po_number = %s OR garment_name = %s OR garment_id = %s
        '''
        cursor.execute(sql, (identifier, identifier, identifier))
        results = cursor.fetchall()
        cursor.close()
        conn.close()
        
        materials = []
        for row in results:
            materials.append({
                "id": row["id"],
                "material_inventory": row["material_inventory"] or "",
                "brand": row["brand"] or "-",
                "selected_sizes": row["selected_sizes"] if isinstance(row["selected_sizes"], list) else (row["selected_sizes"].split(',') if row["selected_sizes"] else []),
                "per_piece_qty": float(row["per_piece_qty"] or 0),
                "total_qty": float(row["total_qty"] or 0),
                "per_unit_price": float(row["per_unit_price"] or 0),
                "final_price": float(row["final_price"] or 0),
                "wastage_margin": float(row["wastage_margin"] or 0)
            })

        return jsonify({"success": True, "materials": materials}), 200
    except Exception as e:
        return jsonify({"success": False, "materials": [], "error": str(e)}), 200

"""

# Insert the new route right before the calculate_bom route
target_index = text.find("@app.route('/api/bom/calculate/<po_number>'")
if target_index != -1:
    text = text[:target_index] + new_route + text[target_index:]
else:
    # If not found, append before if __name__ == '__main__':
    target_index = text.rfind("if __name__ == '__main__':")
    text = text[:target_index] + new_route + text[target_index:]

with open('c:\\Users\\USER\\Pictures\\Sasons_ERP\\App.py', 'w', encoding='utf-8') as f:
    f.write(text)

print("Added /api/bom-calculations/<identifier> route.")
