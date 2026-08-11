import re

with open('App.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace all store_materials with store_articles
content = content.replace('store_materials', 'store_articles')
content = content.replace("data.get('material_name'),", "data.get('material_name') or data.get('article_name'),")

with open('App.py', 'w', encoding='utf-8') as f:
    f.write(content)
print('Replaced store_materials to store_articles')
