import re
with open('App.py', 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace("@app.route('/store_articles/dashboard', methods=['GET'])", "@app.route('/api/store/dashboard-meta', methods=['GET', 'OPTIONS'])\n@app.route('/store_articles/dashboard', methods=['GET'])")
content = content.replace("@app.route('/store_articles/view', methods=['GET', 'OPTIONS'])", "@app.route('/api/store/articles', methods=['GET', 'OPTIONS'])\n@app.route('/store_articles/view', methods=['GET', 'OPTIONS'])")

with open('App.py', 'w', encoding='utf-8') as f:
    f.write(content)
print('Updated routes in App.py')
