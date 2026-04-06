
from flask import Flask, render_template, request, jsonify
from detector.analyzer import analyze_url

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def home():
    result = None
    submitted_url = ''
    if request.method == 'POST':
        submitted_url = request.form.get('url', '').strip()
        if submitted_url:
            result = analyze_url(submitted_url)
    return render_template('index.html', result=result, submitted_url=submitted_url)

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json(silent=True) or {}
    url = (data.get('url') or '').strip()
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    return jsonify(analyze_url(url))

if __name__ == '__main__':
    app.run(debug=True)
