from flask import Flask, render_template, request, redirect, url_for
import os
from parser import parse_log
from analyzer import analyze_log

UPLOAD_FOLDER = 'uploads'
REPORT_FOLDER = 'reports'

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['REPORT_FOLDER'] = REPORT_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    if 'logfile' not in request.files:
        return redirect(url_for('index'))

    file = request.files['logfile']
    if file.filename == '':
        return redirect(url_for('index'))

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filepath)

    parsed_data = parse_log(filepath)
    analysis = analyze_log(parsed_data)

    report_path = os.path.join(app.config['REPORT_FOLDER'], file.filename + '_report.txt')
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(analysis)

    return render_template('report.html', report=analysis)

if __name__ == '__main__':
    app.run(debug=True)
