from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash
import os
from parser import parse_log
from analyzer import analyze_log, analyze_json_log
import json
from flask import render_template_string

UPLOAD_FOLDER = 'uploads'
REPORT_FOLDER = 'reports'

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['REPORT_FOLDER'] = REPORT_FOLDER
app.secret_key = 'your_secret_key'  # Needed for flashing messages

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

def is_file_extension_safe(filename):
    # Only allow .log, .json, .txt
    allowed_extensions = {'.txt', '.log', '.json'}
    ext = os.path.splitext(filename)[1].lower()
    return ext in allowed_extensions

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    if 'logfile' not in request.files:
        flash('No file part.')
        return redirect(url_for('index'))

    file = request.files['logfile']
    if file.filename == '':
        flash('No selected file.')
        return redirect(url_for('index'))

    if not is_file_extension_safe(file.filename):
        flash('❌ File type not allowed for security reasons. Only .log, .json, and .txt are accepted.')
        return redirect(url_for('index'))

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filepath)

    ext = os.path.splitext(filepath)[1].lower()

    try:
        if ext == '.json':
            parsed_data = parse_log(filepath)
            analysis = analyze_json_log(parsed_data.to_dict(orient='records'))
        elif ext == '.log':
            parsed_data = parse_log(filepath)
            if 'datetime' not in parsed_data.columns:
                flash('❌ Uploaded file does not have the required "datetime" column or is not in the correct log format.')
                os.remove(filepath)
                return redirect(url_for('index'))
            analysis = analyze_log(parsed_data)
        elif ext == '.txt':
            try:
                # Try to parse as log (CSV/TSV)
                parsed_data = parse_log(filepath)
                if 'datetime' in parsed_data.columns:
                    analysis = analyze_log(parsed_data)
                else:
                    raise ValueError("No datetime column")
            except Exception:
                # Try to parse as JSON log
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        json_data = json.loads(content)
                        analysis = analyze_json_log(json_data)
                except Exception:
                    # Not a log, not JSON: show as plain text
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        analysis = "Plain text file content:\n\n" + f.read()
        else:
            flash('❌ Unsupported file type.')
            os.remove(filepath)
            return redirect(url_for('index'))
    except Exception as e:
        flash(f'❌ Error processing file: {str(e)}')
        if os.path.exists(filepath):
            os.remove(filepath)
        return redirect(url_for('index'))

    report_filename = file.filename + '_report.html'
    report_path = os.path.join(app.config['REPORT_FOLDER'], report_filename)

    # For browser view (show buttons)
    rendered_html = render_template(
        'report.html',
        report=analysis,
        report_filename=report_filename,
        download=False
    )

    # For saving the downloadable HTML (hide buttons, inline CSS)
    with open(os.path.join('static', 'report.css'), 'r', encoding='utf-8') as f:
        css_content = f.read()
    font_link = '<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;700;800&display=swap" rel="stylesheet">'
    rendered_html_download = render_template(
        'report.html',
        report=analysis,
        report_filename=report_filename,
        download=True,
        inline_css=css_content,
        font_link=font_link
    )
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(rendered_html_download)

    return rendered_html

@app.route('/download/<filename>')
def download_report(filename):
    return send_from_directory(app.config['REPORT_FOLDER'], filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
