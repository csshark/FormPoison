# This is a simple flask server to test filename and XSS injections. It is recommended to test on outdated and vulnerable frameworks, but if you just want to test what does server see feel free to play here. 

from flask import Flask, request, render_template_string, send_from_directory
import os
import uuid

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

HTML_FORM = '''
<!DOCTYPE html>
<html>
<head>
    <title>XSS Simple Sandbox</title>
</head>
<body>
    <h1>File Upload - Test XSS</h1>
    
    <form action="/upload" method="post" enctype="multipart/form-data">
        <input type="file" name="file" required>
        <input type="submit" value="Upload">
    </form>

    <h2>Files uploaded:</h2>
    <ul>
        {% for file in files %}
            <li><a href="/files/{{ file }}">{{ file }}</a></li>
        {% endfor %}
    </ul>

    <h2>Test XSS - Enter text:</h2>
    <form action="/" method="get">
        <input type="text" name="input" placeholder="Try me">
        <input type="submit" value="Submit">
    </form>

    {% if user_input %}
        <h3>Your input:</h3>
        <div>{{ user_input|safe }}</div>
    {% endif %}
</body>
</html>
'''

@app.route('/')
def index():
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    user_input = request.args.get('input', '')
    return render_template_string(HTML_FORM, files=files, user_input=user_input)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'No file part'
    
    file = request.files['file']
    if file.filename == '':
        return 'No selected file'
    
    if file:
        # generate filename 
        filename = str(uuid.uuid4()) + '_' + file.filename
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return f'File uploaded successfully: <a href="/files/{filename}">{filename}</a>'

@app.route('/files/<filename>')
def serve_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
