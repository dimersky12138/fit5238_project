# web_app.py
from flask import Flask, request, render_template, jsonify
import os
import sys
import time
import tempfile
import uuid
from werkzeug.utils import secure_filename

# Use existing code
sys.path.append('Extract')
from Extract.PE_main import extract_infos
import joblib
import pickle

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB

# Create dedicated upload directory
UPLOAD_FOLDER = 'temp_uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Load model (using existing model files)
try:
    clf = joblib.load('Classifier/classifier.pkl')
    features = pickle.loads(open('Classifier/features.pkl', 'rb').read())
    model_loaded = True
    print("✅ Model loaded successfully")
except Exception as e:
    print(f"❌ Model loading failed: {e}")
    clf = None
    features = None
    model_loaded = False


@app.route('/')
def index():
    return render_template('index.html', model_status=model_loaded)


@app.route('/detect', methods=['POST'])
def detect():
    if not model_loaded:
        return jsonify({'error': 'Model not loaded'}), 500

    if 'file' not in request.files:
        return jsonify({'error': 'No file selected'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not file.filename.lower().endswith(('.exe', '.dll', '.sys')):
        return jsonify({'error': 'Unsupported file type, only .exe, .dll, .sys are allowed'}), 400

    temp_path = None
    try:
        # Generate unique filename to avoid conflicts
        original_filename = secure_filename(file.filename)
        file_extension = os.path.splitext(original_filename)[1]
        unique_filename = f"{uuid.uuid4().hex}_{original_filename}"
        temp_path = os.path.join(UPLOAD_FOLDER, unique_filename)

        # Ensure directory exists
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)

        # Save file
        print(f"📁 Saving file to: {temp_path}")
        file.save(temp_path)

        # Check if file saved successfully
        if not os.path.exists(temp_path):
            return jsonify({'error': 'File saving failed'}), 500

        start_time = time.time()
        print(f"🔍 Analyzing file: {original_filename}")

        # Use existing detection logic
        data = extract_infos(temp_path)
        pe_features = list(map(lambda x: data.get(x, 0), features))
        res = clf.predict([pe_features])[0]
        prob = clf.predict_proba([pe_features])[0]

        end_time = time.time()

        # Return result
        result = {
            'filename': original_filename,
            'result': 'Legitimate file' if res == 1 else 'Malware',
            'confidence': float(max(prob)) * 100,
            'prob_malicious': float(prob[0]) * 100,
            'prob_legitimate': float(prob[1]) * 100,
            'analysis_time': round(end_time - start_time, 2),
            'file_size': os.path.getsize(temp_path) if os.path.exists(temp_path) else 0
        }

        print(f"✅ Detection complete: {result['result']} (Confidence: {result['confidence']:.1f}%)")
        return jsonify(result)

    except Exception as e:
        print(f"❌ Detection failed: {str(e)}")
        return jsonify({'error': f'Detection failed: {str(e)}'}), 500

    finally:
        # Safely clean up temp files
        if temp_path and os.path.exists(temp_path):
            try:
                time.sleep(0.1)  # Ensure file is not being used
                os.remove(temp_path)
                print(f"🗑️ Temp file deleted: {temp_path}")
            except PermissionError:
                print(f"⚠️ Cannot delete temp file: {temp_path} (Permission denied)")
            except Exception as cleanup_error:
                print(f"⚠️ Error while deleting temp file: {cleanup_error}")


@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'ok',
        'model_loaded': model_loaded,
        'temp_folder': UPLOAD_FOLDER
    })


if __name__ == '__main__':
    print("🚀 Starting web-based malware detection system...")
    print(f"📁 Temp file directory: {os.path.abspath(UPLOAD_FOLDER)}")
    print("📱 Local access: http://localhost:5000")
    print("🌐 Network access: http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)