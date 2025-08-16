# PE Malware Detection System - Installation Guide

## System Requirements

### Minimum System Requirements
- **Operating System**: Windows 10/11, Linux (Ubuntu 18.04+), macOS 10.14+
- **Python Version**: Python 3.7 - 3.10 (Recommended: Python 3.8)
- **Memory**: Minimum 4GB RAM (Recommended: 8GB+)
- **Disk Space**: 2GB available space

### Recommended Environment
- **Python**: 3.8.x or 3.9.x
- **Memory**: 8GB+ RAM
- **Processor**: Dual-core 2.5GHz+ (Recommended: Quad-core)

## Quick Installation

### 1. Clone the Project
```bash
git clone <repository-url>
cd Malware-Detection-using-Machine-learning
```

### 2. Create Virtual Environment (Recommended)
```bash
# Using conda
conda create -n malware-detection python=3.8
conda activate malware-detection

# Or using venv
python -m venv malware_env
# Windows
malware_env\Scripts\activate
# Linux/macOS
source malware_env/bin/activate
```

### 3. Install Dependencies
```bash
# Core dependencies
pip install -r requirements.txt

# For web interface
pip install -r requirements_web.txt
```

### 4. Quick Start Options

#### Option A: Desktop GUI (Recommended)
```bash
python gui_main.py
```

#### Option B: Web Interface
```bash
python web_app.py
# Access: http://localhost:5000
```

#### Option C: Command Line
```bash
python main.py
```

## Core Dependencies

### Required Dependencies
| Package | Version | Purpose |
|---------|---------|---------|
| scikit-learn | ==0.24.1 | Machine learning algorithms |
| pandas | Latest | Data processing and analysis |
| numpy | ==1.20.3 | Numerical computation |
| pefile | ==2019.4.18 | PE file parsing |
| joblib | ==1.0.1 | Model serialization |
| matplotlib | Latest | Data visualization |
| pyfiglet | Latest | ASCII art text |

### Web Interface Dependencies
| Package | Version | Purpose |
|---------|---------|---------|
| Flask | ==2.3.2 | Web framework |
| gunicorn | ==21.2.0 | Production server |
| Werkzeug | ==2.3.6 | WSGI utilities |

### Development Dependencies
| Package | Version | Purpose |
|---------|---------|---------|
| jupyter | ≥1.0.0 | Interactive development environment |
| notebook | ≥6.0.0 | Jupyter Notebook |
| seaborn | ≥0.11.0 | Advanced visualization |

## Known Compatibility Issues

### pefile Version Issues
- **Recommended Version**: 2019.4.18
- **Avoid Versions**: 2021.9.2+ (may cause parsing exceptions)
- **Solution**: If you encounter "Chained function entry cannot be changed" error, downgrade to recommended version

### Python Version Compatibility
- **Not Supported**: Python 3.6 and below
- **Not Recommended**: Python 3.11+ (some dependencies may be incompatible)
- **Best Choice**: Python 3.8.x

### Common File Access Issues
- **Locked Files**: Chrome.exe, Firefox.exe while browsers are running
- **Solution**: Use the "Copy file before detection" option in GUI
- **Alternative**: Close the target application before analysis

## Installation Verification

Run the following commands to verify successful installation:

```bash
# Check core dependencies
python -c "import sklearn, pandas, numpy, pefile, joblib, matplotlib; print('✅ All core dependencies installed successfully')"

# Test PE file parsing
python Extract/PE_main.py Dataset/chrome.exe

# Test GUI application
python gui_main.py

# Test web interface
python web_app.py
# Then visit: http://localhost:5000

# Test command line interface
python main.py
```

## Troubleshooting

### Common Issues

1. **ModuleNotFoundError: No module named 'pefile'**
   ```bash
   pip install pefile==2019.4.18
   ```

2. **pefile parsing error**
   ```bash
   pip uninstall pefile
   pip install pefile==2019.4.18
   ```

3. **scikit-learn version conflict**
   ```bash
   pip install scikit-learn==0.24.1
   ```

4. **Memory insufficient error**
   - Ensure system has enough available memory
   - Close other memory-intensive programs

5. **File access denied (Chrome.exe, etc.)**
   ```bash
   # Close the running application first, or
   # Use the GUI's "Copy file before detection" option
   ```

6. **Web interface not accessible**
   ```bash
   # Check if port 5000 is available
   netstat -an | grep 5000
   
   # Try different port
   python web_app.py --port 8080
   ```

### Getting Help
- Check [Issues](https://github.com/your-repo/issues) page
- Refer to project README.md
- Ensure all dependency versions meet requirements

## Updating Dependencies

```bash
# Update all packages to latest compatible versions
pip install --upgrade -r requirements.txt

# Or update specific packages
pip install --upgrade scikit-learn

# For web dependencies
pip install --upgrade -r requirements_web.txt
```

## Production Deployment

### Web Server Deployment
```bash
# Install production dependencies
pip install -r requirements_web.txt

# Run with Gunicorn (recommended for production)
gunicorn --bind 0.0.0.0:5000 --workers 4 wsgi:app

# Run with specific configuration
gunicorn --bind 0.0.0.0:8080 --workers 4 --timeout 120 wsgi:app
```

### Network Access
```bash
# For network access (LAN/WAN)
python web_app.py
# Access from other devices: http://YOUR_IP:5000

# For production with nginx
# Configure nginx reverse proxy to your app
```

## Development Environment Setup

If you need to modify code or train new models:

```bash
# Install development dependencies
pip install jupyter notebook ipykernel seaborn

# Start Jupyter Notebook
jupyter notebook

# Open ML_Model/PE.ipynb for model training
```

### IDE Configuration
```bash
# For VS Code users
pip install pylint black

# For PyCharm users - configure Python interpreter
# Point to your virtual environment's Python executable
```

### Model Training and Development
```bash
# Navigate to ML development directory
cd ML_Model

# Launch Jupyter for model experiments
jupyter notebook PE.ipynb

# For model retraining with new data
python retrain_model.py  # (if available)
```

## User Interface Options

### 1. Desktop GUI Application
- **File**: `gui_main.py`
- **Features**: Drag & drop, progress tracking, error handling
- **Best for**: Individual users, offline analysis

### 2. Web Interface
- **File**: `web_app.py`
- **Features**: Responsive design, concurrent users, API endpoints
- **Best for**: Team usage, remote access, integration

### 3. Command Line Interface
- **File**: `main.py`
- **Features**: Traditional CLI, scripting friendly
- **Best for**: Automation, batch processing, servers

## Security Considerations

### File Handling
- System creates temporary copies of files being analyzed
- Automatic cleanup of temporary files after analysis
- Safe handling of potentially malicious files

### Network Security
- Web interface runs on localhost by default
- Configure firewall rules for network access
- Use HTTPS in production environments

### Access Control
- No built-in authentication (add if needed)
- Consider implementing user sessions for multi-user environments
- Log access and analysis activities

---

## Quick Reference Commands

```bash
# Essential installation
pip install -r requirements.txt

# Run desktop GUI
python gui_main.py

# Run web interface
python web_app.py

# Run command line
python main.py

# Check system status
python -c "from web_app import model_loaded; print('Model loaded:', model_loaded)"

# Manual cleanup
curl http://localhost:5000/cleanup
```
