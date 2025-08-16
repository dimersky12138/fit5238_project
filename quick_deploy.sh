#!/bin/bash
# quick_deploy.sh - 本地一键部署脚本
# filepath: e:\StudySpace\MalwareDetection\Malware-Detection-using-Machine-learning\quick_deploy.sh

echo "🚀 Malware Detection System - Quick Deploy"
echo "========================================="

# 检查Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Please install Python 3.7+"
    exit 1
fi

echo "✅ Python $(python3 --version) found"

# 检查虚拟环境
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# 激活虚拟环境
echo "🔄 Activating virtual environment..."
source venv/bin/activate

# 选择部署类型
echo ""
echo "Choose deployment type:"
echo "1) 🖥️  Desktop GUI"
echo "2) 🌐 Web Interface"
echo "3) 💻 Command Line"
read -p "Enter choice (1-3): " choice

case $choice in
    1)
        echo "📥 Installing GUI dependencies..."
        pip install -r requirements.txt
        echo "🚀 Starting Desktop GUI..."
        python gui_main.py
        ;;
    2)
        echo "📥 Installing web dependencies..."
        pip install -r requirements_web.txt
        echo "🚀 Starting Web Interface..."
        echo "📱 Access at: http://localhost:5000"
        python web_app.py
        ;;
    3)
        echo "📥 Installing CLI dependencies..."
        pip install -r requirements.txt
        echo "🚀 Starting Command Line Interface..."
        python main.py
        ;;
    *)
        echo "❌ Invalid choice"
        exit 1
        ;;
esac