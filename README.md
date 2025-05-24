# RT-SRT - RedTeam Stealth Recon Tool

## ⚠️ Educational Purpose Only
This tool is developed strictly for educational purposes and authorized security testing. Unauthorized use is prohibited.

## 📋 Overview
RT-SRT is a modular reconnaissance tool designed for red team operations and security assessments. It demonstrates advanced techniques for data collection while maintaining operational security.

## 🏗️ Project Structure
```
RT-SRT/
├── agent/          # Client-side component (C++)
├── server/         # Server-side component (Python)
├── build/          # Build output directory
├── scripts/        # Build and deployment scripts
└── docs/           # Documentation
```

## 🚀 Quick Start

### Prerequisites
- CMake 3.16+
- C++ compiler (MSVC, GCC, or Clang)
- Python 3.8+
- UPX (optional, for binary packing)

### Building the Project

```bash
# Clone the repository
git clone <repository-url>
cd RT-SRT

# Make build script executable
chmod +x scripts/build.sh

# Build everything
./scripts/build.sh

# Or build specific configuration
./scripts/build.sh Release
```

### Running the Server

```bash
cd server
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Run the server
python src/web_panel/app.py
```

## 📊 Size Constraints
- Agent binary: < 150KB (after packing)
- Optimized for minimal footprint
- No external dependencies in agent

## 🔧 Development

### Agent Development
```bash
cd agent
# Edit source files in src/
# Rebuild: cmake --build ../build/agent
```

### Server Development
```bash
cd server
# Activate virtual environment
source venv/bin/activate
# Run with auto-reload
uvicorn src.web_panel.app:app --reload
```

## 📚 Documentation
- [Architecture](docs/architecture.md)
- [Usage Guide](docs/usage.md)
- [Troubleshooting](docs/troubleshooting.md)

## 🧪 Testing
```bash
# Run agent tests
cd build/agent && ctest

# Run server tests
cd server && pytest
```

## 📦 Distribution
After building, find the distribution package in `dist/` directory:
- `rt_srt_agent` - Compiled agent binary
- `server/` - Server components
- `README.md` - Deployment instructions

## ⚖️ Legal Notice
This software is provided for educational and authorized testing purposes only. Users are responsible for complying with all applicable laws and regulations.

## 🤝 Contributing
This is an educational project. Contributions should focus on improving security awareness and defensive capabilities.# rt-srt
# rt-srt
