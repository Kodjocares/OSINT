# Quick Setup Guide

Get OSINT Tool running in under 5 minutes.

## 1. Clone & enter

```bash
git clone https://github.com/YOUR_USERNAME/osint-tool.git
cd osint-tool
```

## 2. Create virtual environment

```bash
# Linux / macOS
python3 -m venv venv && source venv/bin/activate

# Windows
python -m venv venv && venv\Scripts\activate
```

## 3. Install

```bash
pip install -r requirements.txt
```

## 4. Configure

```bash
cp .env.example .env
# Edit .env — all API keys are optional
```

## 5. Run

```bash
python main.py              # interactive menu (recommended)
python main.py --domain example.com   # CLI mode
python main.py --anonymity            # verify setup
```

## Optional: Install Tesseract OCR (for image text extraction)

```bash
# Ubuntu/Debian
sudo apt install tesseract-ocr && pip install pytesseract

# macOS
brew install tesseract && pip install pytesseract
```

## Optional: Enable Tor routing

```bash
sudo apt install tor && sudo service tor start   # Ubuntu
# Then set USE_TOR=true in .env
```

## Optional: Install dev tools

```bash
pip install -r requirements-dev.txt
pre-commit install
```

---

See [README.md](README.md) for the full module reference and CLI command list.
