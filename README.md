# Unlimited Cloud Storage

[![Docker Build CI](https://github.com/AIGenOps/unlimited-cloud-storage/actions/workflows/docker-ci.yml/badge.svg)](https://github.com/AIGenOps/unlimited-cloud-storage/actions/workflows/docker-ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

An enterprise-grade, encrypted, unlimited cloud storage platform powered by Telegram infrastructure and Flask. Designed and maintained by AIGenOps.

---

## Key Features

- **Unlimited Cloud Capacity**: Store unlimited files, videos, documents, and archives using private Telegram Channel infrastructure.
- **AES-256 Binary Encryption**: Client-side and server-side encryption secures all file streams prior to transmission.
- **Automated Large File Chunking**: Files exceeding Telegram single-file limits are automatically partitioned into 19.5 MB chunk parts and seamlessly reassembled during preview or download.
- **Real-Time NDJSON Streaming Progress**: Real-time progress bar tracking for single and multi-part concurrent uploads.
- **Mobile-First PWA & Responsive Interface**: Optimized mobile app interface complete with fixed bottom tab navigation, touch-friendly file cards, and a quick upload floating action button (FAB).
- **Interactive Onboarding & Info System**: Built-in feature tour powered by Driver.js and comprehensive capability modal.
- **Storage Analytics & Deduplication**: Dashboard with storage pie chart breakdowns, largest file rankings, duplicate file scanner, and folder space calculation.
- **Telegram Bot Integration**: Native bot listener supporting `/storage`, `/search`, `/backup`, and `/sync` commands.
- **CLI Backup & Sync Utility**: Standalone Python CLI (`backupper.py`) for automated folder synchronization and remote directory backups.

---

## Quick Start

### 1. Prerequisites

- Python 3.10 or higher (or Docker & Docker Compose)
- A Telegram Bot token (from BotFather)
- A Private Telegram Channel with your bot added as Administrator

### 2. Environment Configuration

Create a `.env` file in the project root directory:

```env
API_KEY="your_telegram_bot_api_token"
CHANNEL_ID="-100xxxxxxxxx"
APP_USER_NAME="admin"
APP_PASSWORD="your_secure_password"
FILE_ENCRYPTION="True"
ENABLE_SSL="False"
LOGGING_LEVEL="INFO"
```

---

## Deployment Options

### Option A: Docker Compose (Recommended)

Run the application as an isolated container:

```bash
docker compose up --build -d
```

Access the interface at `http://localhost:5000` (or `https://localhost` if SSL is enabled).

### Option B: Local Python Setup

```bash
pip install -r requirements.txt
python bot.py
```

---

## Telegram Bot Commands

When running the background bot listener, interact with your cloud storage directly inside Telegram:

| Command | Description |
| :--- | :--- |
| `/storage` | Display storage metrics (total files, subfolders, space consumed) |
| `/search <filename>` | Search catalog for matching file names |
| `/backup` | Backup `schema.json` catalog directly to your Telegram storage channel |
| `/sync` | Scan channel messages and auto-import external uploads into catalog |

---

## Command Line Interface (CLI Tool)

Manage local-to-cloud directory synchronization using `backupper.py`:

### Upload Local Directory to Cloud

```bash
python backupper.py upload --path "/path/to/local/folder" --path_in_server "Backups/2026"
```

### Download Directory from Cloud

```bash
python backupper.py download --path_in_server "Backups/2026" --path "./Downloads"
```

### Dry Run Mode

Verify upload/download plans before execution:

```bash
python backupper.py upload --path "/path/to/folder" --dry_run
```

---

## Security & Architecture

1. **Schema Metadata Persistence**: File catalog records are stored in `schema/schema.json` and persisted across restarts.
2. **End-to-End Encryption**: When `FILE_ENCRYPTION=True` is set, binary data is encrypted prior to sending to Telegram API endpoints.
3. **Data Integrity**: Built-in re-validation feature verifies local catalog records against live Telegram channel storage.

---

## Author & Maintainer

Developed and maintained by **AIGenOps**.

License: MIT
