# qBittorrent Importer / Reseeder Tool

Match existing media files on disk to `.torrent` metadata and re-import those torrents into qBittorrent so they recheck and seed again — with correct save paths and categories.

This repo includes:
- `qb_import.py` — the importer/reseeder tool
- `config_wizard.py` — an interactive config generator with qB login + path read/write validation

> ⚠️ Legal note: Only use this tool with torrents you are allowed to download/seed.

---

## Features

- Indexes your media library recursively (TV/Animated folders supported)
- Matches torrents by **filename + size** to infer correct location and preserve structure
- Imports matched torrents into qBittorrent **paused** (so you can run hash check / start safely)
- Sets qBittorrent **category** based on media root (Movies/Series/Animated/Documentaries/etc.)
- Optional staging: copies `.torrent` files into a destination folder (e.g. NAS share)
- Maintenance mode: fix existing **uncategorized** torrents by inferring category from save paths

---

## Requirements

- Python 3.10+ (tested on Windows, works on Linux/macOS too)
- qBittorrent Web UI enabled and reachable on your LAN
- Python packages: `requests`, `tqdm`

Install deps:
```bash
pip install -r requirements.txt
