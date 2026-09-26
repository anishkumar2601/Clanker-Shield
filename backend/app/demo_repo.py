"""
Builds the built-in demo repository on disk at scan time.

The demo repository is intentionally vulnerable but harmless: every flaw is
inert (no real database, no real network calls) and exists purely so
ClankerShield has real, deterministic findings to detect and patch.
"""
from __future__ import annotations

import os

FILES: dict[str, str] = {
    "README.md": (
        "# Clanker Demo Service\n\n"
        "A small internal API used to exercise ClankerShield's scanners.\n"
        "This code is intentionally insecure. Do not deploy it.\n"
    ),
    "requirements.txt": (
        "flask==0.12\n"
        "django==1.11\n"
        "requests==2.6.0\n"
        "pyyaml==3.13\n"
    ),
    "app/__init__.py": "",
    "app/config.py": (
        "# Application configuration\n"
        "\n"
        "DEBUG = True\n"
        "\n"
        "ALLOWED_ORIGINS = \"*\"\n"
        "\n"
        "STRIPE_API_KEY = \"sk_live_51Hc9f3KZ8mQnJvTgYxAbCdEf00112233\"\n"
        "\n"
        "DATABASE_URL = \"postgres://clanker:hunter2@db.internal:5432/clanker_prod\"\n"
    ),
    "app/database.py": (
        "import sqlite3\n"
        "\n"
        "\n"
        "def get_connection():\n"
        "    return sqlite3.connect(\"clanker_demo.db\")\n"
        "\n"
        "\n"
        "def find_user_by_name(username):\n"
        "    conn = get_connection()\n"
        "    cursor = conn.cursor()\n"
        "    query = f\"SELECT id, username, role FROM users WHERE username = '{username}'\"\n"
        "    cursor.execute(query)\n"
        "    return cursor.fetchone()\n"
        "\n"
        "\n"
        "def search_orders(term):\n"
        "    conn = get_connection()\n"
        "    cursor = conn.cursor()\n"
        "    query = \"SELECT * FROM orders WHERE note LIKE '%\" + term + \"%'\"\n"
        "    cursor.execute(query)\n"
        "    return cursor.fetchall()\n"
    ),
    "app/utils.py": (
        "import os\n"
        "import subprocess\n"
        "\n"
        "\n"
        "def generate_thumbnail(filename):\n"
        "    os.system(\"convert \" + filename + \" -resize 200x200 thumb_\" + filename)\n"
        "\n"
        "\n"
        "def run_backup(target_dir):\n"
        "    subprocess.call(\"tar -czf backup.tar.gz \" + target_dir, shell=True)\n"
    ),
    "app/auth.py": (
        "import hashlib\n"
        "import jwt\n"
        "\n"
        "\n"
        "def hash_password(password):\n"
        "    return hashlib.md5(password.encode()).hexdigest()\n"
        "\n"
        "\n"
        "def decode_token(token):\n"
        "    return jwt.decode(token, options={\"verify_signature\": False})\n"
        "\n"
        "\n"
        "GITHUB_TOKEN = \"ghp_9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e\"\n"
    ),
    "app/files.py": (
        "import os\n"
        "\n"
        "\n"
        "def read_user_file(base_dir, requested_path):\n"
        "    full_path = os.path.join(base_dir, requested_path)\n"
        "    with open(full_path, \"r\") as handle:\n"
        "        return handle.read()\n"
    ),
    "app/routes.py": (
        "from flask import Flask, request, jsonify\n"
        "\n"
        "from app.database import find_user_by_name, search_orders\n"
        "from app.files import read_user_file\n"
        "from app.utils import generate_thumbnail\n"
        "\n"
        "app = Flask(__name__)\n"
        "\n"
        "\n"
        "@app.route(\"/api/users\")\n"
        "def get_user():\n"
        "    username = request.args.get(\"username\")\n"
        "    return jsonify(find_user_by_name(username))\n"
        "\n"
        "\n"
        "@app.route(\"/api/orders/search\")\n"
        "def orders_search():\n"
        "    term = request.args.get(\"q\")\n"
        "    return jsonify(search_orders(term))\n"
        "\n"
        "\n"
        "@app.route(\"/api/files\")\n"
        "def get_file():\n"
        "    path = request.args.get(\"path\")\n"
        "    return read_user_file(\"/srv/uploads\", path)\n"
        "\n"
        "\n"
        "@app.route(\"/api/thumbnail\")\n"
        "def thumbnail():\n"
        "    filename = request.args.get(\"filename\")\n"
        "    generate_thumbnail(filename)\n"
        "    return jsonify({\"status\": \"ok\"})\n"
    ),
    "frontend/render.js": (
        "export function renderComment(container, comment) {\n"
        "  container.innerHTML = '<p>' + comment.body + '</p>';\n"
        "}\n"
        "\n"
        "export function renderProfile(node, profile) {\n"
        "  node.dangerouslySetInnerHTML = { __html: profile.bio };\n"
        "}\n"
    ),
    "tests/__init__.py": "",
    "tests/test_basic.py": (
        "def test_placeholder():\n"
        "    assert True\n"
    ),
}


def materialize_demo_repository(destination_dir: str) -> int:
    """Writes the demo repository files to disk. Returns the file count."""
    for relative_path, content in FILES.items():
        full_path = os.path.join(destination_dir, relative_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w", encoding="utf-8") as handle:
            handle.write(content)
    return len(FILES)
