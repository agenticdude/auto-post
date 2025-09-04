# Google Drive Video Processor (Streamlit + FFmpeg)

Process videos **one-by-one** from a Google Drive **source folder** using **FFmpeg**, and upload results to a **destination folder** — all via a simple Streamlit UI.

---

## ✨ Features
- Google sign-in (OAuth) — lists **all your Drive folders**
- Select **Source** folder (download) and **Destination** folder (upload)
- Provide your own **FFmpeg command template** (with `{input}` / `{output}`)
- Shows **progress**, **counts**, and a **live results table**
- Stores OAuth token locally (no need to log in every time)
- Sequential processing (one-by-one)

---

## 📦 Project Layout
```
.
├── app.py
├── requirements.txt
├── .env.example
└── (place your client_secret.json here)
```

---

## 🔐 Credentials (one `.env` place for everything)
1. Create a copy of `.env.example` as `.env` and adjust values if needed:
   ```env
   GOOGLE_OAUTH_CLIENT_SECRETS=client_secret.json
   GOOGLE_OAUTH_TOKEN_DIR=.tokens
   #FFMPEG_COMMAND_TEMPLATE=ffmpeg -y -i "{input}" -vf "scale=1280:-2" -c:v libx264 -preset veryfast -crf 23 -c:a aac -b:a 128k "{output}"
   ```
2. Download **OAuth client credentials** from the Google Cloud Console:
   - Go to **APIs & Services → Credentials → Create Credentials → OAuth client ID**
   - Application type: **Desktop app** (Installed app)
   - Download the JSON as `client_secret.json` and place it in the project folder (or change the path in `.env`).

> **Why OAuth (Installed App)?** Service Accounts usually **can't** access your personal Drive unless you share folders with them or use a Google Workspace domain with domain-wide delegation. OAuth is the simplest for personal Drives.

---

## 🛠️ Local Setup (Linux/Mac/WSL recommended)

```bash
# 1) Clone/copy the project
cd gdrive_ffmpeg_streamlit

# 2) Python environment
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 3) Install deps
pip install -r requirements.txt

# 4) FFmpeg (install & ensure it's on PATH)
# Ubuntu/Debian:
sudo apt-get update && sudo apt-get install -y ffmpeg
# macOS (Homebrew):
brew install ffmpeg
# Windows (choco):
choco install ffmpeg

# 5) Put your OAuth file
cp /path/to/client_secret.json ./client_secret.json

# 6) (Optional) Configure .env
cp .env.example .env
# edit if needed

# 7) Run
streamlit run app.py
```

On first run, a browser window opens. Sign in and approve access to your Drive.  
A `token.json` is created in `GOOGLE_OAUTH_TOKEN_DIR` so future runs don't require sign-in.

---

## ▶️ Using the App
1. **Authenticate** → click the button and complete Google sign-in.
2. **Load Folders** → fetches all your Drive folders.
3. Pick **Source** and **Destination** folders.
4. Optionally edit the **FFmpeg command template** (must include `{input}` and `{output}`).
5. Click **Start Processing** — it will:
   - download a video from Source,
   - run FFmpeg,
   - upload the processed file to Destination.
6. Watch the **progress bar** and **results table** update live.

**Output filename**: original name + `_processed` + selected extension (default: `.mp4`).

---

## 🧪 Example FFmpeg Commands
- Re-encode H.264 + scale to 1280 width:
  ```bash
  ffmpeg -y -i "{input}" -vf "scale=1280:-2" -c:v libx264 -preset veryfast -crf 23 -c:a aac -b:a 128k "{output}"
  ```
- Add a watermark (top-right) and boost audio:
  ```bash
  ffmpeg -y -i "{input}" -i watermark.png -filter_complex "overlay=W-w-10:10" -af "volume=1.2" -c:v libx264 -crf 22 -c:a aac "{output}"
  ```
- Pad + drawtext (requires a valid font on your system):
  ```bash
  ffmpeg -y -i "{input}" -vf "pad=iw:ih+200:0:0:white,drawtext=text='Wood Whisperer':x=(w-text_w)/2:y=h-150:fontcolor=#A0522D:fontsize=48" -af "volume=1.2" "{output}"
  ```

> If you get a font error on `drawtext`, specify a font file: `:fontfile=/path/to/YourFont.ttf`

---

## 🧯 Troubleshooting
- **ffmpeg: not found** → install FFmpeg and ensure it's on PATH.
- **Google auth fails** → delete the token and re-auth: remove the `GOOGLE_OAUTH_TOKEN_DIR` folder or click **Clear Token** in the app.
- **Permission errors uploading** → ensure you have write access to the **Destination** folder.
- **Long filter strings** → keep the quotes in your template exactly as in examples; they are preserved by the app when executing FFmpeg.

---

## 🔒 Security Notes
- This app executes an FFmpeg command you provide. Only use it on a trusted machine.
- OAuth tokens are stored locally under `GOOGLE_OAUTH_TOKEN_DIR`. Handle them like passwords.

---

## 🚀 Deploy on Local Server (Persistent)
- Run Streamlit in **headless** mode behind a reverse proxy (optional):
  ```bash
  streamlit run app.py --server.headless true --server.port 8501
  ```
- Use **systemd** to keep it alive (Linux):
  ```ini
  # /etc/systemd/system/drive-ffmpeg.service
  [Unit]
  Description=Drive FFmpeg Streamlit
  After=network.target

  [Service]
  Type=simple
  WorkingDirectory=/path/to/gdrive_ffmpeg_streamlit
  ExecStart=/path/to/gdrive_ffmpeg_streamlit/.venv/bin/streamlit run app.py --server.port 8501 --server.headless true
  Restart=always
  Environment="GOOGLE_OAUTH_CLIENT_SECRETS=/path/to/client_secret.json"
  Environment="GOOGLE_OAUTH_TOKEN_DIR=/path/to/.tokens"

  [Install]
  WantedBy=multi-user.target
  ```
  ```bash
  sudo systemctl daemon-reload
  sudo systemctl enable --now drive-ffmpeg
  ```

---

## ❓ FAQ
**Can I use a Service Account?**  
Only if your folders are owned by a Workspace domain admin with domain-wide delegation, or you share the specific folders with the service account. Otherwise, stick with OAuth Installed App.

**Will it process in parallel?**  
No — by design it processes **one-by-one** to match your requirement and to avoid rate limits.

**Can I resume?**  
Rerun with the same Source; already uploaded outputs won't be overwritten unless they have identical names. You can tweak naming logic if needed.
