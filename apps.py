# app.py
# Streamlit app: Drive → Multi-Channel YouTube Scheduler + Calendar (Unlimited)
# Safe rerun handling, improved DB/PBKDF2, oauth fixups, strong validation and safer UI flows.
# MODIFIED: Immediate download/upload to YouTube upon scheduling.

import os
import json
import sqlite3
import tempfile
import hashlib
import binascii
from datetime import datetime, date, time as dtime, timedelta, timezone
from typing import Optional, List, Tuple

import streamlit as st
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseDownload, MediaFileUpload

# -----------------------------
# Configuration
# -----------------------------
SCOPES = [
    "https://www.googleapis.com/auth/drive.readonly",
    "https://www.googleapis.com/auth/youtube.upload",
    "https://www.googleapis.com/auth/youtube",
    "https://www.googleapis.com/auth/calendar.events",
]
CLIENT_SECRET_FILE = "client_secret.json"
# MODIFIED: Use persistent DB path in production
ENV = os.environ.get("ENV", "dev")
DB_PATH = "/app/data/scheduler.db" if ENV == "prod" else "scheduler.db"
APP_URL = os.environ.get("APP_URL", "https://app.agenticdudes.com/")

# -----------------------------
# Safe rerun helper
# -----------------------------
def trigger_rerun():
    st.session_state["_triggered_rerun"] = True
    st.rerun()

# -----------------------------
# Simple PBKDF2 password hashing
# -----------------------------
def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return salt, dk

def verify_password(password: str, salt: bytes, dk: bytes) -> bool:
    check = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return binascii.hexlify(check) == binascii.hexlify(dk)

# -----------------------------
# Database helpers
# -----------------------------
def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            label TEXT NOT NULL,
            channel_id TEXT,
            channel_title TEXT,
            token_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            channel_id INTEGER NOT NULL,
            drive_file_id TEXT NOT NULL,
            drive_file_name TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            tags TEXT,
            category_id TEXT,
            made_for_kids INTEGER NOT NULL DEFAULT 0,
            publish_at_utc TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued',
            youtube_video_id TEXT,
            calendar_event_id TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            FOREIGN KEY(channel_id) REFERENCES channels(id) ON DELETE CASCADE
        );
    """)
    conn.commit()
    conn.close()

# -----------------------------
# User auth functions
# -----------------------------
def create_user(username: str, password: str) -> bool:
    username = username.strip()
    if not username or not password:
        return False
    salt, dk = hash_password(password)
    salt_hex = binascii.hexlify(salt).decode()
    dk_hex = binascii.hexlify(dk).decode()
    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO users (username, salt, password_hash, created_at) VALUES (?,?,?,?)",
            (username, salt_hex, dk_hex, datetime.utcnow().isoformat() + "Z")
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def authenticate_user(username: str, password: str) -> Optional[int]:
    conn = get_conn()
    row = conn.execute("SELECT id, salt, password_hash FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    if not row:
        return None
    salt = binascii.unhexlify(row["salt"])
    dk = binascii.unhexlify(row["password_hash"])
    if verify_password(password, salt, dk):
        return int(row["id"])
    return None

def get_username(user_id: int) -> Optional[str]:
    conn = get_conn()
    row = conn.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    return row["username"] if row else None

# -----------------------------
# OAuth helpers
# -----------------------------
def ensure_client_secret_file():
    if os.path.exists(CLIENT_SECRET_FILE):
        return
    cfg = None
    try:
        cfg = st.secrets.get("google_oauth_client") if hasattr(st, "secrets") else None
    except Exception:
        cfg = None
    if cfg:
        data = json.loads(cfg) if isinstance(cfg, str) else dict(cfg)
        with open(CLIENT_SECRET_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f)
    elif ENV == "prod":
        st.error("Google OAuth secrets not found in st.secrets or file.")

def creds_from_json(token_json: str) -> Credentials:
    return Credentials.from_authorized_user_info(json.loads(token_json), scopes=SCOPES)

def creds_to_json(creds: Credentials) -> str:
    return creds.to_json()

def flow_local_desktop() -> Optional[Credentials]:
    from google_auth_oauthlib.flow import InstalledAppFlow
    ensure_client_secret_file()
    flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRET_FILE, SCOPES)
    creds = flow.run_local_server(port=0, prompt="consent")
    return creds

def flow_web_redirect() -> Optional[Credentials]:
    ensure_client_secret_file()
    redirect_uri = os.environ.get("PUBLIC_URL", APP_URL)
    qp = st.experimental_get_query_params()
    if "redirect_uri" in qp and qp["redirect_uri"]:
        redirect_uri = qp["redirect_uri"][0]
    flow = Flow.from_client_secrets_file(CLIENT_SECRET_FILE, scopes=SCOPES, redirect_uri=redirect_uri)
    if "code" in qp:
        try:
            flow.fetch_token(code=qp["code"][0])
            return flow.credentials
        except Exception as e:
            st.error(f"OAuth error: {e}")
            return None
    auth_url, _ = flow.authorization_url(access_type="offline", include_granted_scopes="true", prompt="consent")
    st.markdown(f"[Connect Google]({auth_url})")
    return None

# -----------------------------
# Google service builders
# -----------------------------
def build_services(creds: Credentials):
    drive = build("drive", "v3", credentials=creds)
    yt = build("youtube", "v3", credentials=creds)
    cal = build("calendar", "v3", credentials=creds)
    return drive, yt, cal

# -----------------------------
# Drive helpers
# -----------------------------
def list_folders(drive, parent_id: Optional[str] = None, page_size: int = 100):
    q = "mimeType='application/vnd.google-apps.folder' and trashed=false"
    if parent_id:
        q += f" and '{parent_id}' in parents"
    else:
        q += " and 'root' in parents"
    resp = drive.files().list(q=q, fields="files(id,name)", pageSize=page_size).execute()
    return resp.get("files", [])

def list_videos_in_folder(drive, folder_id: str, page_size: int = 1000):
    q = (
        f"'{folder_id}' in parents and trashed=false and (mimeType contains 'video/' or "
        "name contains '.mp4' or name contains '.mov' or name contains '.m4v' or "
        "name contains '.mkv' or name contains '.webm' or name contains '.avi')"
    )
    resp = drive.files().list(q=q, fields="files(id,name,mimeType,size)", pageSize=page_size).execute()
    return resp.get("files", [])

def download_drive_file_to_temp(drive, file_id: str, filename: str) -> str:
    request = drive.files().get_media(fileId=file_id)
    # MODIFIED: Use persistent temp dir in production
    tmp_dir = "/app/data/temp" if ENV == "prod" else None
    if tmp_dir and not os.path.exists(tmp_dir):
        os.makedirs(tmp_dir)
    fd, tmp_path = tempfile.mkstemp(prefix="gdrive_", suffix="_" + filename, dir=tmp_dir)
    os.close(fd)
    fh = open(tmp_path, "wb")
    downloader = MediaIoBaseDownload(fh, request)
    done = False
    progress = st.progress(0, text=f"Downloading {filename} from Drive…")
    try:
        while not done:
            status, done = downloader.next_chunk()
            if status:
                progress.progress(int(status.progress() * 100))
    finally:
        fh.close()
        try:
            progress.progress(100)
            progress.empty()
        except Exception:
            pass
    return tmp_path

# -----------------------------
# YouTube helpers
# -----------------------------
def get_channel_identity(yt):
    resp = yt.channels().list(part="snippet", mine=True).execute()
    items = resp.get("items", [])
    if not items:
        return None, None
    ch = items[0]
    return ch.get("id"), ch.get("snippet", {}).get("title")

def upload_video_scheduled(yt, local_path: str, title: str, description: str, tags: Optional[List[str]],
                          category_id: str, publish_at_iso: Optional[str], made_for_kids: bool):
    body = {
        "snippet": {
            "title": title,
            "description": description,
            "tags": tags or [],
            "categoryId": category_id or "22",
        },
        "status": {
            "privacyStatus": "private" if publish_at_iso else "public",
            **({"publishAt": publish_at_iso} if publish_at_iso else {}),
            "selfDeclaredMadeForKids": made_for_kids,
        },
    }
    media = MediaFileUpload(local_path, chunksize=8 * 1024 * 1024, resumable=True)
    parts = ",".join(body.keys())
    request = yt.videos().insert(part=parts, body=body, media_body=media)
    progress = st.progress(0, text="Uploading to YouTube…")
    response = None
    try:
        while True:
            status, response = request.next_chunk()
            if status:
                progress.progress(int(status.progress() * 100))
            if response is not None:
                break
    except HttpError as e:
        st.error(f"YouTube API error: {e}")
        return None
    finally:
        try:
            progress.progress(100)
            progress.empty()
        except Exception:
            pass
    return response.get("id") if response else None

def patch_video_publish_at(yt, video_id: str, publish_at_iso: Optional[str]) -> bool:
    try:
        body = {"id": video_id, "status": {"privacyStatus": "private" if publish_at_iso else "public"}}
        if publish_at_iso:
            body["status"]["publishAt"] = publish_at_iso
        yt.videos().update(part="status", body=body).execute()
        return True
    except HttpError as e:
        st.warning(f"Failed to patch video publish time: {e}")
        return False

def delete_youtube_video(yt, video_id: str) -> bool:
    try:
        yt.videos().delete(id=video_id).execute()
        return True
    except HttpError as e:
        st.warning(f"Failed to delete YouTube video: {e}")
        return False

# -----------------------------
# Calendar helpers
# -----------------------------
def create_calendar_event(cal, publish_dt_utc: datetime, title: str, description: str) -> Optional[str]:
    start_iso = publish_dt_utc.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    end_iso = (publish_dt_utc + timedelta(minutes=30)).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    body = {
        "summary": f"YouTube Publish: {title}",
        "description": description,
        "start": {"dateTime": start_iso, "timeZone": "UTC"},
        "end": {"dateTime": end_iso, "timeZone": "UTC"},
    }
    try:
        ev = cal.events().insert(calendarId="primary", body=body).execute()
        return ev.get("id")
    except HttpError as e:
        st.warning(f"Calendar event creation failed: {e}")
        return None

def update_calendar_event_with_link(cal, event_id: str, video_url: str):
    try:
        cal.events().patch(calendarId="primary", eventId=event_id,
                           body={"description": f"Scheduled YouTube video: {video_url}"}).execute()
    except HttpError:
        pass

def delete_calendar_event(cal, event_id: str) -> bool:
    try:
        cal.events().delete(calendarId="primary", eventId=event_id).execute()
        return True
    except HttpError as e:
        st.warning(f"Failed to delete calendar event: {e}")
        return False

# -----------------------------
# DB operations for channels & schedules
# -----------------------------
def add_channel_for_user(user_id: int, creds: Credentials, label_hint: Optional[str] = None):
    yt = build("youtube", "v3", credentials=creds)
    ch_id, ch_title = get_channel_identity(yt)
    label = label_hint or ch_title or "YouTube Channel"
    conn = get_conn()
    conn.execute(
        "INSERT INTO channels(user_id, label, channel_id, channel_title, token_json, created_at) VALUES (?,?,?,?,?,?)",
        (user_id, label, ch_id, ch_title, creds_to_json(creds), datetime.utcnow().isoformat() + "Z"),
    )
    conn.commit()
    conn.close()

def list_channels_for_user(user_id: int):
    conn = get_conn()
    rows = conn.execute("SELECT * FROM channels WHERE user_id=? ORDER BY id DESC", (user_id,)).fetchall()
    conn.close()
    return rows

def get_channel_creds(channel_id_db: int) -> Credentials:
    conn = get_conn()
    row = conn.execute("SELECT token_json FROM channels WHERE id=?", (channel_id_db,)).fetchone()
    conn.close()
    if not row:
        raise RuntimeError("Channel not found")
    return creds_from_json(row["token_json"])

def add_schedule_db(channel_id_db: int, drive_file_id: str, drive_file_name: str, title: str, description: str,
                    tags_csv: str, category_id: str, made_for_kids: bool, publish_at_utc: datetime,
                    youtube_video_id: Optional[str], calendar_event_id: Optional[str], status: str):
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO schedules(channel_id, drive_file_id, drive_file_name, title, description, tags, category_id,
                               made_for_kids, publish_at_utc, status, youtube_video_id, calendar_event_id, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            channel_id_db, drive_file_id, drive_file_name, title, description, tags_csv, category_id,
            1 if made_for_kids else 0, publish_at_utc.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            status, youtube_video_id, calendar_event_id, datetime.utcnow().isoformat() + "Z"
        ),
    )
    conn.commit()
    conn.close()

def list_schedules(channel_id_db: int):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM schedules WHERE channel_id=? ORDER BY publish_at_utc ASC",
        (channel_id_db,),
    ).fetchall()
    conn.close()
    return rows

def update_schedule_db(schedule_id: int, **fields):
    if not fields:
        return
    fields["updated_at"] = datetime.utcnow().isoformat() + "Z"
    keys = ", ".join([f"{k}=?" for k in fields.keys()])
    values = list(fields.values()) + [schedule_id]
    conn = get_conn()
    conn.execute(f"UPDATE schedules SET {keys} WHERE id=?", values)
    conn.commit()
    conn.close()

def delete_schedule_db(schedule_id: int):
    conn = get_conn()
    conn.execute("DELETE FROM schedules WHERE id=?", (schedule_id,))
    conn.commit()
    conn.close()

# -----------------------------
# Time helpers
# -----------------------------
def to_rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

# -----------------------------
# Scheduling helper
# -----------------------------
def assign_videos_to_slots(videos: List[dict], date_range: List[date], vids_per_day: int, time_slots: List[dtime]) -> dict:
    scheduled_map = {d: [] for d in date_range}
    if not videos or not time_slots:
        return scheduled_map

    max_slots_per_day = vids_per_day
    video_idx = 0
    for d in date_range:
        slots_assigned = 0
        while slots_assigned < max_slots_per_day and video_idx < len(videos):
            time_idx = slots_assigned % len(time_slots)
            scheduled_map[d].append((videos[video_idx], time_slots[time_idx]))
            video_idx += 1
            slots_assigned += 1
    return scheduled_map

# -----------------------------
# NEW: Cleanup temporary files
# -----------------------------
def cleanup_temp_file(file_path: str):
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            if ENV == "prod":
                st.info(f"Cleaned up temporary file: {file_path}")
    except Exception as e:
        st.warning(f"Failed to clean up temporary file {file_path}: {e}")

# -----------------------------
# Streamlit UI
# -----------------------------
st.set_page_config(page_title="Drive → YouTube Scheduler", page_icon="📺", layout="wide")
init_db()

if "user_id" not in st.session_state:
    st.session_state.user_id = None

if "_triggered_rerun" not in st.session_state:
    st.session_state["_triggered_rerun"] = False

st.title("📺 Drive → Multi-Channel YouTube Scheduler + Calendar (Cross-channel)")

# Authentication UI in sidebar
with st.sidebar:
    st.header("Account • Login / Register")
    if st.session_state.user_id:
        uname = get_username(st.session_state.user_id)
        st.success(f"Signed in as: {uname}")
        if st.button("🔓 Logout"):
            st.session_state.user_id = None
            st.session_state["_triggered_rerun"] = False
            trigger_rerun()
    else:
        auth_tab = st.radio("Mode", ["Login", "Register"], index=0)
        username = st.text_input("Username", key="auth_user")
        password = st.text_input("Password", type="password", key="auth_pass")
        if auth_tab == "Register":
            if st.button("Create account"):
                ok = create_user(username, password)
                if ok:
                    st.success("User created — please log in.")
                else:
                    st.error("User already exists or invalid input.")
        else:
            if st.button("Sign in"):
                uid = authenticate_user(username, password)
                if uid:
                    st.session_state.user_id = uid
                    st.success("Signed in.")
                    trigger_rerun()
                else:
                    st.error("Invalid credentials.")

if not st.session_state.user_id:
    st.info("Please register or login from the sidebar to manage accounts and schedules.")
    st.stop()

# Manage Google account connections
with st.sidebar:
    st.header("🔐 Google Accounts (per user)")
    mode = st.radio("OAuth mode (connect)", ["Local dev (popup)", "This page redirect"], index=0, key="oauth_mode")
    if st.button("➕ Add Google account"):
        creds = None
        if mode == "Local dev (popup)":
            creds = flow_local_desktop()
        else:
            creds = flow_web_redirect()
        if creds:
            try:
                add_channel_for_user(st.session_state.user_id, creds)
                st.success("Google account connected")
                trigger_rerun()
            except Exception as e:
                st.error(f"Failed to add account: {e}")
    if st.button("🔄 Refresh accounts"):
        trigger_rerun()

channels = list_channels_for_user(st.session_state.user_id)
if not channels:
    st.info("You have no connected Google accounts. Add one from the sidebar.")
    st.stop()

channel_map = {f"{c['channel_title'] or c['label']} (id {c['id']})": c['id'] for c in channels}
src_label = st.selectbox("Source account (Drive) — browse files from this account", list(channel_map.keys()))
src_channel_db_id = channel_map[src_label]

try:
    src_creds = get_channel_creds(src_channel_db_id)
except Exception as e:
    st.error(f"Failed to load source credentials: {e}")
    st.stop()
src_drive, _, _ = build_services(src_creds)

target_options = list(channel_map.keys())
target_picks = st.multiselect("Target account(s) — upload to these channels", target_options, default=[src_label])
target_channel_ids = [channel_map[t] for t in target_picks]

tab = st.tabs(["Schedule Videos (cross-channel)", "Scheduled Dashboard", "DB Viewer"])

# -----------------------------
# Schedule Videos Tab
# -----------------------------
with tab[0]:
    st.subheader("Pick Drive folder from Source account")
    try:
        root_folders = list_folders(src_drive)
    except HttpError as e:
        st.error(f"Drive API error: {e}")
        st.stop()

    folder_map = {f["name"]: f["id"] for f in root_folders}
    if not folder_map:
        st.info("No folders in Drive root for this account.")
        st.stop()
    picked = st.selectbox("Root folders", list(folder_map.keys()))
    current_folder = folder_map[picked]

    subs = list_folders(src_drive, parent_id=current_folder)
    if subs:
        sub_map = {f["name"]: f["id"] for f in subs}
        sel2 = st.selectbox("Subfolders", ["(none)"] + list(sub_map.keys()))
        if sel2 != "(none)":
            current_folder = sub_map[sel2]
    st.caption(f"Folder ID (source): {current_folder}")

    st.subheader("Select videos from Source Drive & schedule (within 30 days)")
    try:
        videos = list_videos_in_folder(src_drive, current_folder)
    except HttpError as e:
        st.error(f"Drive API error: {e}")
        st.stop()
    if not videos:
        st.warning("No videos found in this folder.")
        st.stop()

    label_map = {f"{v['name']} ({int(v.get('size','0'))/1e6:.1f} MB)": v for v in videos}
    picks = st.multiselect("Pick videos (no limit)", list(label_map.keys()))

    st.markdown("---")
    st.write("Default metadata (applies to items; override per video below):")
    default_title_prefix = st.text_input("Title prefix", value="")
    default_description = st.text_area("Description", value="Uploaded via scheduler", height=80)
    default_tags_str = st.text_input("Tags (comma)", value="streamlit,scheduler")
    default_tags = [t.strip() for t in default_tags_str.split(",") if t.strip()]
    category = st.selectbox("Category", [
        ("22", "People & Blogs"), ("24", "Entertainment"), ("28", "Science & Technology"),
        ("27", "Education"), ("1", "Film & Animation"), ("10", "Music")
    ], format_func=lambda x: x[1])
    kids = st.checkbox("Made for kids", value=False)

    # -----------------------------
    # Auto-scheduling Settings
    # -----------------------------
    st.markdown("### Auto-scheduling Settings")
    col1, col2 = st.columns(2)
    with col1:
        date_range = st.date_input(
            "Date range (from → to)",
            [date.today(), min(date.today() + timedelta(days=5), date.today() + timedelta(days=30))],
            min_value=date.today(),
            max_value=date.today() + timedelta(days=90)
        )
    with col2:
        vids_per_day = st.number_input("Videos per day", min_value=1, max_value=10, value=2, step=1)

    general_times = st.text_input(
        "Daily upload times (comma HH:MM, e.g. 10:00,14:00,18:00)",
        "10:00,14:00"
    )
    try:
        time_slots = [datetime.strptime(t.strip(), "%H:%M").time()
                      for t in general_times.split(",") if t.strip()]
        if not time_slots:
            raise ValueError("No valid time slots provided")
    except Exception as e:
        st.warning(f"Invalid time format: {e}. Fallback to 10:00")
        time_slots = [dtime(10, 0)]

    # Handle date range: ensure it's a list of two dates
    if isinstance(date_range, tuple) and len(date_range) == 2:
        start_date, end_date = date_range
        if start_date > end_date:
            start_date, end_date = end_date, start_date
    else:
        start_date = end_date = date_range if isinstance(date_range, date) else date.today()

    # Build list of dates
    all_dates = []
    current = start_date
    max_allowed_date = date.today() + timedelta(days=90)
    while current <= end_date and current <= max_allowed_date:
        all_dates.append(current)
        current += timedelta(days=1)

    # Assign videos to slots
    selected_videos = [label_map[lbl] for lbl in picks]
    scheduled_map = assign_videos_to_slots(selected_videos, all_dates, vids_per_day, time_slots)

    # Check for unassigned videos
    total_assigned = sum(len(vids) for vids in scheduled_map.values())
    if selected_videos and total_assigned < len(selected_videos):
        st.warning(f"Only {total_assigned} of {len(selected_videos)} videos assigned due to slot limits.")

    # -----------------------------
    # Render grouped by DATE
    # -----------------------------
    st.markdown("### Scheduled Videos")
    per_video_inputs = []
    for d in all_dates:
        day_videos = scheduled_map[d]
        with st.expander(f"📅 {d.strftime('%A, %d %B %Y')} — {len(day_videos)} videos"):
            if not day_videos:
                st.caption("No videos scheduled for this date.")
            for v, tslot in day_videos:
                with st.expander(f"🎬 {v['name']} — {tslot.strftime('%H:%M')}"):
                    vtitle = st.text_input(
                        f"Title for {v['name']}",
                        value=(default_title_prefix + os.path.splitext(v["name"])[0])[:95],
                        key=f"t_{v['id']}_{d.strftime('%Y%m%d')}"
                    )
                    vdesc = st.text_area(
                        f"Description for {v['name']}",
                        value=default_description, height=80, key=f"d_{v['id']}_{d.strftime('%Y%m%d')}"
                    )
                    vtags_str = st.text_input(
                        f"Tags for {v['name']}",
                        value=default_tags_str, key=f"g_{v['id']}_{d.strftime('%Y%m%d')}"
                    )
                    vtags = [t.strip() for t in vtags_str.split(",") if t.strip()]
                    dsel = st.date_input(
                        f"Date for {v['name']}",
                        value=d,
                        min_value=date.today(),
                        max_value=date.today() + timedelta(days=90),
                        key=f"da_{v['id']}_{d.strftime('%Y%m%d')}"
                    )
                    tsel = st.time_input(f"Time for {v['name']}", value=tslot, key=f"ti_{v['id']}_{d.strftime('%Y%m%d')}")
                    per_video_inputs.append((v, vtitle, vdesc, vtags, dsel, tsel))

    st.markdown("---")
    st.write(f"Total videos scheduled: {total_assigned} across {len(all_dates)} days")
    if st.button("Schedule and upload videos"):
        if not per_video_inputs:
            st.error("No videos selected to schedule.")
        elif not target_channel_ids:
            st.error("No target channels selected.")
        else:
            errors = []
            success_count = 0
            # MODIFIED: Process downloads and uploads one by one
            for v, vtitle, vdesc, vtags, dsel, tsel in per_video_inputs:
                try:
                    local_dt = datetime.combine(dsel, tsel)
                    local_dt = local_dt.astimezone() if local_dt.tzinfo else local_dt.replace(tzinfo=timezone.utc).astimezone()
                except Exception:
                    errors.append(f"Invalid date/time for {v['name']}")
                    continue

                max_allowed = datetime.now(timezone.utc) + timedelta(days=30)
                publish_utc = local_dt.astimezone(timezone.utc)
                if publish_utc > max_allowed:
                    errors.append(f"{v['name']} is scheduled beyond 30 days; skip or adjust.")
                    continue

                # NEW: Download video from Drive
                try:
                    tmp_path = download_drive_file_to_temp(src_drive, v['id'], v['name'])
                except Exception as e:
                    errors.append(f"Failed to download {v['name']} from Drive: {e}")
                    continue

                for tgt_ch_db_id in target_channel_ids:
                    # NEW: Get target channel credentials and services
                    try:
                        creds_tgt = get_channel_creds(tgt_ch_db_id)
                        _, yt_tgt, cal_tgt = build_services(creds_tgt)
                    except Exception as e:
                        errors.append(f"Failed to load credentials for channel {tgt_ch_db_id}: {e}")
                        cleanup_temp_file(tmp_path)
                        continue

                    # NEW: Create calendar event
                    cal_event_id = None
                    try:
                        cal_event_id = create_calendar_event(cal_tgt, publish_utc, vtitle, vdesc)
                    except Exception as e:
                        st.warning(f"Could not create calendar event for channel id {tgt_ch_db_id}: {e}")

                    # NEW: Upload to YouTube
                    try:
                        publish_at_iso = to_rfc3339(publish_utc)
                        video_id = upload_video_scheduled(
                            yt_tgt,
                            tmp_path,
                            vtitle,
                            vdesc,
                            vtags,
                            str(category[0]) if isinstance(category, tuple) else str(category),
                            publish_at_iso,
                            bool(kids)
                        )
                        if not video_id:
                            errors.append(f"Failed to upload {v['name']} to channel {tgt_ch_db_id}")
                            if cal_event_id:
                                delete_calendar_event(cal_tgt, cal_event_id)
                            continue
                    except Exception as e:
                        errors.append(f"YouTube upload error for {v['name']} to channel {tgt_ch_db_id}: {e}")
                        if cal_event_id:
                            delete_calendar_event(cal_tgt, cal_event_id)
                        continue

                    # NEW: Update calendar with video URL
                    if cal_event_id and video_id:
                        try:
                            update_calendar_event_with_link(cal_tgt, cal_event_id, f"https://www.youtube.com/watch?v={video_id}")
                        except Exception as e:
                            st.warning(f"Could not update calendar event for {v['name']}: {e}")

                    # NEW: Save to DB with uploaded status
                    try:
                        add_schedule_db(
                            channel_id_db=tgt_ch_db_id,
                            drive_file_id=v['id'],
                            drive_file_name=v['name'],
                            title=vtitle,
                            description=vdesc,
                            tags_csv=",".join(vtags),
                            category_id=str(category[0]) if isinstance(category, tuple) else str(category),
                            made_for_kids=bool(kids),
                            publish_at_utc=publish_utc,
                            youtube_video_id=video_id,
                            calendar_event_id=cal_event_id,
                            status='uploaded'  # MODIFIED: Mark as uploaded
                        )
                        success_count += 1
                    except Exception as e:
                        errors.append(f"DB error scheduling {v['name']} for channel {tgt_ch_db_id}: {e}")
                        if video_id:
                            delete_youtube_video(yt_tgt, video_id)
                        if cal_event_id:
                            delete_calendar_event(cal_tgt, cal_event_id)
                        continue
                    finally:
                        cleanup_temp_file(tmp_path)

            if success_count:
                st.success(f"Scheduled and uploaded {success_count} videos successfully.")
                trigger_rerun()
            if errors:
                for e in errors:
                    st.warning(e)

# -----------------------------
# Dashboard Tab
# -----------------------------
with tab[1]:
    st.subheader("Scheduled Uploads Dashboard (per channel)")
    ch_map_local = {f"{c['channel_title'] or c['label']} (id {c['id']})": c['id'] for c in channels}
    view_label = st.selectbox("View schedules for channel", list(ch_map_local.keys()))
    view_channel_id = ch_map_local[view_label]

    rows = list_schedules(view_channel_id)
    if not rows:
        st.info("No scheduled uploads for this channel.")
    else:
        for r in rows:
            st.markdown("---")
            cols = st.columns([3, 1, 1, 1])
            with cols[0]:
                st.markdown(f"**{r['title']}**  ")
                st.markdown(f"File: `{r['drive_file_name']}`  ")
                st.markdown(f"Publish (UTC): `{r['publish_at_utc']}`  ")
                st.markdown(f"Status: `{r['status']}`  ")
                if r['youtube_video_id']:
                    st.markdown(f"Video: https://www.youtube.com/watch?v={r['youtube_video_id']}")
                if r['calendar_event_id']:
                    st.markdown(f"Calendar Event ID: `{r['calendar_event_id']}`")

            with cols[1]:
                if st.button(f"Edit", key=f"edit_{r['id']}"):
                    with st.form(f"form_edit_{r['id']}"):
                        new_title = st.text_input("Title", value=r['title'])
                        new_desc = st.text_area("Description", value=r['description'] or "", height=80)
                        new_tags = st.text_input("Tags (comma)", value=r['tags'] or "")
                        old_publish = datetime.fromisoformat(r['publish_at_utc'].replace('Z', '+00:00')).astimezone()
                        new_date = st.date_input("Date", value=old_publish.date())
                        new_time = st.time_input("Time", value=old_publish.time())
                        submit_edit = st.form_submit_button("Save")
                        if submit_edit:
                            new_dt = datetime.combine(new_date, new_time).astimezone()
                            publish_iso = to_rfc3339(new_dt)
                            try:
                                creds_view = get_channel_creds(view_channel_id)
                                _, yt_view, cal_view = build_services(creds_view)
                                if r['youtube_video_id']:
                                    ok = patch_video_publish_at(yt_view, r['youtube_video_id'], publish_iso)
                                    if not ok:
                                        st.warning("Could not patch YouTube publish time; database/calendar will still update.")
                                if r['calendar_event_id']:
                                    try:
                                        delete_calendar_event(cal_view, r['calendar_event_id'])
                                    except Exception:
                                        pass
                                    new_cal_id = create_calendar_event(cal_view, new_dt.astimezone(timezone.utc), new_title, new_desc)
                                else:
                                    new_cal_id = None
                                update_schedule_db(r['id'], title=new_title, description=new_desc, tags=new_tags,
                                                  publish_at_utc=new_dt.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z'),
                                                  calendar_event_id=new_cal_id)
                                trigger_rerun()
                            except Exception as e:
                                st.error(f"Could not save edit: {e}")

            with cols[2]:
                if st.button(f"Delete", key=f"del_{r['id']}"):
                    try:
                        creds_view = get_channel_creds(view_channel_id)
                        _, yt_view, cal_view = build_services(creds_view)
                    except Exception:
                        yt_view = cal_view = None
                    if r['youtube_video_id'] and yt_view:
                        if delete_youtube_video(yt_view, r['youtube_video_id']):
                            st.info("Deleted YouTube video.")
                    if r['calendar_event_id'] and cal_view:
                        if delete_calendar_event(cal_view, r['calendar_event_id']):
                            st.info("Deleted calendar event.")
                    delete_schedule_db(r['id'])
                    st.success("Schedule deleted")
                    trigger_rerun()

            with cols[3]:
                if st.button(f"Refresh", key=f"refresh_{r['id']}"):
                    trigger_rerun()

# -----------------------------
# DB Viewer
# -----------------------------
with tab[2]:
    st.subheader("DB Viewer (users & your channels)")
    conn = get_conn()
    users = conn.execute("SELECT id, username, created_at FROM users ORDER BY id DESC").fetchall()
    st.markdown("**Users**")
    for u in users:
        st.markdown(f"- `{u['id']}` • {u['username']} • created {u['created_at']}")
    st.markdown("**Your connected channels**")
    for c in channels:
        st.markdown(f"- `{c['id']}` • {c['channel_title'] or c['label']} • connected {c['created_at']}")
    conn.close()

st.markdown("---")
st.caption("Notes: Passwords are stored locally with PBKDF2-SHA256. Channels are tied to the user that connected them. Videos are downloaded from Drive and uploaded to YouTube immediately upon scheduling.")

st.markdown("""
### Setup checklist for Production
1. Enable Drive API, YouTube Data API v3, Calendar API in Google Cloud Console.
2. Create OAuth 2.0 client (Web for deployed) and place in .streamlit/secrets.toml.
3. Install deps: pip install -r requirements.txt
4. Run via Docker as described in deployment steps.
5. Ensure sufficient disk space for video downloads (use persistent disk).
""")
