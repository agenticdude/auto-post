# app.py
# Streamlit app: Drive → Multi-Channel YouTube Scheduler + Calendar (Unlimited)
# Fixed: safe rerun handling (no infinite loops). Triggers rerun only after explicit user actions.

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
DB_PATH = "scheduler.db"

# -----------------------------
# Safe rerun helper
# -----------------------------
def trigger_rerun():
    # Mark we intend to rerun (useful if needed), then call rerun.
    # Only call this inside a user-driven action, never at module import time.
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
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
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
          FOREIGN KEY(user_id) REFERENCES users(id)
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
          FOREIGN KEY(channel_id) REFERENCES channels(id)
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
    cfg = st.secrets.get("google_oauth_client") if hasattr(st, "secrets") else None
    if cfg:
        with open(CLIENT_SECRET_FILE, "w", encoding="utf-8") as f:
            json.dump(json.loads(cfg) if isinstance(cfg, str) else dict(cfg), f)

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
    redirect_uri = os.environ.get("PUBLIC_URL") or "http://localhost:8501"
    qp = st.experimental_get_query_params()
    if "redirect_uri" in qp:
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
    fd, tmp_path = tempfile.mkstemp(prefix="gdrive_", suffix="_" + filename)
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
        progress.progress(100)
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

def upload_video_scheduled(yt, local_path: str, title: str, description: str, tags: List[str] | None,
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
    request = yt.videos().insert(part=",".join(body.keys()), body=body, media_body=media)
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
        progress.progress(100)
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
    start_iso = publish_dt_utc.isoformat().replace("+00:00", "Z")
    end_iso = (publish_dt_utc + timedelta(minutes=30)).isoformat().replace("+00:00", "Z")
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
# DB operations for channels & schedules (user-aware)
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
            1 if made_for_kids else 0, publish_at_utc.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"),
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
    keys = ", ".join([f"{k}=?" for k in fields.keys()])
    values = list(fields.values()) + [schedule_id]
    conn = get_conn()
    conn.execute(f"UPDATE schedules SET {keys}, updated_at=? WHERE id=?", values + [datetime.utcnow().isoformat() + "Z"])  # type: ignore
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
# Streamlit UI
# -----------------------------
st.set_page_config(page_title="Drive → YouTube Scheduler", page_icon="📺", layout="wide")
init_db()

if "user_id" not in st.session_state:
    st.session_state.user_id = None

# track triggered rerun (optional)
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
            # safe rerun after logout
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
                    # do NOT auto-rerun; user can switch to Login and sign in
                else:
                    st.error("User already exists or invalid input.")
        else:
            if st.button("Sign in"):
                uid = authenticate_user(username, password)
                if uid:
                    st.session_state.user_id = uid
                    st.success("Signed in.")
                    # safe rerun after successful sign-in
                    trigger_rerun()
                else:
                    st.error("Invalid credentials.")

# Require auth
if not st.session_state.user_id:
    st.info("Please register or login from the sidebar to manage accounts and schedules.")
    st.stop()

# After login: manage Google account connections (per-user)
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
            add_channel_for_user(st.session_state.user_id, creds)
            st.success("Google account connected")
            trigger_rerun()
    if st.button("🔄 Refresh accounts"):
        trigger_rerun()

# List channels for current user
channels = list_channels_for_user(st.session_state.user_id)
if not channels:
    st.info("You have no connected Google accounts. Add one from the sidebar.")
    st.stop()

# Map and selection: choose source (Drive) and targets (upload destinations)
channel_map = {f"{c['channel_title'] or c['label']} (id {c['id']})": c['id'] for c in channels}
src_label = st.selectbox("Source account (Drive) — browse files from this account", list(channel_map.keys()))
src_channel_db_id = channel_map[src_label]

# Build Drive service for source
try:
    src_creds = get_channel_creds(src_channel_db_id)
except Exception as e:
    st.error(f"Failed to load source credentials: {e}")
    st.stop()
src_drive, _, _ = build_services(src_creds)

# Targets: allow multi-select of any connected accounts (including same as source)
target_options = list(channel_map.keys())
target_picks = st.multiselect("Target account(s) — upload to these channels", target_options, default=[src_label])

# Convert to ids
target_channel_ids = [channel_map[t] for t in target_picks]

# Tabs: Schedule / Dashboard / DB Viewer
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

    today = date.today()
    max_day = today + timedelta(days=30)

    per_video_inputs = []
    for lbl in picks:
        v = label_map[lbl]
        with st.expander(f"⏱ {v['name']}"):
            vtitle = st.text_input(f"Title for {v['name']}", value=(default_title_prefix + os.path.splitext(v["name"])[0])[:95], key=f"t_{v['id']}")
            vdesc = st.text_area(f"Description for {v['name']}", value=default_description, height=80, key=f"d_{v['id']}")
            vtags_str = st.text_input(f"Tags for {v['name']}", value=default_tags_str, key=f"g_{v['id']}")
            vtags = [t.strip() for t in vtags_str.split(",") if t.strip()]
            dsel = st.date_input(f"Date for {v['name']}", value=today, min_value=today, max_value=max_day, key=f"da_{v['id']}")
            tsel = st.time_input(f"Time for {v['name']}", value=dtime(10, 0), key=f"ti_{v['id']}")
            per_video_inputs.append((v, vtitle, vdesc, vtags, dsel, tsel))

    if st.button("📤 Schedule cross-channel uploads & create Calendar events"):
        if not picks:
            st.warning("Select at least one video.")
        else:
            # Pre-build services for target channels (to avoid repeated DB reads)
            target_services = {}
            for t_id in target_channel_ids:
                try:
                    creds = get_channel_creds(t_id)
                    _, yt_service, cal_service = build_services(creds)
                    target_services[t_id] = (creds, yt_service, cal_service)
                except Exception as e:
                    st.error(f"Failed to prepare target channel id {t_id}: {e}")
                    target_services[t_id] = (None, None, None)

            any_success = False
            for (v, vtitle, vdesc, vtags, dsel, tsel) in per_video_inputs:
                local_dt = datetime.combine(dsel, tsel).astimezone()
                if local_dt > datetime.now().astimezone() + timedelta(days=31):
                    st.error(f"{v['name']}: publish time must be within 31 days.")
                    continue
                if local_dt <= datetime.now().astimezone() + timedelta(minutes=4):
                    st.warning(f"{v['name']}: publish time is too soon; scheduling 10 minutes from now.")
                    local_dt = datetime.now().astimezone() + timedelta(minutes=10)
                publish_iso = to_rfc3339(local_dt)

                # Download once from source Drive
                tmp_path = download_drive_file_to_temp(src_drive, v["id"], v["name"])

                # For each target channel, upload separately and create schedule row
                for target_db_id, (creds, yt_service, cal_service) in target_services.items():
                    if not creds:
                        st.error(f"Skipping target {target_db_id} due to missing creds.")
                        continue
                    # Upload to target YouTube
                    video_id = upload_video_scheduled(
                        yt_service,
                        local_path=tmp_path,
                        title=vtitle,
                        description=vdesc,
                        tags=vtags,
                        category_id=category[0],
                        publish_at_iso=publish_iso,
                        made_for_kids=kids,
                    )

                    cal_event_id = None
                    if video_id:
                        cal_event_id = create_calendar_event(cal_service, local_dt.astimezone(timezone.utc), vtitle, vdesc)

                    add_schedule_db(
                        channel_id_db=target_db_id,
                        drive_file_id=v["id"],
                        drive_file_name=v["name"],
                        title=vtitle,
                        description=vdesc,
                        tags_csv=",".join(vtags),
                        category_id=category[0],
                        made_for_kids=kids,
                        publish_at_utc=local_dt.astimezone(timezone.utc),
                        youtube_video_id=video_id,
                        calendar_event_id=cal_event_id,
                        status="uploaded" if video_id else "failed",
                    )

                    if video_id:
                        any_success = True
                        url = f"https://www.youtube.com/watch?v={video_id}"
                        st.success(f"Scheduled {v['name']} → {url} at {publish_iso} (UTC) on channel id {target_db_id}")
                        if cal_event_id:
                            update_calendar_event_with_link(cal_service, cal_event_id, url)
                    else:
                        st.error(f"Failed to upload {v['name']} to channel id {target_db_id}")

                # remove temp file after uploading to all targets
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

            if any_success:
                # only trigger rerun when something changed successfully
                trigger_rerun()

# -----------------------------
# Dashboard Tab (per-user channels)
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
                                    delete_calendar_event(cal_view, r['calendar_event_id'])
                                    new_cal_id = create_calendar_event(cal_view, new_dt.astimezone(timezone.utc), new_title, new_desc)
                                else:
                                    new_cal_id = None
                                update_schedule_db(r['id'], title=new_title, description=new_desc, tags=new_tags,
                                                   publish_at_utc=new_dt.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z'),
                                                   calendar_event_id=new_cal_id)
                                # only rerun after successful edit
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
# DB Viewer (simple)
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
st.caption("Notes: Passwords are stored locally with PBKDF2-SHA256. Channels are tied to the user that connected them. Cross-channel uploads download from the selected source Drive account and upload into each selected target channel (one DB schedule entry per target).")

st.markdown("""
### Setup checklist
1. Enable Drive API, YouTube Data API v3, Calendar API in Google Cloud Console.
2. Create OAuth 2.0 client (Desktop for local dev; Web for deployed) and place `client_secret.json` in the project folder or in Streamlit Secrets under `google_oauth_client`.
3. Install deps:
   pip install -r requirements.txt
4. Run:
   streamlit run app.py --server.port 8502
""")
