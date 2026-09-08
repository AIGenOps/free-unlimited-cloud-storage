"""
TelegramCloud - Encrypted Unlimited Cloud Storage Application
Maintained by AIGenOps
"""

import io
import os
import ssl
import time
import logging
import json
import queue
from telegram import Bot
from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify, flash, Response, stream_with_context
from flask_login import LoginManager, login_user, UserMixin, login_required, logout_user
from threading import Thread
from dotenv import load_dotenv
from core import BotActions
from datetime import datetime
from utils.functions import manage_file_shares
load_dotenv()
logger = logging.getLogger()

# Fetch temporary user credentials for app login, chosen by user, set to default if unspecified.
temp_app_username = os.getenv("APP_USER_NAME", "user")
temp_app_password = os.getenv("APP_PASSWORD", "password")
shared_files_dict = {}    # The file_id of files that were enabled to be shared by user. [Everyone can access these files using a unique link, unique to each file.] key is file id, value is a dictionary with details like expiry date etc..,.
enable_ssl = os.getenv("ENABLE_SSL", "True").upper() == "TRUE"
context = None
if enable_ssl:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('certs/cert.pem', 'certs/key.pem')

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Optional for now, For Sake of flash messages.
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Specify the login route, otherwise auto-redirect to login page won't work.
Thread(target=manage_file_shares, args=(shared_files_dict, ), daemon=True).start()  #  start thread for monitoring, enforcing time limit for each file shared.
file_encryption_choice: bool = True if os.getenv("FILE_ENCRYPTION", "True").upper() == "TRUE" else False    # User can set this option from env, default is true if nothing is selected.
bot = BotActions(encrypted=file_encryption_choice)  # Core telegram interaction functions.

def start_bot_polling(bot_instance):
    """Background thread to handle Telegram bot commands (/start, /help, /storage, /search, /backup, /sync)."""
    time.sleep(3)
    token = os.getenv("API_KEY")
    if not token:
        return
    try:
        tg_bot = Bot(token=token)
        last_update_id = 0
        logger.info("Telegram Bot Command Listener background thread started!")
        
        while True:
            try:
                updates = tg_bot.get_updates(offset=last_update_id + 1, timeout=10)
                for u in updates:
                    last_update_id = u.update_id
                    msg = u.message or u.channel_post
                    if not msg or not msg.text:
                        continue
                    
                    text = msg.text.strip()
                    chat_id = msg.chat_id
                    
                    if text.startswith("/start") or text.startswith("/help"):
                        reply = (
                            "☁️ *Telegram Cloud Bot Ready!*\n\n"
                            "Commands:\n"
                            "• `/storage` — View storage stats\n"
                            "• `/search <name>` — Search files\n"
                            "• `/backup` — Backup schema to Telegram\n"
                            "• `/sync` — Auto-sync channel messages"
                        )
                        tg_bot.send_message(chat_id=chat_id, text=reply, parse_mode="Markdown")
                        
                    elif text.startswith("/storage") or text.startswith("/stats"):
                        analytics = bot_instance.get_storage_analytics()
                        reply = (
                            f"📊 *Telegram Cloud Storage Stats*\n\n"
                            f"• *Files*: {analytics.get('total_files', 0)}\n"
                            f"• *Folders*: {analytics.get('total_folders', 0)}\n"
                            f"• *Space Consumed*: {analytics.get('total_size_formatted', '0 KB')}"
                        )
                        tg_bot.send_message(chat_id=chat_id, text=reply, parse_mode="Markdown")
                        
                    elif text.startswith("/search"):
                        parts = text.split(maxsplit=1)
                        if len(parts) > 1:
                            query = parts[1]
                            res = bot_instance._ops.find_record_by_attribute(bot_instance._schema.copy(), "filename", query, partial_match=True)
                            if res:
                                reply = f"🔍 *Found {len(res)} file(s) matching '{query}':*\n\n"
                                for f in res[:5]:
                                    reply += f"• `{f.get('filename')}` ({f.get('size')})\n"
                            else:
                                reply = f"❌ No records matching '{query}' were found."
                        else:
                            reply = "Usage: `/search <filename>`"
                        tg_bot.send_message(chat_id=chat_id, text=reply, parse_mode="Markdown")
                        
                    elif text.startswith("/backup"):
                        success, res_id = bot_instance.backup_schema_to_telegram()
                        reply = f"✅ *Schema Backup Complete!* File ID: `{res_id}`" if success else f"❌ Backup Failed: {res_id}"
                        tg_bot.send_message(chat_id=chat_id, text=reply, parse_mode="Markdown")
                        
                    elif text.startswith("/sync"):
                        tg_bot.send_message(chat_id=chat_id, text="🔄 Running channel auto-sync...")
                        success, count = bot_instance.sync_channel_messages()
                        reply = f"✅ *Sync Complete!* Imported {count} new files into `/Telegram_Imports/`." if success else f"❌ Sync Failed: {count}"
                        tg_bot.send_message(chat_id=chat_id, text=reply, parse_mode="Markdown")
            except Exception:
                time.sleep(3)
    except Exception as e:
        logger.error(f"Error starting Telegram Bot listener: {e}")

Thread(target=start_bot_polling, args=(bot,), daemon=True).start()


class User(UserMixin):
    def __init__(self, user_id):
        self.id = user_id

def authenticate_user(username, password):
    # Replace this with your actual user authentication logic
    if username == temp_app_username and password == temp_app_password:
        return User(1)  # User id is always 1.
    return None

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = authenticate_user(request.form['username'], request.form['password'])
        if user:
            login_user(user)  # Log in the user
            # flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logout successful!', 'success')
    return redirect(url_for('login'))

@app.before_request
def block_on_validation_in_progress():
    """call this function in first line of each route, to block traffic during schema validation process. To maintain schema.json integrity."""
    if bot.is_validation_active() is True:
        return jsonify({"message": "No action allowed this time, A validation Job is in progress. Kindly come back later!"}), 404

# Flask routes
@app.route('/', methods=['GET'])
@login_required
def index():
    block_on_validation_in_progress()
    _, security_warning = bot.get_active_users_in_channel()
    analytics = bot.get_storage_analytics()
    total_size_fmt = analytics.get("total_size_formatted", "0 KB")
    total_files_sys = analytics.get("total_files", 0)
    total_folders_sys = analytics.get("total_folders", 0)
    last_val = bot._schema.get("meta", {}).get("last_validated", "Live")
    if isinstance(last_val, float):
        last_val = str(datetime.fromtimestamp(last_val))

    directory = request.args.get('target_directory', None)
    if directory is None:
        folders = list(bot._schema.keys())
        if "root" in folders: folders.remove("root")
        if "meta" in folders: folders.remove("meta")
        return render_template('index.html', files=bot._schema["root"], folders=folders, working_directory="", total_size=total_size_fmt, total_files_system=total_files_sys, total_folders_system=total_folders_sys, last_validated=last_val, security_warning=security_warning)
    else:
        _, ret_structure, err = bot._ops.get_contents_in_directory(directory, bot._schema.copy(), files_only=False)
        if ret_structure is not False:
            folders = list(ret_structure.keys())
            if "root" in folders: folders.remove("root")
            if "meta" in folders: folders.remove("meta")
            directory_parts = []
            path_str = ""
            for path_item in directory.split('/'):
                if path_item != "":
                    path_str = path_str + '/' + path_item
                    directory_parts.append((path_item, path_str))
            return render_template('index.html', files=ret_structure["root"], folders=folders, working_directory=directory, directory_parts=directory_parts, total_size=total_size_fmt, total_files_system=total_files_sys, total_folders_system=total_folders_sys, last_validated=last_val, security_warning=security_warning)
        return jsonify({"error": err})

@app.route('/bulk-upload/', methods=['GET'])    # For full folder uploads.
@login_required
def bulk():
    """Upload a folder full of files, subdirs to root folder to server"""
    return render_template('bulk-upload.html')

@app.route('/upload/', methods=['POST'])
@login_required
def upload():
    block_on_validation_in_progress()
    files = request.files.getlist('upload_file')
    target_directory = request.form.get('target_directory', "")
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or 'application/json' in request.headers.get('Accept', '') or 'application/x-ndjson' in request.headers.get('Accept', '')

    logger.debug(f"Request received for uploading {len(files)} file[s] to directory: {target_directory}")

    if is_ajax and len(files) == 1:
        file = files[0]
        if not file.filename:
            return jsonify({"status": "error", "message": "No file selected"}), 400

        file_bytes = file.read()
        file_name = file.filename

        q = queue.Queue()

        def cb(pct, msg):
            q.put(json.dumps({"percent": pct, "message": msg}) + "\n")

        def worker():
            try:
                success, result = bot.upload_file(file_bytes, file_name, directory=target_directory, progress_callback=cb)
                if success:
                    q.put(json.dumps({"status": "success", "percent": 100, "message": "Complete!", "file_id": result}) + "\n")
                else:
                    q.put(json.dumps({"status": "error", "message": str(result)}) + "\n")
            except Exception as ex:
                logger.error(f"Upload error: {ex}", exc_info=True)
                q.put(json.dumps({"status": "error", "message": str(ex)}) + "\n")
            finally:
                q.put(None)

        Thread(target=worker, daemon=True).start()

        def generate_progress():
            while True:
                item = q.get()
                if item is None:
                    break
                yield item

        return Response(stream_with_context(generate_progress()), mimetype='application/x-ndjson')

    success_count = 0
    error_messages = []
    if len(files) > 0:
        for file in files:
            if file.filename:
                success, error_message = bot.upload_file(file, file.filename, directory=target_directory)
                if success:
                    success_count += 1
                else:
                    error_messages.append(error_message)
                    logger.error(f"Failed to upload file {file.filename}, Error: {str(error_message)}")
            else:
                if not is_ajax:
                    flash("Please select at-least one file to upload!", "danger")
                logger.warning(f"Rejected a bad file-upload request! Potential empty file / wrong file type content.")
        if is_ajax:
            if success_count == len(files):
                return jsonify({"status": "success", "message": "File(s) uploaded successfully!"})
            else:
                return jsonify({"status": "error", "message": f"Failed {len(files) - success_count} out of {len(files)} files: {error_messages}"}), 400
        if success_count == len(files):
            flash("Recent Upload of File[s] Successful!", "success")
        else:
           flash(f"Failed to upload {len(files) - success_count} out of {len(files)} selected!! Errors: {error_messages}", "danger")
        return redirect(f"{url_for('index')}?target_directory={target_directory}")
    if is_ajax:
        return jsonify({"status": "error", "message": "Please select at least one file to upload!"}), 400
    flash("Please select at-least one file to upload!!", "warning")
    return redirect(f"{url_for('index')}?target_directory={target_directory}")

@app.route('/download/<file_id>')
@login_required
def file_download(file_id):
    block_on_validation_in_progress()
    try:
        file_info_list = bot._ops.find_record_by_attribute(bot._schema.copy(), "file_id", file_id)
        filename = file_info_list[0]["filename"] if file_info_list else f"download_{file_id}"
        raw_bytes = file_info_list[0].get("raw_size_bytes") if file_info_list else None
        def generate():
            for chunk in bot.stream_file(file_id):
                yield chunk
        response = Response(stream_with_context(generate()), mimetype='application/octet-stream')
        response.headers["Content-Disposition"] = f"attachment; filename=\"{filename}\""
        if raw_bytes:
            response.headers["Content-Length"] = str(raw_bytes)
        return response
    except Exception as e:
        logger.error(f"Error in file_download: {e}")
        return jsonify({"message": f"Error Downloading the file: {e}"}), 500

@app.route('/preview/<file_id>')
@login_required
def file_preview(file_id):
    block_on_validation_in_progress()
    try:
        file_info_list = bot._ops.find_record_by_attribute(bot._schema.copy(), "file_id", file_id)
        filename = file_info_list[0]["filename"] if file_info_list else ""
        raw_bytes = file_info_list[0].get("raw_size_bytes") if file_info_list else None
        ext = filename.split('.')[-1].lower() if '.' in filename else ""
        
        mime_types = {
            'png': 'image/png', 'jpg': 'image/jpeg', 'jpeg': 'image/jpeg',
            'gif': 'image/gif', 'webp': 'image/webp', 'svg': 'image/svg+xml',
            'mp4': 'video/mp4', 'webm': 'video/webm', 'ogv': 'video/ogg',
            'mp3': 'audio/mpeg', 'wav': 'audio/wav', 'ogg': 'audio/ogg',
            'pdf': 'application/pdf', 'txt': 'text/plain; charset=utf-8',
            'json': 'application/json', 'html': 'text/plain', 'py': 'text/plain'
        }
        mimetype = mime_types.get(ext, 'application/octet-stream')
        
        def generate():
            for chunk in bot.stream_file(file_id):
                yield chunk
                
        response = Response(stream_with_context(generate()), mimetype=mimetype)
        response.headers["Content-Disposition"] = f"inline; filename=\"{filename}\""
        if raw_bytes:
            response.headers["Content-Length"] = str(raw_bytes)
        return response
    except Exception as e:
        logger.error(f"Error streaming preview for {file_id}: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/search', methods=['GET'])
@login_required
def api_search():
    query = request.args.get('q', '').strip()
    category = request.args.get('category', 'all').lower()
    
    if not query and category == 'all':
        return jsonify({"results": []})
        
    if query:
        records = bot._ops.find_record_by_attribute(bot._schema.copy(), "filename", query, partial_match=True)
    else:
        records, _ = bot._ops.get_file_list_in_a_directory(bot._schema.copy())
        if not isinstance(records, list):
            records = []
    
    cat_exts = {
        'images': ['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg'],
        'videos': ['mp4', 'mkv', 'webm', 'avi', 'mov'],
        'audio': ['mp3', 'wav', 'flac', 'ogg', 'm4a'],
        'documents': ['pdf', 'doc', 'docx', 'txt', 'json', 'csv', 'xlsx', 'pptx'],
        'archives': ['zip', 'rar', '7z', 'tar', 'gz']
    }
    
    if category in cat_exts:
        exts = cat_exts[category]
        records = [r for r in records if r.get('filename', '').split('.')[-1].lower() in exts]
        
    return jsonify({"results": records})

@app.route('/api/backup-schema', methods=['POST'])
@login_required
def api_backup_schema():
    block_on_validation_in_progress()
    success, result = bot.backup_schema_to_telegram()
    if success:
        return jsonify({"status": "success", "message": f"Schema backed up to Telegram successfully! File ID: {result}"})
    else:
        return jsonify({"status": "error", "message": f"Backup failed: {result}"}), 500

@app.route('/api/sync-channel', methods=['POST'])
@login_required
def api_sync_channel():
    block_on_validation_in_progress()
    success, result = bot.sync_channel_messages()
    if success:
        return jsonify({"status": "success", "message": f"Channel Auto-Sync Complete! Imported {result} new files into /Telegram_Imports/."})
    else:
        return jsonify({"status": "error", "message": f"Auto-Sync failed: {result}"}), 500

@app.route('/api/analytics', methods=['GET'])
@login_required
def api_analytics():
    analytics = bot.get_storage_analytics()
    return jsonify(analytics)

@app.route('/api/duplicates', methods=['GET'])
@login_required
def api_duplicates():
    duplicates = bot.find_duplicate_files()
    return jsonify({"duplicates": duplicates})



@app.route('/delete/<message_id>', methods=['POST'])
@login_required
def delete(message_id):
    block_on_validation_in_progress()
    logger.debug(f"Attempting to delete files in message with ID: {message_id}!")
    target_directory = request.form.get('target_directory', "")
    success, err = bot.delete_file(target_directory, message_id)     # supply directory where file is located, message id to delete. [Feature: Add support for deleting message id with out mentioning directory. (needs iterative search)]
    if success is not False:
        logger.debug(f"Deleted the files in message id: {message_id}")
        flash("File deleted successfully!", "success")  # Select category as bootstrap button class, other wise an ugly alert is displayed! Color of alert is based in class of message chosen.
        return redirect(f"{url_for('index')}?target_directory={target_directory}")  # redirect to same location where the delete request came from.
    else:
        logger.error(f"Error deleting file / message with ID: {message_id}")
        return render_template('error.html', error_message=f"Error deleting file / message with ID: {message_id}. Error: {err}")

@app.route('/delete_folder/', methods=['POST'])
@login_required
def delete_folder():
    folder_path = request.form.get('delete_folder', None)   # Which folder must be deleted?
    if folder_path is not None:
        success, err = bot.delete_folder(folder_path)
        if success is not False:
            flash("Folder deletion successful!!", "success")
            return redirect(url_for('index'))   # On success
        else:
            flash("Something went, Folder deletion un-successful! Please check logs.", "danger")
            return render_template('error.html', error_message=err)  # return error message
    return render_template('error.html', error_message="POST request to delete a folder is missing required form fields: 'delete_folder'.")

@app.route('/move_folder/', methods=['POST'])
@login_required
def move_folder():
    folder_to_move = request.form.get("folder_to_move", None)
    target_folder = request.form.get("target_folder", None)
    new_name_for_moved_folder = request.form.get("new_name_for_moved_folder", None)
    if (folder_to_move is None) or (target_folder is None):
        logger.error("MoveFile request is missing required form data, rejected it!")
        return redirect(url_for('index'))
    if new_name_for_moved_folder == "": new_name_for_moved_folder = None   # No new name specified by user.
    res, err = bot.move_folder(folder_to_move, target_folder, new_name_for_moved_folder)    # Invalid folder name sanity checks apply for this new_name_for_moved_folder as well.
    if res is False:
        return jsonify({"error": err})
    return redirect(url_for('index'))

@app.route('/validate/')
@login_required
def validate_schema():
    block_on_validation_in_progress()
    Thread(target=bot.validate_job, daemon=True).start()
    return "This will iterate through all the files in schema, and checks if they still exist in cloud. \
        Finally updates schema with only files that are still available in cloud. This will take a long time, happens in background. \
            Advised to not make any changes to cloud state meanwhile."

@app.route('/persist/upload/', methods=['GET'])
@login_required
def persist_schema():
    block_on_validation_in_progress()
    err_msg = "Unknown error occurred while persisting schema."
    try:
        if not os.path.exists(bot._schema_filepath):
            return render_template('error.html', error_message="Local schema.json file does not exist.")
        with open(bot._schema_filepath, 'rb') as f:
            success, result = bot.upload_file(file=f, file_name=os.path.basename(bot._schema_filepath), update_schema=False)
            if success is True:
                return jsonify({"message": f"Schema Upload successful, Use {result} to recover!"})
            else:
                err_msg = str(result)
    except Exception as err:
        err_msg = str(err)
        logger.error(f"Something went wrong during uploading schema: {err}")
    return render_template('error.html', error_message=err_msg)

@app.route('/persist/download/', methods=['GET', 'POST'])
@login_required
def recover_schema():
    block_on_validation_in_progress()
    if request.method == 'GET':
        return render_template('recovery.html')
    try:
        file_content, _ = bot.download_file(file_id=request.form.get("file_id"))
        if file_content:
            bot.save_schema(file_content)
            logger.info(f"Schema recovery successful!")
            flash("Schema recovery successful!", "success")
            return redirect(url_for('index'))
    except Exception as err:
        logger.error(f"Something went wrong recovering schema from cloud: {err}")
        flash("Something went wrong recovering schema from cloud", "danger")
    return render_template('error.html', error_message='Something went wrong during schema recovery. Please try again!!')

@app.route('/share', methods=['POST'])
@login_required  # Only logged in user should be able to share something.
def share_file():
    """Add a file id to be shared. File shares are stored in memory, lost with a server crash / restart event."""
    file_id = request.form.get("file_id", None)  # get the file_id of file to be shared.
    if file_id is not None:
        if file_id not in list(shared_files_dict.keys()):
            shared_files_dict[file_id] = {"added": datetime.utcnow(), "expiry_in_mins": 100, "attempts": 2}    # expire in 100 mins.
            msg = f"File with ID {file_id} is enabled for sharing, Expires in 100 mins / 2 download attempts (Whichever is hit first). Please use `share_link` to download."
            logger.info(msg + f"Active file shares in this moment: {len(list(shared_files_dict.keys()))}")
            return jsonify({"status_code": 200, "message": msg, "share_link": f"https://{request.headers.get('Host')}/shared/{file_id}"})   # return a link in response with which any user can download file without logging in.
        else:
            return jsonify({"status_code": 400, "message": "The file is already being shared."})
    return jsonify({"status_code": 400, "message": "file_id must be specified as a form field in the request."})

@app.route('/shared/<file_id>', methods=['GET'])    # login not needed for this route, as normal users will use this route to get shared files.
def get_shared_file(file_id):
    if file_id in list(shared_files_dict.keys()):
        file_content, file_name_or_error = bot.download_file(file_id)
        if file_content is not False:
            shared_files_dict[file_id]["attempts"] -= 1  # Each time file is downloaded, 1 attempt over. Link will be disabled after attempts exceeded.
            return send_file(io.BytesIO(file_content), as_attachment=True, download_name=file_name_or_error)    # send download to user if download from telegram is successful. Nothing is saved in this server.
        else:
            return jsonify({"status_code": 500, "message": "Sorry! Not sure what went wrong, but you are not getting this file at the moment!"})
    else:
        return jsonify({"status_code": 404, "message": "File sharing link is either invalid or expired."})

@app.route('/search/', methods=['GET', 'POST'])
@login_required
def search():   # Improve search functionality.
    result = []
    file_name = request.form.get("file_name", None)
    if file_name is not None and file_name != "":
        res = bot._ops.find_record_by_attribute(bot._schema.copy(), "filename", file_name, partial_match=True)
        if len(res) > 0:
            result.extend(res)
            return render_template("index.html", results=result)    # No upload functionality, no breadcrumbs, no schema info footer.
    flash("No Records were found matching the search criteria!!", "warning")
    return redirect(url_for("index"))

if __name__ == '__main__':
    logging.basicConfig(filename="logs.txt", filemode='a', level=os.getenv("LOGGING_LEVEL", 'DEBUG').upper())
    app.run(port=443, host='0.0.0.0', debug=True, ssl_context=context)
