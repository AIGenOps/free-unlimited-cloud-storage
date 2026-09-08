"""
TelegramCloud Core Engine & Cryptography Operations
Maintained by AIGenOps
"""

import os
import threading
import tempfile
import requests
from telegram import Bot, InputFile, error as telegram_error # InputMediaDocument - Used for editing media in a message id.
from os import environ as env, path
from werkzeug import datastructures
from datetime import datetime
from pathvalidate import sanitize_filename, sanitize_filepath
from dotenv import load_dotenv
import time
from hurry.filesize import size
import logging
import json
## file enc / dec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64
####
load_dotenv()
logger = logging.getLogger()

class BotActions:
    def __init__(self, schema_filepath=None, encrypted: bool=True) -> None:
        self._schema_lock = threading.Lock()
        self.__bot_token = str(env["API_KEY"])         # Raises key error if not found.
        channel_id = str(env["CHANNEL_ID"]).strip()
        if not channel_id.startswith("-"):
            channel_id = f"-{channel_id}"
        self.__channel_id = channel_id     # Channel Id where files are uploaded.
        self.__bot = Bot(token=self.__bot_token)  # Bot for all file operations.
        self._is_encryption_enabled = encrypted
        if self._is_encryption_enabled:  # Below helper id needed only when encryption is enabled by user.
            logger.info("File Encryption is enabled for this session! All uploads done in this session will be encrypted uploads.")
            self.__file_ops = EncDecHelper(self.__bot_token + self.__channel_id)    # bot token + channel id combined as a string is used as base encryption key.
        if schema_filepath is None:  # If none, use default, else use user-defined path. This will be used for doing multiple backups using cli. Or for testing purposes.
            self._schema_filepath = './schema/schema.json'   # This folder must be pointed to a named volume for schema persistence.
        self._cache_folder = "./cache/"  # This folder holds recently downloaded files from telegram.
        self._ops = SchemaManipulations()
        self._schema: dict[str, list[dict[str, str|int]] | dict[str, str|int]] = self.load_or_reload_schema()
        self.save_schema()  # SAVE SCHEMA ONCE At start
        self.VALIDATION_ACTIVE = False
        self._default_upload_directory = ""
        logger.info("Required config variables are read from env!")


    def load_or_reload_schema(self):
        try:
            with open(self._schema_filepath, 'r') as schema_file:
                schema = json.load(schema_file)
                if "meta" not in schema:
                    schema["meta"] = {"total_size": "Unknown", "last_validated": "Please re-validate schema ASAP!"}
                return schema
        except (FileNotFoundError, json.decoder.JSONDecodeError):
            logger.info("Schema.json not found in local directory, creating new empty schema.")
            return {'root': [], "meta": {"total_size": 0, "last_validated": "Unavailable! Please Revalidate schema."}}

    def update_schema_total_size(self):
        """Recalculate total consumed space from all files in schema and update meta.total_size."""
        try:
            analytics = self.get_storage_analytics()
            if "meta" not in self._schema:
                self._schema["meta"] = {"total_size": "0 KB", "last_validated": "Never"}
            self._schema["meta"]["total_size"] = analytics.get("total_size_formatted", "0 KB")
        except Exception as e:
            logger.error(f"Error updating schema total size: {e}")

    def save_schema(self, file_content_bytes: bytes = None):
        with self._schema_lock:
            try:
                if file_content_bytes is not None:  # If file is specified explicitly as byte array.
                    self._schema = json.loads(file_content_bytes.decode('utf8'))    # load bytes as str and then to dictionary.
                self.update_schema_total_size()
                dir_name = os.path.dirname(self._schema_filepath) or "."
                os.makedirs(dir_name, exist_ok=True)
                with tempfile.NamedTemporaryFile('w', dir=dir_name, delete=False, encoding='utf-8') as tf:
                    json.dump(self._schema, tf, indent=4)
                    temp_name = tf.name
                os.replace(temp_name, self._schema_filepath)
                logger.debug(f"Latest Schema dumped atomically!!")
                return True, None
            except Exception as err:
                logger.error(f"Failed atomic schema save: {err}")
                return False, err


    def validate_job(self):   # Needs refactoring as schema changed.
        """Works on schema, start this function as a background thread. Finally put the last validation date in schema for future reference (Display last validation date in homepage also.)"""
        self.VALIDATION_ACTIVE = True    # disable all routes during update via a control flag variable.
        try:
            meta = {"total_size": 0, "last_validated": ""}
            def process_schema(schema, meta):
                if isinstance(schema, dict):
                    for key, val in schema.items():
                        if key == "root" and isinstance(val, list):
                            file_validate(val, meta)  # Update the 'root' list in-place
                        else:
                            process_schema(val, meta)
                return schema, meta

            def file_validate(file_list: list[dict], meta: dict):
                for pos, file_info in enumerate(file_list.copy()):
                    try:
                        file_id = file_info["file_id"]
                        message_id = file_info["message_id"]
                    except KeyError:
                        file_list.remove(file_info)
                        logger.error(f"Ill-Formatted record found. File_ID missing. Dropping it.")
                        continue    # no need to proceed further on this file.
                    try:
                        cloud_file = self.__bot.get_file(file_id=file_id)
                        logger.debug(f"File is present in cloud, Ref Files ID: {file_id}")
                    except (telegram_error.BadRequest, telegram_error.TelegramError):
                        logger.info(f"The file no longer exists on cloud! Removing it from schema. Ref Id: {file_id}")
                        file_list.remove(file_info)
                        continue
                    try:
                        underlying_message = self.__bot.copy_message(from_chat_id=self.__channel_id, chat_id=self.__channel_id, message_id=message_id)
                        if underlying_message and underlying_message.message_id:
                            self.__bot.delete_message(chat_id=self.__channel_id, message_id=underlying_message.message_id)
                    except telegram_error.TelegramError as err:
                        if "Message to copy not found" in str(err):
                            logger.info(f"Underlying message for a file with message id '{message_id}' is deleted. SO deleting file record from schema!!")
                            file_list.remove(file_info)
                            continue
                    meta["total_size"] += cloud_file.file_size
                    file_list[pos]["size"] = self._format_size_human(cloud_file.file_size)
                    file_list[pos]["raw_size_bytes"] = cloud_file.file_size
                    time.sleep(1)   # small delay to avoid DDOS scenario.

            process_schema(self._schema, meta)
            self._schema["meta"]["last_validated"] = str(datetime.utcnow())
            self._schema["meta"]["total_size"] = self._format_size_human(meta["total_size"])
            self.save_schema()
            logger.info("Schema Validation completed successfully!!")
            self.VALIDATION_ACTIVE = False
        except Exception as err:
            self.VALIDATION_ACTIVE = False
            logger.error(f"Something went wrong during schema validation. Operation failed. Error: {err}")

    def is_validation_active(self) -> bool:
        return self.VALIDATION_ACTIVE

    def get_active_users_in_channel(self):
        """Get Number of users are currently added to channel. For best security only you and bot (total 2) must be the members present in the private channel."""
        error = None
        try:
            chat_member_count = self.__bot.get_chat_members_count(self.__channel_id)     # Get number of users added to the channel.
            if chat_member_count > 2:
                error = f"[Security Breach] -> Number of users in channel is more than two: '{chat_member_count}' !! Please go to telegram app, manually remove everyone except the bot. Otherwise they may have access to any un-encrypted files in the channel!!"
                logger.warning(error)
            return chat_member_count, error
        except Exception as err:
            error = f"[Telegram Error] Cannot access channel '{self.__channel_id}': {err}. Please add your bot to the Telegram private channel as an Administrator and verify your CHANNEL_ID in .env."
            logger.error(error)
            return 0, error


    def send_admin_notification(self, message_text: str) -> bool:
        """Send a notification message directly to Telegram channel (e.g. registration verification code)."""
        try:
            self.__bot.send_message(chat_id=self.__channel_id, text=message_text, parse_mode="Markdown")
            return True
        except Exception as e:
            logger.error(f"Failed sending admin Telegram notification: {e}")
            return False


    def upload_file(self, file: datastructures.FileStorage | bytes, file_name: str, update_schema: bool = True, directory: str = "", progress_callback=None):
        try:
            file_name = sanitize_filename(file_name)
            res, err = self._ops.get_sanitized_file_path(directory)  # sanity check
            if res is False:
                return False, err   # return the error to caller.

            if isinstance(file, bytes):
                raw_data = file
            elif hasattr(file, 'read'):
                raw_data = file.read()
            else:
                raw_data = bytes(file)

            total_upload_size = len(raw_data)
            max_chunk = 19_500_000  # 19.5 MB chunk size threshold

            if progress_callback:
                progress_callback(10, "Encrypting & preparing file...")

            if total_upload_size <= max_chunk:
                payload = self.__file_ops.get_encrypted_data_binary(raw_data) if self._is_encryption_enabled else raw_data
                if progress_callback:
                    progress_callback(40, "Sending file to Telegram...")
                response = self.__bot.send_document(
                    filename=file_name,
                    caption=file_name,
                    chat_id=self.__channel_id,
                    document=InputFile(payload, filename=file_name),
                    timeout=120
                )
                if progress_callback:
                    progress_callback(90, "Saving schema record...")
                file_info = {
                    'filename': file_name,
                    'message_id': response.message_id,
                    'file_id': response.document.file_id,
                    'size': size(response.document.file_size),
                    'raw_size_bytes': response.document.file_size,
                    'is_encrypted': self._is_encryption_enabled,
                    'is_chunked': False
                }
                primary_file_id = response.document.file_id
            else:
                logger.info(f"File '{file_name}' ({size(total_upload_size)}) exceeds single Telegram limit. Chunking into 19.5MB parts...")
                chunk_slices = [raw_data[i:i + max_chunk] for i in range(0, total_upload_size, max_chunk)]
                chunks_info = []

                total_chunks = len(chunk_slices)
                for idx, chunk_bytes in enumerate(chunk_slices):
                    part_num = idx + 1
                    pct = 10 + int((idx / total_chunks) * 80)
                    msg_text = f"Uploading Part {part_num}/{total_chunks} to Telegram..."
                    if progress_callback:
                        progress_callback(pct, msg_text)

                    part_name = f"{file_name}.part{part_num:03d}"
                    payload = self.__file_ops.get_encrypted_data_binary(chunk_bytes) if self._is_encryption_enabled else chunk_bytes
                    response = self.__bot.send_document(
                        filename=part_name,
                        caption=f"{file_name} Part {part_num}/{total_chunks}",
                        chat_id=self.__channel_id,
                        document=InputFile(payload, filename=part_name),
                        timeout=120
                    )
                    chunks_info.append({
                        'chunk_index': idx,
                        'file_id': response.document.file_id,
                        'message_id': response.message_id,
                        'size': size(len(chunk_bytes)),
                        'raw_size_bytes': len(chunk_bytes)
                    })
                    time.sleep(0.3)

                if progress_callback:
                    progress_callback(95, "Updating schema...")

                file_info = {
                    'filename': file_name,
                    'message_id': chunks_info[0]['message_id'],
                    'file_id': chunks_info[0]['file_id'],
                    'size': size(total_upload_size),
                    'raw_size_bytes': total_upload_size,
                    'is_encrypted': self._is_encryption_enabled,
                    'is_chunked': True,
                    'total_chunks': len(chunks_info),
                    'chunks': chunks_info
                }
                primary_file_id = chunks_info[0]['file_id']

            if update_schema:
                self._schema = self.load_or_reload_schema()
                if directory == "":
                    self._schema["root"].append(file_info)
                else:
                    modified_schema, err = self._ops.manipulate_schema(directory, file_info, self._schema.copy(), False)
                    if modified_schema is False:
                        logger.error(f"File uploaded, but unable to add it to schema, Error: {err}")
                        return False, err
                    self._schema = modified_schema.copy()
                logger.debug(f"File uploaded to path '{directory}' successfully.")
                self.save_schema()

            if progress_callback:
                progress_callback(100, "Complete!")
            return True, primary_file_id
        except Exception as e:
            logger.error(f"Error uploading file: {e}")
            return False, str(e)

    def delete_file(self, full_path: str, message_id: int, with_out_schema_change: bool = False):
        """Delete a file based on `message_id` and remove its corresponding record from schema completely."""
        try:
            self._schema = self.load_or_reload_schema()
            target_msg_id = int(message_id)
            file_record = self._ops.find_record_by_attribute(self._schema.copy(), "message_id", target_msg_id)

            if file_record and len(file_record) > 0 and file_record[0].get("is_chunked"):
                chunk_list = file_record[0].get("chunks", [])
                logger.info(f"Deleting chunked file containing {len(chunk_list)} message chunks from Telegram channel...")
                for chk in chunk_list:
                    try:
                        self.__bot.delete_message(chat_id=self.__channel_id, message_id=int(chk["message_id"]))
                    except Exception as err:
                        logger.warning(f"Could not delete chunk message {chk.get('message_id')}: {err}")
                res = True
            else:
                try:
                    res = self.__bot.delete_message(chat_id=self.__channel_id, message_id=target_msg_id)
                except telegram_error.TelegramError as err:
                    if "Message to delete not found" in str(err) or "message to delete not found" in str(err):
                        res = True
                    else:
                        logger.error(f"Telegram error deleting message {target_msg_id}: {err}")
                        res = True  # Still purge from schema even if message was deleted manually on Telegram

            if res is True:
                if with_out_schema_change is True:
                    return True, ""

                # Purge file record from schema recursively by message_id or chunk message_ids
                def remove_record_recursively(d):
                    if isinstance(d, dict):
                        for k, v in list(d.items()):
                            if k == "root" and isinstance(v, list):
                                d["root"] = [
                                    f for f in v
                                    if str(f.get("message_id")) != str(target_msg_id)
                                    and not any(str(chk.get("message_id")) == str(target_msg_id) for chk in f.get("chunks", []))
                                ]
                            elif isinstance(v, dict):
                                remove_record_recursively(v)

                remove_record_recursively(self._schema)
                self.save_schema()
                logger.info(f"File with Message_ID: {message_id} purged from Telegram and schema successfully!")
                return True, None
            return False, "Failed deleting message from Telegram"
        except Exception as e:
            logger.error(f"Error deleting file: {e}")
            return False, str(e)

    def move_folder(self, folder_to_move: str, target_folder: str, new_name_for_moved_folder: str=None):
        folder_name, sub_schema, err = self._ops.get_contents_in_directory(folder_to_move, self._schema.copy(), False)
        if new_name_for_moved_folder is not None:
            folder_name = new_name_for_moved_folder
        logger.info(f"The folder '{folder_name}' in path {folder_to_move} is requested to be moved to new path '{target_folder}'")
        if sub_schema in [False, None]:
            return False, err
        modified_schema_after_folder_deletion, err = self._ops.manipulate_schema(folder_to_move, None, self._schema.copy().copy(), delete=True)
        if modified_schema_after_folder_deletion in [False, None]:
            return False, err
        logger.info("Substitution success!")
        modified_schema_after_substitution, err = self._ops.manipulate_schema(target_folder, sub_schema, modified_schema_after_folder_deletion, delete=False, add_folder=True, folder_name=folder_name)
        if modified_schema_after_substitution in [False, None]:
            return False, err
        logger.info("delete of original path success!")
        self._schema = modified_schema_after_substitution.copy()
        self.save_schema()
        return True, ""

    def delete_folder(self, folder_path: str):
        try:
            _, sub_schema, err = self._ops.get_contents_in_directory(folder_path, self._schema.copy(), False)
            if sub_schema is False:
                return False, err
            file_list, err = self._ops.get_file_list_in_a_directory(sub_schema)
            if file_list is False:
                return False, err
            logger.info(f"Received {len(file_list)} files for deletion under path: {str(folder_path)}!!")
            modified_schema, err = self._ops.manipulate_schema(folder_path, None, self._schema.copy(), delete=True)
            if modified_schema is False:
                return False, err
            for file_info in file_list:
                logger.info(f"Attempting to delete file: {file_info['filename']}")
                self.delete_file(full_path=None, message_id=file_info["message_id"], with_out_schema_change=True)
            if len(file_list) == 0:
                logger.debug(f"Received folder deletion request, but there are no files inside specified folder path {folder_path}!!")
            self._schema = modified_schema.copy()
            self.save_schema()
            return True, ""
        except Exception as err:
            return False, err

    def download_file(self, file_id: str, is_encrypted: bool=None):
        try:
            file_record = self._ops.find_record_by_attribute(self._schema.copy(), "file_id", file_id)
            if file_record and len(file_record) > 0:
                record = file_record[0]
                file_name = record.get("filename", f"download_{file_id}")
                is_encrypted_flag = is_encrypted if is_encrypted is not None else record.get("is_encrypted", False)

                if record.get("is_chunked"):
                    combined = bytearray()
                    chunks = record.get("chunks", [])
                    logger.info(f"Reassembling chunked file '{file_name}' ({len(chunks)} chunks)...")
                    for chk in chunks:
                        fp = self.__bot.get_file(chk["file_id"], timeout=60)
                        raw_chunk = fp.download_as_bytearray()
                        if is_encrypted_flag:
                            raw_chunk = self.__file_ops.get_decrypted_data_binary(raw_chunk)
                        combined.extend(raw_chunk)
                    return bytes(combined), file_name

            file_pointer = self.__bot.get_file(file_id, timeout=60)
            file_content: bytes = file_pointer.download_as_bytearray()
            file_name = file_pointer.file_path.split('/')[-1]
            if is_encrypted is None:
                if file_record and len(file_record) > 0:
                    is_encrypted = file_record[0].get("is_encrypted", False)
                    file_name = file_record[0].get("filename", file_name)
                else:
                    is_encrypted = False
            if is_encrypted:
                file_content = self.__file_ops.get_decrypted_data_binary(file_content)
            return file_content, file_name
        except Exception as e:
            logger.error(f"Error downloading the file: {e}")
            return False, e

    def stream_file(self, file_id: str, chunk_size: int = 64 * 1024):
        """Yield chunks of file data for memory-efficient streaming delivery."""
        try:
            file_record = self._ops.find_record_by_attribute(self._schema.copy(), "file_id", file_id)
            if file_record and len(file_record) > 0 and file_record[0].get("is_chunked"):
                record = file_record[0]
                is_encrypted = record.get("is_encrypted", False)
                chunks = record.get("chunks", [])
                logger.info(f"Streaming chunked file '{record.get('filename')}' ({len(chunks)} chunks)...")
                for chk in chunks:
                    file_pointer = self.__bot.get_file(chk["file_id"], timeout=60)
                    if is_encrypted:
                        raw_bytes = file_pointer.download_as_bytearray()
                        decrypted = self.__file_ops.get_decrypted_data_binary(raw_bytes)
                        for i in range(0, len(decrypted), chunk_size):
                            yield decrypted[i:i + chunk_size]
                    else:
                        file_url = file_pointer.file_path
                        if not file_url.startswith("http"):
                            file_url = f"https://api.telegram.org/file/bot{self.__bot_token}/{file_url}"
                        r = requests.get(file_url, stream=True, timeout=60)
                        r.raise_for_status()
                        for chunk in r.iter_content(chunk_size=chunk_size):
                            if chunk:
                                yield chunk
                return

            file_pointer = self.__bot.get_file(file_id, timeout=60)
            file_name = file_pointer.file_path.split('/')[-1]
            is_encrypted = False
            if file_record and len(file_record) > 0:
                is_encrypted = file_record[0].get("is_encrypted", False)
                file_name = file_record[0].get("filename", file_name)

            file_url = file_pointer.file_path
            if not file_url.startswith("http"):
                file_url = f"https://api.telegram.org/file/bot{self.__bot_token}/{file_url}"

            if is_encrypted:
                raw_bytes = file_pointer.download_as_bytearray()
                decrypted = self.__file_ops.get_decrypted_data_binary(raw_bytes)
                for i in range(0, len(decrypted), chunk_size):
                    yield decrypted[i:i + chunk_size]
            else:
                r = requests.get(file_url, stream=True, timeout=60)
                r.raise_for_status()
                for chunk in r.iter_content(chunk_size=chunk_size):
                    if chunk:
                        yield chunk
        except Exception as e:
            logger.error(f"Error streaming file {file_id}: {e}")
            raise e

    def backup_schema_to_telegram(self):
        """Upload current schema.json to Telegram storage channel as automated schema backup."""
        try:
            if not os.path.exists(self._schema_filepath):
                return False, "schema.json does not exist locally."
            with open(self._schema_filepath, 'rb') as f:
                now_str = datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")
                backup_name = f"schema_backup_{now_str}.json"
                response = self.__bot.send_document(
                    chat_id=self.__channel_id,
                    document=InputFile(f, filename=backup_name),
                    caption=f"Automated Schema Backup - {now_str}",
                    timeout=60
                )
            logger.info(f"Schema backed up to Telegram! File ID: {response.document.file_id}")
            return True, response.document.file_id
        except Exception as e:
            logger.error(f"Failed to backup schema to Telegram: {e}")
            return False, str(e)

    def sync_channel_messages(self, probe_count: int = 50):
        """Probe recent Telegram channel message IDs to discover and register un-imported files into schema."""
        try:
            all_files, _ = self._ops.get_file_list_in_a_directory(self._schema.copy())
            existing_msg_ids = {int(f["message_id"]) for f in all_files if "message_id" in f and str(f["message_id"]).isdigit()}
            
            max_id = max(existing_msg_ids) if existing_msg_ids else 0
            start_id = max(1, max_id - 5)
            end_id = max_id + probe_count
            
            imported_count = 0
            for msg_id in range(start_id, end_id + 1):
                if msg_id in existing_msg_ids:
                    continue
                try:
                    copied = self.__bot.copy_message(from_chat_id=self.__channel_id, chat_id=self.__channel_id, message_id=msg_id)
                    if copied and copied.message_id:
                        self.__bot.delete_message(chat_id=self.__channel_id, message_id=copied.message_id)
                        file_info = {
                            "filename": f"Telegram_Import_Msg_{msg_id}.dat",
                            "message_id": msg_id,
                            "file_id": f"imported_{msg_id}",
                            "size": "Unknown",
                            "is_encrypted": False
                        }
                        modified_schema, err = self._ops.manipulate_schema("Telegram_Imports", file_info, self._schema.copy(), delete=False)
                        if modified_schema:
                            self._schema = modified_schema.copy()
                            imported_count += 1
                except telegram_error.TelegramError:
                    continue
                    
            if imported_count > 0:
                self.save_schema()
                logger.info(f"Auto-Sync imported {imported_count} new files into schema!")
            return True, imported_count
        except Exception as e:
            logger.error(f"Error during channel auto-sync: {e}")
            return False, str(e)

    @staticmethod
    def _parse_size_string(raw_str: str) -> int:
        """Parse size strings such as '42M', '526K', '1.5 MB', '1024 B', '79MB' into exact byte integers."""
        if not raw_str or str(raw_str).strip().lower() in ("unknown", "none", "null", ""):
            return 0
        import re
        clean_str = str(raw_str).strip()
        match = re.search(r'([0-9]+(?:\.[0-9]+)?)\s*([A-Za-z]*)', clean_str)
        if not match:
            return 0
        try:
            val = float(match.group(1))
            unit = match.group(2).upper()
            multipliers = {
                "": 1,
                "B": 1,
                "K": 1024,
                "KB": 1024,
                "M": 1024**2,
                "MB": 1024**2,
                "G": 1024**3,
                "GB": 1024**3,
                "T": 1024**4,
                "TB": 1024**4,
            }
            mult = multipliers.get(unit, 1)
            return int(val * mult)
        except Exception:
            return 0

    def _parse_file_size_bytes(self, file_info: dict) -> int:
        """Extract exact integer bytes from a file record in schema."""
        if not isinstance(file_info, dict):
            return 0
        raw_bytes = file_info.get("raw_size_bytes")
        if isinstance(raw_bytes, (int, float)) and raw_bytes > 0:
            return int(raw_bytes)
        if file_info.get("is_chunked") and isinstance(file_info.get("chunks"), list):
            chunk_sum = 0
            for chk in file_info["chunks"]:
                if isinstance(chk, dict):
                    cb = chk.get("raw_size_bytes")
                    if isinstance(cb, (int, float)) and cb > 0:
                        chunk_sum += int(cb)
                    else:
                        chunk_sum += self._parse_size_string(str(chk.get("size", "0")))
            if chunk_sum > 0:
                return chunk_sum
        parsed = self._parse_size_string(str(file_info.get("size", "0")))
        if parsed > 0:
            return parsed

        # Fallback for Unknown size files: try fetching cloud file size from Telegram API if file_id exists
        file_id = file_info.get("file_id", "")
        if file_id and not file_id.startswith("imported_"):
            try:
                cloud_file = self.__bot.get_file(file_id=file_id)
                if cloud_file and cloud_file.file_size > 0:
                    file_info["raw_size_bytes"] = cloud_file.file_size
                    file_info["size"] = self._format_size_human(cloud_file.file_size)
                    return cloud_file.file_size
            except Exception:
                pass

        return 0

    @staticmethod
    def _format_size_human(num_bytes: int) -> str:
        """Format raw byte integers into human readable string (e.g. 43.01 MB)."""
        if num_bytes <= 0:
            return "0 KB"
        val = float(num_bytes)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if val < 1024.0:
                if unit == 'B':
                    return f"{int(val)} B"
                return f"{val:.2f} {unit}"
            val /= 1024.0
        return f"{val:.2f} PB"

    def get_storage_analytics(self):
        """Return aggregated storage metrics, category breakdown, and top largest files."""
        try:
            file_list, _ = self._ops.get_file_list_in_a_directory(self._schema.copy())
            if not isinstance(file_list, list):
                file_list = []
                
            categories = {
                "images": 0,
                "videos": 0,
                "audio": 0,
                "documents": 0,
                "archives": 0,
                "other": 0
            }
            
            ext_map = {
                "images": {'png', 'jpg', 'jpeg', 'gif', 'webp', 'svg'},
                "videos": {'mp4', 'mkv', 'webm', 'avi', 'mov'},
                "audio": {'mp3', 'wav', 'flac', 'ogg', 'm4a'},
                "documents": {'pdf', 'doc', 'docx', 'txt', 'json', 'csv', 'xlsx', 'pptx'},
                "archives": {'zip', 'rar', '7z', 'tar', 'gz'}
            }
            
            total_bytes = 0
            parsed_files = []
            
            for file_info in file_list:
                fname = file_info.get("filename", "")
                ext = fname.split('.')[-1].lower() if '.' in fname else ""
                
                num_bytes = self._parse_file_size_bytes(file_info)
                total_bytes += num_bytes
                
                cat_found = "other"
                for cat_name, exts in ext_map.items():
                    if ext in exts:
                        cat_found = cat_name
                        break
                categories[cat_found] += num_bytes
                
                size_display = file_info.get("size")
                if not size_display or size_display in ("Unknown", "0 KB"):
                    size_display = self._format_size_human(num_bytes)
                    
                parsed_files.append({
                    "filename": fname,
                    "size": size_display,
                    "bytes": num_bytes,
                    "file_id": file_info.get("file_id", ""),
                    "message_id": file_info.get("message_id", 0)
                })
                
            parsed_files.sort(key=lambda x: x["bytes"], reverse=True)
            top_largest = parsed_files[:10]
            
            def count_folders(d):
                count = 0
                for k, v in d.items():
                    if k not in ["root", "meta"] and isinstance(v, dict):
                        count += 1 + count_folders(v)
                return count
                
            folder_count = count_folders(self._schema.copy())
            
            return {
                "total_files": len(file_list),
                "total_folders": folder_count,
                "total_size_bytes": total_bytes,
                "total_size_formatted": self._format_size_human(total_bytes),
                "categories_bytes": categories,
                "top_largest": top_largest
            }
        except Exception as e:
            logger.error(f"Error computing storage analytics: {e}")
            return {}

    def find_duplicate_files(self):
        """Identify duplicate files across all directories matching by filename."""
        try:
            file_list, _ = self._ops.get_file_list_in_a_directory(self._schema.copy())
            if not isinstance(file_list, list):
                return []
                
            name_groups = {}
            for file_info in file_list:
                fname = file_info.get("filename", "")
                if not fname:
                    continue
                name_groups.setdefault(fname, []).append(file_info)
                
            duplicates = []
            for fname, group in name_groups.items():
                if len(group) > 1:
                    duplicates.append({
                        "filename": fname,
                        "count": len(group),
                        "copies": group
                    })
            return duplicates
        except Exception as e:
            logger.error(f"Error finding duplicate files: {e}")
            return []




class SchemaManipulations:
    """Offload schema manipulations from other classes, provide methods for easy schema manipulation"""

    def get_sanitized_file_path(self, full_path: str) -> list[str]:
        disallowed_dir_names = ["root", "", " ", "meta", "/", "\\"]    # meta, root are reserved keywords for our schema.
        if full_path is None or full_path == "":     # callers should handle this as root directory.
            return "", ""
        if full_path[0] == "/": full_path = full_path[1:]    # remove first '/' if present.
        if full_path[-1] == "/": full_path = full_path[:-1]    # remove last '/' if present.
        full_path: list = sanitize_filepath(full_path).split('/')
        if len(full_path) > 1 and "" in full_path:  # "".split(/) becomes [""]. This is the default. In case of default, write to first parent directory. Checking if some long path is given, and no empty spaces are there in path.
            logger.error(f"Invalid Path Supplied, Unable to sanitize: {full_path}")
            return False, f"Invalid Filepath: {full_path}, has empty spaces / illegal folder names!"
        if any(sub_dir in disallowed_dir_names for sub_dir in full_path):
            return False, f"Path {full_path} contains invalid sub directory names. Not allowed: {disallowed_dir_names}"
        return full_path, ""

    def get_contents_in_directory(self, directory: str, ret_structure: dict, files_only: bool=False) -> dict | list:
        """Returns the dictionary item by navigating to the given directory (nested)."""
        full_path, err = self.get_sanitized_file_path(directory)  # get sanitized file path from a directory string.
        if full_path is False:  # Invalid path.
            return False, False, err   # return error.
        sub_dir = ""    # avoid unbound local error in some cases.
        for sub_dir in full_path:
            if sub_dir not in ret_structure:
                return False, False, f"Invalid Path - {directory}!!"
            ret_structure = ret_structure[sub_dir]
        if files_only:
            return sub_dir, ret_structure["root"], ""    # no error. Just return files.
        else:
            try:
                ret_structure.pop("meta")   # reserved folder. Not to be displayed to user.
            except KeyError:
                pass
            return sub_dir, ret_structure, ""    # no error. Return final sub_dir in path + files, folders inside given directory.

    def manipulate_schema(self, full_path: str, file_info: dict, schema: dict, delete: bool, add_folder: bool=False, folder_name=None):   # This function needs some severe refactoring.
        """iteratively creates / navigates a nested directory structure in schema, adds the given file_info dict to the nested path, attempts to delete the same from schema if del is set to True. returns updated schema.\n
           1. Ex: self.manipulate_schema("some/valid/path/in_schema", None, full_schema_or_sub_schema_as_dict, True) --> This will delete the specified full_path from specified schema, returns updated schema. Deletes all the sub_directories, files inside specified path completely.\n
           2. Ex: self.manipulate_schema("some/valid/path/in_schema", {"message_id": 123}, full_schema_or_sub_schema_as_dict, True)  --> This will delete the specified file_info single record from specified schema under full_path, returns updated schema.\n
           3. Ex: self.manipulate_schema("some/valid/path/in_schema", {"message_id": 123}, full_schema_or_sub_schema_as_dict, False)  --> This will Add the specified file_info single record to specified schema under full_path, returns updated schema.
           4. self.manipulate_schema("some/valid/path/in_schema", {"root": [], "folder2": {"root": [{"message_id": 123}]}}, full_schema_or_sub_schema_as_dict, False, True, "newFolder5") --> This will add the file_info (folder info in this case) to specified schema under full_path, folder key name would be as supplied `folder_name`.
        """
        def helper_fnc(full_path: list, target: dict, file_info: dict):  # create all nested keys / sub directories into schema, if not present.
            if len(full_path) > 0:
                sub_dir = full_path.pop(0)
                if delete and len(full_path) == 0 and file_info is None:
                    # if delete = True, full_path is given, file_info = None (not specified), it means delete the given whole path.
                    logger.info(f"deleting sub dir: {sub_dir}")
                    target.pop(sub_dir)  # remove final sub_dir specified in path.
                    return target
                if sub_dir not in target.keys():    # this is not a possible scenario during delete.
                    target[sub_dir] = {"root": []}
                if len(full_path) == 0:     # if previously fetched sub_dir was the last in path, add the file to that sub dir only. "root" is a list in each directory that holds file_infos.
                    if delete:  # to delete. No other attribute other than `message_id` needs to be supplied for deletion.
                        logger.debug(f"Attempting to delete stale file from schema. MessageId: {file_info['message_id']}, Path: {full_path}")
                        for pos, info in enumerate(target[sub_dir]["root"].copy()):
                            if info["message_id"] == file_info["message_id"]:     # Delete based on supplied message_id.
                                target[sub_dir]["root"].pop(pos)    # remove the record for this message_id.
                                break   # once found and deleted return from loop.
                    else:   # to add
                        target[sub_dir]["root"].append(file_info)   # Whole target will be returned in next run, as the primary check was len(full_path) > 0. Recursion ends.
                helper_fnc(full_path, target[sub_dir], file_info)
            return target

        def add_folder_in_path(full_path: list, folder_name: str, schema_dict: dict, folder_info: dict):
            if len(full_path) > 0:
                sub_dir = full_path.pop(0)
                if sub_dir not in schema_dict.keys():
                    logger.info(f"Creating new sub directory: {sub_dir}!!")
                    schema_dict[sub_dir] = {"root": []}     # create target path if not already there.
                if len(full_path) == 0:  # If current sub_dir is final one. Add folder here it self, return updated schema.
                    if folder_name not in schema_dict[sub_dir]:  # If a folder with same folder_name is present in specified path, it should not overwrite.
                        schema_dict[sub_dir][folder_name] = folder_info  # Added a folder with specified name, sub_schema in the said path.
                    else:
                        raise Exception("A folder with same name is already present where the folder add is attempted!")
                add_folder_in_path(full_path, folder_name, schema_dict[sub_dir], folder_info)
            return schema_dict

        try:
            sanitized_path, err = self.get_sanitized_file_path(full_path)
            if sanitized_path is False:
                logger.error(f"Schema manipulation aborted, as path sanity check failed for: {full_path}")
                return False, err
            if sanitized_path == "" and delete:   # Special code for delete in root.
                logger.debug("Attempting to delete a file in root folder!!")
                for pos, info in enumerate(schema.copy()["root"]):
                    if info["message_id"] == int(file_info["message_id"]):
                        schema["root"].pop(pos)
                modified_schema = schema
            elif add_folder and folder_name is not None and isinstance(file_info, dict):  # If `add_folder` is specified, consider `file_info` as a sub_schema_dict, full path as target_folder to place this sub_schema on key/folder name specified by arg `folder_name`
                folder_name, err = self.get_sanitized_file_path(folder_name)
                folder_name = folder_name[0]    # As we have given folder name not path.
                if folder_name is False:    # applying name sanity checks for new folder as well.
                    logger.error(f"Schema manipulation aborted, as path sanity check failed for: {folder_name}")
                    return False, err
                if sanitized_path == "":    # A folder move to root.
                    logger.debug("Attempting to Move a folder to root directory!!")
                    schema[folder_name] = file_info  # Added a new folder in root directory.
                    modified_schema = schema.copy()
                else:
                    modified_schema = add_folder_in_path(sanitized_path, folder_name, schema, file_info)
            else:
                modified_schema = helper_fnc(sanitized_path, schema.copy(), file_info)
            return modified_schema, ""   # at the end of recursion, we will get updated schema. Starting schema manipulation on a copy of schema to be safe.
        except Exception as err:
            logger.error(f"Serious Problem in manipulating schema. (During Deletion? {delete}), Error: {err}")
            return False, f"Internal Error: {err}"

    def find_record_by_attribute(self, data, attr: str, attr_val: str | int, partial_match: bool=False, results=None) -> list:
        """If `partial_match` is set to True, records are compared as SQL "like" instead of exact match. \n
        I may have messed up the code. But please don't supply `results` argument during this function call. It is supposed to be for internal recursion use only. """
        if results == None:  # For the actual function call, user shouldn't supply this argument, so we start with empty list at first. Later this list is passed through whole recursion process. To finally return populated list.
            results = []
        if isinstance(data, dict):
            if attr in data:
                if partial_match:
                    if str(attr_val).lower() in str(data[attr]).lower():
                        results.append(data)
                else:   # do exact match
                    if str(data[attr]) == str(attr_val):
                        results.append(data)
            else:
                for value in data.values():  # Iterate through values in the dictionary
                    self.find_record_by_attribute(value, attr, attr_val, partial_match, results)   # Recursively search through the nested structure
        elif isinstance(data, list):    # Check if data is a list
            for item in data:   # Iterate through items in the list
                self.find_record_by_attribute(item, attr, attr_val, partial_match, results)    # Search through list of files.
        return results

    def get_file_list_in_a_directory(self, schema_dict: dict):
        """Iterates through all nested keys in given schema dictionary(this can be whole schema are a sub_schema whose structure is similar to ur standard schema). \n
           Adds each file in each sub_directory to file_list. Same can be looped through to get every individual file for processing. \n
            To get all the files present in a sub_directory in schema, call get_contents_in_directory with a path to sub dir, and feed it's response to this function.
        """
        def get_file_list(schema_dict: dict, file_list: list = None):
            if file_list is None:
                file_list = []
            for key, value in schema_dict.items():
                if isinstance(value, dict):
                    get_file_list(value, file_list)
                elif key == "root" and isinstance(value, list):
                    file_list.extend(value)
            return file_list
        try:
            file_list = get_file_list(schema_dict.copy())
            return file_list, ""
        except Exception as err:
            return False, err


class EncDecHelper:
    """Helper class to provide methods for encrypting and decrypting data from and to binary"""
    def __init__(self, passwd: str) -> None:
        self.__enc_key = self.derive_key_from_password(passwd)
        self.__cipher = Fernet(self.__enc_key)

    def derive_key_from_password(self, password, salt=b"salt", iterations=100000):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 32 bytes for Fernet key
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return base64.urlsafe_b64encode(key).decode('utf-8')

    def get_encrypted_data_binary(self, file_binary):
        return self.__cipher.encrypt(file_binary)

    def get_decrypted_data_binary(self, encrypted_file_binary):
        if isinstance(encrypted_file_binary, bytearray):
            encrypted_file_binary = bytes(encrypted_file_binary)
        return self.__cipher.decrypt(encrypted_file_binary)
