import os
import json
import base64
import time
import getpass
import hashlib
import hmac

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Copyright (c) 2026 Rami
# All Rights Reserved.
# Project: Secure Encryption
# Unauthorized copying, modification, or redistribution is prohibited.

APP_FOLDER = os.path.join(
    os.environ.get("APPDATA", os.path.expanduser("~")),
    "SecureEncryptionApp"
)

IDENTITY_FILE = os.path.join(APP_FOLDER, "identity.json")
CONTACTS_FILE = os.path.join(APP_FOLDER, "contacts.json")
SESSIONS_FILE = os.path.join(APP_FOLDER, "sessions.json")
SESSIONS_INTEGRITY_FILE = os.path.join(
    APP_FOLDER,
    "sessions.json.integrity"
)


# =========================================================
# إعدادات الجلسة
# =========================================================

SESSION_VERSION = 1
SESSION_LIFETIME = 24 * 60 * 60

SESSION_CONTEXT = b"SecureEncryptionApp-Session-Key-v1"
SESSION_STORAGE_CONTEXT = b"SecureEncryptionApp-Session-Storage-v1"


# =========================================================
# إعدادات Integrity
# =========================================================

INTEGRITY_VERSION = 1
INTEGRITY_CONTEXT = b"SecureEncryptionApp-Sessions-Integrity-v1"


# =========================================================
# أدوات Base64
# =========================================================

def from_base64(data):
    try:
        if not isinstance(data, str):
            raise ValueError

        return base64.b64decode(data, validate=True)

    except Exception:
        raise ValueError("بيانات Base64 غير صالحة.")


def to_base64(data):
    return base64.b64encode(data).decode("ascii")


# =========================================================
# مفتاح Integrity المرتبط بالهوية المحلية
# =========================================================

def get_integrity_key():
    try:
        if not os.path.exists(IDENTITY_FILE):
            return None

        with open(IDENTITY_FILE, "r", encoding="utf-8") as file:
            identity = json.load(file)

        if not isinstance(identity, dict):
            return None

        signing_private_key = identity.get("signing_private_key")
        encryption_private_key = identity.get("encryption_private_key")
        user_id = identity.get("user_id")

        if not isinstance(signing_private_key, str):
            return None

        if not isinstance(encryption_private_key, str):
            return None

        if not isinstance(user_id, str):
            return None

        material = (
            INTEGRITY_CONTEXT
            + b"|"
            + user_id.encode("utf-8")
            + b"|"
            + signing_private_key.encode("utf-8")
            + b"|"
            + encryption_private_key.encode("utf-8")
        )

        return hashlib.sha256(material).digest()

    except Exception:
        return None


# =========================================================
# حساب Integrity
# =========================================================

def calculate_integrity(data):
    key = get_integrity_key()

    if key is None:
        return None

    try:
        canonical_data = json.dumps(
            data,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":")
        ).encode("utf-8")

        return hmac.new(
            key,
            canonical_data,
            hashlib.sha256
        ).hexdigest()

    except Exception:
        return None


# =========================================================
# حفظ Integrity
# =========================================================

def save_integrity(data):
    integrity = calculate_integrity(data)

    if integrity is None:
        return False

    temporary_file = SESSIONS_INTEGRITY_FILE + ".tmp"

    try:
        integrity_data = {
            "version": INTEGRITY_VERSION,
            "file": "sessions.json",
            "algorithm": "HMAC-SHA256",
            "integrity": integrity
        }

        with open(temporary_file, "w", encoding="utf-8") as file:
            json.dump(
                integrity_data,
                file,
                indent=4,
                ensure_ascii=False
            )
            file.flush()
            os.fsync(file.fileno())

        os.replace(temporary_file, SESSIONS_INTEGRITY_FILE)
        return True

    except Exception:
        try:
            if os.path.exists(temporary_file):
                os.remove(temporary_file)
        except OSError:
            pass

        return False


# =========================================================
# التحقق من Integrity
# =========================================================

def verify_integrity(data):
    if not os.path.exists(SESSIONS_INTEGRITY_FILE):
        return False

    try:
        with open(
            SESSIONS_INTEGRITY_FILE,
            "r",
            encoding="utf-8"
        ) as file:
            integrity_data = json.load(file)

        if not isinstance(integrity_data, dict):
            return False

        if integrity_data.get("version") != INTEGRITY_VERSION:
            return False

        if integrity_data.get("file") != "sessions.json":
            return False

        if integrity_data.get("algorithm") != "HMAC-SHA256":
            return False

        stored_integrity = integrity_data.get("integrity")

        if not isinstance(stored_integrity, str):
            return False

        calculated_integrity = calculate_integrity(data)

        if calculated_integrity is None:
            return False

        return hmac.compare_digest(
            stored_integrity,
            calculated_integrity
        )

    except Exception:
        return False


# =========================================================
# تحميل الهوية المحلية
# =========================================================

def load_identity():
    if not os.path.exists(IDENTITY_FILE):
        return None

    try:
        with open(IDENTITY_FILE, "r", encoding="utf-8") as file:
            identity = json.load(file)

        if not isinstance(identity, dict):
            return None

        required_fields = [
            "version",
            "name",
            "user_id",
            "signing_public_key",
            "encryption_public_key",
            "signing_private_key",
            "encryption_private_key"
        ]

        for field in required_fields:
            if field not in identity:
                return None

        if identity["version"] != 1:
            return None

        return identity

    except Exception:
        return None


# =========================================================
# تحميل جهات الاتصال
# =========================================================

def load_contacts():
    if not os.path.exists(CONTACTS_FILE):
        return {}

    try:
        with open(CONTACTS_FILE, "r", encoding="utf-8") as file:
            contacts = json.load(file)

        if not isinstance(contacts, dict):
            return {}

        return contacts

    except Exception:
        return {}


# =========================================================
# تحميل الجلسات والتحقق من سلامتها
# =========================================================

def load_sessions():
    if not os.path.exists(SESSIONS_FILE):
        return {}

    try:
        with open(SESSIONS_FILE, "r", encoding="utf-8") as file:
            sessions = json.load(file)

        if not isinstance(sessions, dict):
            print("\n🚨 تحذير أمني:")
            print("ملف sessions.json ليس بالتنسيق المتوقع.")
            return {}

        # التحقق من Integrity إذا كانت البصمة موجودة
        if os.path.exists(SESSIONS_INTEGRITY_FILE):
            if not verify_integrity(sessions):
                print("\n🚨 تحذير أمني:")
                print("تم اكتشاف تعديل أو عبث بملف sessions.json.")
                print("❌ لن يتم استخدام الجلسات.")
                return {}

        else:
            # توافق مع الملفات القديمة التي لا تحتوي على بصمة
            print("\nℹ️ ملف الجلسات قديم ولا يحتوي على Integrity.")
            print("سيتم إنشاء حماية Integrity للنسخة الحالية.")

            if not save_integrity(sessions):
                print("⚠️ تعذر إنشاء حماية Integrity.")

        return sessions

    except Exception:
        print("\n❌ تعذر قراءة ملف الجلسات.")
        return {}


# =========================================================
# حفظ الجلسات مع Integrity
# =========================================================

def save_sessions(sessions):
    os.makedirs(APP_FOLDER, exist_ok=True)

    temp_file = SESSIONS_FILE + ".tmp"

    try:
        with open(temp_file, "w", encoding="utf-8") as file:
            json.dump(
                sessions,
                file,
                ensure_ascii=False,
                indent=2
            )
            file.flush()
            os.fsync(file.fileno())

        os.replace(temp_file, SESSIONS_FILE)

        if not save_integrity(sessions):
            print("\n⚠️ تم حفظ الجلسات، لكن تعذر حفظ Integrity.")
            return False

        return True

    except Exception:
        try:
            if os.path.exists(temp_file):
                os.remove(temp_file)
        except OSError:
            pass

        return False


# =========================================================
# تحميل مفتاح X25519 الخاص
# =========================================================

def load_private_key(identity, password):
    try:
        encrypted_private = from_base64(
            identity["encryption_private_key"]
        )

        private_key = serialization.load_pem_private_key(
            encrypted_private,
            password=password.encode("utf-8")
        )

        if not isinstance(private_key, x25519.X25519PrivateKey):
            return None

        return private_key

    except Exception:
        return None


# =========================================================
# اشتقاق مفتاح الجلسة
# =========================================================

def derive_session_key(private_key, other_public_key):
    shared_secret = private_key.exchange(other_public_key)

    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=SESSION_CONTEXT
    ).derive(shared_secret)

    return session_key


# =========================================================
# إنشاء Session ID ثابت للطرفين
# =========================================================

def generate_session_id(identity, contact):
    user_ids = sorted([
        identity["user_id"],
        contact["user_id"]
    ])

    public_keys = sorted([
        identity["encryption_public_key"],
        contact["encryption_public_key"]
    ])

    data = (
        "|".join(user_ids)
        + "|"
        + "|".join(public_keys)
        + "|SecureEncryptionApp-Session-v1"
    ).encode("utf-8")

    digest = hashlib.sha256(data).hexdigest()

    return digest[:32].upper()


# =========================================================
# اشتقاق مفتاح حماية تخزين الجلسة
# =========================================================

def derive_storage_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000
    )

    return kdf.derive(password.encode("utf-8"))


# =========================================================
# تشفير مفتاح الجلسة للتخزين
# =========================================================

def encrypt_session_key(session_key, password):
    salt = os.urandom(16)

    storage_key = derive_storage_key(password, salt)

    nonce = os.urandom(12)

    cipher = AESGCM(storage_key)

    encrypted_key = cipher.encrypt(
        nonce,
        session_key,
        SESSION_STORAGE_CONTEXT
    )

    return {
        "salt": to_base64(salt),
        "nonce": to_base64(nonce),
        "encrypted_key": to_base64(encrypted_key)
    }


# =========================================================
# فك تشفير مفتاح الجلسة المخزن
# =========================================================

def decrypt_session_key(session_data, password):
    try:
        salt = from_base64(session_data["salt"])
        nonce = from_base64(session_data["nonce"])
        encrypted_key = from_base64(session_data["encrypted_key"])

        if len(salt) != 16:
            return None

        if len(nonce) != 12:
            return None

        storage_key = derive_storage_key(password, salt)

        cipher = AESGCM(storage_key)

        session_key = cipher.decrypt(
            nonce,
            encrypted_key,
            SESSION_STORAGE_CONTEXT
        )

        if len(session_key) != 32:
            return None

        return session_key

    except Exception:
        return None


# =========================================================
# التحقق من جهة الاتصال
# =========================================================

def validate_contact(contact):
    try:
        if not isinstance(contact, dict):
            return False

        required_fields = [
            "name",
            "user_id",
            "signing_public_key",
            "encryption_public_key"
        ]

        for field in required_fields:
            if field not in contact:
                return False

        encryption_public = from_base64(
            contact["encryption_public_key"]
        )

        if len(encryption_public) != 32:
            return False

        x25519.X25519PublicKey.from_public_bytes(
            encryption_public
        )

        return True

    except Exception:
        return False


# =========================================================
# تنظيف الجلسات المنتهية
# =========================================================

def cleanup_sessions(sessions):
    now = int(time.time())
    cleaned = {}

    for session_id, session in sessions.items():
        try:
            expires_at = int(session["expires_at"])

            if expires_at > now:
                cleaned[session_id] = session

        except (TypeError, ValueError, KeyError):
            continue

    return cleaned


# =========================================================
# إنشاء جلسة
# =========================================================

def create_session(user_id):
    identity = load_identity()

    if identity is None:
        print("\n❌ لم يتم العثور على الهوية المحلية.")
        return None

    contacts = load_contacts()

    if user_id not in contacts:
        print("\n❌ جهة الاتصال غير موجودة.")
        return None

    contact = contacts[user_id]

    if not validate_contact(contact):
        print("\n❌ بيانات جهة الاتصال غير صالحة.")
        return None

    print("\n" + "=" * 60)
    print("             إنشاء جلسة آمنة")
    print("=" * 60)

    print("\nالطرف الآخر:")
    print(contact["name"])

    print("\nUser ID:")
    print(contact["user_id"])

    # إنشاء Session ID
    session_id = generate_session_id(identity, contact)

    # تحميل الجلسات وتنظيف المنتهية
    sessions = cleanup_sessions(load_sessions())

    # التحقق من وجود جلسة فعالة
    if session_id in sessions:
        existing_session = sessions[session_id]

        print("\n🟢 توجد جلسة فعالة بالفعل.")
        print("\nSession ID:")
        print(session_id)

        print("\nتنتهي في:")
        print(
            time.strftime(
                "%Y-%m-%d %H:%M:%S",
                time.localtime(existing_session["expires_at"])
            )
        )

        print("\nلن يتم إنشاء مفتاح جلسة جديد.")

        if save_sessions(sessions):
            return "EXISTING_SESSION"

        return None

    # كلمة المرور
    print()
    password = getpass.getpass("أدخل كلمة مرور هويتك: ")

    # تحميل المفتاح الخاص
    private_key = load_private_key(identity, password)

    if private_key is None:
        print("\n❌ كلمة المرور غير صحيحة أو المفتاح الخاص غير صالح.")
        return None

    # تحميل المفتاح العام للطرف الآخر
    try:
        other_public_bytes = from_base64(
            contact["encryption_public_key"]
        )

        other_public_key = x25519.X25519PublicKey.from_public_bytes(
            other_public_bytes
        )

    except Exception:
        print("\n❌ مفتاح التشفير العام لجهة الاتصال غير صالح.")
        return None

    # اشتقاق مفتاح الجلسة
    try:
        session_key = derive_session_key(
            private_key,
            other_public_key
        )

    except Exception:
        print("\n❌ فشل إنشاء الجلسة الآمنة.")
        return None

    # تشفير مفتاح الجلسة للتخزين
    try:
        encrypted_session = encrypt_session_key(
            session_key,
            password
        )

    except Exception:
        print("\n❌ فشل تأمين مفتاح الجلسة للتخزين.")
        return None

    # إنشاء بيانات الجلسة
    created_at = int(time.time())
    expires_at = created_at + SESSION_LIFETIME

    sessions[session_id] = {
        "version": SESSION_VERSION,
        "session_id": session_id,
        "local_user_id": identity["user_id"],
        "remote_user_id": contact["user_id"],
        "created_at": created_at,
        "expires_at": expires_at,
        "encrypted_session_key": encrypted_session
    }

    # حفظ الجلسة
    if not save_sessions(sessions):
        print("\n❌ فشل حفظ الجلسة.")
        return None

    # رسالة النجاح
    print("\n" + "=" * 60)
    print("🟢 تم إنشاء الجلسة الآمنة بنجاح.")
    print("=" * 60)

    print("\nهوية الطرف الآخر:")
    print(contact["name"])

    print("\nSession ID:")
    print(session_id)

    print("\nمدة الجلسة:")
    print("24 ساعة")

    print("\n🔒 مفتاح الجلسة محفوظ بشكل مشفر.")
    print("🔐 المفتاح السري لم يتم عرضه.")
    print("\n🛡 تمت إضافة حماية Integrity للملف.")
    print("\n" + "=" * 60)

    return session_key


# =========================================================
# عرض الجلسات
# =========================================================

def list_sessions():
    identity = load_identity()

    if identity is None:
        print("\n❌ لم يتم العثور على الهوية المحلية.")
        return

    sessions = cleanup_sessions(load_sessions())

    if not save_sessions(sessions):
        print("\n⚠️ تعذر تحديث ملف الجلسات.")

    local_sessions = {}

    for session_id, session in sessions.items():
        if session.get("local_user_id") == identity["user_id"]:
            local_sessions[session_id] = session

    print("\n" + "=" * 60)
    print("                 الجلسات")
    print("=" * 60)

    if not local_sessions:
        print("\nلا توجد جلسات فعالة.")
        return

    for index, (session_id, session) in enumerate(
        local_sessions.items(),
        start=1
    ):
        print(f"\n{index}. Session ID:")
        print(session_id)

        print("\nالطرف الآخر:")
        print(session["remote_user_id"])

        print("\nتنتهي:")
        print(
            time.strftime(
                "%Y-%m-%d %H:%M:%S",
                time.localtime(session["expires_at"])
            )
        )

        print("-" * 60)


# =========================================================
# إغلاق جلسة
# =========================================================

def close_session():
    identity = load_identity()

    if identity is None:
        print("\n❌ لم يتم العثور على الهوية المحلية.")
        return

    sessions = cleanup_sessions(load_sessions())
    local_sessions = {}

    for session_id, session in sessions.items():
        if session.get("local_user_id") == identity["user_id"]:
            local_sessions[session_id] = session

    if not local_sessions:
        print("\n❌ لا توجد جلسات فعالة.")
        return

    session_list = list(local_sessions.items())

    print("\nالجلسات الفعالة:\n")

    for index, (session_id, session) in enumerate(
        session_list,
        start=1
    ):
        print(
            f"{index}. "
            f"{session['remote_user_id']} "
            f"({session_id})"
        )

    print()
    choice = input("اختر رقم الجلسة لإغلاقها: ").strip()

    try:
        choice = int(choice)

    except ValueError:
        print("\n❌ اختيار غير صالح.")
        return

    if choice < 1 or choice > len(session_list):
        print("\n❌ الجلسة غير موجودة.")
        return

    selected_session_id = session_list[choice - 1][0]

    del sessions[selected_session_id]

    if not save_sessions(sessions):
        print("\n❌ فشل إغلاق الجلسة.")
        return

    print("\n🟢 تم إغلاق الجلسة بنجاح.")
    print("\nSession ID:")
    print(selected_session_id)


# =========================================================
# اختبار الجلسة الموجودة
# =========================================================

def test_existing_session():
    identity = load_identity()

    if identity is None:
        print("\n❌ لم يتم العثور على الهوية المحلية.")
        return

    sessions = cleanup_sessions(load_sessions())

    if not sessions:
        print("\n❌ لا توجد جلسات فعالة.")
        return

    session_list = []

    for session_id, session in sessions.items():
        if session.get("local_user_id") == identity["user_id"]:
            session_list.append((session_id, session))

    if not session_list:
        print("\n❌ لا توجد جلسات فعالة لهذه الهوية.")
        return

    print("\nالجلسات الفعالة:\n")

    for index, (session_id, session) in enumerate(
        session_list,
        start=1
    ):
        print(
            f"{index}. "
            f"{session['remote_user_id']} "
            f"({session_id})"
        )

    print()
    choice = input("اختر رقم الجلسة: ").strip()

    try:
        choice = int(choice)

    except ValueError:
        print("\n❌ اختيار غير صالح.")
        return

    if choice < 1 or choice > len(session_list):
        print("\n❌ الجلسة غير موجودة.")
        return

    session_id, session = session_list[choice - 1]

    print()
    password = getpass.getpass("أدخل كلمة مرور هويتك: ")

    encrypted_session = session.get("encrypted_session_key")

    if not encrypted_session:
        print("\n❌ بيانات مفتاح الجلسة غير موجودة.")
        return

    session_key = decrypt_session_key(
        encrypted_session,
        password
    )

    if session_key is None:
        print("\n❌ كلمة المرور غير صحيحة أو مفتاح الجلسة غير صالح.")
        return

    print("\n" + "=" * 60)
    print("🟢 الجلسة صالحة.")
    print("=" * 60)

    print("\nSession ID:")
    print(session_id)

    print("\nالطرف الآخر:")
    print(session["remote_user_id"])

    print("\nالمفتاح السري تم فك حمايته في الذاكرة فقط.")
    print("\n🔒 لم يتم عرض المفتاح السري.")
    print("\n" + "=" * 60)

    return session_key


# =========================================================
# القائمة الرئيسية
# =========================================================

def main():
    while True:
        print("\n" + "=" * 60)
        print("          Secure Encryption - Sessions")
        print("=" * 60)

        print("\n1. إنشاء جلسة")
        print("2. عرض الجلسات")
        print("3. اختبار جلسة موجودة")
        print("4. إغلاق جلسة")
        print("0. خروج")
        print()

        choice = input("اختر: ").strip()

        # إنشاء جلسة
        if choice == "1":
            contacts = load_contacts()

            if not contacts:
                print("\n❌ لا توجد جهات اتصال.")
                continue

            contact_list = list(contacts.items())

            print("\nجهات الاتصال المتاحة:\n")

            for index, (user_id, contact) in enumerate(
                contact_list,
                start=1
            ):
                name = contact.get("name", "بدون اسم")
                print(f"{index}. {name} ({user_id})")

            print()
            selected = input("اختر رقم جهة الاتصال: ").strip()

            try:
                selected = int(selected)

            except ValueError:
                print("\n❌ اختيار غير صالح.")
                continue

            if selected < 1 or selected > len(contact_list):
                print("\n❌ الاختيار غير موجود.")
                continue

            selected_user_id = contact_list[selected - 1][0]
            create_session(selected_user_id)

        # عرض الجلسات
        elif choice == "2":
            list_sessions()

        # اختبار جلسة
        elif choice == "3":
            test_existing_session()

        # إغلاق جلسة
        elif choice == "4":
            close_session()

        # خروج
        elif choice == "0":
            print("\n👋 تم إغلاق إدارة الجلسات.")
            break

        else:
            print("\n❌ اختيار غير صالح.")


# =========================================================
# تشغيل البرنامج
# =========================================================

if __name__ == "__main__":
    main()