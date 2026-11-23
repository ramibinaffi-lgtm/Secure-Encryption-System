import os
import json
import base64
import hashlib
import hmac


# Copyright (c) 2026 Rami
# All Rights Reserved.
# Project: Secure Encryption
# Unauthorized copying, modification, or redistribution is prohibited.

APP_FOLDER = os.path.join(
    os.environ.get("APPDATA", os.path.expanduser("~")),
    "SecureEncryptionApp"
)

CONTACTS_FILE = os.path.join(
    APP_FOLDER,
    "contacts.json"
)

CONTACTS_INTEGRITY_FILE = os.path.join(
    APP_FOLDER,
    "contacts.json.integrity"
)

IDENTITY_FILE = os.path.join(
    APP_FOLDER,
    "identity.json"
)


# =========================================================
# إعدادات Integrity
# =========================================================

INTEGRITY_VERSION = 1

INTEGRITY_CONTEXT = (
    b"SecureEncryptionApp-Contacts-Integrity-v1"
)


# =========================================================
# إنشاء مجلد البرنامج
# =========================================================

def create_app_folder():
    os.makedirs(
        APP_FOLDER,
        exist_ok=True
    )


# =========================================================
# مفتاح Integrity مرتبط بالهوية المحلية
# =========================================================

def get_integrity_key():
    """
    اشتقاق مفتاح Integrity من بيانات الهوية المحلية.
    لا يتم حفظ المفتاح المشتق في ملف مستقل.
    """

    try:
        if not os.path.exists(IDENTITY_FILE):
            return None

        with open(
            IDENTITY_FILE,
            "r",
            encoding="utf-8"
        ) as file:
            identity = json.load(file)

        if not isinstance(identity, dict):
            return None

        signing_private_key = identity.get(
            "signing_private_key"
        )

        encryption_private_key = identity.get(
            "encryption_private_key"
        )

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
    """حساب HMAC-SHA256 لبيانات جهات الاتصال."""

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
    """حفظ بصمة Integrity في ملف جانبي."""

    integrity = calculate_integrity(data)

    if integrity is None:
        return False

    temporary_file = (
        CONTACTS_INTEGRITY_FILE + ".tmp"
    )

    try:
        integrity_data = {
            "version": INTEGRITY_VERSION,
            "file": "contacts.json",
            "algorithm": "HMAC-SHA256",
            "integrity": integrity
        }

        with open(
            temporary_file,
            "w",
            encoding="utf-8"
        ) as file:
            json.dump(
                integrity_data,
                file,
                indent=4,
                ensure_ascii=False
            )

            file.flush()
            os.fsync(file.fileno())

        os.replace(
            temporary_file,
            CONTACTS_INTEGRITY_FILE
        )

        return True

    except Exception:
        try:
            if os.path.exists(temporary_file):
                os.remove(temporary_file)
        except Exception:
            pass

        return False


# =========================================================
# التحقق من Integrity
# =========================================================

def verify_integrity(data):
    """التحقق من سلامة ملف contacts.json."""

    if not os.path.exists(CONTACTS_INTEGRITY_FILE):
        return False

    try:
        with open(
            CONTACTS_INTEGRITY_FILE,
            "r",
            encoding="utf-8"
        ) as file:
            integrity_data = json.load(file)

        if not isinstance(integrity_data, dict):
            return False

        if integrity_data.get("version") != INTEGRITY_VERSION:
            return False

        if integrity_data.get("file") != "contacts.json":
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
# تحميل جهات الاتصال
# =========================================================

def load_contacts():
    create_app_folder()

    if not os.path.exists(CONTACTS_FILE):
        return {}

    try:
        with open(
            CONTACTS_FILE,
            "r",
            encoding="utf-8"
        ) as file:
            contacts = json.load(file)

        if not isinstance(contacts, dict):
            print(
                "❌ ملف جهات الاتصال ليس بالتنسيق المتوقع."
            )
            return {}

        # التحقق من Integrity
        if os.path.exists(CONTACTS_INTEGRITY_FILE):
            if not verify_integrity(contacts):
                print()
                print("🚨 تحذير أمني:")
                print(
                    "تم اكتشاف تعديل أو عبث بملف contacts.json."
                )
                print(
                    "❌ لن يتم استخدام جهات الاتصال."
                )
                return {}

        else:
            # توافق مبدئي مع ملف قديم لا يملك بصمة
            print()
            print(
                "ℹ️ ملف جهات الاتصال لا يحتوي على Integrity."
            )
            print(
                "سيتم محاولة إنشاء بصمة للنسخة الحالية."
            )

            if not save_integrity(contacts):
                print(
                    "⚠️ تعذر إنشاء حماية Integrity."
                )

        return contacts

    except (OSError, json.JSONDecodeError):
        print("❌ تعذر قراءة جهات الاتصال.")
        return {}


# =========================================================
# حفظ جهات الاتصال
# =========================================================

def save_contacts(contacts):
    create_app_folder()

    temporary_file = CONTACTS_FILE + ".tmp"

    try:
        with open(
            temporary_file,
            "w",
            encoding="utf-8"
        ) as file:
            json.dump(
                contacts,
                file,
                indent=4,
                ensure_ascii=False
            )

            file.flush()
            os.fsync(file.fileno())

        os.replace(
            temporary_file,
            CONTACTS_FILE
        )

        # إنشاء بصمة Integrity
        if not save_integrity(contacts):
            print(
                "⚠️ تم حفظ جهات الاتصال، لكن تعذر حفظ Integrity."
            )
            return False

        return True

    except Exception:
        try:
            if os.path.exists(temporary_file):
                os.remove(temporary_file)
        except Exception:
            pass

        return False


# =========================================================
# أدوات المفاتيح و User ID
# =========================================================

def decode_public_key(value):
    if not isinstance(value, str):
        raise ValueError("المفتاح ليس نصًا.")

    key = base64.b64decode(
        value,
        validate=True
    )

    if len(key) != 32:
        raise ValueError(
            "طول المفتاح العام يجب أن يكون 32 بايت."
        )

    return key


def generate_user_id(
    signing_public_key,
    encryption_public_key
):
    digest = hashlib.sha256(
        signing_public_key + encryption_public_key
    ).digest()

    short_id = digest[:12]

    user_id = base64.b32encode(
        short_id
    ).decode("ascii").replace("=", "")

    return "-".join(
        user_id[i:i + 4]
        for i in range(0, len(user_id), 4)
    )


# =========================================================
# التحقق من جهة الاتصال
# =========================================================

def validate_contact(contact, stored_id=None):
    try:
        if not isinstance(contact, dict):
            return False

        name = contact.get("name")
        user_id = contact.get("user_id")

        if not isinstance(name, str) or not name.strip():
            return False

        if not isinstance(user_id, str):
            return False

        if stored_id is not None and stored_id != user_id:
            return False

        signing_key = decode_public_key(
            contact["signing_public_key"]
        )

        encryption_key = decode_public_key(
            contact["encryption_public_key"]
        )

        calculated_id = generate_user_id(
            signing_key,
            encryption_key
        )

        return calculated_id == user_id

    except (KeyError, ValueError, TypeError):
        return False


# =========================================================
# استيراد الهوية العامة من ملف
# =========================================================

def add_contact():
    print()
    print("=" * 55)
    print("إضافة جهة اتصال من ملف الهوية العامة")
    print("=" * 55)

    path = input(
        "أدخل مسار ملف الهوية العامة: "
    ).strip().strip('"')

    if not path:
        print("❌ لم تدخل مسار الملف.")
        return

    try:
        with open(
            path,
            "r",
            encoding="utf-8"
        ) as file:
            public_identity = json.load(file)

    except (OSError, json.JSONDecodeError):
        print(
            "❌ تعذر فتح الملف أو أن محتواه غير صالح."
        )
        return

    if not isinstance(public_identity, dict):
        print("❌ تنسيق ملف الهوية غير صحيح.")
        return

    if public_identity.get("version") != 1:
        print("❌ إصدار الهوية غير مدعوم.")
        return

    name = public_identity.get("name")
    user_id = public_identity.get("user_id")

    if not isinstance(name, str) or not name.strip():
        print("❌ اسم الهوية غير صالح.")
        return

    if not isinstance(user_id, str):
        print("❌ User ID غير صالح.")
        return

    try:
        signing_key = decode_public_key(
            public_identity["signing_public_key"]
        )

        encryption_key = decode_public_key(
            public_identity["encryption_public_key"]
        )

    except (KeyError, ValueError, TypeError):
        print("❌ أحد المفتاحين العامين غير صالح.")
        return

    calculated_id = generate_user_id(
        signing_key,
        encryption_key
    )

    if calculated_id != user_id:
        print("❌ User ID لا يطابق المفاتيح العامة.")
        print("لم تتم إضافة جهة الاتصال.")
        return

    contacts = load_contacts()

    if user_id in contacts:
        existing = contacts[user_id]

        if validate_contact(existing, user_id):
            print("⚠️ هذه الهوية موجودة بالفعل.")
        else:
            print(
                "❌ توجد بيانات غير سليمة لهذه الهوية المحفوظة."
            )
            print("لم يتم استبدالها أو حذفها.")

        return

    # تنسيق متوافق مع secure_message.py
    contacts[user_id] = {
        "name": name.strip(),
        "user_id": user_id,
        "signing_public_key": public_identity[
            "signing_public_key"
        ],
        "encryption_public_key": public_identity[
            "encryption_public_key"
        ]
    }

    if not save_contacts(contacts):
        print(
            "❌ تعذر حفظ جهة الاتصال مع حماية Integrity."
        )
        return

    print()
    print("✅ تمت إضافة الهوية العامة بنجاح.")
    print("الاسم:", name)
    print("User ID:", user_id)
    print()
    print("🔐 تمت إضافة حماية Integrity للملف.")
    print()
    print(
        "تنبيه: مطابقة User ID تتحقق من اتساق المفاتيح،"
    )
    print(
        "لكن تأكد من هوية صاحبها عبر قناة موثوقة مستقلة."
    )


# =========================================================
# عرض جهات الاتصال والتحقق منها
# =========================================================

def list_contacts():
    contacts = load_contacts()

    print()
    print("=" * 55)
    print("جهات الاتصال")
    print("=" * 55)

    if not contacts:
        print("لا توجد جهات اتصال محفوظة.")
        return

    for number, (user_id, contact) in enumerate(
        contacts.items(),
        start=1
    ):
        if validate_contact(contact, user_id):
            print(f"{number}. {contact['name']}")
            print(f"   User ID: {user_id}")
            print("   حالة البيانات: سليمة")
        else:
            print(
                f"{number}. ⚠️ جهة اتصال ببيانات غير سليمة"
            )
            print(f"   المفتاح المحفوظ: {user_id}")

        print()


# =========================================================
# حذف جهة اتصال مع التأكيد
# =========================================================

def delete_contact():
    contacts = load_contacts()

    if not contacts:
        print("لا توجد جهات اتصال.")
        return

    user_id = input(
        "أدخل User ID للشخص المراد حذفه: "
    ).strip().upper()

    if user_id not in contacts:
        print("❌ لم يتم العثور على هذه الهوية.")
        return

    contact = contacts[user_id]
    name = contact.get("name", "بدون اسم")

    print()
    print("الاسم:", name)
    print("User ID:", user_id)

    confirmation = input(
        "اكتب نعم لتأكيد الحذف: "
    ).strip()

    if confirmation != "نعم":
        print("تم إلغاء الحذف.")
        return

    del contacts[user_id]

    if not save_contacts(contacts):
        print(
            "❌ تعذر حفظ التغييرات مع حماية Integrity."
        )
        return

    print("✅ تم حذف جهة الاتصال.")


# =========================================================
# القائمة الرئيسية
# =========================================================

def main():
    while True:
        print()
        print("=" * 55)
        print("نظام جهات الاتصال الآمنة")
        print("=" * 55)
        print("1 - إضافة شخص من ملف الهوية العامة")
        print("2 - عرض الأشخاص والتحقق من بياناتهم")
        print("3 - حذف شخص")
        print("4 - خروج")

        choice = input("اختر: ").strip()

        if choice == "1":
            add_contact()

        elif choice == "2":
            list_contacts()

        elif choice == "3":
            delete_contact()

        elif choice == "4":
            print("تم الخروج.")
            break

        else:
            print("❌ اختيار غير صحيح.")


# =========================================================
# تشغيل
# =========================================================

if __name__ == "__main__":
    main()