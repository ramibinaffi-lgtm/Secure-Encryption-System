import os
import json
import base64
import hashlib


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


# =========================================================
# Base64
# =========================================================

def decode_public_key(data):

    try:

        if not isinstance(data, str):
            raise ValueError

        decoded = base64.b64decode(
            data,
            validate=True
        )

        if len(decoded) != 32:
            raise ValueError

        return decoded

    except Exception:

        raise ValueError(
            "المفتاح العام غير صالح."
        )


# =========================================================
# إنشاء User ID
# =========================================================

def generate_user_id(
    signing_public_key,
    encryption_public_key
):

    combined = (
        signing_public_key
        + encryption_public_key
    )

    digest = hashlib.sha256(
        combined
    ).digest()

    short_digest = digest[:12]

    user_id = base64.b32encode(
        short_digest
    ).decode("ascii").rstrip("=")

    return "-".join(
        user_id[i:i + 4]
        for i in range(
            0,
            len(user_id),
            4
        )
    )


# =========================================================
# إنشاء بصمة الهوية
# =========================================================

def generate_fingerprint(
    signing_public_key,
    encryption_public_key
):

    combined = (
        signing_public_key
        + encryption_public_key
    )

    digest = hashlib.sha256(
        combined
    ).hexdigest()

    # تقسيم البصمة ليسهل قراءتها ومقارنتها
    return " ".join(
        digest[i:i + 4]
        for i in range(
            0,
            len(digest),
            4
        )
    ).upper()


# =========================================================
# التحقق من ملف الهوية العامة
# =========================================================

def validate_public_identity(data):

    required_fields = [
        "version",
        "name",
        "user_id",
        "signing_public_key",
        "encryption_public_key"
    ]

    for field in required_fields:

        if field not in data:
            return False, f"الحقل مفقود: {field}"


    if data["version"] != 1:

        return False, "إصدار الهوية غير مدعوم."


    if not isinstance(
        data["name"],
        str
    ) or not data["name"].strip():

        return False, "اسم المستخدم غير صالح."


    try:

        signing_public_key = decode_public_key(
            data["signing_public_key"]
        )

        encryption_public_key = decode_public_key(
            data["encryption_public_key"]
        )

    except ValueError as error:

        return False, str(error)


    # =====================================================
    # إعادة حساب User ID
    # =====================================================

    calculated_user_id = generate_user_id(
        signing_public_key,
        encryption_public_key
    )


    if calculated_user_id != data["user_id"]:

        return False, (
            "User ID لا يتطابق مع المفاتيح العامة."
        )


    return True, (
        signing_public_key,
        encryption_public_key
    )


# =========================================================
# حفظ جهات الاتصال
# =========================================================

def save_contacts(contacts):

    os.makedirs(
        APP_FOLDER,
        exist_ok=True
    )

    temp_file = CONTACTS_FILE + ".tmp"

    try:

        with open(
            temp_file,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                contacts,
                file,
                ensure_ascii=False,
                indent=2
            )

            file.flush()
            os.fsync(file.fileno())

        os.replace(
            temp_file,
            CONTACTS_FILE
        )

        return True

    except Exception:

        try:

            if os.path.exists(temp_file):
                os.remove(temp_file)

        except Exception:
            pass

        return False


# =========================================================
# تحميل جهات الاتصال
# =========================================================

def load_contacts():

    if not os.path.exists(
        CONTACTS_FILE
    ):

        return {}

    try:

        with open(
            CONTACTS_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            contacts = json.load(file)

        if not isinstance(
            contacts,
            dict
        ):

            return {}

        return contacts

    except Exception:

        return {}


# =========================================================
# استيراد جهة اتصال
# =========================================================

def import_contact():

    print()
    print("=" * 60)
    print("             استيراد هوية عامة")
    print("=" * 60)

    print()

    file_path = input(
        "أدخل مسار ملف الهوية العامة: "
    ).strip().strip('"')


    if not file_path:

        print()
        print("❌ لم يتم إدخال مسار الملف.")
        return


    if not os.path.exists(
        file_path
    ):

        print()
        print("❌ الملف غير موجود.")
        return


    # =====================================================
    # قراءة الملف
    # =====================================================

    try:

        with open(
            file_path,
            "r",
            encoding="utf-8"
        ) as file:

            public_identity = json.load(
                file
            )

    except Exception:

        print()
        print("❌ تعذر قراءة ملف الهوية العامة.")
        return


    if not isinstance(
        public_identity,
        dict
    ):

        print()
        print("❌ محتوى ملف الهوية غير صالح.")
        return


    # =====================================================
    # التحقق من الهوية
    # =====================================================

    valid, result = validate_public_identity(
        public_identity
    )


    if not valid:

        print()
        print("❌ فشل التحقق من الهوية.")
        print(result)
        return


    signing_public_key, encryption_public_key = result


    # =====================================================
    # إنشاء البصمة
    # =====================================================

    fingerprint = generate_fingerprint(
        signing_public_key,
        encryption_public_key
    )


    user_id = public_identity[
        "user_id"
    ]

    name = public_identity[
        "name"
    ]


    # =====================================================
    # عرض بيانات الهوية
    # =====================================================

    print()
    print("=" * 60)
    print("تم التحقق من بنية الهوية العامة")
    print("=" * 60)

    print()
    print("الاسم:")
    print(name)

    print()
    print("User ID:")
    print(user_id)

    print()
    print("بصمة الهوية:")
    print(fingerprint)

    print()
    print(
        "⚠️ قارن هذه البصمة مع صاحب الهوية عبر"
    )
    print(
        "قناة موثوقة قبل اعتبار الهوية موثوقة."
    )


    # =====================================================
    # تأكيد المستخدم
    # =====================================================

    print()

    confirmation = input(
        "هل تريد إضافة جهة الاتصال؟ (نعم/لا): "
    ).strip()


    if confirmation != "نعم":

        print()
        print("تم إلغاء الاستيراد.")
        return


    # =====================================================
    # تحميل جهات الاتصال الحالية
    # =====================================================

    contacts = load_contacts()


    # =====================================================
    # منع التكرار
    # =====================================================

    if user_id in contacts:

        existing = contacts[
            user_id
        ]

        existing_fingerprint = existing.get(
            "fingerprint"
        )


        print()
        print(
            "⚠️ جهة الاتصال موجودة مسبقًا."
        )


        if existing_fingerprint:

            if existing_fingerprint == fingerprint:

                print()
                print(
                    "🟢 البصمة مطابقة للهوية المسجلة."
                )

            else:

                print()
                print(
                    "🚨 تحذير: بصمة الهوية تغيرت!"
                )

                print()
                print(
                    "البصمة القديمة:"
                )

                print(
                    existing_fingerprint
                )

                print()
                print(
                    "البصمة الجديدة:"
                )

                print(
                    fingerprint
                )

                print()
                print(
                    "❌ لن يتم استبدال الهوية تلقائيًا."
                )

            return

        else:

            # جهة اتصال قديمة لا تحتوي على fingerprint
            existing["fingerprint"] = fingerprint

            if save_contacts(contacts):

                print()
                print(
                    "🟢 تم تحديث جهة الاتصال وإضافة بصمة الهوية."
                )

            else:

                print()
                print(
                    "❌ فشل حفظ تحديث جهة الاتصال."
                )

            return


    # =====================================================
    # إنشاء جهة الاتصال
    # =====================================================

    contacts[user_id] = {

        "version": 1,

        "name": name,

        "user_id": user_id,

        "signing_public_key":
            public_identity[
                "signing_public_key"
            ],

        "encryption_public_key":
            public_identity[
                "encryption_public_key"
            ],

        "fingerprint":
            fingerprint
    }


    # =====================================================
    # الحفظ
    # =====================================================

    if not save_contacts(
        contacts
    ):

        print()
        print(
            "❌ فشل حفظ جهة الاتصال."
        )

        return


    # =====================================================
    # النجاح
    # =====================================================

    print()
    print("=" * 60)
    print("🟢 تمت إضافة جهة الاتصال بنجاح.")
    print("=" * 60)

    print()
    print("الاسم:")
    print(name)

    print()
    print("User ID:")
    print(user_id)

    print()
    print("بصمة الهوية:")
    print(fingerprint)

    print()
    print(
        "🔐 تم حفظ المفاتيح العامة فقط."
    )


# =========================================================
# تشغيل
# =========================================================

def main():

    import_contact()


if __name__ == "__main__":
    main()