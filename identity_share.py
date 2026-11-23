import os
import json
import base64


# Copyright (c) 2026 Rami
# All Rights Reserved.
# Project: Secure Encryption
# Unauthorized copying, modification, or redistribution is prohibited.

APP_FOLDER = os.path.join(
    os.environ.get("APPDATA", os.path.expanduser("~")),
    "SecureEncryptionApp"
)

IDENTITY_FILE = os.path.join(
    APP_FOLDER,
    "identity.json"
)

PUBLIC_IDENTITY_FILE = os.path.join(
    APP_FOLDER,
    "my_identity_public.json"
)


# ==========================================
# قراءة الهوية المحلية
# ==========================================

def load_identity():

    if not os.path.exists(IDENTITY_FILE):

        print("❌ لم يتم العثور على الهوية.")
        print("شغّل identity.py وأنشئ الهوية أولًا.")

        return None

    try:

        with open(
            IDENTITY_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except Exception:

        print("❌ تعذر قراءة ملف الهوية.")

        return None


# ==========================================
# التحقق من المفتاح العام
# ==========================================

def validate_public_key(key_text):

    try:

        key = base64.b64decode(
            key_text,
            validate=True
        )

        return len(key) == 32

    except Exception:

        return False


# ==========================================
# تصدير الهوية العامة
# ==========================================

def export_public_identity():

    identity = load_identity()

    if identity is None:
        return


    # ==========================================
    # الحصول على المفاتيح العامة
    # ==========================================

    signing_public_key = identity.get(
        "signing_public_key"
    )

    encryption_public_key = identity.get(
        "encryption_public_key"
    )


    # ==========================================
    # التأكد من صحة المفاتيح
    # ==========================================

    if not validate_public_key(
        signing_public_key
    ):

        print()
        print("❌ مفتاح التوقيع العام غير صالح.")
        return


    if not validate_public_key(
        encryption_public_key
    ):

        print()
        print("❌ مفتاح التشفير العام غير صالح.")
        return


    # ==========================================
    # إنشاء الملف العام
    # ==========================================

    public_identity = {

        "version": 1,

        "name": identity["name"],

        "user_id": identity["user_id"],

        "signing_public_key":
            signing_public_key,

        "encryption_public_key":
            encryption_public_key

    }


    # ==========================================
    # حفظ الملف
    # ==========================================

    with open(
        PUBLIC_IDENTITY_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            public_identity,
            file,
            indent=4,
            ensure_ascii=False
        )


    # ==========================================
    # النتيجة
    # ==========================================

    print()
    print("=" * 55)
    print("تم تصدير الهوية العامة بنجاح")
    print("=" * 55)

    print()
    print("الاسم:")
    print(identity["name"])

    print()
    print("User ID:")
    print(identity["user_id"])

    print()
    print("الملف:")
    print(PUBLIC_IDENTITY_FILE)

    print()
    print("يمكن مشاركة هذا الملف مع الأشخاص الآخرين.")

    print()
    print("⚠️ هذا الملف لا يحتوي على المفاتيح الخاصة.")


# ==========================================
# تشغيل البرنامج
# ==========================================

def main():

    print("=" * 55)
    print("             مشاركة الهوية العامة")
    print("=" * 55)

    export_public_identity()


if __name__ == "__main__":

    main()