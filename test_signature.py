import json
import base64

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

import msvcrt


# Copyright (c) 2026 Rami
# All Rights Reserved.
# Project: Secure Encryption
# Unauthorized copying, modification, or redistribution is prohibited.

import os

APP_FOLDER = os.path.join(
    os.environ.get("APPDATA", os.path.expanduser("~")),
    "SecureEncryptionApp"
)

IDENTITY_FILE = os.path.join(
    APP_FOLDER,
    "identity.json"
)


# ==========================================
# إدخال كلمة المرور مع إظهار *
# ==========================================

def input_password(prompt):

    print(prompt, end="", flush=True)

    password = ""

    while True:

        char = msvcrt.getwch()

        # Enter
        if char in ("\r", "\n"):
            print()
            break

        # Backspace
        elif char == "\b":

            if password:
                password = password[:-1]
                print("\b \b", end="", flush=True)

        # مفاتيح خاصة
        elif char in ("\x00", "\xe0"):

            msvcrt.getwch()

        else:

            password += char
            print("*", end="", flush=True)

    return password


# ==========================================
# تحميل الهوية
# ==========================================

def load_identity():

    if not os.path.exists(IDENTITY_FILE):

        print("لم يتم العثور على الهوية.")
        print()
        print("شغّل identity.py أولاً.")
        return None

    with open(
        IDENTITY_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


# ==========================================
# تحويل Base64
# ==========================================

def from_base64(data):

    return base64.b64decode(data)


# ==========================================
# البرنامج
# ==========================================

def main():

    print("=" * 55)
    print("           اختبار التوقيع الرقمي")
    print("=" * 55)

    identity = load_identity()

    if identity is None:
        return


    print()
    print("اسم المستخدم:")
    print(identity["name"])

    print()
    print("User ID:")
    print(identity["user_id"])


    # ==========================================
    # كلمة المرور
    # ==========================================

    print()

    password = input_password(
        "أدخل كلمة مرور الهوية: "
    )


    # ==========================================
    # تحميل المفتاح الخاص
    # ==========================================

    try:

        private_key_data = from_base64(
            identity["signing_private_key"]
        )

        private_key = serialization.load_pem_private_key(
            private_key_data,
            password=password.encode("utf-8")
        )

    except Exception:

        print()
        print("❌ كلمة المرور غير صحيحة أو المفتاح غير صالح.")
        return


    print()
    print("✅ تم فتح مفتاح التوقيع الخاص بنجاح.")


    # ==========================================
    # إنشاء رسالة للاختبار
    # ==========================================

    print()
    print("-" * 55)

    message = input(
        "اكتب رسالة لاختبار التوقيع: "
    )


    if not message:

        print()
        print("لا يمكن أن تكون الرسالة فارغة.")
        return


    message_bytes = message.encode("utf-8")


    # ==========================================
    # إنشاء التوقيع
    # ==========================================

    signature = private_key.sign(
        message_bytes
    )


    print()
    print("✅ تم إنشاء التوقيع الرقمي.")

    print()
    print("التوقيع تم إنشاؤه آليًا.")
    print("لن تحتاج إلى رؤية المفتاح الخاص.")


    # ==========================================
    # تحميل المفتاح العام
    # ==========================================

    public_key_data = from_base64(
        identity["signing_public_key"]
    )

    public_key = ed25519.Ed25519PublicKey.from_public_bytes(
        public_key_data
    )


    # ==========================================
    # التحقق من التوقيع
    # ==========================================

    try:

        public_key.verify(
            signature,
            message_bytes
        )

        print()
        print("🟢 التحقق ناجح!")
        print("الرسالة أصلية والتوقيع صحيح.")

    except Exception:

        print()
        print("🔴 التحقق فشل!")


    # ==========================================
    # اختبار تعديل الرسالة
    # ==========================================

    print()
    print("-" * 55)

    print("الآن سنختبر ماذا يحدث إذا تم تعديل الرسالة.")

    modified_message = message + " [تم التعديل]"

    modified_bytes = modified_message.encode("utf-8")


    try:

        public_key.verify(
            signature,
            modified_bytes
        )

        print()
        print("⚠️ التوقيع ما زال صالحًا.")
        print("هناك مشكلة في النظام.")

    except Exception:

        print()
        print("🟢 ممتاز!")
        print("تم اكتشاف تعديل الرسالة.")
        print("التوقيع لم يعد صالحًا.")


    print()
    print("=" * 55)
    print("انتهى اختبار التوقيع الرقمي")
    print("=" * 55)


# ==========================================
# تشغيل البرنامج
# ==========================================

if __name__ == "__main__":
    main()