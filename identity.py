import os
import json
import base64
import hashlib
import msvcrt
# Copyright (c) 2026 Rami
# All Rights Reserved.
# Project: Secure Encryption
# Unauthorized copying, modification, or redistribution is prohibited.
from cryptography.hazmat.primitives.asymmetric import (
    ed25519,
    x25519
)

from cryptography.hazmat.primitives import serialization


# =========================================================
# إعداد مجلد البرنامج
# =========================================================

APP_FOLDER = os.path.join(
    os.environ.get(
        "APPDATA",
        os.path.expanduser("~")
    ),
    "SecureEncryptionApp"
)

IDENTITY_FILE = os.path.join(
    APP_FOLDER,
    "identity.json"
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
# Base64
# =========================================================

def to_base64(data):

    return base64.b64encode(
        data
    ).decode("ascii")


def from_base64(data):

    return base64.b64decode(
        data,
        validate=True
    )


# =========================================================
# إنشاء User ID ثابت
# =========================================================

def generate_user_id(
    sign_public_key,
    encryption_public_key
):

    combined = (
        sign_public_key +
        encryption_public_key
    )

    digest = hashlib.sha256(
        combined
    ).digest()

    short_id = digest[:12]

    user_id = base64.b32encode(
        short_id
    ).decode("ascii")

    user_id = user_id.replace(
        "=",
        ""
    )

    user_id = "-".join(
        user_id[i:i + 4]
        for i in range(
            0,
            len(user_id),
            4
        )
    )

    return user_id


# =========================================================
# التحقق من المفتاح العام
# =========================================================

def validate_public_key(
    key_text
):

    try:

        key = from_base64(
            key_text
        )

        return len(key) == 32

    except Exception:

        return False


# =========================================================
# التحقق من سلامة الهوية
# =========================================================

def validate_identity(
    identity
):

    try:

        required_fields = [
            "version",
            "name",
            "user_id",
            "signing_public_key",
            "encryption_public_key",
            "signing_private_key",
            "encryption_private_key"
        ]

        # -----------------------------------------
        # التأكد من وجود الحقول
        # -----------------------------------------

        for field in required_fields:

            if field not in identity:
                return False


        # -----------------------------------------
        # التحقق من الإصدار
        # -----------------------------------------

        if identity["version"] != 1:
            return False


        # -----------------------------------------
        # التحقق من الاسم
        # -----------------------------------------

        if not isinstance(
            identity["name"],
            str
        ):

            return False

        if not identity["name"].strip():
            return False


        # -----------------------------------------
        # التحقق من المفاتيح العامة
        # -----------------------------------------

        if not validate_public_key(
            identity["signing_public_key"]
        ):

            return False


        if not validate_public_key(
            identity["encryption_public_key"]
        ):

            return False


        # -----------------------------------------
        # فك المفاتيح العامة
        # -----------------------------------------

        signing_public = from_base64(
            identity["signing_public_key"]
        )

        encryption_public = from_base64(
            identity["encryption_public_key"]
        )


        # -----------------------------------------
        # إعادة حساب User ID
        # -----------------------------------------

        calculated_id = generate_user_id(
            signing_public,
            encryption_public
        )


        # -----------------------------------------
        # مقارنة User ID
        # -----------------------------------------

        if calculated_id != identity["user_id"]:

            return False


        # -----------------------------------------
        # التأكد أن المفاتيح الخاصة
        # موجودة بصيغة Base64
        # -----------------------------------------

        from_base64(
            identity["signing_private_key"]
        )

        from_base64(
            identity["encryption_private_key"]
        )


        return True


    except Exception:

        return False


# =========================================================
# إنشاء الهوية
# =========================================================

def create_identity(
    name,
    password
):

    # =====================================================
    # مفتاح التوقيع Ed25519
    # =====================================================

    signing_private = (
        ed25519.Ed25519PrivateKey.generate()
    )

    signing_public = (
        signing_private.public_key()
    )


    # =====================================================
    # مفتاح التشفير X25519
    # =====================================================

    encryption_private = (
        x25519.X25519PrivateKey.generate()
    )

    encryption_public = (
        encryption_private.public_key()
    )


    # =====================================================
    # المفاتيح العامة Raw
    # =====================================================

    signing_public_bytes = (
        signing_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    )


    encryption_public_bytes = (
        encryption_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    )


    # =====================================================
    # User ID
    # =====================================================

    user_id = generate_user_id(
        signing_public_bytes,
        encryption_public_bytes
    )


    # =====================================================
    # تشفير مفتاح Ed25519 الخاص
    # =====================================================

    signing_private_bytes = (
        signing_private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=(
                serialization.BestAvailableEncryption(
                    password.encode("utf-8")
                )
            )
        )
    )


    # =====================================================
    # تشفير مفتاح X25519 الخاص
    # =====================================================

    encryption_private_bytes = (
        encryption_private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=(
                serialization.BestAvailableEncryption(
                    password.encode("utf-8")
                )
            )
        )
    )


    # =====================================================
    # بيانات الهوية
    # =====================================================

    identity = {

        "version": 1,

        "name": name,

        "user_id": user_id,

        "signing_public_key":
            to_base64(
                signing_public_bytes
            ),

        "encryption_public_key":
            to_base64(
                encryption_public_bytes
            ),

        "signing_private_key":
            to_base64(
                signing_private_bytes
            ),

        "encryption_private_key":
            to_base64(
                encryption_private_bytes
            )
    }


    # =====================================================
    # التحقق قبل الحفظ
    # =====================================================

    if not validate_identity(identity):

        raise ValueError(
            "فشل التحقق من الهوية قبل حفظها."
        )


    # =====================================================
    # إنشاء المجلد
    # =====================================================

    create_app_folder()


    # =====================================================
    # الحفظ الآمن نسبيًا
    # =====================================================

    temporary_file = (
        IDENTITY_FILE + ".tmp"
    )

    with open(
        temporary_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            identity,
            file,
            indent=4,
            ensure_ascii=False
        )

        file.flush()
        os.fsync(file.fileno())


    # استبدال الملف القديم ذريًا
    os.replace(
        temporary_file,
        IDENTITY_FILE
    )


    return identity


# =========================================================
# التحقق من وجود الهوية
# =========================================================

def identity_exists():

    return os.path.exists(
        IDENTITY_FILE
    )


# =========================================================
# قراءة الهوية
# =========================================================

def load_identity():

    if not identity_exists():

        return None

    try:

        with open(
            IDENTITY_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            identity = json.load(file)


        # التحقق من سلامة الهوية
        if not validate_identity(
            identity
        ):

            print()
            print(
                "❌ تحذير: ملف الهوية غير صالح أو تم تعديله."
            )

            return None


        return identity


    except Exception:

        print()
        print(
            "❌ تعذر قراءة ملف الهوية."
        )

        return None


# =========================================================
# إدخال كلمة المرور مع *
# =========================================================

def input_password(
    prompt
):

    print(
        prompt,
        end="",
        flush=True
    )

    password = ""

    while True:

        char = msvcrt.getwch()


        # Enter
        if char in (
            "\r",
            "\n"
        ):

            print()
            break


        # Backspace
        elif char == "\b":

            if password:

                password = password[:-1]

                print(
                    "\b \b",
                    end="",
                    flush=True
                )


        # مفاتيح التحكم
        elif char in (
            "\x00",
            "\xe0"
        ):

            msvcrt.getwch()


        else:

            password += char

            print(
                "*",
                end="",
                flush=True
            )


    return password


# =========================================================
# البرنامج الرئيسي
# =========================================================

def main():

    print(
        "=" * 55
    )

    print(
        "             نظام الهوية الآمنة"
    )

    print(
        "=" * 55
    )


    create_app_folder()


    # =====================================================
    # إذا كانت الهوية موجودة
    # =====================================================

    if identity_exists():

        identity = load_identity()


        if identity is None:

            print()
            print(
                "❌ لم يتم تشغيل البرنامج."
            )

            print(
                "يجب التحقق من ملف الهوية قبل استخدامه."
            )

            return


        print()
        print(
            "✅ تم العثور على هوية موجودة وسليمة."
        )

        print()

        print(
            "الاسم   :",
            identity["name"]
        )

        print(
            "User ID :",
            identity["user_id"]
        )

        print()

        print(
            "ملف الهوية:"
        )

        print(
            IDENTITY_FILE
        )

        print()

        print(
            "المفاتيح الخاصة محفوظة بشكل مشفّر."
        )

        print(
            "لم يتم إنشاء هوية جديدة."
        )

        return


    # =====================================================
    # إنشاء هوية جديدة
    # =====================================================

    print()
    print(
        "إنشاء هوية جديدة"
    )

    print(
        "-" * 55
    )


    # =====================================================
    # الاسم
    # =====================================================

    name = input(
        "أدخل اسمك: "
    ).strip()


    while not name:

        print(
            "❌ الاسم لا يمكن أن يكون فارغًا."
        )

        name = input(
            "أدخل اسمك: "
        ).strip()


    # =====================================================
    # كلمة المرور
    # =====================================================

    print()

    print(
        "أنشئ كلمة مرور لحماية المفاتيح الخاصة."
    )

    print(
        "يجب أن تكون 8 أحرف على الأقل."
    )

    print()


    password = input_password(
        "كلمة المرور: "
    )


    # =====================================================
    # التحقق من طول كلمة المرور
    # =====================================================

    if len(password) < 8:

        print()
        print(
            "❌ كلمة المرور يجب أن تحتوي على 8 أحرف على الأقل."
        )

        return


    # =====================================================
    # تأكيد كلمة المرور
    # =====================================================

    password_confirm = input_password(
        "تأكيد كلمة المرور: "
    )


    if password != password_confirm:

        print()
        print(
            "❌ كلمتا المرور غير متطابقتين."
        )

        return


    # =====================================================
    # إنشاء الهوية
    # =====================================================

    print()
    print(
        "جاري إنشاء الهوية الآمنة..."
    )


    try:

        identity = create_identity(
            name,
            password
        )

    except Exception as error:

        print()
        print(
            "❌ حدث خطأ أثناء إنشاء الهوية."
        )

        print(
            "التفاصيل:",
            error
        )

        return


    # =====================================================
    # النتيجة
    # =====================================================

    print()

    print(
        "=" * 55
    )

    print(
        "✅ تم إنشاء الهوية بنجاح!"
    )

    print(
        "=" * 55
    )

    print()

    print(
        "الاسم:"
    )

    print(
        identity["name"]
    )

    print()

    print(
        "User ID الخاص بك:"
    )

    print(
        identity["user_id"]
    )

    print()

    print(
        "هذا الـ ID ثابت لهذه الهوية."
    )

    print()

    print(
        "ملف الهوية محفوظ في:"
    )

    print(
        IDENTITY_FILE
    )

    print()

    print(
        "المفاتيح الخاصة محفوظة بشكل مشفّر."
    )

    print(
        "لن يتم عرضها للمستخدم."
    )

    print()

    print(
        "=" * 55
    )


# =========================================================
# تشغيل
# =========================================================

if __name__ == "__main__":

    main()