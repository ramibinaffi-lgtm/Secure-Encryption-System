import os
import json
import base64
import hashlib
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
# أدوات
# =========================================================

def b64encode(data):
    return base64.b64encode(data).decode("ascii")


def generate_user_id(
    signing_public_key,
    encryption_public_key
):

    combined = (
        signing_public_key +
        encryption_public_key
    )

    digest = hashlib.sha256(
        combined
    ).digest()

    short_id = digest[:12]

    user_id = base64.b32encode(
        short_id
    ).decode("ascii")

    user_id = user_id.replace("=", "")

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
# إنشاء المستخدم B
# =========================================================

def create_test_user():

    print("=" * 60)
    print("          إنشاء المستخدم B للاختبار")
    print("=" * 60)

    name = input(
        "اسم المستخدم B: "
    ).strip()

    if not name:

        print("❌ الاسم لا يمكن أن يكون فارغًا.")

        return


    # =====================================================
    # مفتاح التوقيع
    # =====================================================

    signing_private = (
        ed25519.Ed25519PrivateKey.generate()
    )

    signing_public = (
        signing_private.public_key()
    )


    # =====================================================
    # مفتاح التشفير
    # =====================================================

    encryption_private = (
        x25519.X25519PrivateKey.generate()
    )

    encryption_public = (
        encryption_private.public_key()
    )


    # =====================================================
    # المفاتيح العامة
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
    # حفظ المفاتيح الخاصة
    # =====================================================

    signing_private_bytes = (
        signing_private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

    encryption_private_bytes = (
        encryption_private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )


    # =====================================================
    # هوية B التجريبية
    # =====================================================

    identity = {

        "version": 1,

        "name": name,

        "user_id": user_id,

        "signing_public_key":
            b64encode(
                signing_public_bytes
            ),

        "encryption_public_key":
            b64encode(
                encryption_public_bytes
            ),

        "signing_private_key":
            b64encode(
                signing_private_bytes
            ),

        "encryption_private_key":
            b64encode(
                encryption_private_bytes
            )
    }


    # =====================================================
    # حفظ ملف B
    # =====================================================

    file_name = "test_user_B.json"

    with open(
        file_name,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            identity,
            file,
            indent=4,
            ensure_ascii=False
        )


    # =====================================================
    # إنشاء ملف B العام
    # =====================================================

    public_identity = {

        "version": 1,

        "name": name,

        "user_id": user_id,

        "signing_public_key":
            identity["signing_public_key"],

        "encryption_public_key":
            identity["encryption_public_key"]
    }


    public_file = "test_user_B_public.json"

    with open(
        public_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            public_identity,
            file,
            indent=4,
            ensure_ascii=False
        )


    # =====================================================
    # النتيجة
    # =====================================================

    print()
    print("=" * 60)
    print("🟢 تم إنشاء المستخدم B بنجاح")
    print("=" * 60)

    print()

    print("الاسم:")
    print(name)

    print()

    print("User ID:")
    print(user_id)

    print()

    print("تم إنشاء ملفين:")

    print()
    print("1 -", file_name)
    print("2 -", public_file)

    print()

    print("⚠️ ملف test_user_B.json خاص بالاختبار.")
    print("⚠️ لا تشاركه مع أي شخص.")

    print()

    print("الملف الذي سنستخدمه لإضافة B:")
    print(public_file)


# =========================================================
# تشغيل
# =========================================================

if __name__ == "__main__":

    create_test_user()