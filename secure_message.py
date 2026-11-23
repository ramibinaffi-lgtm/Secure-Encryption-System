import os
import json
import base64
import time
import uuid
import getpass

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidSignature, InvalidTag


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

CONTACTS_FILE = os.path.join(
    APP_FOLDER,
    "contacts.json"
)

REPLAY_FILE = os.path.join(
    APP_FOLDER,
    "received_messages.json"
)


# =========================================================
# إعدادات الرسائل
# =========================================================

MESSAGE_VERSION = 1

MESSAGE_CONTEXT = b"SecureEncryptionApp Message v1"

# أقصى عمر مسموح للرسالة:
# 24 ساعة
MAX_MESSAGE_AGE = 24 * 60 * 60


# =========================================================
# Base64
# =========================================================

def from_base64(data):

    try:

        if not isinstance(data, str):
            raise ValueError

        return base64.b64decode(
            data,
            validate=True
        )

    except Exception:

        raise ValueError(
            "بيانات Base64 غير صالحة."
        )


# =========================================================
# تحميل الهوية المحلية
# =========================================================

def load_identity():

    if not os.path.exists(IDENTITY_FILE):
        return None

    try:

        with open(
            IDENTITY_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            identity = json.load(file)

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

        with open(
            CONTACTS_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            contacts = json.load(file)

        if not isinstance(contacts, dict):
            return {}

        return contacts

    except Exception:

        return {}


# =========================================================
# تحميل سجل الرسائل المستلمة
# =========================================================

def load_received_messages():

    if not os.path.exists(REPLAY_FILE):
        return {}

    try:

        with open(
            REPLAY_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            messages = json.load(file)

        if not isinstance(messages, dict):
            return {}

        return messages

    except Exception:

        return {}


# =========================================================
# حفظ سجل الرسائل المستلمة
# =========================================================

def save_received_messages(messages):

    os.makedirs(
        APP_FOLDER,
        exist_ok=True
    )

    temp_file = REPLAY_FILE + ".tmp"

    try:

        with open(
            temp_file,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                messages,
                file,
                ensure_ascii=False,
                indent=2
            )

            file.flush()
            os.fsync(file.fileno())

        os.replace(
            temp_file,
            REPLAY_FILE
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
# تنظيف سجل الرسائل القديمة
# =========================================================

def cleanup_received_messages(messages):

    now = int(time.time())

    cleaned = {}

    for message_id, timestamp in messages.items():

        try:

            timestamp = int(timestamp)

            # الاحتفاظ بالسجل لمدة 7 أيام
            if now - timestamp <= 7 * 24 * 60 * 60:
                cleaned[message_id] = timestamp

        except Exception:

            continue

    return cleaned


# =========================================================
# التحقق من الهوية المحلية
# =========================================================

def validate_local_identity(identity):

    try:

        signing_public = from_base64(
            identity["signing_public_key"]
        )

        encryption_public = from_base64(
            identity["encryption_public_key"]
        )

        if len(signing_public) != 32:
            return False

        if len(encryption_public) != 32:
            return False

        # التأكد من أن المفاتيح العامة صالحة
        ed25519.Ed25519PublicKey.from_public_bytes(
            signing_public
        )

        x25519.X25519PublicKey.from_public_bytes(
            encryption_public
        )

        return True

    except Exception:

        return False


# =========================================================
# التحقق من جهة الاتصال
# =========================================================

def validate_contact(contact):

    try:

        required_fields = [
            "name",
            "user_id",
            "signing_public_key",
            "encryption_public_key"
        ]

        for field in required_fields:

            if field not in contact:
                return False

        signing_public = from_base64(
            contact["signing_public_key"]
        )

        encryption_public = from_base64(
            contact["encryption_public_key"]
        )

        if len(signing_public) != 32:
            return False

        if len(encryption_public) != 32:
            return False

        ed25519.Ed25519PublicKey.from_public_bytes(
            signing_public
        )

        x25519.X25519PublicKey.from_public_bytes(
            encryption_public
        )

        return True

    except Exception:

        return False


# =========================================================
# تحميل مفتاح X25519 الخاص
# =========================================================

def load_encryption_private_key(
    identity,
    password
):

    try:

        encrypted_private = from_base64(
            identity["encryption_private_key"]
        )

        private_key = serialization.load_pem_private_key(
            encrypted_private,
            password=password.encode("utf-8")
        )

        if not isinstance(
            private_key,
            x25519.X25519PrivateKey
        ):
            return None

        return private_key

    except Exception:

        return None


# =========================================================
# تحميل مفتاح Ed25519 الخاص
# =========================================================

def load_signing_private_key(
    identity,
    password
):

    try:

        encrypted_private = from_base64(
            identity["signing_private_key"]
        )

        private_key = serialization.load_pem_private_key(
            encrypted_private,
            password=password.encode("utf-8")
        )

        if not isinstance(
            private_key,
            ed25519.Ed25519PrivateKey
        ):
            return None

        return private_key

    except Exception:

        return None


# =========================================================
# اشتقاق مفتاح التشفير
# =========================================================

def derive_key(shared_secret):

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=MESSAGE_CONTEXT
    ).derive(
        shared_secret
    )


# =========================================================
# بناء البيانات التي سيتم توقيعها
# =========================================================

def build_signed_data(message_data):

    return json.dumps(
        message_data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    ).encode("utf-8")


# =========================================================
# اختيار جهة الاتصال
# =========================================================

def choose_contact(contacts):

    if not contacts:

        print()
        print("❌ لا توجد جهات اتصال.")
        return None


    contact_list = list(
        contacts.items()
    )


    print()
    print("جهات الاتصال:")
    print()


    for index, (user_id, contact) in enumerate(
        contact_list,
        start=1
    ):

        print(
            f"{index}. {contact['name']} "
            f"({user_id})"
        )


    print()

    choice = input(
        "اختر رقم جهة الاتصال: "
    ).strip()


    try:

        choice = int(choice)

    except ValueError:

        print()
        print("❌ اختيار غير صالح.")
        return None


    if choice < 1 or choice > len(contact_list):

        print()
        print("❌ الاختيار غير موجود.")
        return None


    return contact_list[
        choice - 1
    ][1]


# =========================================================
# تشفير رسالة
# =========================================================

def encrypt_message():

    identity = load_identity()

    if identity is None:

        print()
        print("❌ لم يتم العثور على الهوية المحلية.")
        return


    if not validate_local_identity(identity):

        print()
        print("❌ الهوية المحلية غير صالحة.")
        return


    contacts = load_contacts()

    contact = choose_contact(
        contacts
    )

    if contact is None:
        return


    if not validate_contact(contact):

        print()
        print("❌ بيانات جهة الاتصال غير صالحة.")
        return


    print()

    message = input(
        "اكتب الرسالة: "
    )

    if not message:

        print()
        print("❌ الرسالة فارغة.")
        return


    print()

    password = getpass.getpass(
        "أدخل كلمة مرور هويتك: "
    )


    # =====================================================
    # تحميل المفاتيح الخاصة
    # =====================================================

    signing_private = load_signing_private_key(
        identity,
        password
    )

    encryption_private = load_encryption_private_key(
        identity,
        password
    )


    if (
        signing_private is None
        or encryption_private is None
    ):

        print()
        print(
            "❌ كلمة المرور غير صحيحة "
            "أو المفاتيح الخاصة غير صالحة."
        )

        return


    # =====================================================
    # مفتاح الطرف الآخر
    # =====================================================

    try:

        recipient_public_bytes = from_base64(
            contact["encryption_public_key"]
        )

        recipient_public = (
            x25519.X25519PublicKey.from_public_bytes(
                recipient_public_bytes
            )
        )

    except Exception:

        print()
        print(
            "❌ مفتاح التشفير العام للطرف الآخر غير صالح."
        )

        return


    # =====================================================
    # إنشاء مفتاح مؤقت جديد لكل رسالة
    # =====================================================

    ephemeral_private = (
        x25519.X25519PrivateKey.generate()
    )

    ephemeral_public = (
        ephemeral_private.public_key()
    )


    # =====================================================
    # اشتقاق السر المشترك
    # =====================================================

    shared_secret = ephemeral_private.exchange(
        recipient_public
    )


    key = derive_key(
        shared_secret
    )


    # =====================================================
    # Nonce
    # =====================================================

    nonce = os.urandom(12)


    # =====================================================
    # Message ID
    # =====================================================

    message_id = str(
        uuid.uuid4()
    )


    # =====================================================
    # Timestamp
    # =====================================================

    timestamp = int(
        time.time()
    )


    # =====================================================
    # AAD
    # =====================================================

    aad = (
        f"v1|"
        f"{identity['user_id']}|"
        f"{contact['user_id']}|"
        f"{message_id}|"
        f"{timestamp}"
    ).encode("utf-8")


    # =====================================================
    # التشفير
    # =====================================================

    cipher = ChaCha20Poly1305(
        key
    )


    ciphertext = cipher.encrypt(
        nonce,
        message.encode("utf-8"),
        aad
    )


    # =====================================================
    # بيانات الرسالة قبل التوقيع
    # =====================================================

    message_data = {

        "version": MESSAGE_VERSION,

        "message_id": message_id,

        "timestamp": timestamp,

        "sender_id": identity["user_id"],

        "recipient_id": contact["user_id"],

        "ephemeral_public_key": base64.b64encode(
            ephemeral_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        ).decode("ascii"),

        "nonce": base64.b64encode(
            nonce
        ).decode("ascii"),

        "ciphertext": base64.b64encode(
            ciphertext
        ).decode("ascii")
    }


    # =====================================================
    # التوقيع
    # =====================================================

    signed_data = build_signed_data(
        message_data
    )


    signature = signing_private.sign(
        signed_data
    )


    message_data["signature"] = (
        base64.b64encode(
            signature
        ).decode("ascii")
    )


    # =====================================================
    # تحويل الرسالة إلى نص
    # =====================================================

    message_json = json.dumps(
        message_data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    )


    encoded_message = base64.b64encode(
        message_json.encode("utf-8")
    ).decode("ascii")


    # =====================================================
    # النتيجة
    # =====================================================

    print()
    print("=" * 60)
    print("🟢 تم تشفير الرسالة وتوقيعها بنجاح.")
    print("=" * 60)

    print()
    print("الرسالة المشفرة:")

    print()
    print(encoded_message)

    print()
    print("=" * 60)


# =========================================================
# استقبال رسالة
# =========================================================

def receive_message():

    identity = load_identity()

    if identity is None:

        print()
        print("❌ لم يتم العثور على الهوية المحلية.")
        return


    if not validate_local_identity(identity):

        print()
        print("❌ الهوية المحلية غير صالحة.")
        return


    contacts = load_contacts()


    print()
    print("=" * 60)
    print("             استقبال رسالة آمنة")
    print("=" * 60)

    print()

    encoded_message = input(
        "الصق الرسالة المشفرة: "
    ).strip()


    if not encoded_message:

        print()
        print("❌ لم يتم إدخال رسالة.")
        return


    # =====================================================
    # فك Base64
    # =====================================================

    try:

        message_json = from_base64(
            encoded_message
        ).decode("utf-8")

        message_data = json.loads(
            message_json
        )

    except Exception:

        print()
        print("❌ صيغة الرسالة غير صحيحة.")
        return


    # =====================================================
    # الحقول المطلوبة
    # =====================================================

    required_fields = [
        "version",
        "message_id",
        "timestamp",
        "sender_id",
        "recipient_id",
        "ephemeral_public_key",
        "nonce",
        "ciphertext",
        "signature"
    ]


    for field in required_fields:

        if field not in message_data:

            print()
            print(
                f"❌ الرسالة ناقصة: {field}"
            )

            return


    # =====================================================
    # إصدار الرسالة
    # =====================================================

    if message_data["version"] != MESSAGE_VERSION:

        print()
        print("❌ إصدار الرسالة غير مدعوم.")
        return


    # =====================================================
    # التحقق من Message ID
    # =====================================================

    message_id = message_data["message_id"]

    if not isinstance(
        message_id,
        str
    ):

        print()
        print("❌ معرف الرسالة غير صالح.")
        return


    try:

        uuid.UUID(
            message_id
        )

    except Exception:

        print()
        print("❌ معرف الرسالة غير صالح.")
        return


    # =====================================================
    # التحقق من Timestamp
    # =====================================================

    try:

        timestamp = int(
            message_data["timestamp"]
        )

    except Exception:

        print()
        print("❌ وقت الرسالة غير صالح.")
        return


    now = int(
        time.time()
    )


    if timestamp > now + 5 * 60:

        print()
        print("❌ وقت الرسالة غير صالح.")
        print("الرسالة تحمل وقتًا مستقبليًا.")
        return


    if now - timestamp > MAX_MESSAGE_AGE:

        print()
        print("❌ الرسالة قديمة جدًا.")
        print(
            "تم رفضها لحماية النظام من إعادة استخدام الرسائل القديمة."
        )

        return


    # =====================================================
    # التحقق من المستلم
    # =====================================================

    if (
        message_data["recipient_id"]
        != identity["user_id"]
    ):

        print()
        print("❌ هذه الرسالة ليست موجهة إليك.")
        return


    # =====================================================
    # البحث عن المرسل
    # =====================================================

    sender_id = message_data[
        "sender_id"
    ]


    if sender_id not in contacts:

        print()
        print(
            "❌ المرسل غير موجود في جهات الاتصال."
        )

        return


    sender = contacts[
        sender_id
    ]


    if not validate_contact(sender):

        print()
        print(
            "❌ بيانات المرسل غير صالحة."
        )

        return


    # =====================================================
    # التحقق من أن User ID صحيح
    # =====================================================

    if sender["user_id"] != sender_id:

        print()
        print(
            "❌ هوية المرسل غير متطابقة."
        )

        return


    # =====================================================
    # منع Replay Attack
    # =====================================================

    received_messages = load_received_messages()

    received_messages = cleanup_received_messages(
        received_messages
    )


    if message_id in received_messages:

        print()
        print("=" * 60)
        print("❌ تم رفض الرسالة.")
        print("=" * 60)

        print()
        print(
            "هذه الرسالة تم استقبالها مسبقًا."
        )

        print(
            "تم اكتشاف محاولة إعادة إرسال الرسالة."
        )

        return


    # =====================================================
    # التحقق من التوقيع
    # =====================================================

    try:

        signature = from_base64(
            message_data["signature"]
        )


        if len(signature) != 64:

            print()
            print("❌ التوقيع غير صالح.")
            return


        signed_data = {

            "version":
                message_data["version"],

            "message_id":
                message_data["message_id"],

            "timestamp":
                message_data["timestamp"],

            "sender_id":
                message_data["sender_id"],

            "recipient_id":
                message_data["recipient_id"],

            "ephemeral_public_key":
                message_data["ephemeral_public_key"],

            "nonce":
                message_data["nonce"],

            "ciphertext":
                message_data["ciphertext"]
        }


        data_to_verify = build_signed_data(
            signed_data
        )


        public_key_bytes = from_base64(
            sender["signing_public_key"]
        )


        public_key = (
            ed25519.Ed25519PublicKey.from_public_bytes(
                public_key_bytes
            )
        )


        public_key.verify(
            signature,
            data_to_verify
        )


    except InvalidSignature:

        print()
        print("=" * 60)
        print("❌ فشل التحقق من التوقيع.")
        print("=" * 60)

        print()
        print(
            "تم رفض الرسالة لأن محتواها "
            "لا يتطابق مع التوقيع."
        )

        return


    except Exception:

        print()
        print("❌ التوقيع غير صالح.")
        return


    # =====================================================
    # كلمة مرور الهوية
    # =====================================================

    print()

    password = getpass.getpass(
        "أدخل كلمة مرور هويتك: "
    )


    # =====================================================
    # تحميل المفتاح الخاص
    # =====================================================

    private_key = load_encryption_private_key(
        identity,
        password
    )


    if private_key is None:

        print()
        print(
            "❌ كلمة المرور غير صحيحة "
            "أو مفتاح التشفير الخاص غير صالح."
        )

        return


    # =====================================================
    # فك المفاتيح
    # =====================================================

    try:

        ephemeral_public_bytes = from_base64(
            message_data[
                "ephemeral_public_key"
            ]
        )


        if len(ephemeral_public_bytes) != 32:

            print()
            print(
                "❌ المفتاح المؤقت غير صالح."
            )

            return


        ephemeral_public = (
            x25519.X25519PublicKey.from_public_bytes(
                ephemeral_public_bytes
            )
        )


        nonce = from_base64(
            message_data["nonce"]
        )


        if len(nonce) != 12:

            print()
            print("❌ Nonce غير صالح.")
            return


        ciphertext = from_base64(
            message_data["ciphertext"]
        )


    except Exception:

        print()
        print(
            "❌ بيانات التشفير غير صالحة."
        )

        return


    # =====================================================
    # اشتقاق السر المشترك
    # =====================================================

    try:

        shared_secret = private_key.exchange(
            ephemeral_public
        )


        key = derive_key(
            shared_secret
        )


        aad = (
            f"v1|"
            f"{sender_id}|"
            f"{identity['user_id']}|"
            f"{message_id}|"
            f"{timestamp}"
        ).encode("utf-8")


        cipher = ChaCha20Poly1305(
            key
        )


        plaintext = cipher.decrypt(
            nonce,
            ciphertext,
            aad
        )


        message = plaintext.decode(
            "utf-8"
        )


    except InvalidTag:

        print()
        print(
            "❌ فشل فك التشفير."
        )

        print(
            "الرسالة قد تكون معدلة أو غير صالحة."
        )

        return


    except Exception:

        print()
        print(
            "❌ فشل فك تشفير الرسالة."
        )

        return


    # =====================================================
    # تسجيل الرسالة بعد نجاح التحقق وفك التشفير
    # =====================================================

    received_messages[message_id] = timestamp

    received_messages = cleanup_received_messages(
        received_messages
    )


    if not save_received_messages(
        received_messages
    ):

        print()
        print(
            "⚠️ تم فك الرسالة، لكن تعذر حفظ سجل منع إعادة الإرسال."
        )

        print(
            "لن يتم اعتبار حماية Replay مكتملة."
        )

        return


    # =====================================================
    # عرض الرسالة
    # =====================================================

    print()
    print("=" * 60)
    print("🟢 تم التحقق من الرسالة وفك تشفيرها.")
    print("=" * 60)

    print()
    print("المرسل:")
    print(sender["name"])

    print()
    print("User ID:")
    print(sender_id)

    print()
    print("الرسالة:")
    print(message)

    print()
    print("=" * 60)


# =========================================================
# القائمة الرئيسية
# =========================================================

def main():

    while True:

        print()
        print("=" * 60)
        print("             Secure Encryption App")
        print("=" * 60)

        print()
        print("1. إرسال رسالة")
        print("2. استقبال رسالة")
        print("0. خروج")

        print()

        choice = input(
            "اختر: "
        ).strip()


        if choice == "1":

            encrypt_message()


        elif choice == "2":

            receive_message()


        elif choice == "0":

            print()
            print("👋 تم إغلاق البرنامج.")
            break


        else:

            print()
            print("❌ اختيار غير صالح.")


# =========================================================
# تشغيل
# =========================================================

if __name__ == "__main__":
    main()