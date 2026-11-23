import os
import json
import base64
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk

import identity
import contacts
import import_contact


# =========================================================
# إعدادات التطبيق
# =========================================================

APP_NAME = "SECURE ENCRYPTION"

APP_FOLDER = os.path.join(
    os.environ.get("APPDATA", os.path.expanduser("~")),
    "SecureEncryptionApp"
)

IDENTITY_FILE = os.path.join(APP_FOLDER, "identity.json")

BG = "#0B1120"
SIDEBAR = "#101A2C"
CARD = "#152238"
CARD_HOVER = "#1B2B43"
BORDER = "#263953"
ACCENT = "#38BDF8"
ACCENT_HOVER = "#0EA5E9"
TEXT = "#F1F5F9"
MUTED = "#94A3B8"
GREEN = "#34D399"
RED = "#FB7185"
PURPLE = "#A78BFA"

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


# =========================================================
# أدوات مساعدة
# =========================================================

def read_local_identity():
    if not os.path.exists(IDENTITY_FILE):
        return None

    try:
        with open(IDENTITY_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

        return data if isinstance(data, dict) else None

    except (OSError, json.JSONDecodeError):
        return None


def load_contacts_safely():
    try:
        result = contacts.load_contacts()
        return result if isinstance(result, dict) else {}
    except Exception:
        return {}


def export_identity_to_file():
    data = read_local_identity()

    if not data:
        messagebox.showwarning(
            "الهوية غير موجودة",
            "أنشئ هويتك الأمنية أولاً."
        )
        return

    public_identity = {
        "version": 1,
        "name": data.get("name", ""),
        "user_id": data.get("user_id", ""),
        "signing_public_key": data.get("signing_public_key", ""),
        "encryption_public_key": data.get("encryption_public_key", "")
    }

    if not all(public_identity.values()):
        messagebox.showerror(
            "خطأ",
            "بيانات الهوية العامة غير مكتملة."
        )
        return

    path = filedialog.asksaveasfilename(
        title="تصدير الهوية العامة",
        defaultextension=".json",
        initialfile="my_identity_public.json",
        filetypes=[("JSON", "*.json")]
    )

    if not path:
        return

    try:
        with open(path, "w", encoding="utf-8") as file:
            json.dump(
                public_identity,
                file,
                ensure_ascii=False,
                indent=4
            )

        messagebox.showinfo(
            "تم التصدير",
            "تم تصدير الهوية العامة بنجاح.\n\n"
            "هذا الملف يحتوي على المفاتيح العامة فقط."
        )

    except OSError as error:
        messagebox.showerror("تعذر التصدير", str(error))


# =========================================================
# التطبيق الرئيسي
# =========================================================

class SecureEncryptionApp(ctk.CTk):

    def __init__(self):
        super().__init__()

        self.title("Secure Encryption | نظام التشفير الآمن")
        self.geometry("1250x780")
        self.minsize(1000, 650)
        self.configure(fg_color=BG)

        self.current_page = None
        self.nav_buttons = {}
        self.pages = {}

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.create_sidebar()
        self.create_main_area()
        self.create_pages()

        self.show_page("الرئيسية")
        self.refresh_dashboard()

    # =====================================================
    # القائمة الجانبية
    # =====================================================

    def create_sidebar(self):
        self.sidebar = ctk.CTkFrame(
            self,
            width=245,
            corner_radius=0,
            fg_color=SIDEBAR
        )
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)

        logo_area = ctk.CTkFrame(
            self.sidebar,
            fg_color="transparent"
        )
        logo_area.pack(fill="x", padx=18, pady=(28, 22))

        ctk.CTkLabel(
            logo_area,
            text="⬡",
            font=ctk.CTkFont(size=42, weight="bold"),
            text_color=ACCENT
        ).pack(anchor="center")

        ctk.CTkLabel(
            logo_area,
            text="SECURE",
            font=ctk.CTkFont(size=23, weight="bold"),
            text_color=TEXT
        ).pack(anchor="center")

        ctk.CTkLabel(
            logo_area,
            text="ENCRYPTION SYSTEM",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=ACCENT
        ).pack(anchor="center", pady=(0, 5))

        ctk.CTkFrame(
            self.sidebar,
            height=1,
            fg_color=BORDER
        ).pack(fill="x", padx=18, pady=(0, 18))

        ctk.CTkLabel(
            self.sidebar,
            text="القائمة الرئيسية",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=MUTED,
            anchor="e"
        ).pack(fill="x", padx=20, pady=(0, 10))

        # ترتيب ثابت للأقسام.
        # فصل الرمز عن النص يقلل اضطراب عرض العربية.
        menu = [
            ("الرئيسية", "⌂"),
            ("هويتي الأمنية", "◇"),
            ("جهات الاتصال", "◎"),
            ("الرسائل الآمنة", "✉"),
            ("الجلسات الأمنية", "⛨"),
        ]

        for title, symbol in menu:
            button = ctk.CTkButton(
                self.sidebar,
                text=f"{title}    {symbol}",
                anchor="e",
                height=48,
                corner_radius=10,
                fg_color="transparent",
                hover_color=CARD_HOVER,
                text_color=MUTED,
                font=ctk.CTkFont(size=14, weight="bold"),
                command=lambda name=title: self.show_page(name)
            )
            button.pack(fill="x", padx=14, pady=5)
            self.nav_buttons[title] = button

        ctk.CTkFrame(
            self.sidebar,
            fg_color="transparent"
        ).pack(fill="both", expand=True)

        security_box = ctk.CTkFrame(
            self.sidebar,
            fg_color=CARD,
            corner_radius=12,
            border_width=1,
            border_color=BORDER
        )
        security_box.pack(fill="x", padx=14, pady=(0, 12))

        ctk.CTkLabel(
            security_box,
            text="●  الوضع الأمني",
            text_color=GREEN,
            font=ctk.CTkFont(size=13, weight="bold"),
            anchor="e"
        ).pack(fill="x", padx=14, pady=(13, 4))

        ctk.CTkLabel(
            security_box,
            text="المفاتيح الخاصة لا تُعرض",
            text_color=MUTED,
            font=ctk.CTkFont(size=11),
            anchor="e"
        ).pack(fill="x", padx=14, pady=(0, 13))

        ctk.CTkLabel(
            self.sidebar,
            text="SECURE ENCRYPTION  •  v1.0",
            text_color="#64748B",
            font=ctk.CTkFont(size=9)
        ).pack(pady=(0, 18))

    # =====================================================
    # مساحة المحتوى وشريط العنوان
    # =====================================================

    def create_main_area(self):
        self.main_area = ctk.CTkFrame(
            self,
            fg_color=BG,
            corner_radius=0
        )
        self.main_area.grid(row=0, column=1, sticky="nsew")
        self.main_area.grid_columnconfigure(0, weight=1)
        self.main_area.grid_rowconfigure(1, weight=1)

        self.topbar = ctk.CTkFrame(
            self.main_area,
            height=82,
            fg_color=SIDEBAR,
            corner_radius=0
        )
        self.topbar.grid(row=0, column=0, sticky="ew")
        self.topbar.grid_columnconfigure(0, weight=1)

        self.page_title = ctk.CTkLabel(
            self.topbar,
            text="الرئيسية",
            font=ctk.CTkFont(size=23, weight="bold"),
            text_color=TEXT,
            anchor="e"
        )
        self.page_title.grid(
            row=0, column=0, sticky="e", padx=28, pady=(14, 0)
        )

        self.page_subtitle = ctk.CTkLabel(
            self.topbar,
            text="مركز التحكم بالتشفير والهوية الرقمية",
            font=ctk.CTkFont(size=12),
            text_color=MUTED,
            anchor="e"
        )
        self.page_subtitle.grid(
            row=1, column=0, sticky="e", padx=28, pady=(0, 14)
        )

        self.content = ctk.CTkFrame(
            self.main_area,
            fg_color=BG,
            corner_radius=0
        )
        self.content.grid(
            row=1, column=0, sticky="nsew", padx=24, pady=20
        )
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(0, weight=1)

    # =====================================================
    # إنشاء الصفحات
    # =====================================================

    def create_pages(self):
        names = [
            "الرئيسية",
            "هويتي الأمنية",
            "جهات الاتصال",
            "الرسائل الآمنة",
            "الجلسات الأمنية"
        ]

        for name in names:
            page = ctk.CTkScrollableFrame(
                self.content,
                fg_color=BG,
                corner_radius=0
            )
            page.grid_columnconfigure(0, weight=1)
            self.pages[name] = page

        self.build_home_page()
        self.build_identity_page()
        self.build_contacts_page()
        self.build_messages_page()
        self.build_sessions_page()

    # =====================================================
    # أدوات تصميم مشتركة
    # =====================================================

    def section_title(self, parent, title, description=""):
        ctk.CTkLabel(
            parent,
            text=title,
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=TEXT,
            anchor="e"
        ).pack(fill="x", pady=(0, 6))

        if description:
            ctk.CTkLabel(
                parent,
                text=description,
                font=ctk.CTkFont(size=12),
                text_color=MUTED,
                anchor="e",
                justify="right",
                wraplength=800
            ).pack(fill="x", pady=(0, 18))

    def make_card(self, parent, title, value, detail, accent=ACCENT):
        card = ctk.CTkFrame(
            parent,
            fg_color=CARD,
            corner_radius=14,
            border_width=1,
            border_color=BORDER
        )

        ctk.CTkLabel(
            card,
            text=title,
            text_color=MUTED,
            font=ctk.CTkFont(size=13, weight="bold"),
            anchor="e"
        ).pack(fill="x", padx=15, pady=(16, 7))

        value_label = ctk.CTkLabel(
            card,
            text=value,
            text_color=accent,
            font=ctk.CTkFont(size=25, weight="bold"),
            anchor="e"
        )
        value_label.pack(fill="x", padx=15, pady=2)

        ctk.CTkLabel(
            card,
            text=detail,
            text_color=MUTED,
            font=ctk.CTkFont(size=11),
            anchor="e",
            justify="right",
            wraplength=220
        ).pack(fill="x", padx=15, pady=(5, 15))

        return card, value_label

    def make_button(self, parent, text, command, secondary=False):
        return ctk.CTkButton(
            parent,
            text=text,
            command=command,
            height=43,
            corner_radius=9,
            fg_color=CARD_HOVER if secondary else ACCENT_HOVER,
            hover_color=BORDER if secondary else "#0284C7",
            text_color=TEXT,
            font=ctk.CTkFont(size=13, weight="bold")
        )

    def make_entry(self, parent, placeholder, show=None):
        options = {
            "placeholder_text": placeholder,
            "height": 44,
            "corner_radius": 9,
            "justify": "right"
        }
        if show is not None:
            options["show"] = show

        return ctk.CTkEntry(parent, **options)

    # =====================================================
    # الرئيسية
    # =====================================================

    def build_home_page(self):
        page = self.pages["الرئيسية"]

        hero = ctk.CTkFrame(
            page,
            fg_color="#10243B",
            corner_radius=18,
            border_width=1,
            border_color="#1D4664"
        )
        hero.pack(fill="x", pady=(0, 20))

        ctk.CTkLabel(
            hero,
            text="مرحبًا بك في نظام التشفير الآمن",
            text_color=TEXT,
            font=ctk.CTkFont(size=25, weight="bold"),
            anchor="e"
        ).pack(fill="x", padx=23, pady=(22, 8))

        ctk.CTkLabel(
            hero,
            text=(
                "إدارة هويتك الرقمية وجهات الاتصال "
                "والرسائل المشفرة من مكان واحد."
            ),
            text_color="#B7C9DD",
            font=ctk.CTkFont(size=13),
            anchor="e",
            justify="right",
            wraplength=800
        ).pack(fill="x", padx=23, pady=(0, 17))

        self.make_button(
            hero,
            "عرض هويتي الأمنية",
            lambda: self.show_page("هويتي الأمنية")
        ).pack(anchor="e", padx=23, pady=(0, 22))

        stats = ctk.CTkFrame(page, fg_color="transparent")
        stats.pack(fill="x", pady=(0, 22))

        for column in range(3):
            stats.grid_columnconfigure(column, weight=1, uniform="stats")

        card, self.identity_stat = self.make_card(
            stats, "الهوية المحلية", "—", "حالة ملف الهوية", GREEN
        )
        card.grid(row=0, column=0, sticky="ew", padx=(0, 7))

        card, self.contacts_stat = self.make_card(
            stats, "جهات الاتصال", "0", "الهويات المحفوظة", ACCENT
        )
        card.grid(row=0, column=1, sticky="ew", padx=7)

        card, self.sessions_stat = self.make_card(
            stats, "الجلسات الأمنية", "غير متصلة",
            "حالة الربط مع نظام الجلسات", PURPLE
        )
        card.grid(row=0, column=2, sticky="ew", padx=(7, 0))

        self.section_title(
            page,
            "الوصول السريع",
            "اختر القسم الذي تريد استخدامه."
        )

        quick = ctk.CTkFrame(page, fg_color="transparent")
        quick.pack(fill="x")

        for column in range(2):
            quick.grid_columnconfigure(column, weight=1, uniform="quick")

        shortcuts = [
            ("إدارة الهوية", "إنشاء الهوية وتصدير المفاتيح العامة",
             "هويتي الأمنية"),
            ("جهات الاتصال", "استيراد هوية عامة ومراجعة البصمة",
             "جهات الاتصال"),
            ("الرسائل الآمنة", "واجهة الرسائل المشفرة",
             "الرسائل الآمنة"),
            ("الجلسات الأمنية", "واجهة إدارة جلسات التشفير",
             "الجلسات الأمنية")
        ]

        for index, (title, detail, destination) in enumerate(shortcuts):
            row, col = divmod(index, 2)

            box = ctk.CTkFrame(
                quick,
                fg_color=CARD,
                corner_radius=12,
                border_width=1,
                border_color=BORDER
            )
            box.grid(
                row=row,
                column=col,
                sticky="ew",
                padx=(0, 7) if col == 0 else (7, 0),
                pady=7
            )

            ctk.CTkLabel(
                box,
                text=title,
                text_color=TEXT,
                font=ctk.CTkFont(size=15, weight="bold"),
                anchor="e"
            ).pack(fill="x", padx=15, pady=(15, 5))

            ctk.CTkLabel(
                box,
                text=detail,
                text_color=MUTED,
                font=ctk.CTkFont(size=11),
                anchor="e",
                justify="right",
                wraplength=320
            ).pack(fill="x", padx=15, pady=(0, 12))

            self.make_button(
                box,
                "فتح القسم",
                lambda target=destination: self.show_page(target),
                secondary=True
            ).pack(fill="x", padx=15, pady=(0, 15))

    def refresh_dashboard(self):
        if not hasattr(self, "identity_stat"):
            return

        data = read_local_identity()
        saved_contacts = load_contacts_safely()

        self.identity_stat.configure(
            text="موجودة" if data else "غير منشأة",
            text_color=GREEN if data else RED
        )
        self.contacts_stat.configure(text=str(len(saved_contacts)))

    # =====================================================
    # هويتي الأمنية
    # =====================================================

    def build_identity_page(self):
        page = self.pages["هويتي الأمنية"]

        self.section_title(
            page,
            "هويتي الأمنية",
            "إدارة هويتك المحلية ومشاركة المعلومات العامة فقط."
        )

        card = ctk.CTkFrame(
            page,
            fg_color=CARD,
            corner_radius=15,
            border_width=1,
            border_color=BORDER
        )
        card.pack(fill="x", pady=(0, 18))

        self.identity_status = ctk.CTkLabel(
            card,
            text="",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=GREEN,
            anchor="e"
        )
        self.identity_status.pack(fill="x", padx=20, pady=(18, 10))

        self.identity_name = ctk.CTkLabel(
            card,
            text="الاسم: —",
            font=ctk.CTkFont(size=14),
            text_color=TEXT,
            anchor="e"
        )
        self.identity_name.pack(fill="x", padx=20, pady=5)

        self.identity_id = ctk.CTkLabel(
            card,
            text="User ID: —",
            font=ctk.CTkFont(size=12),
            text_color=ACCENT,
            anchor="e",
            justify="right",
            wraplength=800
        )
        self.identity_id.pack(fill="x", padx=20, pady=(5, 18))

        actions = ctk.CTkFrame(page, fg_color="transparent")
        actions.pack(fill="x", pady=(0, 20))
        actions.grid_columnconfigure((0, 1), weight=1, uniform="identity")

        self.make_button(
            actions,
            "تحديث بيانات الهوية",
            self.refresh_identity_page
        ).grid(row=0, column=0, sticky="ew", padx=(0, 7), pady=5)

        self.make_button(
            actions,
            "تصدير الهوية العامة",
            export_identity_to_file,
            secondary=True
        ).grid(row=0, column=1, sticky="ew", padx=(7, 0), pady=5)

        self.section_title(
            page,
            "إنشاء هوية جديدة",
            "لن يتم استبدال الهوية الحالية تلقائيًا."
        )

        form = ctk.CTkFrame(
            page,
            fg_color=CARD,
            corner_radius=15,
            border_width=1,
            border_color=BORDER
        )
        form.pack(fill="x", pady=(0, 15))

        self.name_entry = self.make_entry(
            form, "الاسم الذي سيظهر للآخرين"
        )
        self.name_entry.pack(fill="x", padx=18, pady=(18, 10))

        self.password_entry = self.make_entry(
            form, "كلمة مرور قوية لحماية المفاتيح الخاصة", "●"
        )
        self.password_entry.pack(fill="x", padx=18, pady=10)

        self.confirm_password_entry = self.make_entry(
            form, "تأكيد كلمة المرور", "●"
        )
        self.confirm_password_entry.pack(fill="x", padx=18, pady=10)

        self.make_button(
            form,
            "إنشاء الهوية الأمنية",
            self.create_identity_action
        ).pack(fill="x", padx=18, pady=(10, 18))

        self.refresh_identity_page()

    def refresh_identity_page(self):
        data = read_local_identity()

        if not data:
            self.identity_status.configure(
                text="● لا توجد هوية محلية",
                text_color=RED
            )
            self.identity_name.configure(text="الاسم: —")
            self.identity_id.configure(text="User ID: —")
        else:
            self.identity_status.configure(
                text="● تم العثور على الهوية المحلية",
                text_color=GREEN
            )
            self.identity_name.configure(
                text=f"الاسم: {data.get('name', 'غير معروف')}"
            )
            self.identity_id.configure(
                text=f"User ID: {data.get('user_id', 'غير معروف')}"
            )

        self.refresh_dashboard()

    def create_identity_action(self):
        if read_local_identity():
            messagebox.showwarning(
                "الهوية موجودة",
                "توجد هوية محلية بالفعل. لن يتم استبدالها."
            )
            return

        name = self.name_entry.get().strip()
        password = self.password_entry.get()
        confirmation = self.confirm_password_entry.get()

        if not name:
            messagebox.showwarning("بيانات ناقصة", "أدخل الاسم أولاً.")
            return

        if len(password) < 8:
            messagebox.showwarning(
                "كلمة المرور",
                "استخدم كلمة مرور من 8 أحرف على الأقل."
            )
            return

        if password != confirmation:
            messagebox.showerror(
                "عدم تطابق",
                "كلمتا المرور غير متطابقتين."
            )
            return

        try:
            os.makedirs(APP_FOLDER, exist_ok=True)
            identity.create_identity(name, password)

            self.password_entry.delete(0, "end")
            self.confirm_password_entry.delete(0, "end")
            self.refresh_identity_page()

            if read_local_identity():
                messagebox.showinfo(
                    "الهوية الأمنية",
                    "تم إنشاء الهوية. تحقق من بياناتها قبل المتابعة."
                )
            else:
                messagebox.showwarning(
                    "تعذر التأكد",
                    "لم أتمكن من التأكد من وجود ملف الهوية."
                )

        except Exception as error:
            messagebox.showerror(
                "تعذر إنشاء الهوية",
                str(error)
            )

    # =====================================================
    # جهات الاتصال
    # =====================================================

    def build_contacts_page(self):
        page = self.pages["جهات الاتصال"]

        self.section_title(
            page,
            "جهات الاتصال",
            "استيراد الهويات العامة ومراجعة معرّفاتها وبصماتها."
        )

        buttons = ctk.CTkFrame(page, fg_color="transparent")
        buttons.pack(fill="x", pady=(0, 15))
        buttons.grid_columnconfigure((0, 1), weight=1, uniform="contacts")

        self.make_button(
            buttons,
            "استيراد هوية عامة",
            self.import_contact_action
        ).grid(row=0, column=0, sticky="ew", padx=(0, 7), pady=5)

        self.make_button(
            buttons,
            "تحديث القائمة",
            self.refresh_contacts_page,
            secondary=True
        ).grid(row=0, column=1, sticky="ew", padx=(7, 0), pady=5)

        self.contacts_count_label = ctk.CTkLabel(
            page,
            text="جهات الاتصال: 0",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=ACCENT,
            anchor="e"
        )
        self.contacts_count_label.pack(fill="x", pady=(0, 10))

        self.contacts_list = ctk.CTkFrame(
            page,
            fg_color="transparent"
        )
        self.contacts_list.pack(fill="x")

        self.refresh_contacts_page()

    def import_contact_action(self):
        path = filedialog.askopenfilename(
            title="اختر ملف الهوية العامة",
            filetypes=[("JSON", "*.json")]
        )

        if not path:
            return

        try:
            with open(path, "r", encoding="utf-8") as file:
                public_identity = json.load(file)
        except (OSError, json.JSONDecodeError):
            messagebox.showerror(
                "ملف غير صالح",
                "تعذر قراءة ملف الهوية العامة."
            )
            return

        if not isinstance(public_identity, dict):
            messagebox.showerror(
                "ملف غير صالح",
                "محتوى الملف ليس هوية عامة صالحة."
            )
            return

        try:
            valid, result = import_contact.validate_public_identity(
                public_identity
            )
        except Exception as error:
            messagebox.showerror("فشل التحقق", str(error))
            return

        if not valid:
            messagebox.showerror("فشل التحقق", str(result))
            return

        # دالة التحقق تعيد المفتاحين العامين بصيغة bytes.
        signing_key, encryption_key = result

        import hashlib

        digest = hashlib.sha256(
            signing_key + encryption_key
        ).hexdigest()

        fingerprint = " ".join(
            digest[i:i + 4].upper()
            for i in range(0, len(digest), 4)
        )

        user_id = public_identity["user_id"]
        name = public_identity["name"]

        details = (
            f"الاسم: {name}\n\n"
            f"User ID:\n{user_id}\n\n"
            f"بصمة الهوية:\n{fingerprint}\n\n"
            "قارن البصمة مع صاحب الهوية عبر قناة موثوقة.\n\n"
            "هل تريد إضافة جهة الاتصال؟"
        )

        if not messagebox.askyesno("التحقق من الهوية", details):
            return

        saved = load_contacts_safely()

        if user_id in saved:
            old = saved[user_id]
            old_fingerprint = old.get("fingerprint")

            if old_fingerprint and old_fingerprint != fingerprint:
                messagebox.showerror(
                    "تحذير أمني",
                    "البصمة مختلفة عن البصمة المسجلة. لم يتم الاستبدال."
                )
                return

            if old_fingerprint == fingerprint:
                messagebox.showinfo(
                    "جهة اتصال موجودة",
                    "هذه الهوية موجودة بالفعل والبصمة مطابقة."
                )
                return

        saved[user_id] = {
            "name": name,
            "user_id": user_id,
            "signing_public_key": public_identity["signing_public_key"],
            "encryption_public_key": public_identity["encryption_public_key"],
            "fingerprint": fingerprint
        }

        try:
            result = contacts.save_contacts(saved)

            if result is False:
                raise OSError("لم يتم حفظ جهات الاتصال.")

            self.refresh_contacts_page()

            messagebox.showinfo(
                "تمت الإضافة",
                "تمت إضافة جهة الاتصال.\n"
                "تحقق من البصمة عبر قناة موثوقة."
            )

        except Exception as error:
            messagebox.showerror(
                "فشل الحفظ",
                f"تعذر حفظ جهة الاتصال:\n{error}"
            )

    def refresh_contacts_page(self):
        if not hasattr(self, "contacts_list"):
            return

        for widget in self.contacts_list.winfo_children():
            widget.destroy()

        saved = load_contacts_safely()

        self.contacts_count_label.configure(
            text=f"جهات الاتصال: {len(saved)}"
        )

        if not saved:
            empty = ctk.CTkFrame(
                self.contacts_list,
                fg_color=CARD,
                corner_radius=12,
                border_width=1,
                border_color=BORDER
            )
            empty.pack(fill="x", pady=5)

            ctk.CTkLabel(
                empty,
                text="لا توجد جهات اتصال بعد",
                font=ctk.CTkFont(size=16, weight="bold"),
                text_color=TEXT
            ).pack(pady=(22, 6))

            ctk.CTkLabel(
                empty,
                text="استورد ملف الهوية العامة لشخص تريد التواصل معه.",
                font=ctk.CTkFont(size=12),
                text_color=MUTED
            ).pack(pady=(0, 22))

            self.refresh_dashboard()
            return

        for user_id, contact in saved.items():
            card = ctk.CTkFrame(
                self.contacts_list,
                fg_color=CARD,
                corner_radius=12,
                border_width=1,
                border_color=BORDER
            )
            card.pack(fill="x", pady=5)

            ctk.CTkLabel(
                card,
                text=contact.get("name", "بدون اسم"),
                font=ctk.CTkFont(size=16, weight="bold"),
                text_color=TEXT,
                anchor="e"
            ).pack(fill="x", padx=16, pady=(14, 5))

            ctk.CTkLabel(
                card,
                text=f"User ID: {user_id}",
                font=ctk.CTkFont(size=11),
                text_color=ACCENT,
                anchor="e",
                justify="right",
                wraplength=800
            ).pack(fill="x", padx=16, pady=4)

            ctk.CTkLabel(
                card,
                text=f"البصمة: {contact.get('fingerprint', 'غير مسجلة')}",
                font=ctk.CTkFont(size=10),
                text_color=MUTED,
                anchor="e",
                justify="right",
                wraplength=800
            ).pack(fill="x", padx=16, pady=(4, 12))

        self.refresh_dashboard()

    # =====================================================
    # الرسائل الآمنة
    # =====================================================

    def build_messages_page(self):
        page = self.pages["الرسائل الآمنة"]

        self.section_title(
            page,
            "الرسائل الآمنة",
            "واجهة إعداد الرسائل وإرسالها واستقبالها."
        )

        warning = ctk.CTkFrame(
            page,
            fg_color="#241D2B",
            corner_radius=12,
            border_width=1,
            border_color="#704054"
        )
        warning.pack(fill="x", pady=(0, 18))

        ctk.CTkLabel(
            warning,
            text="الإرسال والاستقبال غير مربوطين بالواجهة بعد",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#FDA4AF",
            anchor="e"
        ).pack(fill="x", padx=18, pady=(15, 7))

        ctk.CTkLabel(
            warning,
            text=(
                "سنربط هذه الصفحة بدوال secure_message.py "
                "بعد فصل التفاعل عبر الطرفية عن منطق التشفير."
            ),
            font=ctk.CTkFont(size=12),
            text_color="#E2C5D0",
            anchor="e",
            justify="right",
            wraplength=800
        ).pack(fill="x", padx=18, pady=(0, 15))

        self.section_title(page, "إرسال رسالة", "معاينة واجهة كتابة الرسالة.")

        send_card = ctk.CTkFrame(
            page,
            fg_color=CARD,
            corner_radius=14,
            border_width=1,
            border_color=BORDER
        )
        send_card.pack(fill="x", pady=(0, 20))

        self.message_recipient = self.make_entry(
            send_card, "معرّف المستلم (User ID)"
        )
        self.message_recipient.pack(fill="x", padx=18, pady=(18, 10))

        self.message_text = ctk.CTkTextbox(
            send_card,
            height=130,
            corner_radius=9,
            border_width=1,
            border_color=BORDER
        )
        self.message_text.pack(fill="x", padx=18, pady=10)
        self.message_text.insert("1.0", "اكتب رسالتك هنا...")
        
        self.make_button(
            send_card,
            "الإرسال غير مفعّل بعد",
            lambda: messagebox.showinfo(
                "الربط قيد الإعداد",
                "لم يتم ربط الإرسال بالوظائف الأمنية بعد."
            ),
            secondary=True
        ).pack(fill="x", padx=18, pady=(10, 18))

        self.section_title(
            page,
            "استقبال رسالة",
            "سيُضاف هنا التحقق من التوقيع وفك التشفير."
        )

        receive_card = ctk.CTkFrame(
            page,
            fg_color=CARD,
            corner_radius=14,
            border_width=1,
            border_color=BORDER
        )
        receive_card.pack(fill="x")

        ctk.CTkLabel(
            receive_card,
            text="لن يُعرض محتوى الرسالة إلا بعد التحقق منها.",
            font=ctk.CTkFont(size=12),
            text_color=MUTED,
            anchor="e",
            justify="right",
            wraplength=800
        ).pack(fill="x", padx=18, pady=18)

    # =====================================================
    # الجلسات الأمنية
    # =====================================================

    def build_sessions_page(self):
        page = self.pages["الجلسات الأمنية"]

        self.section_title(
            page,
            "الجلسات الأمنية",
            "واجهة إدارة جلسات التشفير بين جهات الاتصال."
        )

        card = ctk.CTkFrame(
            page,
            fg_color=CARD,
            corner_radius=15,
            border_width=1,
            border_color=BORDER
        )
        card.pack(fill="x", pady=(0, 18))

        ctk.CTkLabel(
            card,
            text="إدارة الجلسات",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=TEXT,
            anchor="e"
        ).pack(fill="x", padx=20, pady=(20, 8))

        ctk.CTkLabel(
            card,
            text=(
                "واجهة الجلسات جاهزة للتطوير، لكن عمليات الإنشاء "
                "والاختبار والإغلاق لم تُربط بعد بدوال session.py."
            ),
            font=ctk.CTkFont(size=12),
            text_color=MUTED,
            anchor="e",
            justify="right",
            wraplength=800
        ).pack(fill="x", padx=20, pady=(0, 16))

        self.make_button(
            card,
            "تحديث الجلسات",
            lambda: messagebox.showinfo(
                "الجلسات الأمنية",
                "لم يتم ربط عمليات الجلسات بالواجهة بعد."
            ),
            secondary=True
        ).pack(fill="x", padx=20, pady=(0, 20))

    # =====================================================
    # التنقل بين الصفحات
    # =====================================================

    def show_page(self, page_name):
        self.current_page = page_name

        for name, page in self.pages.items():
            page.grid_forget()

            self.nav_buttons[name].configure(
                fg_color=ACCENT_HOVER if name == page_name else "transparent",
                text_color=TEXT if name == page_name else MUTED
            )

        self.pages[page_name].grid(
            row=0,
            column=0,
            sticky="nsew"
        )

        self.page_title.configure(text=page_name)

        subtitles = {
            "الرئيسية": "مركز التحكم بالتشفير والهوية الرقمية",
            "هويتي الأمنية": "إدارة الهوية والمفاتيح العامة",
            "جهات الاتصال": "استيراد الهويات والتحقق من بصماتها",
            "الرسائل الآمنة": "إعداد الرسائل المشفرة",
            "الجلسات الأمنية": "إدارة جلسات التشفير"
        }

        self.page_subtitle.configure(
            text=subtitles.get(page_name, "")
        )

        if page_name == "هويتي الأمنية":
            self.refresh_identity_page()
        elif page_name == "جهات الاتصال":
            self.refresh_contacts_page()
        elif page_name == "الرئيسية":
            self.refresh_dashboard()


# =========================================================
# تشغيل البرنامج
# =========================================================

if __name__ == "__main__":
    try:
        app = SecureEncryptionApp()
        app.mainloop()
    except Exception:
        import traceback

        traceback.print_exc()
        input("حدث خطأ أثناء تشغيل الواجهة. اضغط Enter للإغلاق...")