# c:\Users\MARCOS\Desktop\LOGS BOT\keyboards.py
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton

def main_menu_keyboard() -> InlineKeyboardMarkup:
    """Generates the main menu interactive keyboard."""
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="📖 How to Use", callback_data="how_to_use"),
            InlineKeyboardButton(text="🟢 Status: ONLINE", callback_data="status_check")
        ]
    ])

def session_action_keyboard() -> InlineKeyboardMarkup:
    """Interactive actions after an archive is unpacked."""
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="🔍 Search Keyword / Domain", callback_data="action_search"),
            InlineKeyboardButton(text="🍪 Extract Cookies", callback_data="action_cookies")
        ],
        [
            InlineKeyboardButton(text="💳 Extract Cards / Autofill", callback_data="action_cards"),
            InlineKeyboardButton(text="🔑 Extract Passwords", callback_data="action_passwords")
        ],
        [
            InlineKeyboardButton(text="✈️ Extract TData", callback_data="action_tdata"),
            InlineKeyboardButton(text="🖥️ Extract RDP", callback_data="action_rdp")
        ],
        [
            InlineKeyboardButton(text="📊 Archive Stats", callback_data="action_stats"),
            InlineKeyboardButton(text="🗑️ Delete / Clear Session", callback_data="action_clear")
        ]
    ])
