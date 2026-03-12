"""
app/gui/widgets.py — Small reusable widget helpers shared by all pages.

Color convention: tuples (light_value, dark_value) let CTk automatically
pick the right shade for the current appearance mode, fixing the "white
text on white background" problem in light mode.
"""

import customtkinter as ctk

# Theme-aware secondary / muted colours
_MUTED_TEXT = ("gray30", "gray65")  # visible in both light and dark mode
_DIVIDER_FG  = ("gray65", "gray35")  # subtle separator in both modes


def section_title(parent, text: str) -> ctk.CTkLabel:
    """Render a bold section-heading label."""
    return ctk.CTkLabel(parent, text=text, font=ctk.CTkFont(size=18, weight="bold"))


def subtitle(parent, text: str) -> ctk.CTkLabel:
    """Render a small grey subtitle label (readable in light + dark mode)."""
    return ctk.CTkLabel(parent, text=text, font=ctk.CTkFont(size=12), text_color=_MUTED_TEXT)


def divider(parent) -> ctk.CTkFrame:
    """Render a 1-px horizontal separator visible in both appearance modes."""
    return ctk.CTkFrame(parent, height=1, fg_color=_DIVIDER_FG)


def labeled_entry_row(
    parent,
    label: str,
    variable: ctk.StringVar,
    *,
    show: str = "",
    placeholder: str = "",
    label_width: int = 110,
) -> ctk.CTkEntry:
    """
    Render a full-width ``Label + Entry`` row inside *parent*.

    Returns the CTkEntry so callers can configure it further.
    """
    row = ctk.CTkFrame(parent, fg_color="transparent")
    row.pack(fill="x", padx=24, pady=4)
    ctk.CTkLabel(row, text=label, width=label_width, anchor="w").pack(side="left")
    entry = ctk.CTkEntry(row, textvariable=variable, show=show, placeholder_text=placeholder)
    entry.pack(side="left", fill="x", expand=True)
    return entry


def password_row(
    parent,
    label: str,
    variable: ctk.StringVar,
    *,
    placeholder: str = "Enter password…",
    label_width: int = 110,
):
    """
    Password row with a ``Show`` checkbox that toggles character masking.

    Returns (entry, checkbox).
    """
    row = ctk.CTkFrame(parent, fg_color="transparent")
    row.pack(fill="x", padx=24, pady=4)
    ctk.CTkLabel(row, text=label, width=label_width, anchor="w").pack(side="left")
    entry = ctk.CTkEntry(row, textvariable=variable, show="●", placeholder_text=placeholder)
    entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
    checkbox = ctk.CTkCheckBox(row, text="Show", width=60,
                               command=lambda: _toggle_show(entry, checkbox))
    checkbox.pack(side="left")
    return entry, checkbox


def browse_row(
    parent,
    label: str,
    variable: ctk.StringVar,
    browse_command,
    *,
    placeholder: str = "",
    label_width: int = 110,
    button_text: str = "Browse",
) -> ctk.CTkEntry:
    """
    Row with a label, entry and a browse button.

    Returns the CTkEntry.
    """
    row = ctk.CTkFrame(parent, fg_color="transparent")
    row.pack(fill="x", padx=24, pady=4)
    ctk.CTkLabel(row, text=label, width=label_width, anchor="w").pack(side="left")
    entry = ctk.CTkEntry(row, textvariable=variable, placeholder_text=placeholder)
    entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
    ctk.CTkButton(row, text=button_text, width=80, command=browse_command).pack(side="left")
    return entry


def status_label(parent) -> ctk.CTkLabel:
    """Return a status / feedback label visible in light and dark mode."""
    return ctk.CTkLabel(parent, text="Ready", font=ctk.CTkFont(size=12), text_color=_MUTED_TEXT)


# ── Internal ───────────────────────────────────────────────────────────────────

def _toggle_show(entry: ctk.CTkEntry, checkbox: ctk.CTkCheckBox) -> None:
    entry.configure(show="" if checkbox.get() else "●")
