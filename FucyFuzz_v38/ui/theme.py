"""
FucyFuzz GUI Theme — Premium Dark Cybersecurity Aesthetic v2
"""

COLORS = {
    'bg_primary':    '#070b10',
    'bg_secondary':  '#0c1219',
    'bg_card':       '#111825',
    'bg_elevated':   '#182030',
    'bg_input':      '#0e1520',
    'border':        '#1c2d42',
    'border_bright': '#274060',
    'border_glow':   '#00d4ff44',
    'accent_cyan':   '#00d4ff',
    'accent_blue':   '#3b82f6',
    'accent_pink':   '#f43f5e',
    'accent_yellow': '#fbbf24',
    'accent_purple': '#a78bfa',
    'accent_green':  '#10b981',
    'accent_orange': '#f97316',
    'accent_teal':   '#14b8a6',
    'text_primary':  '#e2eaf5',
    'text_secondary':'#8fa8c8',
    'text_muted':    '#3d5470',
    'critical': '#f43f5e',
    'high':     '#f97316',
    'medium':   '#fbbf24',
    'low':      '#00d4ff',
    'success':  '#10b981',
}

GRAD_SIDEBAR    = "qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #0c1219, stop:1 #07111a)"
GRAD_TITLE      = "qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #070b10, stop:0.5 #0c1825, stop:1 #070b10)"
GRAD_NAV_ACTIVE = "qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #00d4ff1a, stop:1 transparent)"
GRAD_BTN_RUN    = "qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #10b981, stop:1 #0ea57b)"

FONT_UI   = "'Inter', 'Segoe UI', 'Ubuntu', 'Helvetica Neue', sans-serif"
FONT_MONO = "'JetBrains Mono', 'Fira Code', 'Consolas', 'Courier New', monospace"

C = COLORS

GLOBAL_STYLESHEET = f"""
* {{ font-family: {FONT_UI}; color: {C['text_primary']}; }}

QMainWindow, QDialog {{ background-color: {C['bg_primary']}; }}
QWidget {{ background-color: transparent; }}

QScrollBar:vertical {{ background: {C['bg_secondary']}; width: 5px; border-radius: 3px; margin: 0; }}
QScrollBar::handle:vertical {{ background: {C['border_bright']}; border-radius: 3px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: {C['accent_cyan']}88; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{ background: {C['bg_secondary']}; height: 5px; border-radius: 3px; }}
QScrollBar::handle:horizontal {{ background: {C['border_bright']}; border-radius: 3px; min-width: 30px; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

QLabel {{ background: transparent; color: {C['text_primary']}; }}

QLineEdit {{
    background-color: {C['bg_input']}; border: 1px solid {C['border']};
    border-radius: 6px; padding: 7px 12px; color: {C['text_primary']}; font-size: 12px;
    selection-background-color: {C['accent_cyan']}44;
}}
QLineEdit:focus {{ border: 1px solid {C['accent_cyan']}; background-color: {C['bg_elevated']}; }}
QLineEdit::placeholder {{ color: {C['text_muted']}; }}

QTextEdit, QPlainTextEdit {{
    background-color: {C['bg_input']}; border: 1px solid {C['border']};
    border-radius: 6px; padding: 10px; color: {C['accent_green']};
    font-family: {FONT_MONO}; font-size: 11.5px;
    selection-background-color: {C['border_bright']};
}}

QComboBox {{
    background-color: {C['bg_input']}; border: 1px solid {C['border']};
    border-radius: 6px; padding: 7px 12px; color: {C['text_primary']};
    font-size: 12px; min-width: 130px;
}}
QComboBox:focus {{ border: 1px solid {C['accent_cyan']}; }}
QComboBox:hover {{ border: 1px solid {C['border_bright']}; }}
QComboBox::drop-down {{ border: none; width: 28px; }}
QComboBox::down-arrow {{
    image: none;
    border-left: 5px solid transparent; border-right: 5px solid transparent;
    border-top: 6px solid {C['text_secondary']}; margin-right: 8px;
}}
QComboBox QAbstractItemView {{
    background-color: {C['bg_elevated']}; border: 1px solid {C['border_bright']};
    selection-background-color: {C['accent_cyan']}22; selection-color: {C['accent_cyan']};
    color: {C['text_primary']}; padding: 4px; outline: none;
}}

QSpinBox, QDoubleSpinBox {{
    background-color: {C['bg_input']}; border: 1px solid {C['border']};
    border-radius: 6px; padding: 7px 10px; color: {C['text_primary']}; font-size: 12px;
}}
QSpinBox:focus, QDoubleSpinBox:focus {{ border: 1px solid {C['accent_cyan']}; }}
QSpinBox::up-button, QSpinBox::down-button,
QDoubleSpinBox::up-button, QDoubleSpinBox::down-button {{
    background: {C['bg_elevated']}; border: none; border-radius: 2px; width: 18px;
}}

QCheckBox {{ spacing: 9px; color: {C['text_primary']}; font-size: 12px; }}
QCheckBox::indicator {{
    width: 16px; height: 16px;
    border: 1px solid {C['border_bright']}; border-radius: 4px; background: {C['bg_input']};
}}
QCheckBox::indicator:hover {{ border: 1px solid {C['accent_cyan']}; }}
QCheckBox::indicator:checked {{ background: {C['accent_cyan']}; border-color: {C['accent_cyan']}; }}

QGroupBox {{
    border: 1px solid {C['border']}; border-radius: 8px;
    margin-top: 18px; padding-top: 10px;
    font-size: 10px; font-weight: 700;
    color: {C['text_secondary']}; letter-spacing: 2px;
}}
QGroupBox::title {{
    subcontrol-origin: margin; subcontrol-position: top left;
    padding: 0 10px; left: 14px;
    color: {C['accent_cyan']}; letter-spacing: 2px;
}}

QTabWidget::pane {{ border: 1px solid {C['border']}; border-radius: 8px; background: {C['bg_card']}; }}
QTabBar::tab {{
    background: {C['bg_secondary']}; border: none;
    border-bottom: 2px solid transparent;
    padding: 8px 18px; color: {C['accent_blue']};
    font-size: 11px; font-weight: 600; letter-spacing: 0.8px; min-width: 70px;
}}
QTabBar::tab:selected {{
    background: {C['bg_card']}; color: {C['accent_cyan']};
    border-bottom: 2px solid {C['accent_cyan']};
}}
QTabBar::tab:hover:!selected {{
    color: #60a5fa; background: {C['bg_elevated']};
    border-bottom: 2px solid {C['border_bright']};
}}

QTableWidget {{
    background-color: {C['bg_card']}; border: 1px solid {C['border']};
    gridline-color: {C['border']}; border-radius: 6px; font-size: 12px; outline: none;
}}
QTableWidget::item {{ padding: 8px 12px; border: none; color: {C['text_primary']}; }}
QTableWidget::item:selected {{ background-color: {C['accent_cyan']}18; color: {C['accent_cyan']}; }}
QTableWidget::item:hover {{ background-color: {C['bg_elevated']}; }}
QHeaderView::section {{
    background-color: {C['bg_secondary']}; border: none;
    border-right: 1px solid {C['border']}; border-bottom: 1px solid {C['border']};
    padding: 8px 12px; color: {C['text_secondary']};
    font-size: 10px; font-weight: 700; letter-spacing: 1.5px;
}}

QSplitter::handle {{ background: {C['border']}; width: 1px; height: 1px; }}
QSplitter::handle:hover {{ background: {C['accent_cyan']}55; }}

QToolTip {{
    background-color: {C['bg_elevated']}; border: 1px solid {C['accent_cyan']}55;
    color: {C['text_primary']}; padding: 7px 12px; border-radius: 6px; font-size: 12px;
}}

QMenuBar {{
    background: {C['bg_primary']}; border-bottom: 1px solid {C['border']};
    color: {C['text_secondary']}; font-size: 12px; padding: 2px 4px;
}}
QMenuBar::item {{ padding: 5px 12px; background: transparent; border-radius: 4px; }}
QMenuBar::item:selected {{ background: {C['bg_elevated']}; color: {C['text_primary']}; }}
QMenu {{
    background: {C['bg_elevated']}; border: 1px solid {C['border_bright']};
    font-size: 12px; padding: 4px; border-radius: 8px;
}}
QMenu::item {{ padding: 8px 24px 8px 16px; border-radius: 4px; margin: 1px 4px; }}
QMenu::item:selected {{ background: {C['accent_cyan']}22; color: {C['accent_cyan']}; }}
QMenu::separator {{ height: 1px; background: {C['border']}; margin: 4px 8px; }}

QProgressBar {{
    background: {C['border']}; border: none; border-radius: 4px; height: 6px;
    color: transparent;
}}
QProgressBar::chunk {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 {C['accent_cyan']}, stop:1 {C['accent_purple']});
    border-radius: 4px;
}}

QStatusBar {{
    background: {C['bg_secondary']}; border-top: 1px solid {C['border']};
    color: {C['text_secondary']}; font-size: 11px; padding: 3px 12px;
}}
"""
