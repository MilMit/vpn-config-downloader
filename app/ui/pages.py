"""Modular PySide6 page builders for the modern 10-page VPN Config Downloader workspace."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)


def _scroll_wrap(inner: QWidget) -> QScrollArea:
    sc = QScrollArea()
    sc.setWidgetResizable(True)
    sc.setFrameShape(QFrame.Shape.NoFrame)
    sc.setWidget(inner)
    return sc


def _pill(text: str, style: str = 'BadgeNeutral') -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName(style)
    return lbl


def _configure_table(table: QTableWidget, *, min_h: int = 150, max_h: int | None = None):
    table.setAlternatingRowColors(True)
    table.verticalHeader().hide()
    table.verticalHeader().setDefaultSectionSize(34)
    table.setShowGrid(False)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setMinimumHeight(min_h)
    if max_h is not None:
        table.setMaximumHeight(max_h)


def make_dashboard(w) -> QWidget:
    page, lay = w.page()

    # Hero Welcome + 3-Step Workflow Banner
    hero = QFrame()
    hero.setObjectName('HeroCard')
    hl = QVBoxLayout(hero)
    hl.setContentsMargins(22, 18, 22, 18)
    hl.setSpacing(14)

    top_row = QHBoxLayout()
    htext = QVBoxLayout()
    htext.setSpacing(4)
    htext.addWidget(w.text('Secure Multi-Provider VPN Configuration Hub', style='Heading'))
    htext.addWidget(
        w.text(
            'Extract official OpenVPN & WireGuard profiles, validate them in 3 independent stages, and package into verified AES-256 archives.',
            style='Muted',
        )
    )
    top_row.addLayout(htext, 1)
    quick_btn = QPushButton('Choose Provider →')
    quick_btn.setObjectName('Primary')
    quick_btn.clicked.connect(lambda: w.nav_to(1))
    top_row.addWidget(quick_btn, alignment=Qt.AlignmentFlag.AlignTop)
    hl.addLayout(top_row)

    steps = QHBoxLayout()
    steps.setSpacing(10)
    for num, title, desc, target_idx in [
        ('STEP 1', 'Provider & Account', 'Pick Windscribe, Surfshark or Proton & verify portal session', 2),
        ('STEP 2', 'Servers & Protocols', 'Discover live catalogs, filter countries & choose protocols', 3),
        ('STEP 3', 'Validate & AES-256', 'Run 3-stage checks & verify real AES-256 ZIP decryption', 6),
    ]:
        sc = QFrame()
        sc.setObjectName('StepCard')
        sl = QVBoxLayout(sc)
        sl.setContentsMargins(14, 11, 14, 11)
        sl.setSpacing(4)
        s_top = QHBoxLayout()
        s_top.addWidget(_pill(num, 'BadgeInfo'))
        s_top.addStretch(1)
        go = QPushButton('Open →')
        go.setObjectName('Ghost')
        go.clicked.connect(lambda _=False, i=target_idx: w.nav_to(i))
        s_top.addWidget(go)
        sl.addLayout(s_top)
        sl.addWidget(w.text(title, style='CardTitle'))
        sl.addWidget(w.text(desc, style='Muted'))
        steps.addWidget(sc, 1)
    hl.addLayout(steps)
    lay.addWidget(hero)

    # Color-accented KPI Stat Cards
    metrics = QHBoxLayout()
    metrics.setSpacing(12)
    w.metric_labels = []
    for title, info, card_style in [
        ('SERVERS DISCOVERED', 'Active provider catalog', 'KpiBlue'),
        ('SUCCEEDED', 'Downloaded / reused / imported', 'KpiGreen'),
        ('FAILED', 'Errors requiring retry', 'KpiRed'),
        ('SKIPPED / DEDUPED', 'Duplicates or filtered items', 'KpiAmber'),
    ]:
        c, lab = w.card(title, info, card_style=card_style)
        metrics.addWidget(c, 1)
        w.metric_labels.append(lab)
    lay.addLayout(metrics)

    # Accounts overview table
    acc_grp = QGroupBox('ACCOUNTS && SESSION HEALTH')
    acc_lay = QVBoxLayout(acc_grp)
    w.dashboard_accounts_table = QTableWidget(0, 5)
    w.dashboard_accounts_table.setHorizontalHeaderLabels(
        ['Provider', 'Account', 'Local Profile', 'Last Portal Check', 'Keyring Secrets']
    )
    _configure_table(w.dashboard_accounts_table, min_h=150, max_h=230)
    w.dashboard_accounts_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
    w.dashboard_accounts_table.setColumnWidth(0, 125)
    w.dashboard_accounts_table.setColumnWidth(1, 110)
    w.dashboard_accounts_table.setColumnWidth(2, 165)
    w.dashboard_accounts_table.setColumnWidth(4, 155)
    acc_lay.addWidget(w.dashboard_accounts_table)

    acc_actions = QHBoxLayout()
    b_acc = QPushButton('Manage Accounts')
    b_acc.clicked.connect(lambda: w.nav_to(2))
    acc_actions.addWidget(b_acc)
    b_val = QPushButton('Open 3-Stage Validator')
    b_val.clicked.connect(lambda: w.nav_to(6))
    acc_actions.addWidget(b_val)
    b_exp = QPushButton('Configure AES-256 Export')
    b_exp.clicked.connect(lambda: w.nav_to(7))
    acc_actions.addWidget(b_exp)
    acc_actions.addStretch(1)
    acc_lay.addLayout(acc_actions)
    lay.addWidget(acc_grp)

    # Security Notice Card
    warning = QFrame()
    warning.setObjectName('Card')
    wl = QVBoxLayout(warning)
    wl.setContentsMargins(18, 14, 18, 14)
    wl.setSpacing(6)
    wl.addWidget(w.text('Security & Accuracy Guarantees', style='CardTitle'))
    wl.addWidget(
        w.text(
            '• Encrypted archives use WinZip AES-256 (pyzipper) verified by full decryption — never silent plaintext fallback.\n'
            '• Local Chromium profile presence never claims an authenticated session; use Check session via official portal.\n'
            '• DNS/TCP reachability is strictly separated from VPN tunnel verification (which stays Not Tested without explicit consent).',
            style='Muted',
        )
    )
    lay.addWidget(warning)
    lay.addStretch(1)
    return _scroll_wrap(page)


def make_providers(w) -> QWidget:
    page, lay = w.page()

    # Interactive Clickable Provider Cards
    cards_row = QHBoxLayout()
    cards_row.setSpacing(12)
    w.provider_cards = {}
    card_meta = {
        'windscribe': ('202 Public Locations', 'OpenVPN + WireGuard Generator', 'BadgeInfo'),
        'surfshark': ('178 Live Clusters', 'OpenVPN + WireGuard + IKEv2', 'BadgeOk'),
        'proton': ('Official Portal', 'Browser-Assisted Extraction', 'BadgeWarn'),
    }
    for prov in w.providers.values():
        tag_text, sub_text, tag_style = card_meta.get(prov.key, ('Plugin', prov.label, 'BadgeNeutral'))
        card = QFrame()
        card.setObjectName('ProviderCard')
        card.setCursor(Qt.CursorShape.PointingHandCursor)
        cl = QVBoxLayout(card)
        cl.setContentsMargins(16, 14, 16, 14)
        cl.setSpacing(8)
        head = QHBoxLayout()
        head.addWidget(w.text(prov.label, style='CardTitle'))
        head.addStretch(1)
        head.addWidget(_pill(tag_text, tag_style))
        cl.addLayout(head)
        cl.addWidget(w.text(sub_text, style='Muted'))
        btn = QPushButton(f'Select {prov.label}')
        btn.setObjectName('Ghost')
        btn.clicked.connect(lambda _=False, k=prov.key: w.select_provider_by_key(k))
        cl.addWidget(btn, alignment=Qt.AlignmentFlag.AlignLeft)
        card.mousePressEvent = lambda _ev, k=prov.key: w.select_provider_by_key(k)
        cards_row.addWidget(card, 1)
        w.provider_cards[prov.key] = (card, btn)
    lay.addLayout(cards_row)

    # Provider combo + portal link (synced with provider cards)
    grp = QGroupBox('ACTIVE PROVIDER && PORTAL')
    v = QVBoxLayout(grp)
    row = QHBoxLayout()
    w.provider_choice = QComboBox()
    for prov in w.providers.values():
        w.provider_choice.addItem(prov.label, prov.key)
    w.provider_choice.currentIndexChanged.connect(w.apply_provider_mode)
    row.addWidget(w.provider_choice, 1)
    open_btn = QPushButton('↗ Open Official Portal')
    open_btn.clicked.connect(w.open_provider_page)
    row.addWidget(open_btn)
    v.addLayout(row)
    w.provider_description = w.text('', style='Muted')
    v.addWidget(w.provider_description)
    w.capability_text = w.text('', style='Muted')
    v.addWidget(w.capability_text)
    lay.addWidget(grp)

    # Full 6-protocol capability matrix with colored badge pills
    mat_grp = QGroupBox('PROTOCOL CAPABILITY MATRIX && SERVICE LIMITATIONS')
    mv = QVBoxLayout(mat_grp)
    w.provider_matrix_table = QTableWidget(0, 3)
    w.provider_matrix_table.setHorizontalHeaderLabels(['Protocol', 'Support Status', 'Details & Limitations'])
    _configure_table(w.provider_matrix_table, min_h=235)
    w.provider_matrix_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
    w.provider_matrix_table.setColumnWidth(0, 140)
    w.provider_matrix_table.setColumnWidth(1, 200)
    mv.addWidget(w.provider_matrix_table)
    lay.addWidget(mat_grp)

    grp2 = QGroupBox('ACQUISITION MODE (SURFSHARK / PROTON VPN)')
    v2 = QVBoxLayout(grp2)
    w.acquire_mode = QComboBox()
    w.acquire_mode.addItem('Automatic · official downloads', 'auto')
    w.acquire_mode.addItem('Import existing profiles · file / folder / ZIP', 'import')
    w.acquire_mode.currentIndexChanged.connect(w.apply_provider_mode)
    v2.addWidget(w.acquire_mode)
    w.acquire_help = w.text(
        'AUTO: Surfshark OpenVPN uses official bulk ZIP; account-only downloads reuse your local Chromium profile.'
    )
    v2.addWidget(w.acquire_help)
    w.source_input = QLineEdit()
    w.source_input.setPlaceholderText('Leave empty in AUTO mode · in Import mode choose a folder, ZIP, or .ovpn/.conf')
    v2.addWidget(w.source_input)
    choose_row = QHBoxLayout()
    b = QPushButton('Choose folder')
    b.clicked.connect(w.choose_source_folder)
    choose_row.addWidget(b)
    b = QPushButton('Choose ZIP / file')
    b.clicked.connect(w.choose_source_file)
    choose_row.addWidget(b)
    choose_row.addStretch(1)
    v2.addLayout(choose_row)
    lay.addWidget(grp2)
    lay.addStretch(1)
    return _scroll_wrap(page)


def make_accounts(w) -> QWidget:
    page, lay = w.page()

    # Always-visible table of ALL saved accounts across all providers (click any row to switch!)
    all_grp = QGroupBox('ALL SAVED ACCOUNTS (CLICK A ROW TO SWITCH)')
    all_lay = QVBoxLayout(all_grp)
    w.accounts_overview_table = QTableWidget(0, 5)
    w.accounts_overview_table.setHorizontalHeaderLabels(
        ['Provider', 'Account', 'Saved Session', 'Portal Status', 'Keyring Secrets']
    )
    _configure_table(w.accounts_overview_table, min_h=130, max_h=200)
    w.accounts_overview_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
    w.accounts_overview_table.setColumnWidth(0, 120)
    w.accounts_overview_table.setColumnWidth(1, 110)
    w.accounts_overview_table.setColumnWidth(2, 175)
    w.accounts_overview_table.setColumnWidth(4, 155)
    w.accounts_overview_table.cellClicked.connect(w.select_account_from_table)
    all_lay.addWidget(w.accounts_overview_table)
    lay.addWidget(all_grp)

    grp = QGroupBox('PERSISTENT BROWSER SESSION && PORTAL CHECK')
    v = QVBoxLayout(grp)
    top_sel = QHBoxLayout()
    w.account_provider = QComboBox()
    for prov in w.providers.values():
        w.account_provider.addItem(prov.label, prov.key)
    w.account_provider.currentIndexChanged.connect(w.refresh_aliases)
    top_sel.addWidget(w.account_provider, 1)

    w.account_alias = QComboBox()
    w.account_alias.currentIndexChanged.connect(w.refresh_account_state)
    w.account_alias.currentIndexChanged.connect(w.save_account_selection)
    top_sel.addWidget(w.account_alias, 1)

    a = QPushButton('+ Add account')
    a.clicked.connect(w.add_account)
    top_sel.addWidget(a)
    a = QPushButton('Remove')
    a.clicked.connect(w.remove_account)
    top_sel.addWidget(a)
    v.addLayout(top_sel)

    status_row = QHBoxLayout()
    w.account_profile_badge = _pill('No Profile', 'BadgeNeutral')
    status_row.addWidget(w.account_profile_badge)
    w.account_state = w.text('', style='Muted')
    status_row.addWidget(w.account_state, 1)
    v.addLayout(status_row)

    row = QHBoxLayout()
    w.login_button = QPushButton('🔐 Login / Re-login in Browser')
    w.login_button.setObjectName('Primary')
    w.login_button.clicked.connect(w.start_login)
    row.addWidget(w.login_button)
    w.logout_button = QPushButton('Forget local session')
    w.logout_button.setObjectName('Danger')
    w.logout_button.clicked.connect(w.delete_session)
    row.addWidget(w.logout_button)
    w.cancel_login_btn = QPushButton('Cancel login')
    w.cancel_login_btn.setEnabled(False)
    w.cancel_login_btn.clicked.connect(w.cancel_login)
    row.addWidget(w.cancel_login_btn)
    b = QPushButton('↗ Official Portal')
    b.clicked.connect(w.open_account_portal)
    row.addWidget(b)
    w.ws_guide_btn_acc = QPushButton('📖 راهنمای تصویری Windscribe (کوکی)')
    w.ws_guide_btn_acc.setToolTip('آموزش تصویری مرحله‌به‌مرحله ورود Windscribe از مرورگر معمولی بدون مشکل CAPTCHA')
    w.ws_guide_btn_acc.clicked.connect(w.open_windscribe_cookie_guide)
    row.addWidget(w.ws_guide_btn_acc)
    v.addLayout(row)

    checkrow = QHBoxLayout()
    b = QPushButton('Check Session via Official Portal')
    b.clicked.connect(w.start_session_check)
    checkrow.addWidget(b)
    w.session_badge = _pill('Not Checked', 'BadgeNeutral')
    checkrow.addWidget(w.session_badge)
    w.session_result = w.text('Not checked online yet.', style='Muted')
    checkrow.addWidget(w.session_result, 1)
    v.addLayout(checkrow)

    w.account_event = w.text(
        'Close the Chromium window after login/2FA. Website passwords and 2FA tokens are never captured or logged.',
        style='Muted',
    )
    v.addWidget(w.account_event)
    lay.addWidget(grp)

    # OpenVPN Keyring Card
    vaultbox = QGroupBox('OPENVPN MANUAL SERVICE CREDENTIALS (OS KEYRING ONLY)')
    a_lay = QGridLayout(vaultbox)
    w.vault_username = QLineEdit()
    w.vault_username.setPlaceholderText('Manual OpenVPN service username from provider dashboard')
    w.vault_password = QLineEdit()
    w.vault_password.setEchoMode(QLineEdit.EchoMode.Password)
    w.vault_password.setPlaceholderText('Manual OpenVPN service password (stored only in OS keyring)')
    a_lay.addWidget(w.text('Service username'), 0, 0)
    a_lay.addWidget(w.vault_username, 0, 1)
    b_copy_u = QPushButton('Copy Username')
    b_copy_u.setToolTip('Copy OpenVPN service username (from field or saved OS Keyring) for Ubuntu/OpenVPN import')
    b_copy_u.clicked.connect(w.copy_openvpn_username)
    a_lay.addWidget(b_copy_u, 0, 2)

    a_lay.addWidget(w.text('Service password'), 1, 0)
    a_lay.addWidget(w.vault_password, 1, 1)
    pw_btns = QHBoxLayout()
    pw_btns.setSpacing(6)
    w.vault_pw_toggle = QPushButton('Show')
    w.vault_pw_toggle.setCheckable(True)
    w.vault_pw_toggle.toggled.connect(w.toggle_vault_password_visibility)
    pw_btns.addWidget(w.vault_pw_toggle)
    b_copy_p = QPushButton('Copy Password')
    b_copy_p.setToolTip('Copy OpenVPN service password (from field or saved OS Keyring) to clipboard')
    b_copy_p.clicked.connect(w.copy_openvpn_password)
    pw_btns.addWidget(b_copy_p)
    a_lay.addLayout(pw_btns, 1, 2)

    row2 = QHBoxLayout()
    b = QPushButton('Save in OS Keyring')
    b.setObjectName('Primary')
    b.clicked.connect(w.save_openvpn_secret)
    row2.addWidget(b)
    b = QPushButton('Delete saved')
    b.clicked.connect(w.delete_openvpn_secret)
    row2.addWidget(b)
    discover = QPushButton('Read visible fields (Beta)')
    discover.clicked.connect(w.discover_service_credentials)
    row2.addWidget(discover)
    w.vault_state = w.text('', style='Muted')
    row2.addWidget(w.vault_state, 1)
    a_lay.addLayout(row2, 2, 0, 1, 3)
    lay.addWidget(vaultbox)

    # WireGuard Keypair Card
    wgbox = QGroupBox('WIREGUARD X25519 KEYPAIR (OS KEYRING ONLY)')
    wg_lay = QGridLayout(wgbox)
    w.wgsecret = QLineEdit()
    w.wgsecret.setEchoMode(QLineEdit.EchoMode.Password)
    w.wgsecret.setPlaceholderText('Paste Base64 32-byte WireGuard private key, or click Import from .conf')
    wg_lay.addWidget(w.wgsecret, 0, 0, 1, 5)
    b = QPushButton('Save existing key')
    b.clicked.connect(w.save_wg_secret)
    wg_lay.addWidget(b, 1, 0)
    b = QPushButton('Import from .conf')
    b.setToolTip('Extract PrivateKey from an existing WireGuard .conf downloaded from Surfshark/Proton/Windscribe')
    b.clicked.connect(w.import_wg_from_conf)
    wg_lay.addWidget(b, 1, 1)
    b = QPushButton('Generate X25519 Keypair')
    b.setObjectName('Primary')
    b.clicked.connect(w.generate_wg_secret)
    wg_lay.addWidget(b, 1, 2)
    b = QPushButton('Register on Portal ↗')
    b.clicked.connect(w.open_wg_registration_portal)
    wg_lay.addWidget(b, 1, 3)
    b = QPushButton('Delete key')
    b.setObjectName('Danger')
    b.clicked.connect(w.delete_wg_secret)
    wg_lay.addWidget(b, 1, 4)
    w.wg_public_text = w.text('Public key: none stored', style='Muted')
    wg_lay.addWidget(w.wg_public_text, 2, 0, 1, 4)
    b = QPushButton('Copy Public Key')
    b.clicked.connect(w.copy_wg_public)
    wg_lay.addWidget(b, 2, 4)
    lay.addWidget(wgbox)

    lay.addStretch(1)
    w.refresh_aliases()
    return _scroll_wrap(page)


def make_servers(w) -> QWidget:
    page, lay = w.page()

    toolbar = QFrame()
    toolbar.setObjectName('Card')
    tl = QVBoxLayout(toolbar)
    tl.setContentsMargins(14, 12, 14, 12)
    tl.setSpacing(10)

    row = QHBoxLayout()
    w.country_filter = QComboBox()
    w.country_filter.addItem('All countries', '')
    w.country_filter.currentIndexChanged.connect(w.filter_servers)
    w.country_filter.setMinimumWidth(160)
    row.addWidget(w.country_filter)
    w.search_servers = QLineEdit()
    w.search_servers.setPlaceholderText('Search country, city, hostname, or tier...')
    w.search_servers.textChanged.connect(w.filter_servers)
    row.addWidget(w.search_servers, 1)
    b = QPushButton('↻ Refresh Locations')
    b.setObjectName('Primary')
    b.clicked.connect(w.refresh_locations)
    row.addWidget(b)
    tl.addLayout(row)

    row2 = QHBoxLayout()
    b = QPushButton('Select visible')
    b.clicked.connect(lambda: w.set_visible_checked(True))
    row2.addWidget(b)
    b = QPushButton('Clear visible')
    b.clicked.connect(lambda: w.set_visible_checked(False))
    row2.addWidget(b)
    w.server_count_pill = _pill('0 / 0 selected', 'BadgeNeutral')
    row2.addWidget(w.server_count_pill)
    w.server_note = w.text('Click Refresh Locations to load live public server catalog.', style='Muted')
    row2.addWidget(w.server_note, 1)
    tl.addLayout(row2)
    lay.addWidget(toolbar)

    w.server_table = QTableWidget(0, 4)
    w.server_table.setHorizontalHeaderLabels(['SELECT', 'COUNTRY', 'CITY / SERVER', 'TIER / LOAD'])
    _configure_table(w.server_table, min_h=300)
    w.server_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
    w.server_table.setColumnWidth(0, 82)
    w.server_table.setColumnWidth(1, 110)
    w.server_table.setColumnWidth(3, 125)
    w.server_table.itemChanged.connect(w.update_server_selection_count)
    lay.addWidget(w.server_table, 1)
    return page


def make_protocols(w) -> QWidget:
    page, lay = w.page()

    group = QGroupBox('ENABLED PROTOCOLS')
    g = QGridLayout(group)
    g.setSpacing(10)
    w.proto_boxes = {}
    display = [
        ('wireguard', 'WireGuard (.conf)'),
        ('udp', 'OpenVPN UDP (.ovpn)'),
        ('tcp', 'OpenVPN TCP (.ovpn)'),
        ('ikev2', 'IKEv2 / IPsec (StrongSwan .swanctl.conf)'),
        ('stealth', 'Stealth (Experimental · proxy kit)'),
        ('wstunnel', 'WStunnel (Experimental · proxy kit)'),
    ]
    for i, (key, caption) in enumerate(display):
        b = QCheckBox(caption)
        b.setChecked(key in ('wireguard', 'udp', 'tcp'))
        g.addWidget(b, i // 2, i % 2)
        w.proto_boxes[key] = b
    lay.addWidget(group)

    ports = QGroupBox('REQUESTED PORTS (WINDSCRIBE MANUAL GENERATOR)')
    pg = QGridLayout(ports)
    w.port_inputs = {}
    for i, (key, label, default) in enumerate([
        ('wireguard', 'WireGuard', '65142'),
        ('udp', 'OpenVPN UDP', '443'),
        ('tcp', 'OpenVPN TCP', '54783'),
    ]):
        pg.addWidget(w.text(label, style='Muted'), i, 0)
        edit = QLineEdit(default)
        pg.addWidget(edit, i, 1)
        w.port_inputs[key] = edit
    lay.addWidget(ports)

    auth = QGroupBox('WINDSCRIBE MEMORY-ONLY OVERRIDES (NEVER SAVED TO DISK)')
    al = QGridLayout(auth)
    w.cookie = QLineEdit()
    w.cookie.setEchoMode(QLineEdit.EchoMode.Password)
    w.cookie.setPlaceholderText('Optional: leave empty to reuse saved Accounts browser session')
    al.addWidget(w.text('Website session cookie'), 0, 0)
    al.addWidget(w.cookie, 0, 1)
    ws_guide_proto = QPushButton('📖 راهنمای تصویری (F12)')
    ws_guide_proto.setToolTip('آموزش تصویری کپی کردن ws_session_auth_hash از Chrome / Firefox')
    ws_guide_proto.clicked.connect(w.open_windscribe_cookie_guide)
    al.addWidget(ws_guide_proto, 0, 2)
    w.wgpub = QLineEdit()
    w.wgpub.setPlaceholderText('Optional: auto-derived if private key is stored in Accounts')
    al.addWidget(w.text('WireGuard public key'), 1, 0)
    al.addWidget(w.wgpub, 1, 1)
    w.wgpriv = QLineEdit()
    w.wgpriv.setPlaceholderText('Optional existing private-key file (portable profiles)')
    al.addWidget(w.text('WireGuard private key file'), 2, 0)
    al.addWidget(w.wgpriv, 2, 1)
    b = QPushButton('Browse')
    b.clicked.connect(lambda: w.choose_path(w.wgpriv))
    al.addWidget(b, 2, 2)
    w.ikefile = QLineEdit()
    w.ikefile.setPlaceholderText('Optional JSON: username + password')
    al.addWidget(w.text('IKEv2 credentials JSON'), 3, 0)
    al.addWidget(w.ikefile, 3, 1)
    b = QPushButton('Browse')
    b.clicked.connect(lambda: w.choose_path(w.ikefile))
    al.addWidget(b, 3, 2)
    w.ikehash = QLineEdit()
    w.ikehash.setEchoMode(QLineEdit.EchoMode.Password)
    al.addWidget(w.text('IKEv2 API auth hash (optional)'), 4, 0)
    al.addWidget(w.ikehash, 4, 1)
    w.ikehosts = QLineEdit()
    w.ikehosts.setPlaceholderText('CSV: location_id,hostname from official generator')
    al.addWidget(w.text('Verified hostname CSV'), 5, 0)
    al.addWidget(w.ikehosts, 5, 1)
    b = QPushButton('Browse')
    b.clicked.connect(lambda: w.choose_path(w.ikehosts))
    al.addWidget(b, 5, 2)
    w.transport = QLineEdit()
    w.transport.setPlaceholderText('CSV: location_id,mode,host,port,backend_port')
    al.addWidget(w.text('Stealth/WStunnel endpoints'), 6, 0)
    al.addWidget(w.transport, 6, 1)
    b = QPushButton('Browse')
    b.clicked.connect(lambda: w.choose_path(w.transport))
    al.addWidget(b, 6, 2)
    lay.addWidget(auth)
    lay.addStretch(1)
    return _scroll_wrap(page)


def make_downloads(w) -> QWidget:
    page, lay = w.page()

    ctrl = QFrame()
    ctrl.setObjectName('Card')
    cl = QVBoxLayout(ctrl)
    cl.setContentsMargins(16, 14, 16, 14)
    cl.setSpacing(10)

    bar = QHBoxLayout()
    w.run_btn = QPushButton('▶ Start Export')
    w.run_btn.setObjectName('Primary')
    w.run_btn.clicked.connect(w.start_job)
    bar.addWidget(w.run_btn)
    w.pause_btn = QPushButton('Ⅱ Pause')
    w.pause_btn.setEnabled(False)
    w.pause_btn.clicked.connect(w.pause_job)
    bar.addWidget(w.pause_btn)
    w.stop_btn = QPushButton('■ Stop')
    w.stop_btn.setObjectName('Danger')
    w.stop_btn.setEnabled(False)
    w.stop_btn.clicked.connect(w.stop_job)
    bar.addWidget(w.stop_btn)
    retry = QPushButton('↻ Retry Failed Only')
    retry.clicked.connect(w.retry_failed)
    bar.addWidget(retry)
    bar.addStretch(1)
    bar.addWidget(w.text('Workers:', style='Muted'))
    w.quick_concurrency = QSpinBox()
    w.quick_concurrency.setRange(1, 8)
    w.quick_concurrency.setValue(6)
    w.quick_concurrency.setToolTip('Concurrent download workers (1–8)')
    bar.addWidget(w.quick_concurrency)
    bar.addWidget(w.text('Delay(s):', style='Muted'))
    w.quick_delay = QDoubleSpinBox()
    w.quick_delay.setRange(0.1, 120.0)
    w.quick_delay.setDecimals(2)
    w.quick_delay.setSingleStep(0.1)
    w.quick_delay.setValue(0.25)
    w.quick_delay.setToolTip('Minimum spacing between API requests in seconds (HTTP 429 auto-backoff is always active)')
    bar.addWidget(w.quick_delay)
    cl.addLayout(bar)

    w.progress = QProgressBar()
    w.progress.setRange(0, 100)
    w.progress.setValue(0)
    cl.addWidget(w.progress)
    w.progress_text = w.text('Idle — ready to start concurrent download & verification.', style='Muted')
    cl.addWidget(w.progress_text)
    lay.addWidget(ctrl)

    res_grp = QGroupBox('VALIDATED CONFIGURATIONS')
    rl = QVBoxLayout(res_grp)
    w.profile_result_table = QTableWidget(0, 4)
    w.profile_result_table.setHorizontalHeaderLabels(['Config / Location', 'Protocol', 'Country', 'Status'])
    _configure_table(w.profile_result_table, min_h=185)
    w.profile_result_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
    w.profile_result_table.setColumnWidth(1, 110)
    w.profile_result_table.setColumnWidth(2, 95)
    w.profile_result_table.setColumnWidth(3, 145)
    rl.addWidget(w.profile_result_table)
    lay.addWidget(res_grp, 1)

    err_grp = QGroupBox('DOWNLOAD ERRORS')
    el = QVBoxLayout(err_grp)
    w.download_errors_table = QTableWidget(0, 4)
    w.download_errors_table.setHorizontalHeaderLabels(['Item', 'Protocol', 'Error Type', 'Details'])
    _configure_table(w.download_errors_table, min_h=115, max_h=175)
    w.download_errors_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
    el.addWidget(w.download_errors_table)
    lay.addWidget(err_grp)
    return page


def make_validator(w) -> QWidget:
    page, lay = w.page()

    single_grp = QGroupBox('SINGLE CONFIGURATION — 3-STAGE INDEPENDENT DIAGNOSTIC')
    sv = QVBoxLayout(single_grp)
    sv.setSpacing(12)
    hrow = QHBoxLayout()
    w.health_path = QLineEdit()
    w.health_path.setPlaceholderText('Choose a .ovpn or .conf file to inspect...')
    hrow.addWidget(w.health_path, 1)
    choose = QPushButton('Choose file')
    choose.clicked.connect(lambda: w.choose_path(w.health_path))
    hrow.addWidget(choose)
    check = QPushButton('▶ Run 3-Stage Check')
    check.setObjectName('Primary')
    check.clicked.connect(w.start_health_check)
    hrow.addWidget(check)
    sv.addLayout(hrow)

    w.vpn_verify_consent = QCheckBox(
        'Explicit consent: also attempt isolated non-routing VPN client verification (never alters default system routes)'
    )
    w.vpn_verify_consent.setChecked(False)
    sv.addWidget(w.vpn_verify_consent)

    cards = QHBoxLayout()
    cards.setSpacing(12)
    w.val_syntax_badge, w.val_syntax_detail = _status_card(w, cards, '1 · SYNTAX VALIDATION', 'KpiBlue')
    w.val_reach_badge, w.val_reach_detail = _status_card(w, cards, '2 · ENDPOINT REACHABILITY', 'KpiAmber')
    w.val_vpn_badge, w.val_vpn_detail = _status_card(w, cards, '3 · VPN CONNECTION', 'KpiGreen')
    sv.addLayout(cards)
    w.health_result = w.text('Ready. Select a config file and click Run 3-Stage Check.', style='Muted')
    sv.addWidget(w.health_result)
    lay.addWidget(single_grp)

    batch_grp = QGroupBox('BATCH FOLDER VALIDATOR')
    bv = QVBoxLayout(batch_grp)
    brow = QHBoxLayout()
    w.batch_val_path = QLineEdit()
    w.batch_val_path.setPlaceholderText('Choose an exported folder containing .ovpn / .conf files...')
    brow.addWidget(w.batch_val_path, 1)
    b_pick = QPushButton('Browse folder')
    b_pick.clicked.connect(w.choose_batch_validator_folder)
    brow.addWidget(b_pick)
    w.batch_reach_cb = QCheckBox('Test DNS/TCP')
    brow.addWidget(w.batch_reach_cb)
    w.batch_run_btn = QPushButton('Scan Folder')
    w.batch_run_btn.setObjectName('Primary')
    w.batch_run_btn.clicked.connect(w.start_batch_validation)
    brow.addWidget(w.batch_run_btn)
    w.batch_stop_btn = QPushButton('Stop')
    w.batch_stop_btn.setObjectName('Danger')
    w.batch_stop_btn.setEnabled(False)
    w.batch_stop_btn.clicked.connect(w.stop_batch_validation)
    brow.addWidget(w.batch_stop_btn)
    bv.addLayout(brow)

    w.batch_summary = w.text('No batch scan run yet.', style='Muted')
    bv.addWidget(w.batch_summary)

    w.validator_table = QTableWidget(0, 5)
    w.validator_table.setHorizontalHeaderLabels(
        ['File', 'Protocol', 'Syntax Validation', 'Endpoint Reachability', 'VPN Connection']
    )
    _configure_table(w.validator_table, min_h=215)
    w.validator_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
    w.validator_table.setColumnWidth(1, 95)
    w.validator_table.setColumnWidth(2, 165)
    w.validator_table.setColumnWidth(3, 180)
    w.validator_table.setColumnWidth(4, 155)
    bv.addWidget(w.validator_table)
    lay.addWidget(batch_grp, 1)
    return _scroll_wrap(page)


def _status_card(w, parent_layout, title: str, card_style: str) -> tuple[QLabel, QLabel]:
    box = QFrame()
    box.setObjectName(card_style)
    vl = QVBoxLayout(box)
    vl.setContentsMargins(15, 13, 15, 13)
    vl.setSpacing(8)
    vl.addWidget(w.text(title, style='KpiTitle'))
    badge = _pill('Not Tested', 'BadgeNeutral')
    vl.addWidget(badge, alignment=Qt.AlignmentFlag.AlignLeft)
    detail = w.text('Waiting for check…', style='Muted')
    vl.addWidget(detail)
    vl.addStretch(1)
    parent_layout.addWidget(box, 1)
    return badge, detail


def make_exports(w) -> QWidget:
    page, lay = w.page()

    group = QGroupBox('EXPORT DESTINATION && AES-256 ENCRYPTION POLICY')
    l = QVBoxLayout(group)
    l.setSpacing(10)
    row = QHBoxLayout()
    w.output_input = QLineEdit()
    row.addWidget(w.output_input, 1)
    b = QPushButton('Browse')
    b.clicked.connect(w.choose_output)
    row.addWidget(b)
    b2 = QPushButton('Open folder')
    b2.clicked.connect(w.open_output)
    row.addWidget(b2)
    l.addLayout(row)

    w.archive_checkbox = QCheckBox('Create ZIP archive after export')
    w.archive_checkbox.setChecked(True)
    l.addWidget(w.archive_checkbox)
    w.secure_archive = QCheckBox('Encrypt ZIP with WinZip AES-256 (strongly recommended — prevents accidental plaintext export)')
    w.secure_archive.setChecked(True)
    l.addWidget(w.secure_archive)

    pw_row = QHBoxLayout()
    w.zip_password = QLineEdit()
    w.zip_password.setEchoMode(QLineEdit.EchoMode.Password)
    w.zip_password.setPlaceholderText('AES-256 passphrase (minimum 12 characters · memory-only, never saved)')
    w.zip_password.textChanged.connect(w.update_password_strength)
    pw_row.addWidget(w.zip_password, 1)
    w.pw_strength_badge = _pill('Enter >= 12 chars', 'BadgeNeutral')
    pw_row.addWidget(w.pw_strength_badge)
    l.addLayout(pw_row)

    w.pw_strength_bar = QProgressBar()
    w.pw_strength_bar.setRange(0, 100)
    w.pw_strength_bar.setValue(0)
    w.pw_strength_bar.setTextVisible(False)
    w.pw_strength_bar.setFixedHeight(7)
    l.addWidget(w.pw_strength_bar)

    w.keep_plaintext = QCheckBox('Keep plaintext working folder after verified AES-256 ZIP is created')
    w.keep_plaintext.setChecked(False)
    l.addWidget(w.keep_plaintext)
    w.embed_auth = QCheckBox('INCLUDE plaintext OpenVPN service credentials inside export/AES-ZIP (explicit opt-in)')
    w.embed_auth.setChecked(False)
    l.addWidget(w.embed_auth)
    lay.addWidget(group)

    grp = QGroupBox('LAST EXPORTED ARCHIVE')
    l2 = QHBoxLayout(grp)
    w.last_archive = w.text('None exported in this session yet.', style='Muted')
    l2.addWidget(w.last_archive, 1)
    b = QPushButton('Open archive folder')
    b.clicked.connect(w.open_last)
    l2.addWidget(b)
    lay.addWidget(grp)

    ver_grp = QGroupBox('VERIFY AES-256 ZIP DECRYPTION')
    vl = QVBoxLayout(ver_grp)
    vrow = QHBoxLayout()
    w.verify_zip_path = QLineEdit()
    w.verify_zip_path.setPlaceholderText('Choose an existing *-AES256.zip archive to run a real decryption test...')
    vrow.addWidget(w.verify_zip_path, 1)
    b_zip = QPushButton('Choose ZIP')
    b_zip.clicked.connect(lambda: w.choose_path(w.verify_zip_path))
    vrow.addWidget(b_zip)
    b_ver = QPushButton('Verify Decryption')
    b_ver.setObjectName('Primary')
    b_ver.clicked.connect(w.verify_existing_zip)
    vrow.addWidget(b_ver)
    vl.addLayout(vrow)
    w.verify_zip_status = w.text('Reads and decrypts every archive entry using pyzipper to confirm integrity.', style='Muted')
    vl.addWidget(w.verify_zip_status)
    lay.addWidget(ver_grp)

    lay.addStretch(1)
    return _scroll_wrap(page)


def make_logs(w) -> QWidget:
    page, lay = w.page()

    bar_card = QFrame()
    bar_card.setObjectName('Card')
    bar = QHBoxLayout(bar_card)
    bar.setContentsMargins(14, 10, 14, 10)
    w.log_level_filter = QComboBox()
    for label, key in [
        ('All levels', 'all'),
        ('Success', 'success'),
        ('Info', 'info'),
        ('Skip', 'skip'),
        ('Fail / Error', 'fail'),
    ]:
        w.log_level_filter.addItem(label, key)
    w.log_level_filter.currentIndexChanged.connect(w.refresh_log_view)
    bar.addWidget(w.log_level_filter)
    w.log_search = QLineEdit()
    w.log_search.setPlaceholderText('Filter logs by keyword...')
    w.log_search.textChanged.connect(w.refresh_log_view)
    bar.addWidget(w.log_search, 1)
    b_exp = QPushButton('Export Redacted Log')
    b_exp.clicked.connect(w.export_logs_to_file)
    bar.addWidget(b_exp)
    b_clr = QPushButton('Clear')
    b_clr.setObjectName('Danger')
    b_clr.clicked.connect(w.clear_logs)
    bar.addWidget(b_clr)
    lay.addWidget(bar_card)

    w.logs = QPlainTextEdit()
    w.logs.setReadOnly(True)
    w.logs.setPlaceholderText('Secret-redacted export, scheduler, session, and validation activity will appear here.')
    w.logs.setMaximumBlockCount(5000)
    lay.addWidget(w.logs, 1)
    return page


def make_settings(w) -> QWidget:
    page, lay = w.page()

    theme_grp = QGroupBox('APPEARANCE')
    tg = QHBoxLayout(theme_grp)
    tg.addWidget(w.text('Interface color theme:', style='Muted'))
    w.theme_choice = QComboBox()
    w.theme_choice.addItem('🌙  Dark Mode (Obsidian)', 'dark')
    w.theme_choice.addItem('☀  Light Mode (Porcelain)', 'light')
    w.theme_choice.currentIndexChanged.connect(w.apply_theme)
    tg.addWidget(w.theme_choice)
    tg.addStretch(1)
    lay.addWidget(theme_grp)

    grp = QGroupBox('CONCURRENT DOWNLOAD ENGINE && NETWORK')
    g = QGridLayout(grp)
    w.concurrency = QSpinBox()
    w.concurrency.setRange(1, 8)
    w.concurrency.setValue(6)
    g.addWidget(w.text('Concurrent workers (1–8)'), 0, 0)
    g.addWidget(w.concurrency, 0, 1)

    w.delay = QDoubleSpinBox()
    w.delay.setRange(0.1, 120)
    w.delay.setDecimals(2)
    w.delay.setSingleStep(0.1)
    w.delay.setValue(0.25)
    g.addWidget(w.text('Delay between requests (seconds)'), 1, 0)
    g.addWidget(w.delay, 1, 1)

    w.timeout = QSpinBox()
    w.timeout.setRange(5, 120)
    w.timeout.setValue(25)
    g.addWidget(w.text('Request timeout (seconds)'), 2, 0)
    g.addWidget(w.timeout, 2, 1)

    w.retries = QSpinBox()
    w.retries.setRange(0, 6)
    w.retries.setValue(2)
    g.addWidget(w.text('Automatic transient / HTTP 429 retries'), 3, 0)
    g.addWidget(w.retries, 3, 1)

    w.overwrite = QCheckBox('Overwrite existing valid profiles')
    w.overwrite.setChecked(False)
    g.addWidget(w.overwrite, 4, 0, 1, 2)

    w.browser_limit = QSpinBox()
    w.browser_limit.setRange(1, 250)
    w.browser_limit.setValue(40)
    g.addWidget(w.text('Max browser download clicks per run'), 5, 0)
    g.addWidget(w.browser_limit, 5, 1)

    w.location_source = QComboBox()
    w.location_source.addItem('Live public Windscribe list', 'live')
    w.location_source.addItem('Legacy community list', 'legacy')
    g.addWidget(w.text('Windscribe location source'), 6, 0)
    g.addWidget(w.location_source, 6, 1)
    lay.addWidget(grp)

    taskbox = QGroupBox('AUTOMATIC SCHEDULER · SURFSHARK PUBLIC OPENVPN ARCHIVE ONLY')
    sch = QVBoxLayout(taskbox)
    sgrid = QGridLayout()
    w.schedule_enabled = QCheckBox('Enable automatic periodic refresh while app is open')
    sgrid.addWidget(w.schedule_enabled, 0, 0, 1, 2)
    w.schedule_minutes = QSpinBox()
    w.schedule_minutes.setRange(15, 43200)
    w.schedule_minutes.setValue(1440)
    sgrid.addWidget(w.text('Interval (minutes)'), 1, 0)
    sgrid.addWidget(w.schedule_minutes, 1, 1)
    sch.addLayout(sgrid)
    sch.addWidget(
        w.text(
            'Security policy: tasks requiring interactive login, 2FA, cookies, or ZIP passphrases are never scheduled unattended.',
            style='Muted',
        )
    )
    sbtns = QHBoxLayout()
    w.run_sched_now_btn = QPushButton('▶ Run Scheduled Refresh Now')
    w.run_sched_now_btn.setObjectName('Primary')
    w.run_sched_now_btn.clicked.connect(w.run_scheduled_now)
    sbtns.addWidget(w.run_sched_now_btn)
    b_clr_h = QPushButton('Clear history')
    b_clr_h.clicked.connect(w.clear_scheduler_history)
    sbtns.addWidget(b_clr_h)
    sbtns.addStretch(1)
    sch.addLayout(sbtns)

    w.scheduler_history_table = QTableWidget(0, 7)
    w.scheduler_history_table.setHorizontalHeaderLabels(
        ['Timestamp (UTC)', 'Provider', 'Status', 'New', 'Changed', 'Unchanged', 'Error']
    )
    _configure_table(w.scheduler_history_table, min_h=145, max_h=210)
    w.scheduler_history_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
    sch.addWidget(w.scheduler_history_table)
    lay.addWidget(taskbox)

    b = QPushButton('Save Preferences')
    b.setObjectName('Primary')
    b.clicked.connect(w.save_settings)
    lay.addWidget(b, alignment=Qt.AlignmentFlag.AlignLeft)
    lay.addStretch(1)
    return _scroll_wrap(page)
