// ─── Console Modal ────────────────────────────────────────────────────────────
let _consoleTerm   = null;
let _consoleFit    = null;
let _consoleWs     = null;
let _consoleId     = '';
let _consoleName   = '';
let _consoleShell  = 'bash';

function openConsoleModal(id, name) {
  _consoleId   = id;
  _consoleName = name;
  _consoleShell = 'bash';
  el('console-modal').classList.add('open');
  el('console-title').textContent = `Console — ${name}`;
  _updateShellBtns();
  _startConsole();
}

function switchShell(shell) {
  if (_consoleShell === shell) return;
  _consoleShell = shell;
  _updateShellBtns();
  _startConsole(); // reconnect with new shell
}

function _updateShellBtns() {
  const active   = 'background:var(--accent);color:white;border-color:var(--accent);';
  const inactive = 'background:none;color:var(--text3);border-color:var(--border2);';
  el('console-bash-btn').style.cssText += _consoleShell === 'bash' ? active : inactive;
  el('console-sh-btn'  ).style.cssText += _consoleShell === 'sh'   ? active : inactive;
}

function _startConsole() {
  // Tear down any existing session
  if (_consoleWs)   { try { _consoleWs.close(); } catch {} _consoleWs = null; }
  if (_consoleTerm) { _consoleTerm.dispose(); _consoleTerm = null; }

  const termDiv = el('console-terminal');
  termDiv.innerHTML = '';

  // Init xterm
  _consoleTerm = new Terminal({
    theme: { background: '#0d1117', foreground: '#e2e8ff', cursor: '#4f8ef7',
             black: '#0d1117', brightBlack: '#545b7a',
             blue: '#4f8ef7',  brightBlue: '#8b5cf6',
             cyan: '#4f8ef7',  green: '#22c55e',
             red:  '#ef4444',  yellow: '#eab308',
             white: '#e2e8ff', magenta: '#ec4899' },
    fontFamily: "'JetBrains Mono', monospace",
    fontSize: 13, lineHeight: 1.4,
    cursorBlink: true, scrollback: 2000,
  });

  _consoleTerm.open(termDiv);

  // Fit addon
  if (window.FitAddon) {
    _consoleFit = new FitAddon.FitAddon();
    _consoleTerm.loadAddon(_consoleFit);
    setTimeout(() => { try { _consoleFit.fit(); } catch {} }, 50);
  }

  _consoleTerm.write(`Connecting to \x1b[1;35m${_consoleName}\x1b[0m via \x1b[1;33m${_consoleShell}\x1b[0m…\r\n`);

  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${proto}//${location.host}/ws/console/${_consoleId}/${_consoleShell}`;
  _consoleWs  = new WebSocket(wsUrl);
  _consoleWs.binaryType = 'arraybuffer';

  _consoleWs.onopen = () => {
    _consoleTerm.write('\x1b[32mConnected.\x1b[0m\r\n');
    // Send initial terminal size
    if (_consoleFit) {
      try {
        const dims = _consoleFit.proposeDimensions();
        if (dims && _consoleWs.readyState === 1) {
          _consoleWs.send(JSON.stringify({ type: 'resize', cols: dims.cols, rows: dims.rows }));
        }
      } catch {}
    }
    _consoleTerm.onData(data => {
      if (_consoleWs && _consoleWs.readyState === 1) _consoleWs.send(data);
    });
  };

  _consoleWs.onmessage = e => {
    const data = e.data instanceof ArrayBuffer
      ? new TextDecoder().decode(e.data) : e.data;
    _consoleTerm.write(data);
  };

  _consoleWs.onerror = ()  => _consoleTerm.write('\r\n\x1b[31m[WebSocket error]\x1b[0m\r\n');
  _consoleWs.onclose = ()  => _consoleTerm.write('\r\n\x1b[33m[Disconnected]\x1b[0m\r\n');
}

function closeConsoleModal() {
  el('console-modal').classList.remove('open');
  if (_consoleWs)   { try { _consoleWs.close(); } catch {} _consoleWs = null; }
  if (_consoleTerm) { _consoleTerm.dispose(); _consoleTerm = null; }
}

// Resize terminal when window resizes
window.addEventListener('resize', () => {
  if (_consoleFit && el('console-modal').classList.contains('open')) {
    try { _consoleFit.fit(); } catch {}
  }
});

el('console-modal').addEventListener('click', e => { if (e.target === el('console-modal')) closeConsoleModal(); });

