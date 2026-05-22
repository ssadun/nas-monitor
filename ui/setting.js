// ═══════════════════════════════════════════════════════════════════════════
// setting.js — Settings form logic for NAS Monitor
// ═══════════════════════════════════════════════════════════════════════════

function getElement(id) {
  return document.getElementById(id);
}

function showSettingsMessage(message, isError = false) {
  const el = getElement('settings-message');
  if (!el) return;
  el.textContent = message;
  el.style.display = 'block';
  el.style.background = isError ? 'rgba(239,68,68,.12)' : 'rgba(34,197,94,.12)';
  el.style.border = isError ? '1px solid rgba(239,68,68,.3)' : '1px solid rgba(34,197,94,.3)';
  el.style.color = isError ? 'var(--red)' : 'var(--green)';
}

function hideSettingsMessage() {
  const el = getElement('settings-message');
  if (!el) return;
  el.style.display = 'none';
}

function setSettingsInputValue(id, value) {
  const input = getElement(id);
  if (!input) return;
  if (input.type === 'checkbox') {
    input.checked = Boolean(value);
    return;
  }
  input.value = value == null ? '' : String(value);
}

async function loadSettingsForm() {
  hideSettingsMessage();
  try {
    const res = await fetch('/api/settings', { cache: 'no-cache' });
    const data = await res.json();
    if (!res.ok || !data.ok) {
      throw new Error(data.error || 'Unable to load settings.');
    }

    const settings = data.settings || {};
    setSettingsInputValue('settings-logLevel', settings.logLevel || 'INFO');
    setSettingsInputValue('settings-authenticationType', String(Boolean(settings.authenticationType)));
    setSettingsInputValue('settings-sessionTimeoutHours', settings.sessionTimeoutHours ?? 4);
    setSettingsInputValue('settings-warnThresholdSeconds', settings.warnThresholdSeconds ?? 3);
    setSettingsInputValue('settings-pruneIntervalHours', settings.pruneIntervalHours ?? 24);
    setSettingsInputValue('settings-composeInactivityTimeoutSeconds', settings.composeInactivityTimeoutSeconds ?? 120);
    setSettingsInputValue('settings-dockerConfigFolder', settings.dockerConfigFolder || '');
    setSettingsInputValue('settings-dockerDataFolder', settings.dockerDataFolder || '');
    setSettingsInputValue('settings-refreshIntervalSeconds', settings.refreshIntervalSeconds ?? 3);
  } catch (error) {
    showSettingsMessage(error.message || 'Failed to load settings.', true);
  }
}

function parseNumberField(id, defaultValue) {
  const input = getElement(id);
  if (!input) return defaultValue;
  const value = Number(input.value);
  return Number.isFinite(value) ? value : defaultValue;
}

async function submitSettingsForm() {
  hideSettingsMessage();
  const payload = {
    logLevel: getElement('settings-logLevel')?.value || 'INFO',
    authenticationType: getElement('settings-authenticationType')?.value === 'true',
    sessionTimeoutHours: parseNumberField('settings-sessionTimeoutHours', 4),
    warnThresholdSeconds: parseNumberField('settings-warnThresholdSeconds', 3),
    pruneIntervalHours: parseNumberField('settings-pruneIntervalHours', 24),
    composeInactivityTimeoutSeconds: parseNumberField('settings-composeInactivityTimeoutSeconds', 120),
    dockerConfigFolder: getElement('settings-dockerConfigFolder')?.value || '',
    dockerDataFolder: getElement('settings-dockerDataFolder')?.value || '',
    refreshIntervalSeconds: parseNumberField('settings-refreshIntervalSeconds', 3),
  };

  try {
    const res = await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok || !data.ok) {
      throw new Error(data.error || 'Unable to save settings.');
    }
    showSettingsMessage('Settings saved successfully.');
    if (typeof startStream === 'function') startStream();
    if (data.settings) {
      setSettingsInputValue('settings-logLevel', data.settings.logLevel || 'INFO');
      setSettingsInputValue('settings-authenticationType', String(Boolean(data.settings.authenticationType)));
      setSettingsInputValue('settings-sessionTimeoutHours', data.settings.sessionTimeoutHours ?? 4);
      setSettingsInputValue('settings-warnThresholdSeconds', data.settings.warnThresholdSeconds ?? 3);
      setSettingsInputValue('settings-pruneIntervalHours', data.settings.pruneIntervalHours ?? 24);
      setSettingsInputValue('settings-composeInactivityTimeoutSeconds', data.settings.composeInactivityTimeoutSeconds ?? 120);
      setSettingsInputValue('settings-dockerConfigFolder', data.settings.dockerConfigFolder || '');
      setSettingsInputValue('settings-dockerDataFolder', data.settings.dockerDataFolder || '');
      setSettingsInputValue('settings-refreshIntervalSeconds', data.settings.refreshIntervalSeconds ?? 3);
    }
  } catch (error) {
    showSettingsMessage(error.message || 'Failed to save settings.', true);
  }
}

window.loadSettingsForm = loadSettingsForm;
window.submitSettingsForm = submitSettingsForm;

window.addEventListener('DOMContentLoaded', () => {
  if (window.currentTab === 'settings') {
    loadSettingsForm();
  }
});
