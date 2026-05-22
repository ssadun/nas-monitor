'use strict';

const fs   = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3232;

const SETTINGS_FILE        = path.join(__dirname, '..', 'data', 'settings.json');
const LEGACY_SETTINGS_FILE = path.join(__dirname, '..', 'setting.json');

const LOG_LEVELS = { DEBUG: 10, INFO: 20, WARN: 30, ERROR: 40 };

/**
 * @typedef {Object} AppSettings
 * @property {'DEBUG'|'INFO'|'WARN'|'ERROR'} logLevel
 * @property {boolean} authenticationType
 * @property {number} sessionTimeoutHours
 * @property {number} warnThresholdSeconds
 * @property {number} pruneIntervalHours
 * @property {number} composeInactivityTimeoutSeconds
 * @property {string} dockerConfigFolder
 * @property {string} dockerDataFolder
 * @property {number} refreshIntervalSeconds
 */

/** @type {AppSettings} */
const DEFAULT_SETTINGS = {
  logLevel: 'INFO',
  authenticationType: true,
  sessionTimeoutHours: 4,
  warnThresholdSeconds: 3,
  pruneIntervalHours: 24,
  composeInactivityTimeoutSeconds: 120,
  dockerConfigFolder: '/volume1/docker/_config',
  dockerDataFolder: '/volume1/docker/_data',
  refreshIntervalSeconds: 3,
};

/** @param {object} raw @returns {AppSettings} */
function normalizeSettings(raw = {}) {
  const level = String(raw.logLevel || DEFAULT_SETTINGS.logLevel).toUpperCase();
  const safeLevel = Object.prototype.hasOwnProperty.call(LOG_LEVELS, level) ? level : DEFAULT_SETTINGS.logLevel;
  const auth = raw.authenticationType;
  const timeoutRaw = raw.sessionTimeoutHours ?? DEFAULT_SETTINGS.sessionTimeoutHours;
  const timeoutNum = Number(timeoutRaw);
  const thresholdRaw = raw.warnThresholdSeconds ?? raw.thresholdSeconds ?? DEFAULT_SETTINGS.warnThresholdSeconds;
  const thresholdNum = Number(thresholdRaw);
  const pruneHoursRaw = raw.pruneIntervalHours ?? DEFAULT_SETTINGS.pruneIntervalHours;
  const pruneHoursNum = Number(pruneHoursRaw);
  const composeInactivityRaw = raw.composeInactivityTimeoutSeconds ?? DEFAULT_SETTINGS.composeInactivityTimeoutSeconds;
  const composeInactivityNum = Number(composeInactivityRaw);
  const dockerConfigFolder = String(raw.dockerConfigFolder || DEFAULT_SETTINGS.dockerConfigFolder).trim() || DEFAULT_SETTINGS.dockerConfigFolder;
  const dockerDataFolder = String(raw.dockerDataFolder || DEFAULT_SETTINGS.dockerDataFolder).trim() || DEFAULT_SETTINGS.dockerDataFolder;
  const refreshIntervalRaw = raw.refreshIntervalSeconds ?? DEFAULT_SETTINGS.refreshIntervalSeconds;
  const refreshIntervalNum = Number(refreshIntervalRaw);
  /** @type {AppSettings} */
  const normalized = {
    logLevel: safeLevel,
    authenticationType: typeof auth === 'boolean' ? auth : DEFAULT_SETTINGS.authenticationType,
    sessionTimeoutHours: Number.isFinite(timeoutNum) && timeoutNum > 0 ? timeoutNum : DEFAULT_SETTINGS.sessionTimeoutHours,
    warnThresholdSeconds: Number.isFinite(thresholdNum) && thresholdNum >= 0 ? thresholdNum : DEFAULT_SETTINGS.warnThresholdSeconds,
    pruneIntervalHours: Number.isFinite(pruneHoursNum) && pruneHoursNum > 0 ? pruneHoursNum : DEFAULT_SETTINGS.pruneIntervalHours,
    composeInactivityTimeoutSeconds: Number.isFinite(composeInactivityNum) && composeInactivityNum > 0
      ? composeInactivityNum
      : DEFAULT_SETTINGS.composeInactivityTimeoutSeconds,
    dockerConfigFolder,
    dockerDataFolder,
    refreshIntervalSeconds: Number.isFinite(refreshIntervalNum) && refreshIntervalNum >= 1 && refreshIntervalNum <= 60
      ? refreshIntervalNum
      : DEFAULT_SETTINGS.refreshIntervalSeconds,
  };
  return normalized;
}

/** @returns {AppSettings} */
function loadSettings() {
  try {
    const data = JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
    return normalizeSettings(data);
  } catch (e) {
    try {
      const legacyData = JSON.parse(fs.readFileSync(LEGACY_SETTINGS_FILE, 'utf8'));
      const normalized = normalizeSettings(legacyData);
      try { fs.writeFileSync(SETTINGS_FILE, JSON.stringify(normalized, null, 2), 'utf8'); } catch {}
      return normalized;
    } catch {
      return { ...DEFAULT_SETTINGS };
    }
  }
}

/** @param {AppSettings} nextSettings @returns {AppSettings} */
function saveSettingsFile(nextSettings) {
  const normalized = normalizeSettings(nextSettings);
  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(normalized, null, 2), 'utf8');
  return normalized;
}

module.exports = {
  PORT,
  SETTINGS_FILE,
  LEGACY_SETTINGS_FILE,
  LOG_LEVELS,
  DEFAULT_SETTINGS,
  normalizeSettings,
  loadSettings,
  saveSettingsFile,
};
