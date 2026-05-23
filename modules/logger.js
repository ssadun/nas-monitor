'use strict';

const fs = require('fs');
const path = require('path');
const { LOG_LEVELS } = require('./config.js');

const AUDIT_LOG = path.join(__dirname, '..', 'logs', 'audit.log');

// Receives a getter so it always reads the live appSettings (which may be reassigned on save)
let getSettings = () => ({ logLevel: 'INFO', warnThresholdSeconds: 3 });

function setDependencies(deps = {}) {
  if (typeof deps.getSettings === 'function') getSettings = deps.getSettings;
}

function shouldLog(level) {
  const s = getSettings();
  const current = LOG_LEVELS[String(s.logLevel || 'INFO').toUpperCase()] ?? LOG_LEVELS.INFO;
  const incoming = LOG_LEVELS[level] ?? LOG_LEVELS.INFO;
  return incoming >= current;
}

function formatMeta(meta) {
  const entries = Object.entries(meta || {}).filter(([, v]) => v !== undefined && v !== null && v !== '');
  if (!entries.length) return '';
  return ' ' + entries.map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(' ');
}

function writeLog(level, message, meta = {}) {
  if (!shouldLog(level)) return;
  const ts = new Date().toISOString();
  const line = `[${ts}] [${level}] ${message}${formatMeta(meta)}`;
  if (level === 'ERROR') console.error(line);
  else console.log(line);
}

function logDebug(message, meta) { writeLog('DEBUG', message, meta); }
function logInfo(message, meta)  { writeLog('INFO',  message, meta); }
function logWarn(message, meta)  { writeLog('WARN',  message, meta); }
function logError(message, meta) { writeLog('ERROR', message, meta); }

function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0].trim() ||
         req.headers['x-real-ip'] ||
         req.socket.remoteAddress || 'unknown';
}

function auditLog(action, details, req) {
  const ts = new Date().toISOString();
  const ip = getClientIp(req);
  const user = details.user || 'unknown';
  const status = details.status || 'success';
  const auditLine = JSON.stringify({
    timestamp: ts,
    action,
    user,
    ip,
    status,
    details: details.details || '',
  });
  try {
    fs.appendFileSync(AUDIT_LOG, auditLine + '\n');
  } catch (e) {
    logError('Failed to write audit log', { error: e.message });
  }
}

function warnThresholdMs() {
  return Math.max(0, Number(getSettings().warnThresholdSeconds || 3) * 1000);
}

module.exports = {
  setDependencies,
  logDebug,
  logInfo,
  logWarn,
  logError,
  getClientIp,
  auditLog,
  warnThresholdMs,
};
