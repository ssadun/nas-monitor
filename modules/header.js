const fs = require('fs');

function sendFile(res, filePath, contentType, encoding = 'utf8', cacheControl = 'no-cache') {
  try {
    if (!fs.existsSync(filePath)) return false;
    const headers = {
      'Content-Type': contentType,
      'Cache-Control': cacheControl,
    };
    res.writeHead(200, headers);
    res.end(fs.readFileSync(filePath, encoding));
    return true;
  } catch {
    return false;
  }
}

function sendJavaScript(res, script) {
  res.writeHead(200, {
    'Content-Type': 'application/javascript; charset=utf-8',
    'Cache-Control': 'no-cache',
  });
  res.end(script);
}

function sendNotFound(res, message = 'Not found') {
  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end(message);
}

module.exports = {
  sendFile,
  sendJavaScript,
  sendNotFound,
};
