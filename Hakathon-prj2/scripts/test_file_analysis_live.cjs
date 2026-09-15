const http = require('http');

function uploadFile(endpoint, filename, content) {
  return new Promise((resolve, reject) => {
    const boundary = '----WebKitFormBoundary' + Math.random().toString(16).substring(2);
    const crlf = '\r\n';

    let header = '--' + boundary + crlf;
    header += 'Content-Disposition: form-data; name="file"; filename="' + filename + '"' + crlf;
    header += 'Content-Type: application/octet-stream' + crlf + crlf;

    const footer = crlf + '--' + boundary + '--' + crlf;

    const payload = Buffer.concat([
      Buffer.from(header, 'utf8'),
      Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8'),
      Buffer.from(footer, 'utf8')
    ]);

    const req = http.request({
      hostname: 'localhost',
      port: 5000,
      path: endpoint,
      method: 'POST',
      headers: {
        'Content-Type': 'multipart/form-data; boundary=' + boundary,
        'Content-Length': payload.length
      }
    }, res => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(body) });
        } catch {
          resolve({ status: res.statusCode, body });
        }
      });
    });

    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

async function main() {
  console.log('1. Testing 0-byte file rejection...');
  const emptyRes = await uploadFile('/api/analyze/file', 'empty.txt', '');
  console.log('0-byte status:', emptyRes.status, 'code:', emptyRes.body.error?.code);

  console.log('\n2. Testing synchronous file analysis with disguised executable (MZ header as .pdf)...');
  const mzPayload = Buffer.concat([Buffer.from([0x4d, 0x5a]), Buffer.from('DOS header test executable')]);
  const syncRes = await uploadFile('/api/analyze/file?sync=true', 'contract.pdf', mzPayload);
  console.log('Sync status:', syncRes.status);
  console.log('File type:', syncRes.body.file_type);
  console.log('File size:', syncRes.body.file_size);
  console.log('Risk score:', syncRes.body.risk_score);
  console.log('Classification:', syncRes.body.classification);
  console.log('Indicators:', syncRes.body.detected_indicators);
  console.log('Recommended Action:', syncRes.body.recommended_action);

  console.log('\n3. Testing dedicated /api/files/analyze endpoint...');
  const directRes = await uploadFile('/api/files/analyze', 'test_memo.txt', 'This is a clean business text file.');
  console.log('Direct status:', directRes.status);
  console.log('File type:', directRes.body.file_type);
  console.log('Classification:', directRes.body.classification);
  console.log('Score:', directRes.body.risk_score);

  console.log('\n4. Testing double extension detection (invoice.pdf.exe)...');
  const dblRes = await uploadFile('/api/files/analyze', 'invoice.pdf.exe', Buffer.from('echo hello'));
  console.log('Double ext status:', dblRes.status);
  console.log('Score:', dblRes.body.risk_score);
  console.log('Classification:', dblRes.body.classification);
  console.log('Indicators:', dblRes.body.detected_indicators);
}

main().catch(console.error);
