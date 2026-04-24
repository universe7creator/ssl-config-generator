export default function handler(req, res) {
  res.json({
    status: 'healthy',
    service: 'ssl-config-generator',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
}
