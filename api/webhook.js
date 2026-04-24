export default function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { meta } = req.body || {};

  if (meta?.event_name === 'order_created' || meta?.event_name === 'subscription_created') {
    console.log('Payment received:', meta.event_name);
    return res.json({
      status: 'success',
      message: 'License activated',
      event: meta.event_name
    });
  }

  res.json({
    status: 'received',
    event: meta?.event_name || 'unknown'
  });
}
