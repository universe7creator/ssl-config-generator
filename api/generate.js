export default function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { server, compatibility, domain, hsts, ocsp, protocols } = req.body;
    const srv = server || 'nginx';
    const compat = compatibility || 'modern';
    const dom = domain || 'example.com';

    // Protocol configuration
    const protocolConfig = protocols || (compat === 'modern' ? ['TLSv1.3'] : ['TLSv1.2', 'TLSv1.3']);
    const protocolStr = Array.isArray(protocolConfig) ? protocolConfig.join(' ') : protocolConfig;

    // Cipher suites
    const ciphers = {
      modern: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
      intermediate: 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384',
      old: 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384'
    };

    // Generate configs based on server type
    const configs = {
      nginx: generateNginxConfig(srv, compat, dom, ciphers[compat], protocolStr, hsts, ocsp),
      apache: generateApacheConfig(srv, compat, dom, ciphers[compat], protocolStr, hsts, ocsp),
      caddy: generateCaddyConfig(srv, compat, dom, protocolStr, hsts),
      haproxy: generateHAProxyConfig(srv, compat, dom, ciphers[compat], protocolStr, hsts)
    };

    const config = configs[srv] || configs.nginx;
    const rating = compat === 'modern' ? 'A+' : compat === 'intermediate' ? 'A' : 'B';

    res.json({
      success: true,
      server: srv,
      compatibility: compat,
      domain: dom,
      config: config,
      rating: rating,
      protocols: protocolConfig,
      security: {
        hsts: hsts !== false,
        ocsp: ocsp !== false,
        forwardSecrecy: true,
        tls13: protocolConfig.includes('TLSv1.3')
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
}

function generateNginxConfig(server, compat, domain, ciphers, protocols, hsts, ocsp) {
  const hstsLine = hsts !== false ? `    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;` : '';
  const ocspLine = ocsp !== false ? `    ssl_stapling on;\n    ssl_stapling_verify on;` : '';
  const dhparam = compat === 'old' ? '    ssl_dhparam /etc/nginx/dhparam.pem;' : '';

  return `server {
    listen 443 ssl http2;
    server_name ${domain};

    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;

    ssl_protocols ${protocols};
    ssl_ciphers ${ciphers};
    ssl_prefer_server_ciphers ${compat === 'modern' ? 'off' : 'on'};
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
${ocspLine ? '    ' + ocspLine + '\n' : ''}${dhparam ? dhparam + '\n' : ''}${hstsLine ? hstsLine + '\n' : ''}    # Modern security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
}`;
}

function generateApacheConfig(server, compat, domain, ciphers, protocols, hsts, ocsp) {
  const hstsLine = hsts !== false ? `    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"` : '';
  const ocspLine = ocsp !== false ? `    SSLUseStapling on\n    SSLStaplingCache "shmcb:logs/stapling-cache(150000)"` : '';
  const dhparam = compat === 'old' ? '    SSLOpenSSLConfCmd DHParameters "/etc/ssl/certs/dhparam.pem"' : '';

  return `<VirtualHost *:443>
    ServerName ${domain}
    DocumentRoot /var/www/html

    SSLEngine on
    SSLCertificateFile /path/to/cert.pem
    SSLCertificateKeyFile /path/to/key.pem
    SSLCertificateChainFile /path/to/chain.pem

    SSLProtocol ${protocols.replace(/ /g, ' ')}
    SSLCipherSuite ${ciphers}
    SSLHonorCipherOrder ${compat === 'modern' ? 'off' : 'on'}
${ocspLine ? '    ' + ocspLine.replace(/\n/g, '\n    ') + '\n' : ''}${dhparam ? dhparam + '\n' : ''}${hstsLine ? hstsLine + '\n' : ''}    # Security headers
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
</VirtualHost>`;
}

function generateCaddyConfig(server, compat, domain, protocols, hsts) {
  const tlsConfig = compat === 'modern' ? 'tls internal {' : 'tls {';
  return `${domain} {
    reverse_proxy localhost:8080

    ${tlsConfig}
        protocols ${protocols.replace('TLSv', '').replace(/\./g, '_').replace(/ /g, ' ')}
    }
${hsts !== false ? '\n    header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"\n' : ''}    header X-Frame-Options "SAMEORIGIN"
    header X-Content-Type-Options "nosniff"
}`;
}

function generateHAProxyConfig(server, compat, domain, ciphers, protocols, hsts) {
  const hstsLine = hsts !== false ? `    http-response set-header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"` : '';

  return `frontend https_frontend
    bind *:443 ssl crt /path/to/combined.pem ${protocols.includes('TLSv1.3') ? 'alpn h2,http/1.1 tls-ticket-keys /etc/haproxy/tickets.keys' : ''}

    # SSL configuration
    ssl-default-bind-ciphers ${ciphers}
    ssl-default-bind-options ${protocols.includes('TLSv1.2') ? 'no-sslv3 no-tlsv10 no-tlsv11' : 'ssl-max-ver TLSv1.3'}
${hstsLine ? '    ' + hstsLine + '\n' : ''}    # Security headers
    http-response set-header X-Frame-Options SAMEORIGIN
    http-response set-header X-Content-Type-Options nosniff

    default_backend servers`;
}
