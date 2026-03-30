import { NextResponse } from 'next/server';

export async function GET() {
    return NextResponse.json({ error: 'Method not allowed. Please use the frontend scanner to submit a POST request.' }, { status: 405 });
}
export async function POST(request: Request) {
    try {
        const { url } = await request.json();

        if (!url) {
            return NextResponse.json({ error: 'URL is required' }, { status: 400 });
        }

        let targetUrl = url;
        if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
            targetUrl = `https://${targetUrl}`; // Default to https
        }

        try {
            new URL(targetUrl); // Validate URL format
        } catch {
            return NextResponse.json({ error: 'Invalid URL format' }, { status: 400 });
        }

        const results = {
            target: targetUrl,
            headers: {} as Record<string, any>,
            exposedFiles: [] as any[],
            serverInfo: {} as Record<string, any>,
            cookieFlags: [] as any[],
            ssl: null as any,
            ports: [] as any[],
            dnsRecords: { spf: false, dmarc: false } as Record<string, boolean>,
            wafDetected: null as boolean | null,
            fingerprint: [] as string[],
            timestamp: new Date().toISOString(),
        };

        // 1. Check Security Headers
        try {
            const response = await fetch(targetUrl, {
                method: 'HEAD',
                redirect: 'follow',
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 AegisScanner/1.0'
                }
            });
            const currentHeaders = response.headers;

            const headerChecks = [
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'Referrer-Policy',
                'Permissions-Policy'
            ];

            headerChecks.forEach(header => {
                results.headers[header] = {
                    present: currentHeaders.has(header.toLowerCase()),
                    value: currentHeaders.get(header.toLowerCase()) || null
                };
            });

            // Server Info
            results.serverInfo = {
                server: currentHeaders.get('server') || 'Unknown',
                poweredBy: currentHeaders.get('x-powered-by') || 'Unknown',
            };

        } catch (e: any) {
            console.error('Fetch error for headers:', e);
            return NextResponse.json({ error: `Failed to access target URL. Reason: ${e.message || 'Unknown'}. Ensure the site is reachable and online.` }, { status: 400 });
        }

        // 2. Check for common exposed files (Basic implementation)
        const filesToCheck = [
            '/.env',
            '/.git/config',
            '/robots.txt',
            '/.well-known/security.txt',
            '/package.json',
            '/admin',
            '/wp-admin',
            '/backup',
            '/.svn'
        ];

        for (const file of filesToCheck) {
            try {
                const fileUrl = new URL(file, targetUrl).href;
                const res = await fetch(fileUrl, {
                    method: 'HEAD',
                    headers: {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 AegisScanner/1.0'
                    }
                });

                results.exposedFiles.push({
                    path: file,
                    status: res.status,
                    exists: res.status === 200 && !res.redirected, // Simple heuristic to avoid soft 404s for now
                });
            } catch (e) {
                results.exposedFiles.push({
                    path: file,
                    status: 'Error',
                    exists: false,
                });
            }
        }

        // 3. Check for Cookie Security Flags
        try {
            const response = await fetch(targetUrl, { method: 'HEAD', redirect: 'follow' });
            const setCookieHeaders = response.headers.get('set-cookie');
            if (setCookieHeaders) {
                // This is a simplified check, Next.js fetch headers might combine multiple set-cookies into one string
                // A real-world scanner would parse this more robustly
                const cookies = setCookieHeaders.split(/,(?=\s*[a-zA-Z0-9_\-]+(?:=|$))/);

                results.cookieFlags = cookies.map((cookieStr: string) => {
                    const parts = cookieStr.split(';').map((p: string) => p.trim());
                    const nameValuePair = parts[0].split('=');
                    const name = nameValuePair[0];

                    const flags = parts.slice(1).map((p: string) => p.toLowerCase());
                    return {
                        name,
                        secure: flags.includes('secure'),
                        httpOnly: flags.includes('httponly'),
                        sameSite: flags.find((f: string) => f.startsWith('samesite='))?.split('=')[1] || 'None (Missing)'
                    }
                });
            } else {
                results.cookieFlags = []; // No cookies set
            }
        } catch (e) {
            console.error('Cookie flag extraction error', e);
        }

        // 4. Check SSL/TLS Certificate Check
        if (targetUrl.startsWith('https://')) {
            try {
                const tls = require('tls');
                const { hostname } = new URL(targetUrl);
                const certData = await new Promise<any>((resolve, reject) => {
                    const socket = tls.connect(443, hostname, { servername: hostname }, () => {
                        const cert = socket.getPeerCertificate();
                        socket.end();

                        if (!socket.authorized) {
                            resolve({ valid: false, error: socket.authorizationError });
                        } else {
                            resolve({
                                valid: true,
                                issuer: cert.issuer.O || cert.issuer.CN || 'Unknown',
                                validFrom: cert.valid_from,
                                validTo: cert.valid_to,
                                subjectAltName: cert.subjectaltname
                            });
                        }
                    });
                    socket.on('error', reject);
                    socket.on('timeout', () => { socket.destroy(); reject(new Error('TLS Timeout')); });
                    socket.setTimeout(3000);
                });
                results.ssl = certData;
            } catch (e: any) {
                results.ssl = { valid: false, error: e.message || 'Failed to check SSL' };
            }
        }

        // 5. Check Open Port Scanning (Basic)
        try {
            const net = require('net');
            const { hostname } = new URL(targetUrl);
            const portsToCheck = [
                { port: 21, service: 'FTP' },
                { port: 22, service: 'SSH' },
                { port: 23, service: 'Telnet' },
                { port: 25, service: 'SMTP' },
                { port: 53, service: 'DNS' },
                { port: 80, service: 'HTTP' },
                { port: 110, service: 'POP3' },
                { port: 111, service: 'RPCBind' },
                { port: 135, service: 'MSRPC' },
                { port: 139, service: 'NetBIOS' },
                { port: 143, service: 'IMAP' },
                { port: 443, service: 'HTTPS' },
                { port: 445, service: 'SMB' },
                { port: 993, service: 'IMAPS' },
                { port: 995, service: 'POP3S' },
                { port: 1723, service: 'PPTP' },
                { port: 3306, service: 'MySQL' },
                { port: 3389, service: 'RDP' },
                { port: 5432, service: 'PostgreSQL' },
                { port: 5900, service: 'VNC' },
                { port: 6379, service: 'Redis' },
                { port: 8080, service: 'HTTP-Alt' },
                { port: 13000, service: 'SecApp (Current)' }
            ];

            const portResults = await Promise.all(portsToCheck.map(async ({ port, service }) => {
                return new Promise((resolve) => {
                    const socket = new net.Socket();
                    socket.setTimeout(5000); 

                    let isOpen = false;
                    let hasResolved = false;

                    const safeResolve = (data: any) => {
                        if (hasResolved) return;
                        hasResolved = true;
                        socket.destroy();
                        resolve(data);
                    };

                    socket.on('connect', () => {
                        isOpen = true;
                        // For banner services, give it a moment to send data
                        if ([21, 22, 23, 3306].includes(port)) {
                            setTimeout(() => {
                                safeResolve({ port, service, open: true, verified: false });
                            }, 1500);
                        } 
                        // For HTTP ports, send a HEAD probe to verify the service
                        else if ([80, 443, 8080, 13000].includes(port)) {
                            socket.write(`HEAD / HTTP/1.0\r\nHost: ${hostname}\r\nConnection: close\r\n\r\n`);
                            setTimeout(() => {
                                safeResolve({ port, service, open: true, verified: false, note: 'No HTTP response received' });
                            }, 2000);
                        }
                        else {
                            safeResolve({ port, service, open: true, verified: true });
                        }
                    });

                    socket.on('data', (data: Buffer) => {
                        const banner = data.toString().trim();
                        // Verify if it looks like a real service response
                        const isVerified = banner.length > 5 || banner.includes('HTTP/1.') || banner.includes('SSH-');
                        
                        safeResolve({ 
                            port, 
                            service, 
                            open: true, 
                            verified: isVerified, 
                            banner: banner.slice(0, 100)
                        });
                    });

                    socket.on('timeout', () => {
                        safeResolve({ port, service, open: false, reason: 'timeout' });
                    });

                    socket.on('error', (e: any) => {
                        safeResolve({ port, service, open: false, reason: e.code === 'ECONNREFUSED' ? 'closed' : 'filtered' });
                    });

                    socket.connect(port, hostname);
                });
            }));

            results.ports = portResults;
        } catch (e) {
            results.ports = [];
            console.error('Port scan error', e);
        }
        // 6. Check DNS Records (SPF / DMARC)
        try {
            const dns = require('dns').promises;
            const { hostname } = new URL(targetUrl);

            // SPF
            try {
                const txtRecords = await dns.resolveTxt(hostname);
                const hasSpf = txtRecords.some((record: string[]) => record.join('').includes('v=spf1'));
                results.dnsRecords.spf = hasSpf;
            } catch (e) {
                // Ignore standard dns errors if no txt found
            }

            // DMARC
            try {
                const dmarcRecords = await dns.resolveTxt(`_dmarc.${hostname}`);
                const hasDmarc = dmarcRecords.some((record: string[]) => record.join('').includes('v=DMARC1'));
                results.dnsRecords.dmarc = hasDmarc;
            } catch (e) {
                // Ignore if _dmarc doesn't exist
            }
        } catch (e) {
            console.error('DNS lookup error', e);
        }

        // 7. Basic WAF Detection
        try {
            const wafUrl = new URL(targetUrl);
            wafUrl.searchParams.append('test', "../../../etc/passwd"); // Simple payload
            wafUrl.searchParams.append('id', "1' OR '1'='1"); // SQLi payload

            const wafRes = await fetch(wafUrl.href, {
                method: 'GET',
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 AegisScanner/1.0'
                }
            });

            // If we get a 403, 406, 429, or 501, it's highly likely a WAF caught the payload
            if ([403, 406, 429, 501].includes(wafRes.status)) {
                results.wafDetected = true;
            } else {
                results.wafDetected = false;
            }
        } catch (e) {
            results.wafDetected = null; // Error or timeout
        }

        // 8. Deep Tech Stack & Version Fingerprinting (V5)
        try {
            const htmlRes = await fetch(targetUrl, {
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 AegisScanner/1.0'
                }
            });
            const html = await htmlRes.text();

            const fingerprintSet = new Set<string>();

            // 8a. Parse Server & X-Powered-By for versions
            const serverHeader = results.serverInfo.server;
            const poweredBy = results.serverInfo.poweredBy;

            if (serverHeader && serverHeader !== 'Unknown') {
                const match = serverHeader.match(/^([a-zA-Z\-]+)\/?([\d\.]*)/);
                if (match && match[2]) {
                    fingerprintSet.add(`${match[1].charAt(0).toUpperCase() + match[1].slice(1)} (${match[2]})`);
                } else if (match && match[1]) {
                    fingerprintSet.add(match[1].charAt(0).toUpperCase() + match[1].slice(1));
                } else {
                    fingerprintSet.add(serverHeader);
                }
            }

            if (poweredBy && poweredBy !== 'Unknown') {
                const match = poweredBy.match(/^([a-zA-Z\-]+)\/?([\d\.]*)/);
                if (match && match[2]) {
                    fingerprintSet.add(`${match[1].charAt(0).toUpperCase() + match[1].slice(1)} (${match[2]})`);
                } else {
                    fingerprintSet.add(poweredBy);
                }
            }

            // 8b. Parse Meta Generator for CMS string/versions
            const metaGenMatch = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i) ||
                html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator["']/i);
            if (metaGenMatch && metaGenMatch[1]) {
                fingerprintSet.add(metaGenMatch[1]);
            }

            // 8c. CDN Script Regex Extraction
            const regex = /<script[^>]+src=["']([^"']+)["']/gi;
            let match;
            while ((match = regex.exec(html)) !== null) {
                const src = match[1].toLowerCase();

                // UNPKG / JSDelivr (e.g. unpkg.com/react@18.2.0/...)
                const npmMatch = src.match(/(?:unpkg\.com|cdn\.jsdelivr\.net\/npm)\/([a-z0-9\-_]+)@([\d\.]+)/);
                if (npmMatch) {
                    const pkg = npmMatch[1].charAt(0).toUpperCase() + npmMatch[1].slice(1);
                    fingerprintSet.add(`${pkg} (${npmMatch[2]})`);
                    continue;
                }

                // CDNJS (e.g. cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/...)
                const cdnjsMatch = src.match(/cdnjs\.cloudflare\.com\/ajax\/libs\/([a-z0-9\-_]+)\/([\d\.]+)/);
                if (cdnjsMatch) {
                    const pkg = cdnjsMatch[1].charAt(0).toUpperCase() + cdnjsMatch[1].slice(1);
                    fingerprintSet.add(`${pkg} (${cdnjsMatch[2]})`);
                    continue;
                }

                // Local generic jquery files
                const localJqMatch = src.match(/jquery-([\d\.]+)\.min\.js/);
                if (localJqMatch) {
                    fingerprintSet.add(`JQuery (${localJqMatch[1]})`);
                }
            }

            // 8d. Fallback heuristics for common tools if no version was explicitly found
            const fingerprintStr = Array.from(fingerprintSet).join(' ').toLowerCase();

            if (html.includes('_next') && !fingerprintStr.includes('next.js')) fingerprintSet.add('Next.js');
            if (html.includes('wp-content') && !fingerprintStr.includes('wordpress')) fingerprintSet.add('WordPress');
            if (html.match(/data-reactroot|react-dom/i) && !fingerprintStr.includes('react')) fingerprintSet.add('React');
            if (html.match(/data-v-|__VUE__/i) && !fingerprintStr.includes('vue')) fingerprintSet.add('Vue.js');
            if (html.match(/__NUXT__/i) && !fingerprintStr.includes('nuxt')) fingerprintSet.add('Nuxt.js');
            if (html.match(/ng-version|ng-app/i) && !fingerprintStr.includes('angular')) fingerprintSet.add('Angular');
            if (html.match(/tailwind/i) && !fingerprintStr.includes('tailwind')) fingerprintSet.add('Tailwind CSS');
            if (html.match(/bootstrap/i) && !fingerprintStr.includes('bootstrap')) fingerprintSet.add('Bootstrap');

            results.fingerprint = Array.from(fingerprintSet);

        } catch (e) {
            console.error('Fingerprinting error', e);
        }

        return NextResponse.json(results);
    } catch (error) {
        console.error('Scan error:', error);
        return NextResponse.json({ error: 'Internal server error during scan' }, { status: 500 });
    }
}
