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
                { port: 3306, service: 'MySQL' },
                { port: 8080, service: 'HTTP Alternative' }
            ];

            const portResults = await Promise.all(portsToCheck.map(async ({ port, service }) => {
                return new Promise((resolve) => {
                    const socket = new net.Socket();
                    socket.setTimeout(2000); // 2 second timeout per port

                    socket.on('connect', () => {
                        socket.destroy();
                        resolve({ port, service, open: true });
                    });

                    socket.on('timeout', () => {
                        socket.destroy();
                        resolve({ port, service, open: false, reason: 'timeout' });
                    });

                    socket.on('error', (e: any) => {
                        socket.destroy();
                        resolve({ port, service, open: false, reason: 'closed/filtered' });
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

        // 8. Tech Stack Fingerprinting (HTML parsing)
        try {
            const htmlRes = await fetch(targetUrl, {
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 AegisScanner/1.0'
                }
            });
            const html = await htmlRes.text();

            const checks = [
                { id: 'WordPress', regex: /wp-content|wp-includes/i },
                { id: 'React', regex: /data-reactroot|react-dom/i },
                { id: 'Vue.js', regex: /data-v-|__VUE__/i },
                { id: 'Next.js', regex: /__NEXT_DATA__|_next\/static/i },
                { id: 'Nuxt.js', regex: /__NUXT__/i },
                { id: 'Angular', regex: /ng-version|ng-app/i },
                { id: 'jQuery', regex: /jquery[\.0-9a-z-]*\.js/i },
                { id: 'Bootstrap', regex: /bootstrap[\.0-9a-z-]*\.js|bootstrap[\.0-9a-z-]*\.css/i },
                { id: 'Tailwind CSS', regex: /tailwind/i },
            ];

            const foundTech = checks.filter(check => check.regex.test(html)).map(check => check.id);
            results.fingerprint = foundTech;

        } catch (e) {
            console.error('Fingerprinting error', e);
        }

        return NextResponse.json(results);
    } catch (error) {
        console.error('Scan error:', error);
        return NextResponse.json({ error: 'Internal server error during scan' }, { status: 500 });
    }
}
