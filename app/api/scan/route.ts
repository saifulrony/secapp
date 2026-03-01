import { NextResponse } from 'next/server';

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
            return NextResponse.json({ error: `Failed to access target URL. Reason: ${e.message || 'Unknown'}` }, { status: 500 });
        }

        // 2. Check for common exposed files (Basic implementation)
        const filesToCheck = [
            '/.env',
            '/.git/config',
            '/robots.txt',
            '/.well-known/security.txt',
            '/package.json'
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


        return NextResponse.json(results);
    } catch (error) {
        console.error('Scan error:', error);
        return NextResponse.json({ error: 'Internal server error during scan' }, { status: 500 });
    }
}
