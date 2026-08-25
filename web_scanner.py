import requests
from datetime import datetime

SECURITY_HEADERS = [
    'Content-Security-Policy',
    'X-Frame-Options',
    'Strict-Transport-Security',
    'X-Content-Type-Options',
    'X-XSS-Protection',
    'Referrer-Policy',
    'Permissions-Policy',
    'Cross-Origin-Opener-Policy',
    'Cross-Origin-Resource-Policy',
    'Cache-Control',
]

def scan_url(url):
    results = []
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

        results.append(f'\nScanning: {url}')
        results.append(f'Status code: {response.status_code}')
        results.append('-' * 40)
        results.append('Security Headers Check:')

        score = 0
        for header in SECURITY_HEADERS:
            if header in headers:
                results.append(f'  [PASS] {header}')
                score += 1
            else:
                results.append(f'  [MISSING] {header}')

        out_of_10 = round((score / len(SECURITY_HEADERS)) * 10)
        results.append('-' * 40)
        results.append(f'Score: {out_of_10}/10')

        if out_of_10 >= 8:
            results.append('Rating: EXCELLENT')
        elif out_of_10 >= 5:
            results.append('Rating: MODERATE')
        else:
            results.append('Rating: POOR')

    except Exception as e:
        results.append(f'Error scanning {url}: {e}')

    return results

print('=== Web Vulnerability Scanner ===')
print('Enter URLs to scan one per line.')
print('Type DONE when finished.')
print('')

urls = []
while True:
    url = input('Enter URL (or DONE): ')
    if url.upper() == 'DONE':
        break
    urls.append(url)

all_results = []
all_results.append(f'Scan Report - {datetime.now()}')
all_results.append('=' * 40)

for url in urls:
    results = scan_url(url)
    for line in results:
        print(line)
        all_results.append(line)

save = input('\nSave results to file? (y/n): ').lower() == 'y'
if save:
    filename = f'scan_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
    with open(filename, 'w') as f:
        for line in all_results:
            f.write(line + '\n')
    print(f'Saved to {filename}')
