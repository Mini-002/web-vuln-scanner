import requests

SECURITY_HEADERS = [
     'Content-Security-Policy',
     'X-Frame-Options',
     'Strict-Transport-Security',
     'X-Content-Type-Options',
     'X-XSS-Protection',
]
url = input('Enter URL to scan (include https://) : ')

try:
   response = requests.get(url, timeout=10)
   headers = response.headers

   print(f'\nScanning: {url}')
   print('-' * 40)
   print('Security Headers Check:')

   score = 0
   for header in SECURITY_HEADERS:
      if header in headers:
         print(f'  [PASS] {header}')
         score = score + 1
      else:
         print(f'  [MISSING] {header}')

   print('-' * 40)
   print(f'Score: {score}/{len(SECURITY_HEADERS)}')

   if score == len(SECURITY_HEADERS):
      print('Rating:EXCELLENT')
   elif score>= 3:
      print('Rating:MODERATE')
   else:
      print('Rating:POOR')

except Exception as e:
   print(f'Error: {e}')
