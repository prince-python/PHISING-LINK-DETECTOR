from django.shortcuts import render


from django.shortcuts import render

def index(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        result = analyze_url(url) 
        return render(request, 'index.html', {'result': result})

    return render(request, 'index.html')

import re
from urllib.parse import urlparse

def analyze_url(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    path = parsed_url.path
    score = 0    
    if re.search(r"(login|secure|account|verify|update|bank|signin|password|confirm|pay|paypal)", domain, re.IGNORECASE):
        score += 2
    if re.search(r"(login|signin|account|verify|update|confirm|secure|password|bank|paypal)", path, re.IGNORECASE):
        score += 2


    if re.search(r"[-]{2,}|[0-9]{3,}", path) or "-" in domain or domain.count(".") > 2:
        score += 1

    # Detect if an IP address is used in the domain instead of a name
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):  # Pattern for IP addresses
        score += 2

    # Check for uncommon or suspicious TLDs
    if re.search(r"\.(top|xyz|club|info|support|app|live|click|link|network|work|gq|ml|ga)$", domain, re.IGNORECASE):
        score += 1

    # Check for shortened URLs or other indicators (optional, can increase sensitivity)
    if re.search(r"(bit\.ly|t\.co|tinyurl|goo\.gl|shorte\.st|ow\.ly|is\.gd|buff\.ly)", domain, re.IGNORECASE):
        score += 2

    # Determine result based on score
    if score >= 3:
        return "Phishing suspected!"
    else:
        return "URL looks safe."

