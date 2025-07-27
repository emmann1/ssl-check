from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseRedirect
from ciphers.scan import SSLScan

from ciphers.forms import SiteInputForm

# Create your views here.
def index(request):
    
    
    if request.method == "POST":
        form = SiteInputForm(request.POST)
        if form.is_valid():
            return redirect(f"./results/{form.cleaned_data['site']}")

    context = {
        'form': SiteInputForm()
    }

    return render(request, "ciphers/index.html", context)

def results(request, hostname):
    scan_data = []
    data_present = False
    if hostname:
        scan_data = SSLScan(hostname).scan_results
        data_present = True

    context= {
        'scandata': scan_data,
        'data_present': data_present,
        'alltlsv': ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']
    }
    return render(request, 'ciphers/results.html', context)