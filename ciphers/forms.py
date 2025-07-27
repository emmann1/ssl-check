from django import forms

class SiteInputForm(forms.Form):
    site = forms.CharField(
        max_length=100, 
        widget=forms.TextInput(
            attrs={"class": "form-control form-control-lg", "placeholder":"Enter a web domain..."}
        )
    )