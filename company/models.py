from django.db import models
from simple_history.models import HistoricalRecords

# Create your models here.
class Company(models.Model):
    date_created=models.DateTimeField(auto_now_add=True,editable=False)
    company_name=models.CharField(max_length=200,unique=True)
    country=models.CharField(max_length=200,blank=True)
    address=models.CharField(max_length=200,blank=True)
    location=models.CharField(max_length=200, blank=True)
    company_activity=models.CharField(max_length=200,blank=True)
    pin_number=models.CharField(max_length=50,blank=True)    
    vat_number=models.CharField(max_length=50,blank=True)
    certificate_number=models.CharField(max_length=50,blank=True)
    contact_person=models.CharField(max_length=200, blank=True)
    phone=models.CharField(max_length=50)
    email=models.EmailField()
    email_2=models.EmailField(blank=True)
    email_3=models.EmailField(blank=True)
    last_invoice=models.DateField(blank=True,default="2020-01-01") 
    deactivate=models.BooleanField(default=False)
    history = HistoricalRecords()

    class Meta:
        ordering = ['date_created']

    def __str__(self):
        return self.company_name