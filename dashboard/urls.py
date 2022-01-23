from django.urls import path
from . import views
#from dashboard.views import home_view

app_name="dashboard"
urlpatterns=[
    
    path('', views.home_view, name="home"),
    
]