from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.contrib.auth import get_user_model


User =get_user_model()

@login_required(login_url='users:login')
def home_view(request):

    allusers=User.objects.all()
    total_users=allusers.count()
 
    context={'allusers':allusers,'total_users':total_users}  
    return render (request, 'index.html',context)


