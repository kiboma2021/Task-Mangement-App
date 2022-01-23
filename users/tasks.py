from celery import shared_task
import smtplib, ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from .data import store_login_attempt
from . import config



@shared_task
def send_new_user_email(to_email,message):

    from_email="LSP_System@libertylife.co.ke"
    
    hostname = "10.235.130.162"
    password = "Password1"
    server = smtplib.SMTP(hostname, 587)
    server.connect(hostname, 587)


    server.sendmail(from_email, to_email, message)





def add_login_attempt_task(
    user_agent, ip_address, username, http_accept, path_info, login_valid
):
    """ Create a record for the login attempt """
    store_login_attempt(
        user_agent, ip_address, username, http_accept, path_info, login_valid
    )

if config.USE_CELERY:
    from celery import shared_task
    add_login_attempt_task = shared_task(add_login_attempt_task)