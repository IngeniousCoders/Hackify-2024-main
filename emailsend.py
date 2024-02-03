import smtplib
import os
import email.message
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import credparse
env_var = credparse.parse(".credentials")
email_address = env_var["email"]
password = env_var['password']

# print(f"\"{email_address}\"")
# print(f"\"{password}\"")


def sendEmail(recipient, subject, content):
    msg = MIMEMultipart('alternative')
    msg['From'] = "City Bug Reports"
    msg["To"] = recipient
    msg["Subject"] = subject
    html = MIMEText(content, 'html')
    msg.attach(html)
    s = smtplib.SMTP('smtp.gmail.com', 587)
    s.ehlo()
    s.starttls()
    s.login(email_address, password)
    s.sendmail(email_address, recipient, msg.as_string())
    s.quit()
    return True
