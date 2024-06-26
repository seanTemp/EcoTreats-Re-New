import pandas as pd
from sklearn.ensemble import IsolationForest
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import time


#  log and initialise
def load_and_preprocess_log_data(log_file='test_app.log'):
    log_data = pd.read_csv(log_file, sep=' - ', header=None, names=['timestamp', 'level', 'message'], engine='python')
    log_data['message'] = log_data['message'].fillna('')  # replace NaNs with empty strings
    log_data['length'] = log_data['message'].apply(len)
    return log_data


# train the isolation forest model
def train_model(log_data):
    model = IsolationForest(contamination=0.01)
    model.fit(log_data[['length']])
    return model


# send email alert
from dotenv import load_dotenv
load_dotenv()
import os

# Get environment variables
from_email = os.getenv('EMAIL_SMTP_AILOG')
password = os.getenv('PASSWORD_SMTP_AILOG')
def send_email_alert(subject, body, to_email):


    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp.mail.yahoo.com', 587)
        server.starttls()
        server.login(from_email, password)
        text = msg.as_string()
        server.sendmail(from_email, to_email, text)
        server.quit()
    except Exception as e:
        print(f"Failed to send email: {e}")


#send alert with detected anomalies
def send_alert(anomalies):
    subject = "Security Alert: Anomalies Detected"
    body = f"Anomalies detected:\n{anomalies.to_string(index=False)}"
    send_email_alert(subject, body, '233093Y@mymail.nyp.edu.sg')


#finding for anomalies
# def monitor_logs(log_file='test_app.log', model=None):
#     while True:
#         log_data = load_and_preprocess_log_data(log_file)
#         log_data['anomaly'] = model.predict(log_data[['length']])
#         anomalies = log_data[log_data['anomaly'] == -1]
#         if not anomalies.empty:
#             send_alert(anomalies)
#         time.sleep(60)  #every  minute
def monitor_logs(log_file='test_app.log', model=None):
    while True:
        print("Monitoring logs...")
        log_data = load_and_preprocess_log_data(log_file)
        log_data['anomaly'] = model.predict(log_data[['length']])
        anomalies = log_data[log_data['anomaly'] == -1]
        if not anomalies.empty:
            print("Anomalies detected. Sending email alert...")
            send_alert(anomalies)
            print(anomalies)
        else:
            print("No anomalies detected.")
        time.sleep(60)



if __name__ == "__main__":
    log_data = load_and_preprocess_log_data()
    model = train_model(log_data)
    monitor_logs(model=model)
