import snowflake.connector
import requests
import json
from urllib.parse import urlencode
import base64
import pandas as pd
import os
from datetime import datetime
from azure.storage.blob import BlobServiceClient, BlobClient
import urllib3

# Suppress SSL certificate verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Path to the certificate in the Function App environment
cert_path = "/home/site/wwwroot/certs/tmobilesnowflakepub.cer"

# Set environment variable for SSL certificates (if you have a custom CA, otherwise bypass)
os.environ['REQUESTS_CA_BUNDLE'] = cert_path

# Snowflake OAuth credentials
client_id = 'OqucQN2z+R814wveF/Tc7UB2X7o='
client_secret = 'zfNYKaYG/Htx9MAEuabI8aKhXvk1kyl3+dF18/9v4f8='
redirect_uri = 'https://localhost.com'
authorization_endpoint = 'https://tmobilenpe.west-us-2.privatelink.snowflakecomputing.com/oauth/authorize'
token_endpoint = 'https://tmobilenpe.west-us-2.privatelink.snowflakecomputing.com/oauth/token-request'
refresh_token = 'ver:2-hint:48279735571054-did:2006-ETMsDgAAAZPV35khABRBRVMvQ0JDL1BLQ1M1UGFkZGluZwEAABAAEHki2BxI5B1LQrKAITCSup0AAAEA58kBSK3SktyXlfTfvVvx2odf1WJTXSWZuy5Oo+T2LJR8hH5XPxQ965lysVXh045n4caR7in6RhZlUh6ayV1A5iiQDfq9wW3kwi96N83fuprg8C3M23SJQFIIhoUj2lIODysFO9pEQLWkZU22elGRmU62INQKT08vpsnnsTfVOka4bESCnt7KqkXf577kiMP0+CJrvt8d9aBpnKfqQiRhdSywuPjysriclU2YGZAX9HRZyNPnnBcJqnrBDCPn6ztEMOJkp6Q4BaRTZMUHbe0tjvB9OVg0MDjLT9Wjz7sGZNoy925mzGazqTyT29jsrZnexrJuUbyhvsibS+l2HJJ/dgAUCM7VKe1AC/7YwBrHkrmO46hodZA='

# Azure Blob Storage connection string
azure_blob_connection_string = "DefaultEndpointsProtocol=https;AccountName=devedsrapwu2blob01;AccountKey=4DJYrRfwPCV6rIl1D4uAdxf2zctOzy0kilUr1Qq20QMcGi/hWOkMnRyvX3DSn+cRBNbT3onIHvmymg+gB/q1gA==;EndpointSuffix=core.windows.net"
container_name = 'landing'
blob_folder_path = 'dev02/config_ui'

# Function to fetch data from Snowflake and upload it to Azure Blob Storage
def fetch_and_upload_snowflake_data(req):
    try:
        # Snowflake OAuth authentication logic
        hdrs = {
            'Authorization': 'Basic {}'.format(
                base64.b64encode(f'{client_id}:{client_secret}'.encode()).decode()
            ),
            'Content-type': 'application/x-www-form-urlencoded;charset=utf-8'
        }

        data = urlencode({
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'redirect_uri': redirect_uri
        })
        data = data.encode('ascii')

        # Get the access token from Snowflake (bypassing SSL cert verification)
        r = requests.post(
            token_endpoint,
            headers=hdrs,
            data=data,
            verify=False  # Bypass SSL verification
        )

        access_token = r.json()['access_token']

        # Connect to Snowflake
        conn = snowflake.connector.connect(
            user="gurpreet.kaur33@t-mobile.com",
            account='tmobilenpe.west-us-2.privatelink',
            authenticator='oauth',
            warehouse='ETS_REVAP_DI_DEV_WH_01',
            database='ETS_REVAP02_DB_DEV',
            schema='REVAP_CONFIG',
            token=access_token
        )

        # Create a cursor and fetch data
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM CON_GENERAL_LOOKUP WHERE dbt_valid_to IS NULL")
        records = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]

        # Create DataFrame
        df = pd.DataFrame(records, columns=columns)

        # Save to Excel file
        current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        local_file = f"CON_GENERAL_LOOKUP_{current_time}.xlsx"
        df.to_excel(local_file, index=False)

        # Upload file to Azure Blob Storage
        upload_to_blob(local_file, f"{blob_folder_path}/{local_file}")
        
        # Clean up local file
        if os.path.exists(local_file):
            os.remove(local_file)
        
        return "Data fetched and uploaded successfully."

    except Exception as e:
        return f"An error occurred: {str(e)}"

# Helper function to upload to Azure Blob Storage
def upload_to_blob(file_path, blob_name):
    blob_service_client = BlobServiceClient.from_connection_string(azure_blob_connection_string)
    blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
    
    with open(file_path, "rb") as data:
        blob_client.upload_blob(data, overwrite=True)
