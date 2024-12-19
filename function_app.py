import azure.functions as func
import logging
from Fetchsnowflake import fetch_and_upload_snowflake_data  # Import the function from fetchSnowflake.py

# Create the function app with anonymous authentication level
app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@app.route(route="fetch_snowflake_data")
def fetch_snowflake_data(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    try:
        # Call the function from fetchSnowflake.py to fetch and store data
        result = fetch_and_upload_snowflake_data(req)  # Pass the request object to the function
        
        # Return a successful response
        return func.HttpResponse(f"Snowflake data successfully fetched and stored. Result: {result}", status_code=200)
    
    except Exception as e:
        # Log error if something goes wrong
        logging.error(f"Error occurred: {str(e)}")
        return func.HttpResponse(f"An error occurred: {str(e)}", status_code=500)
