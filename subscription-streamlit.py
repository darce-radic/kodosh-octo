import streamlit as st
import os
import pandas as pd
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.discovery import build
from openai import OpenAI
from pinecone import Pinecone
import hashlib
import json
import datetime
from dotenv import load_dotenv
import uuid
import base64
import hashlib

# Load environment variables
load_dotenv()

# Comprehensive application code integrating all discussed functionalities
# Define constants
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/userinfo.email", "openid"]
CLIENT_ID = st.secrets["GMAIL_API_CREDENTIALS"]["CLIENT_ID"]
CLIENT_SECRET = st.secrets["GMAIL_API_CREDENTIALS"]["CLIENT_SECRET"]

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
MAIN_REDIRECT_URI = "https://kodosh.streamlit.app/api/auth/google/callback"
CLIENT_CONFIG = {
    "web": {
        "client_id": "161366495022-dovct3o0ofamo5d17q9heva3h54n735n.apps.googleusercontent.com",
        "client_secret": "your-client-secret",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": [
            "https://kodosh.streamlit.app/api/auth/google/callback"
        ]
    }
}


def detect_subscriptions(df, date_format="%d/%m/%Y"):
    """
    Detect potential subscriptions based on recurring charges from the same merchant
    across multiple months.
    """
    try:
        # Standardize the Date column
        df["Date"] = pd.to_datetime(df["Date"], format=date_format, errors="coerce")
        df = df.dropna(subset=["Date"])  # Remove rows with invalid dates

        # Extract Month-Year for grouping
        df["Month"] = df["Date"].dt.to_period("M")

        # Group by Description and Amount
        subscriptions = []
        grouped = df.groupby(["Description", "Amount"])
        for (description, amount), group in grouped:
            unique_months = group["Month"].nunique()
            if unique_months > 2:  # Subscription-like pattern
                subscriptions.append({
                    "Merchant": description,
                    "Amount": amount,
                    "Occurrences": unique_months,
                    "First Charge": group["Date"].min().strftime("%Y-%m-%d"),
                    "Last Charge": group["Date"].max().strftime("%Y-%m-%d")
                })

        return pd.DataFrame(subscriptions)

    except Exception as e:
        raise ValueError(f"Error during subscription detection: {e}")



def authorize_gmail_api():
    """
    Handles Gmail API authorization and generates an authorization URL for the user.
    """
    creds = None
    SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

    # Check for existing credentials in token.json
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
        if creds and creds.valid:
            st.info("Already logged in!")
            st.session_state.creds = creds
            st.session_state.user_email = get_user_info(creds)
            return creds

    # OAuth Flow for new login
    flow = InstalledAppFlow.from_client_config(CLIENT_CONFIG, SCOPES)
    flow.redirect_uri = MAIN_REDIRECT_URI

    # Generate the authorization URL
    authorization_url, _ = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent"
    )

    # Display custom button for user authorization
    st.markdown(
        f"""
        <style>
        .custom-button {{
            display: inline-block;
            background-color: #4CAF50;
            color: white !important;
            padding: 10px 24px;
            text-align: center;
            text-decoration: none;
            font-size: 16px;
            border-radius: 5px;
            margin-top: 5px;
            margin-bottom: 5px;
        }}
        .custom-button:hover {{
            background-color: #45a049;
        }}
        </style>
        <a href="{authorization_url}" target="_blank" class="custom-button">Authorize with Google</a>
        """,
        unsafe_allow_html=True
    )
    st.info("After authorizing, return to this page to complete the login.")



def fetch_credentials():
    """
    Fetch credentials after Google OAuth callback.
    """
    SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

    query_params = st.query_params
    auth_code = query_params.get("code", [None])[0]
    if auth_code:
        st.write("Debug: Received authorization code.")
        flow = InstalledAppFlow.from_client_config(
            CLIENT_CONFIG, SCOPES
        )
        flow.redirect_uri = MAIN_REDIRECT_URI
        try:
            flow.fetch_token(code=auth_code)
            creds = flow.credentials
            st.session_state.creds = creds
            with open("token.json", "w") as token_file:
                token_file.write(creds.to_json())
            st.write("Debug: Token fetched successfully.")

            user_email = get_user_info(creds)
            st.session_state.user_email = user_email
            st.experimental_set_query_params()  # Clear query params
            st.success(f"Logged in as {user_email}")
            st.experimental_rerun()
        except Exception as e:
            st.error(f"Error fetching token: {e}")
            st.write(f"Debug: Error details: {e}")
    else:
        st.error("Authorization code not found in query parameters.")
        st.write("Debug: Query parameters:", st.query_params)

def fetch_credentials():
    """
    Fetches credentials using the authorization code from the query parameters.
    """
    auth_code = st.query_params.get('code', None)
    if auth_code:
        logger.info("Fetching credentials with authorization code.")
        flow = InstalledAppFlow.from_client_config(
            CLIENT_CONFIG, SCOPES
        )
        flow.redirect_uri = MAIN_REDIRECT_URI
        flow.fetch_token(code=auth_code)
        creds = flow.credentials

        # Save credentials to session state and token.json
        st.session_state.creds = creds
        with open('token.json', 'w') as token_file:
            token_file.write(creds.to_json())

        # Get user email
        user_email = get_user_info(creds)
        st.session_state.user_email = user_email
        st.experimental_set_query_params()  # Clear query parameters
        st.success(f"Logged in as {user_email}")
        st.experimental_rerun()
    else:
        st.error("Authorization code not found in query parameters.")




# Initialize Pinecone
PINECONE_API_KEY = st.secrets["PINECONE_API_KEY"]
pc = Pinecone(api_key=PINECONE_API_KEY)
index_name = "mails"
index = pc.Index(index_name)

# Initialize OpenAI
openai_client = OpenAI(api_key=st.secrets["OPENAI_API_KEY"])

# Super Admin Credentials
SUPER_ADMIN_EMAIL = "darko.radiceski@gmail.com"
SUPER_ADMIN_PASSWORD = "Myfittech1!!!!"

# Initialize session state variables
if "google_credentials" not in st.session_state:
    st.session_state.google_credentials = None
if "is_super_admin" not in st.session_state:
    st.session_state.is_super_admin = False
if "connected_accounts" not in st.session_state:
    st.session_state.connected_accounts = {}
if "organisations" not in st.session_state:
    st.session_state.organisations = {}
if "invitations" not in st.session_state:
    st.session_state.invitations = {}
if "user_activities" not in st.session_state:
    st.session_state.user_activities = []
if "selected_account" not in st.session_state:
    st.session_state.selected_account = None
if "organisation_id" not in st.session_state:
    st.session_state.organisation_id = None
if "bank_data" not in st.session_state:
    st.session_state.bank_data = {}
if "page" not in st.session_state:
    st.session_state.page = "login"



def get_user_info(creds):
    """
    Fetches the user's profile information using the Gmail API.
    """
    try:
        service = build("oauth2", "v2", credentials=creds)
        user_info = service.userinfo().get().execute()
        return user_info.get("email", "Unknown User")
    except Exception as e:
        st.error(f"Failed to fetch user information: {e}")
        return None


# Error logging
def log_error(error_message):
    timestamp = datetime.datetime.now().isoformat()
    error_entry = {
        "timestamp": timestamp,
        "error": error_message
    }
    st.session_state.error_logs.append(error_entry)
    with open("error_log.txt", "a") as error_file:
        error_file.write(json.dumps(error_entry) + "\\n")

# Activity logging
def log_activity(user_email, activity, details=None):
    timestamp = datetime.datetime.now().isoformat()
    activity_entry = {
        "email": user_email,
        "activity": activity,
        "details": details,
        "timestamp": timestamp
    }
    st.session_state.user_activities.append(activity_entry)
    with open("activity_log.txt", "a") as activity_file:
        activity_file.write(json.dumps(activity_entry) + "\\n")

def authenticate_user():
    """
    Handles OAuth callback and fetches credentials after Google login.
    """
    auth_code = st.query_params.get('code', None)
    if auth_code is not None:
        from utility import CLIENT_CONFIG

        # Create a new flow to fetch tokens
        flow = InstalledAppFlow.from_client_config(CLIENT_CONFIG, SCOPES)
        flow.redirect_uri = MAIN_REDIRECT_URI

        try:
            flow.fetch_token(code=auth_code)
            creds = flow.credentials

            if creds:
                # Store credentials in session state and token.json
                st.session_state.creds = creds
                with open('token.json', 'w') as token_file:
                    token_file.write(creds.to_json())
                st.success("Successfully authenticated!")

                # Get and store user email
                user_email = get_user_info(creds)
                st.session_state.user_email = user_email

                # Clear query parameters and reload
                st.experimental_set_query_params()
                st.experimental_rerun()
        except Exception as e:
            st.error(f"Authentication failed: {e}")
    else:
        st.warning("Authorization code not found. Please ensure you authorized the application.")



# Fetch emails and subscriptions
def fetch_emails(service, start_date, end_date):
    try:
        query = f"after:{start_date} before:{end_date}"
        emails = []
        results = service.users().messages().list(userId='me', q=query, maxResults=100).execute()
        while results:
            messages = results.get('messages', [])
            for message in messages:
                msg = service.users().messages().get(userId='me', id=message['id']).execute()
                headers = msg.get('payload', {}).get('headers', [])
                body = base64.urlsafe_b64decode(msg.get('payload', {}).get('body', {}).get('data', '')).decode('utf-8')
                emails.append({
                    "text": body,
                    "id": msg['id'],
                    "subject": next((header['value'] for header in headers if header['name'] == 'Subject'), ''),
                    "from": next((header['value'] for header in headers if header['name'] == 'From'), ''),
                    "date": next((header['value'] for header in headers if header['name'] == 'Date'), '')
                })
            if 'nextPageToken' in results:
                results = service.users().messages().list(userId='me', q=query, maxResults=100,
                                                          pageToken=results['nextPageToken']).execute()
            else:
                break
        log_activity(st.session_state.selected_account, "Fetched emails", {"count": len(emails)})
        return emails
    except Exception as e:
        log_error(f"Error fetching emails: {e}")
        return []

# Organisation and Namespace Management
def handle_organisation_creation():
    user_email = st.session_state.connected_accounts.get(st.session_state.selected_account, {}).get("email", "")
    user_limit = st.session_state.user_organisation_limits.get(user_email, 1)
    user_org_count = sum(1 for org in st.session_state.organisations.values() if user_email in org.get("users", []))
    if user_org_count >= user_limit:
        st.warning("You have reached your organisation creation limit. Contact the Super Admin to request an upgrade.")
        return False
    return True

def create_organisation():
    st.title("Create Organization")
    org_name = st.text_input("Organization Name")
    org_description = st.text_area("Organization Description")
    
    if st.button("Create Organization"):
        org_id = str(uuid.uuid4())
        user_email = st.session_state.google_credentials and get_user_info(st.session_state.google_credentials)
        st.session_state.organisations[org_id] = {
            "name": org_name,
            "description": org_description,
            "users": [user_email],
            "namespace": org_id,
            "email_accounts_with_data": 0,
            "bank_accounts_uploaded": 0
        }
        st.success(f"Organization '{org_name}' created successfully!")


# Super Admin Dashboard
if st.session_state.is_super_admin:
    st.title("Super Admin Dashboard")
    st.write("## Organisations Overview")
    for org_id, org_data in st.session_state.organisations.items():
        st.write(f"### Organisation ID: {org_id}")
        st.write(f"Name: {org_data['name']}")
        st.write(f"Namespace: {org_data.get('namespace', 'N/A')}")
        st.write(f"Email Accounts: {org_data.get('email_accounts_with_data', 0)}")
        st.write(f"Bank Accounts: {org_data.get('bank_accounts_uploaded', 0)}")

# Additional code to process bank statements and correlate subscriptions from email and bank data
# Process Bank Statements




def upload_and_process_bank_statement(org_id):
    """
    Upload and process a CSV file for bank account data.
    Identifies potential subscriptions based on recurring charges.
    """
    st.title("Upload Bank Statement")

    uploaded_file = st.file_uploader("Upload CSV File", type=["csv"])

    if uploaded_file:
        try:
            # Load the CSV file into a DataFrame
            df = pd.read_csv(uploaded_file)

            # Validate required columns
            required_columns = ["Description", "Amount", "Date"]
            missing_columns = [col for col in required_columns if col not in df.columns]
            if missing_columns:
                st.error(f"Missing required columns: {', '.join(missing_columns)}")
                return

            # Convert Date column to datetime with `dayfirst=True`
            df["Date"] = pd.to_datetime(df["Date"], errors="coerce", dayfirst=True)
            if df["Date"].isna().any():
                st.error("Invalid date format detected. Please ensure all dates are valid.")
                return

            # Extract Month-Year for grouping
            df["Month"] = df["Date"].dt.to_period("M")

            # Group by Description and Amount, check for repeated charges across months
            subscriptions = []
            grouped = df.groupby(["Description", "Amount"])
            for (description, amount), group in grouped:
                unique_months = group["Month"].nunique()
                if unique_months > 2:  # Subscription-like pattern: appears in at least 3 months
                    subscriptions.append({
                        "Merchant": description,
                        "Amount": amount,
                        "Occurrences": unique_months,
                        "First Charge": group["Date"].min().strftime("%Y-%m-%d"),
                        "Last Charge": group["Date"].max().strftime("%Y-%m-%d")
                    })

            # Save processed subscriptions to session state
            if org_id not in st.session_state.bank_data:
                st.session_state.bank_data[org_id] = []
            st.session_state.bank_data[org_id].extend(subscriptions)

            # Display results
            st.success(f"Identified {len(subscriptions)} potential subscriptions!")
            if subscriptions:
                st.write("### Identified Subscriptions")
                st.dataframe(pd.DataFrame(subscriptions))

        except Exception as e:
            st.error(f"An error occurred while processing the file: {e}")
    else:
        st.info("Please upload a CSV file to process.")





# Upsert Data to Pinecone
def upsert_data_to_pinecone(data, organisation_id, source_type):
    namespace = organisation_id
    vectors = []
    for item in data:
        embedding = openai_client.embeddings.create(input=[item["service"]], model="text-embedding-ada-002").data[0].embedding
        vectors.append({
            "id": hashlib.sha256(f"{item['service']}-{source_type}".encode()).hexdigest(),
            "values": embedding,
            "metadata": {
                "organisation_id": organisation_id,
                "source": source_type,
                "service": item["service"],
                "amount": item.get("amount", 0),
                "date": item.get("date", ""),
                "confidence": item.get("confidence", 0.0)
            }
        })
    try:
        index.upsert(vectors=vectors, namespace=namespace)
        st.success(f"Uploaded {len(vectors)} vectors to Pinecone for namespace {namespace}.")
    except Exception as e:
        log_error(f"Error upserting data to Pinecone: {e}")
        st.error("There was an error storing the data in Pinecone.")

# Handle False Positives
def mark_as_false_positive(item_id, organisation_id):
    try:
        namespace = organisation_id
        index.delete(ids=[item_id], namespace=namespace)
        log_activity(st.session_state.selected_account, "Marked as false positive", {"item_id": item_id})
        st.success(f"Item {item_id} marked as false positive and removed.")
    except Exception as e:
        log_error(f"Error marking as false positive: {e}")
        st.error("Failed to mark the item as false positive.")
# Correlate Email and Bank Data
def correlate_email_and_bank_data(email_data, bank_data):
    correlated_subscriptions = []
    try:
        for email in email_data:
            for bank in bank_data:
                if email["text"] in bank["service"]:
                    correlated_subscriptions.append({
                        "service": bank["service"],
                        "email_subject": email["subject"],
                        "email_date": email["date"],
                        "bank_date": bank["date"],
                        "amount": bank["amount"],
                        "confidence": 0.9
                    })
        log_activity(st.session_state.selected_account, "Correlated email and bank data", {"matches": len(correlated_subscriptions)})
        return correlated_subscriptions
    except Exception as e:
        log_error(f"Error correlating email and bank data: {e}")
        st.error("Failed to correlate email and bank data. Please try again.")
        return []


def super_user_login():
    st.title("Super Admin Login")

    # Input fields for login
    email = st.text_input("Enter your email")
    password = st.text_input("Enter your password", type="password", help="Super admin credentials")

    # Hardcoded super admin credentials (replace with secure method)
    super_user_credentials = {
        "admin@example.com": hashlib.sha256("superpassword".encode()).hexdigest()
    }

    if st.button("Login as Super Admin"):
        if email in super_user_credentials:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            if super_user_credentials[email] == hashed_password:
                st.session_state.is_super_admin = True
                st.success("Logged in as Super Admin!")
                st.session_state.page = "super_admin_dashboard"
            else:
                st.error("Invalid password!")
        else:
            st.error("Invalid email for Super Admin!")


def generate_invitation_link(org_id):
    """
    Generates a unique invite link for a specific organization.
    """
    invite_token = str(uuid.uuid4())
    base_url = "https://kodosh.streamlit.app"
    invite_link = f"{base_url}/invite?org_id={org_id}&token={invite_token}"

    if "invitations" not in st.session_state:
        st.session_state.invitations = {}
    st.session_state.invitations[invite_token] = org_id

    return invite_link


def google_login():
    """
    Handles Google OAuth for Gmail access, using the correct redirect_uri.
    """
    SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

    # OAuth client configuration from Streamlit secrets
    client_config = {
        "web": {
            "client_id": st.secrets["GMAIL_API_CREDENTIALS"]["CLIENT_ID"],
            "client_secret": st.secrets["GMAIL_API_CREDENTIALS"]["CLIENT_SECRET"],
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": ["https://kodosh.streamlit.app/api/auth/google/callback"]
        }
    }

    flow = InstalledAppFlow.from_client_config(client_config, SCOPES)
    flow.redirect_uri = "https://kodosh.streamlit.app/api/auth/google/callback"

    # Generate and display the authorization URL
    auth_url, _ = flow.authorization_url(prompt="consent", access_type="offline")
    st.write("### Connect Gmail")
    st.markdown(f"[Click here to authorize Gmail access]({auth_url})", unsafe_allow_html=True)

    # Handle the OAuth callback
    query_params = st.query_params  # Fetch query parameters from the URL
    auth_code = query_params.get("code", [None])[0]
    if auth_code:
        try:
            flow.fetch_token(code=auth_code)
            creds = flow.credentials
            st.session_state.google_credentials = creds  # Store credentials in session state
            st.success("Gmail account connected successfully!")
        except Exception as e:
            st.error(f"Failed to connect Gmail: {e}")




def super_admin_organisation_management():
    st.title("Super Admin Organization Management")

    if "organisations" not in st.session_state or not st.session_state.organisations:
        st.info("No organizations available to manage.")
        return

    for org_id, org_data in st.session_state.organisations.items():
        st.write(f"### Organization: {org_data['name']}")
        st.write(f"- Namespace: {org_data.get('namespace', 'N/A')}")
        st.write(f"- Email Accounts with Data: {org_data.get('email_accounts_with_data', 0)}")
        st.write(f"- Bank Accounts Uploaded: {org_data.get('bank_accounts_uploaded', 0)}")
        st.write(f"- Users: {', '.join(org_data.get('users', []))}")
        if st.button(f"Delete Organization {org_data['name']}", key=org_id):
            delete_organisation(org_id)

def delete_organisation(org_id):
    try:
        namespace = st.session_state.organisations[org_id]["namespace"]
        index.delete(namespace=namespace)  # Assumes Pinecone integration
        del st.session_state.organisations[org_id]
        st.success(f"Deleted organization {org_id} and its associated data.")
    except Exception as e:
        log_error(f"Error deleting organization {org_id}: {e}")
        st.error(f"Failed to delete organization {org_id}.")


# Display Subscriptions
def display_subscriptions(subscriptions):
    st.write("## Identified Subscriptions")
    if subscriptions:
        for subscription in subscriptions:
            st.write(f"- **Service:** {subscription['service']}")
            st.write(f"  - **Email Subject:** {subscription.get('email_subject', 'N/A')}")
            st.write(f"  - **Email Date:** {subscription.get('email_date', 'N/A')}")
            st.write(f"  - **Bank Date:** {subscription.get('bank_date', 'N/A')}")
            st.write(f"  - **Amount:** {subscription.get('amount', 'N/A')}")
            st.write(f"  - **Confidence:** {subscription['confidence']:.2f}")
            if st.button(f"Mark as False Positive", key=subscription["service"]):
                mark_as_false_positive(subscription["service"], st.session_state.organisation_id)
    else:
        st.write("No subscriptions identified yet.")

# UI for Uploading Bank Data
def upload_bank_statement_ui():
    st.write("## Upload Bank Statement")
    uploaded_file = st.file_uploader("Upload your bank statement (CSV format)", type="csv")
    if uploaded_file:
        organisation_id = st.session_state.organisation_id
        processed_data = upload_and_process_bank_statement(uploaded_file, organisation_id)
        display_subscriptions(processed_data)

# UI for Managing Subscriptions
def manage_subscriptions_ui():
    st.write("## Manage Subscriptions")
    
    # Ensure selected_account is set and exists in connected_accounts
    if st.session_state.selected_account is None or st.session_state.selected_account not in st.session_state.connected_accounts:
        st.error("No account selected or the selected account is not connected. Please connect an account first.")
        return  # Exit the function if prerequisites are not met

    try:
        # Build the Gmail service using the selected account credentials
        gmail_service = build('gmail', 'v1', credentials=st.session_state.connected_accounts[st.session_state.selected_account])
        
        # Fetch emails within the specified date range
        email_data = fetch_emails(gmail_service, "2023-01-01", "2023-12-31")
        
        # Retrieve bank data for the active organization
        bank_data = st.session_state.bank_data.get(st.session_state.organisation_id, [])
        
        # Correlate email and bank data
        correlated_data = correlate_email_and_bank_data(email_data, bank_data)
        
        # Display the correlated subscriptions
        display_subscriptions(correlated_data)
    except Exception as e:
        log_error(f"Error in manage_subscriptions_ui: {e}")
        st.error("An error occurred while managing subscriptions. Please try again.")


# Delete Organisation
def delete_organisation(organisation_id):
    try:
        namespace = st.session_state.organisations[organisation_id]["namespace"]
        index.delete(namespace=namespace)
        del st.session_state.organisations[organisation_id]
        log_activity(SUPER_ADMIN_EMAIL, "Deleted organisation", {"organisation_id": organisation_id})
        st.success(f"Deleted organisation {organisation_id} and its associated data.")
    except Exception as e:
        log_error(f"Error deleting organisation {organisation_id}: {e}")
        st.error(f"Failed to delete organisation {organisation_id}.")

# Super Admin Adjust User Limits
def super_admin_adjust_user_limits():
    st.write("## Adjust User Organisation Limits")
    for email, current_limit in st.session_state.user_organisation_limits.items():
        st.write(f"### User: {email}")
        new_limit = st.number_input(f"Set new limit for {email}", value=current_limit, step=1, key=email)
        if st.button(f"Update Limit for {email}", key=f"limit-{email}"):
            st.session_state.user_organisation_limits[email] = new_limit
            log_activity(SUPER_ADMIN_EMAIL, "Updated user limit", {"email": email, "new_limit": new_limit})
            st.success(f"Updated limit for {email} to {new_limit}.")
# User Dashboard for Organisation Management
def user_dashboard():
    st.write("## Organisation Dashboard")
    if not st.session_state.organisation_id:
        st.write("You are not part of an organisation. Create or join an organisation to proceed.")
        return

    org_id = st.session_state.organisation_id
    org_data = st.session_state.organisations.get(org_id, {})
    st.write(f"### Organisation: {org_data.get('name', 'Unknown')}")
    st.write(f"- Namespace: {org_data.get('namespace', 'N/A')}")
    st.write(f"- Email Accounts with Data: {org_data.get('email_accounts_with_data', 0)}")
    st.write(f"- Bank Accounts Uploaded: {org_data.get('bank_accounts_uploaded', 0)}")

    st.write("### Manage Users")
    users = org_data.get("users", [])
    for user in users:
        st.write(f"- {user}")
    if st.button("Invite New User"):
        invite_link = generate_invite_link(org_id)
        st.success(f"Invite link generated: {invite_link}")

# Generate Invite Link for New Users
def generate_invite_link(org_id):
    base_url = "https://kodosh.streamlit.app"
    return f"{base_url}/invite?org_id={org_id}"

# Organisation Invitation Handling
def handle_organisation_invite(org_id, invited_user_email):
    if org_id in st.session_state.organisations:
        org_data = st.session_state.organisations[org_id]
        if invited_user_email not in org_data["users"]:
            org_data["users"].append(invited_user_email)
            st.session_state.organisations[org_id] = org_data
            log_activity(SUPER_ADMIN_EMAIL, "User invited to organisation", {"organisation_id": org_id, "email": invited_user_email})
            st.success(f"User {invited_user_email} has been added to the organisation.")
        else:
            st.warning(f"User {invited_user_email} is already a member of the organisation.")
    else:
        st.error("Invalid organisation ID.")
# View Error Logs
def view_error_logs():
    st.write("## Error Logs")
    if st.session_state.error_logs:
        for error in st.session_state.error_logs:
            st.write(f"- **Timestamp:** {error['timestamp']}")
            st.write(f"  - **Error:** {error['error']}")
            st.write("---")
    else:
        st.write("No errors logged yet.")

# View User Activities
def view_user_activities():
    st.write("## User Activity Logs")
    if st.session_state.user_activities:
        for activity in st.session_state.user_activities:
            st.write(f"- **Timestamp:** {activity['timestamp']}")
            st.write(f"  - **User Email:** {activity['email']}")
            st.write(f"  - **Activity:** {activity['activity']}")
            if activity.get("details"):
                st.write(f"  - **Details:** {json.dumps(activity['details'], indent=2)}")
            st.write("---")
    else:
        st.write("No user activities logged yet.")

def create_organization(name, description):
    """
    Creates a new organization and stores it in session state.
    """
    if not name:
        st.error("Organization name is required!")
        return
    org_id = str(uuid.uuid4())
    st.session_state.organisations[org_id] = {
        "name": name,
        "description": description,
        "users": [],
        "email_accounts_with_data": 0,
        "bank_accounts_uploaded": 0,
    }
    st.success(f"Organization '{name}' created successfully!")

def delete_organization(org_id):
    """
    Deletes an organization from session state.
    """
    try:
        del st.session_state.organisations[org_id]
        st.success("Organization deleted successfully!")
    except KeyError:
        st.error("Organization not found!")



def super_admin_dashboard():
    """
    Super Admin Dashboard with functionalities to manage organizations,
    invite users, upload and view bank data, and connect Gmail accounts for email scanning.
    """
    st.title("Super Admin Dashboard")

    # Tabs for managing functionalities
    tabs = st.tabs([
        "Manage Organizations",
        "Invite Users",
        "Upload Bank Data",
        "View Subscriptions",
        "Connect Gmail"
    ])

    # Tab 1: Manage Organizations
    with tabs[0]:
        st.header("Manage Organizations")
        org_name = st.text_input("Organization Name", key="org_name")
        org_description = st.text_area("Organization Description", key="org_description")

        if st.button("Create Organization", key="create_org_button"):
            create_organization(org_name, org_description)

        # Display existing organizations
        st.write("### Existing Organizations")
        for org_id, org_data in st.session_state.organisations.items():
            st.write(f"**{org_data['name']}** - {org_data['description']}")
            if st.button(f"Delete {org_data['name']}", key=f"delete_{org_id}"):
                delete_organization(org_id)

    # Tab 2: Invite Users
    with tabs[1]:
        st.header("Invite Users")
        org_id = st.selectbox("Select Organization", list(st.session_state.organisations.keys()), key="invite_org_id")
        if org_id:
            if st.button("Generate Invite Link", key="generate_invite_link"):
                invite_link = generate_invitation_link(org_id)
                st.success(f"Invite link: {invite_link}")

    # Tab 3: Upload Bank Data
    with tabs[2]:
        st.header("Upload Bank Statement")
        org_id = st.selectbox("Select Organization for Upload", list(st.session_state.organisations.keys()), key="upload_org_id")
        if org_id:
            upload_and_process_bank_statement(org_id)

    # Tab 4: View Subscriptions
    with tabs[3]:
        st.header("View Subscriptions")
        org_id = st.selectbox("Select Organization to View Subscriptions", list(st.session_state.organisations.keys()), key="view_org_id")
        if org_id:
            view_identified_subscriptions(org_id)

    # Tab 5: Connect Gmail
    with tabs[4]:
        st.header("Connect Gmail Account for Email Scanning")
        org_id = st.selectbox("Select Organization to Connect Gmail", list(st.session_state.organisations.keys()), key="gmail_org_id")
        if org_id:
            google_login()



def view_identified_subscriptions(org_id):
    """
    Display identified subscriptions for a specific organization.
    """
    st.title("Identified Subscriptions")

    if org_id not in st.session_state.bank_data or not st.session_state.bank_data[org_id]:
        st.info("No subscriptions identified yet. Please upload and process bank statements.")
        return

    subscriptions = st.session_state.bank_data[org_id]
    df = pd.DataFrame(subscriptions)
    st.write(f"### Subscriptions for Organization ID: {org_id}")
    st.dataframe(df)

def main():
    """
    Main function for the application, including user login, Super Admin login,
    and post-login functionalities.
    """
    if "page" not in st.session_state:
        st.session_state.page = "login"

    if "creds" not in st.session_state:
        st.session_state.creds = None
        st.session_state.user_email = None

    # Handle login page
    if st.session_state.page == "login":
        st.title("Login to the Application")
        login_option = st.radio("Login as", ["User", "Super Admin"])

        if login_option == "User":
            if not st.session_state.creds:
                st.write("### Google Login")
                authorize_gmail_api()  # Generate authorization link
                authenticate_user()   # Handle callback and fetch credentials
            else:
                st.success(f"Welcome back, {st.session_state.user_email}!")
                # Navigate to the user dashboard or other user-specific pages
                st.session_state.page = "user_dashboard"
                st.experimental_rerun()

        elif login_option == "Super Admin":
            super_admin_login()  # Existing Super Admin login functionality

    # Handle Super Admin Dashboard
    elif st.session_state.page == "super_admin_dashboard" and st.session_state.is_super_admin:
        super_admin_dashboard()

    # Handle User Dashboard
    elif st.session_state.page == "user_dashboard":
        if st.session_state.user_email:
            st.title("User Dashboard")
            st.write(f"Welcome, {st.session_state.user_email}!")
            st.write("This is your user dashboard.")
            # Add any user-specific functionalities here
        else:
            st.error("Session expired. Please log in again.")
            st.session_state.page = "login"
            st.experimental_rerun()

    # Default behavior for undefined states
    else:
        st.title("Welcome to the App")
        st.write("Please log in to access the application.")





EMAIL = "admin@example.com"
PASSWORD_HASH = "34819d7beeabb9260a5c854bc85b3e44"



import hashlib

def super_admin_login():
    """
    Handles secure super admin login with hardcoded credentials.
    """
    st.title("Super Admin Login")

    # Hardcoded credentials
    super_admin_email = "admin@example.com"
    super_admin_password = "superpassword"

    # Input fields for email and password
    email = st.text_input("Enter your email", key="super_admin_email")
    password = st.text_input("Enter your password", type="password", key="super_admin_password")

    # Compare input with hardcoded credentials
    if st.button("Login as Super Admin"):
        if email == super_admin_email and password == super_admin_password:
            st.session_state.is_super_admin = True
            st.session_state.page = "super_admin_dashboard"
            st.success("Logged in as Super Admin!")
        else:
            st.error("Invalid email or password!")








# Start the application
if __name__ == "__main__":
    main()
