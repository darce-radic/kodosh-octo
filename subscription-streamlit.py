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
MAIN_REDIRECT_URI = "https://kodosh.streamlit.app"

CLIENT_CONFIG = {
    "web": {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": [MAIN_REDIRECT_URI],
        "javascript_origins": ["https://kodosh.streamlit.app"]
    }
}





def authorize_gmail_api():
    """
    Handles the Google OAuth process for Gmail access.
    """
    creds = None
    # Check if token.json exists to reuse credentials
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
        if creds and creds.valid:
            st.success("Already logged in.")
            return creds

    # No valid credentials, start OAuth flow
    flow = InstalledAppFlow.from_client_config(CLIENT_CONFIG, SCOPES)
    flow.redirect_uri = MAIN_REDIRECT_URI

    # Generate the authorization URL
    auth_url, _ = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent"
    )

    st.markdown(f"[Click here to authorize with Google]({auth_url})", unsafe_allow_html=True)

    # Handle the authorization code input
    auth_code = st.text_input("Enter the authorization code here:")
    if auth_code:
        flow.fetch_token(code=auth_code)
        creds = flow.credentials
        if creds:
            # Save credentials for future use
            with open("token.json", "w") as token_file:
                token_file.write(creds.to_json())

            # Store credentials in session state
            st.session_state.google_credentials = creds
            st.success("Authorization successful!")
            return creds
        else:
            st.error("Authorization failed. Please try again.")

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

# Initialize session state variables with default values if not already set
if "is_super_admin" not in st.session_state:
    st.session_state.is_super_admin = False  # Default to non-admin users
if "connected_accounts" not in st.session_state:
    st.session_state.connected_accounts = {}
if "organisations" not in st.session_state:
    st.session_state.organisations = {}
if "error_logs" not in st.session_state:
    st.session_state.error_logs = []
if "user_activities" not in st.session_state:
    st.session_state.user_activities = []
if "selected_account" not in st.session_state:
    st.session_state.selected_account = None
if "organisation_id" not in st.session_state:
    st.session_state.organisation_id = None
if "user_organisation_limits" not in st.session_state:
    st.session_state.user_organisation_limits = {}
if "bank_data" not in st.session_state:
    st.session_state.bank_data = {}

def get_user_info(creds):
    """Retrieve user email using OAuth2 credentials."""
    try:
        oauth2_service = build('oauth2', 'v2', credentials=creds)
        user_info = oauth2_service.userinfo().get().execute()
        return user_info.get('email')
    except Exception as e:
        log_error(f"Error fetching user info: {e}")
        st.error("Failed to fetch user info. Please re-authenticate.")
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

# Authenticate user
def authenticate_user():
    auth_code = st.query_params.get('code', None)
    if auth_code:
        try:
            flow = InstalledAppFlow.from_client_config(CLIENT_CONFIG, SCOPES)
            flow.redirect_uri = MAIN_REDIRECT_URI
            flow.fetch_token(code=auth_code)
            creds = flow.credentials
            if creds:
                user_info = get_user_info(creds)
                email = user_info.get('email')
                if email not in st.session_state.connected_accounts:
                    st.session_state.connected_accounts[email] = creds
                    log_activity(email, "User authenticated")
                    st.success(f"Successfully connected to {email}")
                else:
                    st.warning(f"{email} is already connected.")
                st.experimental_rerun()
        except Exception as e:
            log_error(f"Error during authentication: {e}")
            st.error("Authentication failed. Please try again.")
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
    organisation_name = st.text_input("Organisation Name", value="")
    organisation_description = st.text_area("Organisation Description", value="")
    if st.button("Create Organisation"):
        if handle_organisation_creation():
            org_id = str(uuid.uuid4())
            user_email = st.session_state.connected_accounts.get(st.session_state.selected_account, {}).get("email", "")
            st.session_state.organisations[org_id] = {
                "name": organisation_name,
                "description": organisation_description,
                "users": [user_email],
                "email_accounts_with_data": 0,
                "bank_accounts_uploaded": 0,
                "namespace": org_id
            }
            log_activity(user_email, "Created organisation", {"organisation_id": org_id, "name": organisation_name})
            st.success(f"Organisation '{organisation_name}' created successfully.")

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
def upload_and_process_bank_statement(file, organisation_id):
    try:
        # Read CSV and parse relevant data
        df = pd.read_csv(file)
        subscriptions = []
        for _, row in df.iterrows():
            description = row.get("Description", "")
            amount = row.get("Amount", 0)
            date = row.get("Date", "")
            if "subscription" in description.lower() or "recurring" in description.lower():
                subscriptions.append({
                    "service": description,
                    "amount": amount,
                    "date": date,
                    "confidence": 0.85
                })
        # Store parsed subscriptions in Pinecone
        upsert_data_to_pinecone(subscriptions, organisation_id, "bank_data")
        log_activity(st.session_state.selected_account, "Uploaded and processed bank statement", {"rows": len(df)})
        st.success(f"Successfully processed {len(subscriptions)} subscriptions from the uploaded bank statement.")
        return subscriptions
    except Exception as e:
        log_error(f"Error processing bank statement: {e}")
        st.error("There was an error processing the bank statement. Please try again.")

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
    st.title("Super User Login")
    
    # Input fields for email and password
    email = st.text_input("Enter your email")
    password = st.text_input("Enter your password", type="password")
    
    # Securely store super admin credentials (replace with a secure method)
    # Use hashed passwords to compare
    super_user_credentials = {
        "darko.radiceski@gmail.com": hashlib.sha256("Myfittech1!!!!".encode()).hexdigest()
    }

    if st.button("Login"):
        # Check if email is in the super user list
        if email in super_user_credentials:
            # Hash the entered password and compare
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            if super_user_credentials[email] == hashed_password:
                st.session_state.is_super_admin = True
                st.success("Logged in as Super Admin!")
                st.experimental_rerun()
            else:
                st.error("Invalid password for Super User!")
        else:
            st.error("Invalid email for Super User!")


def generate_invitation_link():
    if not st.session_state.is_super_admin:
        st.error("Only super admins can generate invitations!")
        return

    st.title("Generate Invitation Link")
    organization_id = st.selectbox("Select Organization", list(st.session_state.organisations.keys()))
    if st.button("Generate Link"):
        invite_token = str(uuid.uuid4())
        base_url = "https://kodosh.streamlit.app"
        invite_link = f"{base_url}/invite?org_id={organization_id}&token={invite_token}"
        
        # Save the invite token and organization mapping
        if "invitations" not in st.session_state:
            st.session_state.invitations = {}
        st.session_state.invitations[invite_token] = organization_id
        
        st.success(f"Invitation Link: {invite_link}")


def handle_invitation():
    query_params = st.experimental_get_query_params()
    org_id = query_params.get("org_id", [None])[0]
    token = query_params.get("token", [None])[0]
    
    if org_id and token and token in st.session_state.invitations:
        email = st.text_input("Enter your email to join the organization")
        if st.button("Join"):
            if org_id in st.session_state.organisations:
                st.session_state.organisations[org_id]["users"].append(email)
                del st.session_state.invitations[token]  # Remove used token
                st.success(f"Successfully joined organization {org_id}!")
            else:
                st.error("Invalid organization ID!")
    else:
        st.warning("Invalid or expired invitation link!")

def google_login():
    st.title("Connect to Google for Email Processing")
    
    if st.session_state.google_credentials:
        email = get_user_info(st.session_state.google_credentials)
        st.success(f"Connected as {email}")
    else:
        authorize_gmail_api()  # Ensure `authorize_gmail_api()` is implemented

def user_dashboard():
    st.title("User Dashboard")
    if not st.session_state.organisation_id:
        st.info("You are not part of an organization. Please create or join an organization.")
        return

    org_id = st.session_state.organisation_id
    org_data = st.session_state.organisations.get(org_id, {})
    st.write(f"### Organization: {org_data.get('name', 'Unknown')}")
    st.write(f"- Namespace: {org_data.get('namespace', 'N/A')}")
    st.write(f"- Email Accounts with Data: {org_data.get('email_accounts_with_data', 0)}")
    st.write(f"- Bank Accounts Uploaded: {org_data.get('bank_accounts_uploaded', 0)}")

    st.write("### Manage Users")
    users = org_data.get("users", [])
    for user in users:
        st.write(f"- {user}")
    if st.button("Invite New User"):
        invite_link = generate_invitation_link()
        st.success(f"Invite link generated: {invite_link}")



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

# Initialise Application
def main():
    # Initialize session state variables
    if "is_super_admin" not in st.session_state:
        st.session_state.is_super_admin = False
    if "google_credentials" not in st.session_state:
        st.session_state.google_credentials = None
    if "connected_accounts" not in st.session_state:
        st.session_state.connected_accounts = {}
    if "organisations" not in st.session_state:
        st.session_state.organisations = {}
    if "error_logs" not in st.session_state:
        st.session_state.error_logs = []
    if "user_activities" not in st.session_state:
        st.session_state.user_activities = []
    if "selected_account" not in st.session_state:
        st.session_state.selected_account = None
    if "organisation_id" not in st.session_state:
        st.session_state.organisation_id = None
    if "user_organisation_limits" not in st.session_state:
        st.session_state.user_organisation_limits = {}
    if "bank_data" not in st.session_state:
        st.session_state.bank_data = {}
    if "invitations" not in st.session_state:
        st.session_state.invitations = {}

    st.sidebar.title("Navigation")

    # Check if the user is logged in as a super admin
    if not st.session_state.is_super_admin:
        # Display login options
        login_option = st.sidebar.radio("Choose Login Type", ["User Login", "Super Admin Login"])

        if login_option == "User Login":
            google_login()  # Regular user Google login
        elif login_option == "Super Admin Login":
            super_user_login()  # Super admin login
    else:
        # Super Admin Dashboard
        st.sidebar.title("Super Admin Controls")
        if st.sidebar.button("View Organizations"):
            super_admin_organisation_management()
        if st.sidebar.button("Generate Invitations"):
            generate_invitation_link()
        if st.sidebar.button("Adjust User Limits"):
            super_admin_adjust_user_limits()
        if st.sidebar.button("View Error Logs"):
            view_error_logs()
        if st.sidebar.button("View User Activities"):
            view_user_activities()
        if st.sidebar.button("Logout Super Admin"):
            st.session_state.is_super_admin = False
            st.success("Logged out as Super Admin!")
            st.experimental_rerun()

    # Regular user dashboard (if logged in with Google)
    if st.session_state.google_credentials:
        st.sidebar.title("User Controls")
        if st.sidebar.button("Manage Organization"):
            user_dashboard()
        if st.sidebar.button("Upload Bank Statement"):
            upload_bank_statement_ui()
        if st.sidebar.button("Manage Subscriptions"):
            manage_subscriptions_ui()
        if st.sidebar.button("Logout"):
            st.session_state.google_credentials = None
            st.session_state.selected_account = None
            st.success("Logged out successfully!")
            st.experimental_rerun()

    # Fallback if neither super admin nor user logged in
    if not st.session_state.is_super_admin and not st.session_state.google_credentials:
        st.title("Welcome to the Organization and Subscription Management App")
        st.write("Please log in as a user or super admin to continue.")




# Start the application
if __name__ == "__main__":
    main()
