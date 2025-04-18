import json
import os

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from typing import Dict, List
import base64
from datetime import datetime


# If modifying these scopes, delete the file token.json.
SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/gmail.compose",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.readonly",
]
RECIPIENT_COL = "Owner Email"
EMAIL_SENT_COL = "Email Sent"


def load_credentials():
    """Loads or creates user credentials for API access."""
    
    creds = None
    
    if not os.environ.get('CLIENT_ID'):
        print("ERROR: Credentials not configured")
        return None
    
    if os.path.exists("token.json"):
      creds = Credentials.from_authorized_user_file("token.json", SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            client_config = {
                "web": {
                    "client_id": os.environ.get("CLIENT_ID"),
                    "auth_uri": os.environ.get("AUTH_URI"),
                    "token_uri": os.environ.get("TOKEN_URI"),
                    "auth_provider_x509_cert_url": os.environ.get("AUTH_PROVIDER_X509_CERT_URL"),
                    "client_secret": os.environ.get("CLIENT_SECRET"),
                    "redirect_uris": json.loads(os.environ.get("REDIRECT_URIS")),
                }
            }

            flow = InstalledAppFlow.from_client_config(client_config, SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open("token.json", "w") as token:
            token.write(creds.to_json())
    return creds


def get_sheet_data(creds: Credentials, spreadsheet_id: str, sheet_name: str) -> List[Dict]:
    """Fetches data from a Google Sheet."""
    try:
        service = build("sheets", "v4", credentials=creds)
        sheet = service.spreadsheets()
        result = (
            sheet.values()
            .get(spreadsheetId=spreadsheet_id, range=sheet_name)
            .execute()
        )
        values = result.get("values", [])
        if not values:
            return []
        heads = values.pop(0)
        obj = [
            {heads[i]: row[i] for i in range(len(heads))} for row in values
        ]
        return obj
    except HttpError as err:
        print(f"Error in get_sheet_data: {err}")
        return []


def update_sheet_data(
    creds: Credentials, spreadsheet_id: str, sheet_name: str, values: List[List]
) -> None:
    """Updates data in a Google Sheet."""
    try:
        service = build("sheets", "v4", credentials=creds)
        body = {"values": values}
        result = (
            service.spreadsheets()
            .values()
            .update(
                spreadsheetId=spreadsheet_id,
                range=f"{sheet_name}!{EMAIL_SENT_COL}2",
                valueInputOption="USER_ENTERED",
                body=body,
            )
            .execute()
        )
        print(f"Updated {result.get('updatedCells')} cells.")
    except HttpError as err:
        print(f"Error in update_sheet_data: {err}")


def get_gmail_template_from_drafts(creds: Credentials, subject_line: str) -> Dict:
    """Retrieves a Gmail draft based on the subject line."""
    try:
        service = build("gmail", "v1", credentials=creds)
        drafts = service.users().drafts().list(userId="me").execute().get("drafts")
        if not drafts:
            raise ValueError("No drafts found.")

        for draft in drafts:
            draft_data = (
                service.users()
                .drafts()
                .get(userId="me", id=draft["id"], format="full")
                .execute()
            )
            message_data = draft_data["message"]
            message_payload = message_data["payload"]
            headers = message_payload["headers"]
            for header in headers:
                if header["name"] == "Subject" and header["value"] == subject_line:
                    message_parts = message_payload.get("parts", [])
                    text_body, html_body, attachments, inline_images = extract_message_content(message_parts, service, "me", draft['message']['id'])

                    return {
                        "message": {"subject": subject_line, "text": text_body, "html": html_body},
                        "attachments": attachments,
                        "inlineImages": inline_images
                    }

        raise ValueError(f"Draft with subject '{subject_line}' not found.")
    except HttpError as err:
        print(f"Error in get_gmail_template_from_drafts: {err}")
        raise
    except ValueError as err:
        print(f"Error in get_gmail_template_from_drafts: {err}")
        raise
    except Exception as err:
        print(f"Unexpected error: {err}")
        raise

def extract_message_content(message_parts, service, user_id, message_id):
    """
    Extracts text body, HTML body, attachments, and inline images from a message payload.
    """
    text_body = ""
    html_body = ""
    attachments = []
    inline_images = {}

    for part in message_parts:
        if part["mimeType"] == "text/plain":
            text_body = base64.urlsafe_b64decode(part["body"]["data"].encode("utf-8")).decode("utf-8")
        elif part["mimeType"] == "text/html":
            html_body = base64.urlsafe_b64decode(part["body"]["data"].encode("utf-8")).decode("utf-8")
        elif part.get("filename"):
            attachment_id = part["body"]["attachmentId"]
            if attachment_id:
                attachment = service.users().messages().attachments().get(
                    userId=user_id, messageId=message_id, id=attachment_id
                ).execute()
                file_data = base64.urlsafe_b64decode(attachment["data"].encode("utf-8"))
                attachment_filename = part["filename"]
                if part.get("headers"):
                  for header in part['headers']:
                    if header['name'] == 'Content-ID':
                      inline_images[header['value'].replace('<','').replace('>','')] = file_data
                      attachment_filename = ''
                if attachment_filename != '':
                  attachments.append((attachment_filename, file_data))

    return text_body, html_body, attachments, inline_images

def fill_in_template_from_object(template: Dict, data: Dict) -> Dict:
    """Fills in placeholders in the email template with data."""
    template_string = json.dumps(template)
    template_string = template_string.replace(
        r"{{[^{}]+}}",
        lambda match: escape_data(data.get(match[2:-2], ""))
    )
    return json.loads(template_string)


def escape_data(str_to_escape: str) -> str:
    """Escapes special characters to make the data JSON safe."""
    return (
        str_to_escape.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("/", "\\/")
        .replace("\b", "\\b")
        .replace("\f", "\\f")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )

def create_message(to, subject, message_text, message_html, attachments, inline_images):
    """
    Creates a message for sending.

    Args:
      to: Email address of the receiver
      subject: The subject of the email message.
      message_text: The plain text of the email message.
      message_html: The HTML content of the email message.
      attachments: A list of tuples with attachment file name and data
      inline_images: A dict with image name as keys and image data as value

    Returns:
      An object containing a base64url encoded email object.
    """
    message = MIMEMultipart()
    message["to"] = to
    message["subject"] = subject

    if message_text:
        message.attach(MIMEText(message_text, "plain"))

    if message_html:
        message.attach(MIMEText(message_html, "html"))
    
    for image_name, image_data in inline_images.items():
        mime_type = "application/octet-stream"
        if image_name.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
          mime_type = 'image/' + image_name.split('.')[-1]
        image = MIMEBase(*mime_type.split('/'))
        image.set_payload(image_data)
        encoders.encode_base64(image)
        image.add_header("Content-ID", f"<{image_name}>")
        image.add_header("Content-Disposition", "inline", filename=image_name)
        message.attach(image)

    for attachment_filename, attachment_data in attachments:
        mime_type = "application/octet-stream"
        if attachment_filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
          mime_type = 'image/' + attachment_filename.split('.')[-1]
        attachment = MIMEBase(*mime_type.split('/'))
        attachment.set_payload(attachment_data)
        encoders.encode_base64(attachment)
        attachment.add_header("Content-Disposition", "attachment", filename=attachment_filename)
        message.attach(attachment)

    return {"raw": base64.urlsafe_b64encode(message.as_bytes()).decode()}


def send_email(creds, user_id, message, is_draft = False):
    """Sends or creates a draft of an email. If is_draft is true, it will save a draft.
    Args:
      user_id: User's email address. The special value "me"
      can be used to indicate the authenticated user.
      message: Message to be sent.
      is_draft: Boolean indicating whether to save as draft.

    Returns:
      Message or draft.
    """
    if is_draft:
        try:
            service = build("gmail", "v1", credentials=creds)
            message = (
                service.users().drafts().create(userId=user_id, body=message).execute()
            )
            return message
        except HttpError as error:
            print("An error occurred: %s" % error)
            return None


    try:
        service = build("gmail", "v1", credentials=creds)
        message = (
            service.users().messages().send(userId=user_id, body=message).execute()
        )
        return message
    except HttpError as error:
        print("An error occurred: %s" % error)
        return None
    
def process_emails(
    spreadsheet_id: str, sheet_name: str, subject_line: str, from_email : str = "srhamadisonwi@gmail.com", send : bool = False
) -> None:
    """
    Processes emails from sheet data.
    Args:
        spreadsheet_id: id of the spreadsheet
        sheet_name: name of the sheet
        send: if we want to send the email or just create a draft.
        subject_line: Subject of the email

    Returns:
        None
    """
    creds = load_credentials()
    try:
        email_template = get_gmail_template_from_drafts(creds, subject_line)
        data = get_sheet_data(creds, spreadsheet_id, sheet_name)
        out = []
        for row_idx, row in enumerate(data):
            if (
                row[RECIPIENT_COL]
                and not row.get(EMAIL_SENT_COL)
            ):
                try:
                    msg_obj = fill_in_template_from_object(
                        email_template["message"], row
                    )
                    message = create_message(
                        row[RECIPIENT_COL],
                        msg_obj["subject"],
                        msg_obj["text"],
                        msg_obj["html"],
                        email_template["attachments"],
                        email_template["inlineImages"],
                    )
                    send_email(creds, "me", message, not send)
                    out.append([datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
                except Exception as e:
                    out.append([e.message])
            else:
                out.append([row.get(EMAIL_SENT_COL, "")])
        update_sheet_data(creds, spreadsheet_id, sheet_name, out)
    except Exception as e:
        print(f"An error has occurred: {e}")

def send_emails(spreadsheet_id: str, sheet_name: str, subject_line: str, from_email : str) -> None:
  process_emails(spreadsheet_id, sheet_name, subject_line, from_email, True)

def create_drafts(spreadsheet_id: str, sheet_name: str, subject_line: str, from_email : str) -> None:
    process_emails(spreadsheet_id, sheet_name, subject_line, from_email)
