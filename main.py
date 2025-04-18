from mail_merge import create_drafts, send_emails
import sys

if __name__ == "__main__":
    spreadsheet_id = sys.argv[1]
    sheet_name = sys.argv[2]
    subject_line = sys.argv[3]
    from_email = sys.argv[4]

    if len(sys.argv) > 5 and sys.argv[5] == "True":
        send_emails(spreadsheet_id, sheet_name, subject_line, from_email)
    else:
        create_drafts(spreadsheet_id, sheet_name, subject_line, from_email)