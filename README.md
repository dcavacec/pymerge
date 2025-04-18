# Authorization

The following environment variables need to be set before running. 

export CLIENT_ID="YOUR_CLIENT_ID"
export AUTH_URI="https://accounts.google.com/o/oauth2/auth"
export TOKEN_URI="https://oauth2.googleapis.com/token"
export AUTH_PROVIDER_X509_CERT_URL="https://www.googleapis.com/oauth2/v1/certs"
export CLIENT_SECRET="YOUR_CLIENT_SECRET"
export REDIRECT_URIS='["http://localhost"]'

These correspond to the data in your OAuth 2.0 clients, which can be viewed and downloaded from the APIs + Services Credentials section of Google Cloud console. 

# Flask Web App Starter

A Flask starter template as per [these docs](https://flask.palletsprojects.com/en/3.0.x/quickstart/#a-minimal-application).

## Getting Started

Previews should run automatically when starting a workspace.