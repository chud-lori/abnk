import os

env = os.getenv('ENV')
urlEnvironmentPrefix = "" if env == "prod" else f"{env}."

APP_CONFIG = {
  "DEMO_APP_CLIENT_ID": "STG2-MYINFO-SELF-TEST",
  "DEMO_APP_SUBENTITY_ID": "",
  "DEMO_APP_CLIENT_PRIVATE_SIGNING_KEY": "./cert/your-sample-app-signing-private-key.pem",
  "DEMO_APP_CLIENT_PRIVATE_ENCRYPTION_KEYS": "./cert/encryption-private-keys/",
  "DEMO_APP_CALLBACK_URL": "http://localhost:3001/callback",
  "DEMO_APP_PURPOSE_ID": "demonstration",
  "DEMO_APP_SCOPES" : "uinfin name sex race nationality dob email mobileno regadd housingtype hdbtype marital edulevel noa-basic ownerprivate cpfcontributions cpfbalances",
  "MYINFO_API_AUTHORIZE": f"https://{urlEnvironmentPrefix}api.myinfo.gov.sg/com/v4/authorize"
}

MYINFO_CONNECTOR_CONFIG = {
  "CLIENT_ID": APP_CONFIG["DEMO_APP_CLIENT_ID"],
  "SUBENTITY_ID": APP_CONFIG["DEMO_APP_SUBENTITY_ID"],
  "REDIRECT_URL": APP_CONFIG["DEMO_APP_CALLBACK_URL"],
  "SCOPE" : APP_CONFIG["DEMO_APP_SCOPES"],
  "AUTHORIZE_JWKS_URL": f"https://{urlEnvironmentPrefix}authorise.singpass.gov.sg/.well-known/keys.json",
  "MYINFO_JWKS_URL": f"https://{urlEnvironmentPrefix}authorise.singpass.gov.sg/.well-known/keys.json",
  "TOKEN_URL": f"https://{urlEnvironmentPrefix}api.myinfo.gov.sg/com/v4/token",
  "PERSON_URL": f"https://{urlEnvironmentPrefix}api.myinfo.gov.sg/com/v4/person",
  "CLIENT_ASSERTION_SIGNING_KID" :'', # optional parameter to specify specific kid for signing. Default will be thumbprint of JWK
  "USE_PROXY": "N",
  "PROXY_TOKEN_URL": "",
  "PROXY_PERSON_URL": "",
  "DEBUG_LEVEL": "info"
}
