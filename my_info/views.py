import json
import os
from django.shortcuts import render
from django.http import JsonResponse
from my_info.utils.security import generate_code_challenge
from my_info.utils.logging_utils import logger
from my_info.utils.client import MyInfoPersonalClientV4
from my_info.config import APP_CONFIG, MYINFO_CONNECTOR_CONFIG

session_ids = {}

def index(request):
    return render(request, 'index.html')


def getenv(request):
    try:
        if not APP_CONFIG.get("DEMO_APP_CLIENT_ID"):
            return JsonResponse({"error": "Missing Client ID"}, status=500)

        return JsonResponse({
            "clientId": APP_CONFIG.get("DEMO_APP_CLIENT_ID"),
            "redirectUrl": APP_CONFIG.get("DEMO_APP_CALLBACK_URL"),
            "scope": APP_CONFIG.get("DEMO_APP_SCOPES"),
            "purpose_id": APP_CONFIG.get("DEMO_APP_PURPOSE_ID"),
            "authApiUrl": APP_CONFIG.get("MYINFO_API_AUTHORIZE"),
            "subentity": APP_CONFIG.get("DEMO_APP_SUBENTITY_ID"),
        })
    except Exception as e:
        logger.error("Error: %s", e)
        return JsonResponse({"error": str(e)}, status=500)


def callback(request):
    return render(request, 'index.html')

def read_files(dirname):
    try:
        files_content = {}
        for filename in os.listdir(dirname):
            with open(os.path.join(dirname, filename), "r", encoding="utf-8") as file:
                files_content[filename] = file.read()
        return files_content
    except Exception as e:
        logger.error("Error: %s", e)
        raise e


def getpersondata(request):
    if request.method == 'POST':
        try:
            body = json.loads(request.body)
            auth_code = body.get("authCode")
            code_verifier = session_ids.get(request.COOKIES.get('sid'))
            client = MyInfoPersonalClientV4()
            person_data = client.retrieve_resource(auth_code, code_verifier, MYINFO_CONNECTOR_CONFIG.get("REDIRECT_URL"))

            return JsonResponse(person_data, safe=False)
        except Exception as e:
            logger.error("Error: %s", e)
            return JsonResponse({"error": str(e)}, status=500)


def gencode(request):
    if request.method == "POST":
        try:
            code_verifier = os.urandom(32).hex()
            code_challenge = generate_code_challenge(code_verifier)

            session_id = os.urandom(16).hex()
            session_ids[session_id] = code_verifier
            response = JsonResponse(code_challenge, safe=False)
            response.set_cookie("sid", session_id)

            return response
        except Exception as e:
            logger.error("Error: %s", e)
            return JsonResponse({"error": str(e)}, status=500)
