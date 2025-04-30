import json
import unittest
from unittest.mock import patch
import django
import os

import responses
from my_info.utils import settings as myinfo_settings
from my_info.config import MYINFO_CONNECTOR_CONFIG
from jwcrypto import jwk, jws
from my_info.utils.security import (
    decrypt_jwe,
    generate_client_assertion,
    generate_dpop_header,
    get_jwkset,
    verify_jws,
)

# load settings
os.environ['DJANGO_SETTINGS_MODULE'] = 'abnk.settings'
django.setup()


SAMPLE_EPHEMERAL_SESSION_KEYPAIR_EXPORT = '{"alg":"ES256","crv":"P-256","d":"-8hBIRHZNsjhM0VLmpvUXnmFJGjwk9D54A292wZIHKc","kty":"EC","use":"sig","x":"hzP7o6QSUsqoEG1_ia7uXKWUxMnLZyDsc_Q_58vX9Gg","y":"UNTaMkOSmhCcZdVbClmKNOYD3i8LJ3yYMNjFCyV8zOk"}'  # noqa: E501


SAMPLE_TOKEN_RESP = {
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IkFGTW5uS1JXVGFCWUVoTmZFQjZpUTVFckMxeXFHVnlaY2hIOEE3bmxfeU0ifQ.eyJzdWIiOiJhZWNjNWFmOS0zYTMxLTQzMmMtYWIwOS1kODMxNWE2ODE4OWEiLCJqdGkiOiJteWluZm8tY29tLUE4MlUzbDhtazhZZ3BEZ3FUTEsxUTFpSEdDTWUwSUJKSld4QVpUem4iLCJzY29wZSI6InVpbmZpbiBuYW1lIHNleCByYWNlIGRvYiByZXNpZGVudGlhbHN0YXR1cyBuYXRpb25hbGl0eSBiaXJ0aGNvdW50cnkgcGFzc3R5cGUgcGFzc3N0YXR1cyBwYXNzZXhwaXJ5ZGF0ZSBlbXBsb3ltZW50c2VjdG9yIG1vYmlsZW5vIGVtYWlsIHJlZ2FkZCBob3VzaW5ndHlwZSBoZGJ0eXBlIGNwZmNvbnRyaWJ1dGlvbnMgbm9haGlzdG9yeSBvd25lcnByaXZhdGUgZW1wbG95bWVudCBvY2N1cGF0aW9uIGNwZmVtcGxveWVycyBtYXJpdGFsIiwiZXhwaXJlc19pbiI6MTgwMCwiYXVkIjoiaHR0cHM6Ly90ZXN0LmFwaS5teWluZm8uZ292LnNnL2NvbS92NC9wZXJzb24iLCJyZWFsbSI6Im15aW5mby1jb20iLCJpc3MiOiJodHRwczovL3Rlc3QuYXBpLm15aW5mby5nb3Yuc2cvc2VydmljZWF1dGgvbXlpbmZvLWNvbSIsImNsaWVudCI6eyJjbGllbnRfaWQiOiJTVEctMjAyMzI3OTU2Sy1BQk5LLUJOUExBUFBMTiIsImNsaWVudF9uYW1lIjoiQWJuayIsImVudGl0eV91ZW4iOiIyMDIzMjc5NTZLIiwiZW50aXR5X25hbWUiOiJBQk5LIChTSU5HQVBPUkUpIFBURS4gTFRELiJ9LCJjbmYiOnsiamt0IjoiakQyM2lCd2lvWFhlRVY3RDJTbDd5dlM5RVdBbmJIbkJ0MWNZS1NyeEZTUSJ9LCJqa3UiOiJodHRwczovL2JhY2tlbmQudWF0LmFibmsuYWkvLndlbGwta25vd24vandrcy5qc29uIiwiaWF0IjoxNzEwOTA2MDMzLCJuYmYiOjE3MTA5MDYwMzMsImV4cCI6MTcxMDkwNzgzM30.VKsF7u5l5cVux2PKXov1wwZG1AJWwUGdHUrOaRurMLsKRhIwAhL0UOpTcxtVSOwlDXmh9n1wi5rmJAKl_PbrXw",  # noqa: E501
    "token_type": "DPoP",
    "expires_in": 1799,
    "scope": "uinfin name sex race dob residentialstatus nationality birthcountry passtype passstatus passexpirydate employmentsector mobileno email regadd housingtype hdbtype cpfcontributions noahistory ownerprivate employment occupation cpfemployers marital",  # noqa: E501
}

SAMPLE_MYINFO_JWKS_TOKEN_VERIFICATION_DATA = json.dumps(
    {
        "keys": [
            {
                "alg": "RS256",
                "use": "sig",
                "kty": "RSA",
                "kid": "_RC6xwOMvbtt6ajWuZe6Glgs-j3wm5riAyCUoRasa-I",
                "x5t": "tsPLUcV212j_gO4vY-2pUI9CHhw",
                "n": "sGBNIs4nsiHNfLqoR40h06We1IvWVaGISvETHKlJATWIURd9wx1bqHZ6tesVmLYqKT776kgxXwVD8NP0Vu-Th8C-IF-9fMNOa8_TeowvcqDiIRjL7RId8kmpcmjtIS2G-MolfSbH7CRWVRko4q88LMbJUAlglSnFppfQhsEVYlwLtZlHAYy9cl8PcsxPmFUzCUH4Fefyq77BBUPMpzbZLLjlAj97rF1oSQJKHM6RBLcvI-AauRpKe34O3GR9bCCTbkhETVerWsemtFUznr9moOSaDkEMIGA5wDyt12kjKKvbbm-k2Y5TMq1IIQXfhihGAbTttVpmZLYwJda0nemL4Q",  # noqa: E501
                "e": "AQAB",
            },
            {
                "alg": "ES256",
                "use": "sig",
                "kty": "EC",
                "kid": "AFMnnKRWTaBYEhNfEB6iQ5ErC1yqGVyZchH8A7nl_yM",
                "crv": "P-256",
                "x": "L_GG9F-hIWXxUEWCB4Fco6zXJkbaU_aUMSbHVbwEwso",
                "y": "lNPEj7SHn5IFsO76Xel13d3NDlql8JyToZFylm5V-kU",
            },
            {
                "alg": "ECDH-ES+A256KW",
                "use": "enc",
                "kty": "EC",
                "kid": "M-JXqh0gh1GGUUdzNue3IUDyUiagqjHathnscUk2nS8",
                "crv": "P-256",
                "x": "qrR8PAUO6fDouV-6mVdix5IyrVMtu0PVS0nOqWBZosA",
                "y": "6xSbySYW6ke2V727TCgSOPiH4XSDgxFCUrAAMSbl9tI",
            },
        ]
    }
)

SAMPLE_MYINFO_JWKS_DATA_VERIFICATION_DATA = json.dumps(
    {
        "keys": [
            {
                "alg": "RS256",
                "use": "sig",
                "kty": "RSA",
                "kid": "_RC6xwOMvbtt6ajWuZe6Glgs-j3wm5riAyCUoRasa-I",
                "x5t": "tsPLUcV212j_gO4vY-2pUI9CHhw",
                "n": "sGBNIs4nsiHNfLqoR40h06We1IvWVaGISvETHKlJATWIURd9wx1bqHZ6tesVmLYqKT776kgxXwVD8NP0Vu-Th8C-IF-9fMNOa8_TeowvcqDiIRjL7RId8kmpcmjtIS2G-MolfSbH7CRWVRko4q88LMbJUAlglSnFppfQhsEVYlwLtZlHAYy9cl8PcsxPmFUzCUH4Fefyq77BBUPMpzbZLLjlAj97rF1oSQJKHM6RBLcvI-AauRpKe34O3GR9bCCTbkhETVerWsemtFUznr9moOSaDkEMIGA5wDyt12kjKKvbbm-k2Y5TMq1IIQXfhihGAbTttVpmZLYwJda0nemL4Q",  # noqa: E501
                "e": "AQAB",
            },
            {
                "alg": "ES256",
                "use": "sig",
                "kty": "EC",
                "kid": "AFMnnKRWTaBYEhNfEB6iQ5ErC1yqGVyZchH8A7nl_yM",
                "crv": "P-256",
                "x": "L_GG9F-hIWXxUEWCB4Fco6zXJkbaU_aUMSbHVbwEwso",
                "y": "lNPEj7SHn5IFsO76Xel13d3NDlql8JyToZFylm5V-kU",
            },
            {
                "alg": "ECDH-ES+A256KW",
                "use": "enc",
                "kty": "EC",
                "kid": "M-JXqh0gh1GGUUdzNue3IUDyUiagqjHathnscUk2nS8",
                "crv": "P-256",
                "x": "qrR8PAUO6fDouV-6mVdix5IyrVMtu0PVS0nOqWBZosA",
                "y": "6xSbySYW6ke2V727TCgSOPiH4XSDgxFCUrAAMSbl9tI",
            },
        ]
    }
)

EXPECTED_DECODED_ACCESS_TOKEN = {
    "sub": "aecc5af9-3a31-432c-ab09-d8315a68189a",
    "jti": "myinfo-com-A82U3l8mk8YgpDgqTLK1Q1iHGCMe0IBJJWxAZTzn",
    "scope": "uinfin name sex race dob residentialstatus nationality birthcountry passtype passstatus passexpirydate employmentsector mobileno email regadd housingtype hdbtype cpfcontributions noahistory ownerprivate employment occupation cpfemployers marital",  # noqa: E501
    "expires_in": 1800,
    "aud": "https://test.api.myinfo.gov.sg/com/v4/person",
    "realm": "myinfo-com",
    "iss": "https://test.api.myinfo.gov.sg/serviceauth/myinfo-com",
    "client": {
        "client_id": "STG-202327956K-ABNK-BNPLAPPLN",
        "client_name": "Abnk",
        "entity_uen": "202327956K",
        "entity_name": "ABNK (SINGAPORE) PTE. LTD.",
    },
    "cnf": {"jkt": "jD23iBwioXXeEV7D2Sl7yvS9EWAnbHnBt1cYKSrxFSQ"},
    "jku": "https://backend.uat.abnk.ai/.well-known/jwks.json",
    "iat": 1710906033,
    "nbf": 1710906033,
    "exp": 1710907833,
}

# SAMPLE_PERSON_ENCRYPTED = "eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJraWQiOiJYa19zZ1RwWXdzWmF5V2trV0JyVk1veHBlaGhGRkNkLVFwVHZ1SnBQdlI4IiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiSzRyQmlYOUExS3pMLXdTOHFoQ0xGOVE2NXpveTBoWnQzcTVRanZrWnJyZyIsInkiOiJZMDI0R1FVSWdTdDlEYzFZcDZ0OG5lZ2p0YmxsRThLaXhqbXdIakplYjl3In19.ji7HqpLIsMFpSVfNa29ACAtiJKQmhN1HxNadq3lB69ZUYBAVupnqFg.vHAiaOe36YPg7Ezk.8uTeJmOnvRXbQJZ4Fvn36bU42pbljYI_SjmkguWizahEhFbVh0Dgnw7OeWUIRWQpCHnUewwZ3m0ZpCq6DEfwdpBqxvxLe60tX85yHCHo6AGsTh_3s6Z6IrfxGC6x_PP_bL-fXn3GJaCzkmT0OcjzgP-e-x6_EsWuAZYt0kic_KNEYcuQHdQiNXESlfz9_Cr6VlY71rMPbouAbiiFya8Kdb_BPjdt3JnYex1J8DUsYYEQc_XMoDlW5RK5e8_r4ZFcdQVTeS4h09yrAycJopI30h3WQ2aHCVhrByxik-2zQQRgu2jl2sHvyf_NfQ7VEpgGmlDOGpLcJN7228aXwbhXdMUfJEtNA8DFtkYMCsYw4bO12y57Iy50pRIr11tiMGu8vl_ugzEpu_9aF9hjQVOkPXJ9dj0HZs--FOm9_anAlAB5xOguJDGlU3MyOAK-5V6rlS5sQyQzmZCVrboUevj88QPr7dt6o150iBEcjkXWIsfMzDTqz8JL4QDcy5LXYF06vxSKBw47z0mGnRxQG9MUbPG3h_LlDyNpwvmYcaNeUUqxvgrTIaNfRpCuKA05Aw39G3P7jDknuQJY1wCFJwXnLUdheMUX8OHhpVdpGgU9z_r5hCQ5nrJx3lr9Mj6Vk4acIn5YyVAuoNZw3rWE9UhY2WYRYeMtNZx5Rb20dO4RaONTb7oqsHe8oNCWp9BZxEI--4e3ycvkA62k2lkvkP_z_g7pVUXf0ObujoGH-enIDVPQpb6-gueu3a9XeWx9ZhlwcifFhzAO177KpGL0CBqyfCmqAjugX2_CsrwYehVW_dLcj3pq1rH3ThvQFJNTZK7dhFVW6nAq6BcMdTOq1OUbuLCt5AQDxI5yFJxZyqA4Ixi63BxYevrIXjltCKLI84DrO0ThSxK2gUSUYAXsbbGOfGPpxLzuzH8-DylUqDrggq_HZLCNn2bXNfBiBbZ6myn2YuKpK6_f9jIwbCiNwj2_rDkXqCgCUeSlgzfIJ6PBu3IfAH9j0qbjEMo5aGuwduIIB1ufC3Dgv6uW_1fjuiZDSYEtAHMfOzLi33WV5uH-s7hL1fbLBGXqVfCXGWVdcnMKGSg4I1S5oDhVUO31bp_F_hzVHlc10o-yw27LRdx1bs6fJGWPpPkx_ObzM_zr_bZW-JELT2gtThGglcqLjTxsglwTGwRvrhNpqvDqoSRtrhPOMJUC8HcKU6uzm_87fXD-BEIkSYpHPvwf0P-80nu0My96lDRAwaE_XehnH1oml4QTUrKvlLfGs0_sxLaNcEa6s9uH0D4arTWJBJZX9PBH5OxK-9LoGNxeH-W9Y0svT5ncAKZr0iyDUjN-H_v9m3QTelcUj9FId0QeI1uxKrBfBKb55iSS8Q6VF8FzYs51lrG8NKOTIDdnc6SPTi7wDWIE_rumkHVHmpL0UrAnxk3wtqXR2Y7L9SVCUu6HLe83dPlMPYHmYoDH-P0xRj0hgiZsigLtMM68kaEfzHeRLLptUWzVDF3W_ryoWCQC4NoDVdoueKdL7C08SmOz3ViUw9Ryu2nwlYZrHWapAspp8CxmsmIEVkr-0RrgfeqFkIJ7gUt28QkAiJpUritBfGAWs1dOizszW68TEBrKX93h-4Lr8VOh6BFgOk2tLIVlNJGWlgMCEPYBgP5WC7vxaNdWWiKRr9vmrVGfnqQkWQh8RkwZ0OqYi5-S-MgxS1vP4O4H1WyjkUBFow7yhWxcedaTR7XwsTtjq9kj40Ad0IhpVJmdTx8rwIIYlEvVwMB3e275KOCCUZSJYVTjl5EFrWCg87jdR9qaLfCuf7vkFz_ExdFeLSppZWu2L4RsymsDX1tPT5pWUlzdT9N6RM52qgFPSLlGi5zpQ5kWqeiTh3hoIhRuTg2qVpLcG_le2EPeefW6AU1MEQakLeAPqeOHIHR5jbk4iZI86D9Do9-HUeINkVDAvuFczW23I0nvP8HNmovthIi4sPxHixFSJrLpHpBj3Mx3U0P0TGWXL-NyR9IwJ6KMT7b2EDcsfbslqouV6J7hmHnBLqw7mFXesQXXLTb3Ag8ostorvX2zWNOxO_S4Gl9VBo7Mvl9xnIyHtuncvie9rei9Py20SwUfiAbT0xc6SHH6JWvYJn4U6SlvH9f7LXFiPJf5k4LOdGsyv8Fj5pusP1l92UEREbJxyba-dMhSxD5XApELsLBRKs-t1sbBBNOb8d-fFo3UEcrTeUU4dXs6-0MmUHA4HjYUbhcfvMjYGno7ieZ-2-g59ztkr4tojs6H0GfhPQCRSZwuUnn1ManREMgKRlN4prqHcc0ASpT4tBDxCcDbnQolAQxEWzrIINKpM2iYAi2C2xlo6uqqalaWhGapXGO4zweoXHRiFw4_SoJPY8cIsrndq0dfYuGB95lTZgMavw-xL4KiDxCOl0cQOFcS63VAVigRbjBS1RAAOyOxcs_4veEGmXO7xPCfuabrOe5dZFf6vFltFy8I2dJsjfJLtIzhi0ktHIuKeTzoIbcoYU9Mxk_OAKclBqs4sndHgb6IsPzneV1lmGiWh0BkM_318zZAvesMZnpcwNQQlh9obA4I0Qj2iJuvHFI1Cqz3fMltFovGagLJIBoItt6f2dOIof7OSWATEjecP34fU4opBApzIfAgXiydqBCvcCP8djQvjITdszMQmksUfto5sToLPioQMqBEicxfoH9BXa5Akh92qECncYzzIIQ8NW-xDBV0B7XHbfa7aB07oiwm9CbRYushJ6fWCvRodv_JyBDcRX4PlLCNgkNtkPC7kJllGgtuDvfXcJPmUDuGW8zLGCZNiDJSIJu9n9lZfzGSk9A8OxTd7QTKv-HTHrKW1ditxYIAckOQkCiGIHtcdFsbY9jeVfo5XfghdMVh6UOgOSVc4GFeWyTUorDT6cGmrDScYQ27X-c7YNKfLOIf6x32ncGFgKtTsS6ebqGdrsFfNNkzzMRO3u71UYHX4Pdt6gcCJEYdmp8Q1hq7j_JASK_oCknTMojYUOj0Gp9TmMujAQDarsrOB5qwHDSimsaQf4QO26Tvvapi8jofzzEawFo8g5d0h_lbNRtw-P3inRNwofseW9Qwse4RC2nVfarKXSCNSlBStklT3AX3oj5-LBYFyHXGH3NQ4nqICkyxXt216MF-NlhLTVb1PlH_-uyxij7cA_UuITc0rx614hGlfJbnT6kaIiASvGfDn_wbVM2BhEVIaWQwfmEZGbTTJvVq8GsBlCk7X7oSPfG8X4gQttYidGo2MS_2gw2Sf_pLIhtPgnHHlAII6JO9DtXTcAJWmj2Ejc2E23RHbbfuP6r2p4i2D3ABn0xpBKHQ86-mCJjdOXXb4GLnCzzZp5KkL7u-LIUyzB0nWHW1tlUEbttwwFkh96FBnz1qpPSv_uO0LvG6Nsa8k_eeWQGk91gUqJUkO3_nuLfRzMvv2kOzhtdafmw9h3RYYQEumurLSHNpLbUlMFKBrR_F5_fyZa-AAbCtBws-HF9hdptehaaXkXKGcNRL_aIm_e9z8BbYka_RuNc7QsuaBUrRxff--KNFv4A4UXMU1MvTRe83Gc9bDHkT0NbbQQ2zin4uNEtB3adUZRgspQe8H1jd8q4q1PKyJxb0YQkFK6iITrQb5WTv4ANr4lcmj0brCrrcE5e16lLL8fQUavFWKSOMyfaev8ai141RKVEq5en7yFzl2eVIC-5fdB3lQTX53PwspArxhk0RsYxbAmDi-XNzguIzX3CeUTJ6ugeb9yVjke6G1kyBvYDtpQ_XU7KpzycDAXImEsIc73k-1BPgvqGinCCiXNj4EnAlk_XI6NwGSpHMyNOKaSs30XaedUEQCkkWiVBYGNAaqQNzu_GSkhu2ctR3R8ntsHUu4jDOXxsUykkZICV2wt-yAujvZiaAUlnDz9mO2ZWrjTSrVMXUEZzVjmlfv14qYwGcAKXK7LF34qDj8j0x0XzARy0QHV9RGvyXjSFOGxhw8npJkq21eJ_oxUaJFsDn6Jup9hwwNxUyWaEMhA69R3dWU4H3UqZ2bHnl3OG4lvT3qdSC5dAOF6vFZV6d8zaIY6CSLhulPPaZWy7Gz9Ig8kcV7mKK1_sf9xVpRwWHM-dEzlIW6h-rUK3JW_SjW4h7shJ7X0iiPIHdx8q2rTgiKG04-mRfE6ALgMWOcBE7loG8rgyRTU4m4GaBGX6fJi2qOf__3XU7UBhlhzfWMQ6JoBNghXEh9OxvvHf0bBhgBVrkEieKmdThAa_TsZP500JFB-rJRao9LLfJIA1PdCtCrT0ogx_t04QQ2f8gRl21A0Dhrem58kBrfK58t31vuJeHfhCpW6erVvacuqCcvNd3NJPdoMdRyLLWy4OplrsGC2SGT0me9J6CLv_xpF9SavDiaehwpp0AmcnUokGEwoK3AlfCe-1nrEZ35DpFuxoSzyoI4dv9u-AOStFvcnw6LopgEWc13e2oc_gnyTjTAiXr_wKLPLrlQ22uoczXSTVlwKtTX6hRGxR1lzD9TQJn2hjtUHgswcNvy_RkmDx1rZRY3GrtOVNpYxd6klZ-lIFdQF4bpygTrF6sAv6mOFjEI23-mXSNLPvgyDh9ObBnB_UujxtiYi1NpZFYU1x1SlFEMGba5KAsm-qOghX_JS125DSYhytAxnbuP_lohU24cZpAwe5evIto3QhF7yTUqZFEu3moI9YO2kZDJnHy6nlVerXbZELMoSkWNKyLuSXnJAQUnHtzsv7amIvz1YyLK5_C6-YmwcPqc8GWW5SJ3POJKDC8xMTXl-AyG74nM--6FEPO0ITZtEYFNlps83o2-3og6sy_eboXPp9GJ5MDTq-opv909YfucW8_nwuDi2PsfwAze8Df6AmOzZtf0-pLJK9lKBkRjRrA8eb8dgOrfeK-hLzUL4qlc8yy6MENRZh4OP349ea6wQEi7IYmCWY3CYu8CX8VChRO7bKQFLV_GMCHlfgqzVCET2WYIIci2VceY62VuXi3uyUTs9qUrWgm1oXnx57uY6_ek3EtouANLc4poY3X2Nn4NNhdKAPqPUNqG-zV66iQiSEGRueKfv030WH9IIrcU7KAg1RNQ0mlp5Kh57PSB1l4FDtIODYdNajuMVkkNkWiFs0EtXvHPHgIAjohFzj8t97yTxQJix_vdDGMtsB6Dpvz66Jp3UN2b6kXOsJbzIWsUea_zqnfX6_e7JzYC8I7O3ZfBkQvKNtyRg_3qN-y_clrhPgr29yuWMB4Z5pfIbHTvbXJqfc4vOmghfz-QBA_nDPouC6feWAzqKC4rOkCBa4Q7BH3EtRdmrLQD26orFj1_iviW-ye4LoRahjaukkaEOsIy7l46hlMV7W7-j0vuf3ooqYDDgGY-BlDN4lLyRFM4UbusZ3IxGwGZknB3rveZkYQen5tAyJgM8qL9MxhKtQefZHCM4X3NoZ5U6voAfwrvWZdoXtdww55uCVD9UTLyPlXJ47KashM6FTZlqDbnTdvnNv0r8rhL9Svsm0YVppoAWmkribIiN9gguK3H8im6eIkucvSHt3T7aQKWM9D9nQ86CCn-Epeti3YB4RhtYU-pZv-ABX1Xa58LfHbCMZR_MEgY17R4Wz3oixZiuDlGj7D9P_STs6VQ3yAA37rVMTGHRLSTa3BQKAgh6R2n4xfOTSy7CchoippeJMcmVJFyXFUHxn9eCkVp4aRREcd0NBY2TVsrYrFfxUftxY5uKqlH6CxLAIUnB87greTSIbaggzvgLTGvItzKQ-NoitllTMEdn50LRtZPFfcaIgZJrJK4T0JQq3iSMG7mkkDkFDVUZVAeTx7ELvv65nWoFN9TG07ouBYhM3w-ujSsk5eQMzSKKrPO4HDuh6s_FDmw7YkR7EBBWrZB95i6cKQK4eHKBp9schvoa15yygul7JUoJOnhvsBquh8Wq42dfVvsuL5Qy4QOLJokvjiz3TbgjIsg5YQj-UrSzpLuPUVFJlpJU1OD8Q0MeCj2qlP5fDEY0zUz6aFDNf3Ab7vlvnOunXmJ-ZHuM5jZ1e56uBUj7Fl_xDjpO6Hdl8QgQBqo48DBnLG14S6TJB8YDvkGOneV68CEN3sTYRpz7_UaOf6z9pJLLY-o9wfWfgAyslNh6eiO_oAHNJQb61vEZVHR1Ughy3McIRNQlKIhGp1Qezn67TBfB3pfLrAu548OCsJwjWf6BenIax5qgeDKsk9EulD-7FFgF980-KhSQhOKEF4j9b0NxlrkE-dBV0fWwtwgRZT1eJS816HbKpi3JmylLICqhHz-adomuUtE9RAsyVjD97kJZ8U3dkzOXMF2--Ptvn_093HshVzOgFkeFfg8U6H-y6SxtpofUxeT1kloBuH5ugtLaBGLFHN1HUsYwoJXdsXwq_1BOFfIMf1lYUJPaYCcw7WoeFBTdjVTbB1g-AxJ3e5eM5iU4K9LrKtzQfv5zUgkvtUojmwOc1qn-8nXEEvxnzY1LCX7_yMGHYV6v4njvCrqNuLLlmLrynHJq5OC8ZRmQxv-yqkb7aL1q59SYkPcbVTyXT1lcmo4rz6bqBn3sELQIUTz44BiM-8hE8sKdUFobh4EjMRxHzPK5df-79X2bJo0cLWbcZTwfQ_lzOmw5jzmjyPgYUZBOJ_-o5SrWefE9rJkMK9eJz60T-Ggs0fCd4OAGZJKSe3AR_MoZ75k0lkSfCKKmeIsVt58MzJm8NTXA2r_4qTjrngS9x1b3h4yxNhDlOk5HL4GLrVAyg6NCQYLfRhxTbGdI-j2Z7GuV9RYc8_qyvhSxqaxMP5xec4KQORDlL208ofSVYD6RCVfNEhAxG2NOoCxELjgx_vefCjJYCfldRFbyJsmr-2oK47H6-H5xrpjL9fnbNkXdIe-wkFMWE_Q4hL4KJkie5BYsVmIOW5cjIWVF7SrzJb9Sc9G7dCz2i2cQstIsx-8lQTNTBuxWOt7kj25QO3z3qOyAUPX_N6FNJ0NlDcigl3hKOGv_a5f9YvJT-SEQ85ZcmW5Ca0vOKkEMuIQhW4Qr833oRiX_S2TOHkrYIgBlrSMD4fsA5MN3HELwUcvz9eu4gbqg7K5iEA873hVzTIo8ZQBLpdIpgEmCVtfQ_PC2wklLVR05XzoJq9gYOdJeJiOGxIrdyOV6ikVjZf1qWXvKytM1Si_FltG_HMDNGZ_QV8XxvV5pkQqt4rB0JD13w1HhhtAlCds_aAD_PDlv_yrQg8u-WQRVTFt-H9w0xrSPnp0ZtLA3LFq4g85Tahd2EOJWjg7GqBoJRiHJf4Mp_tybLLr1_Kj3DTCHZrOIWsn0Q3x0LyotWGr1wSpH_ycp4fgsxZV5xpuoCl26ztmec14F5pYSxwLU6Jzd1juu1XFATavh2bA3-49Cq3H3ZlQ79FYZTZnXXSgbWWtost8nEWLx_ujV9R2KIXGZe_aXbr8yLN7_9MU5yxrcCLGwxQvoK9W40btgOipi0KMQ4IZg7_EJtFDT0QY_q8oh7-2ZWkFRbhY5zhgLTrpT4cihuXi8tuHHel5-BnFSA5z7i-ncawYKxrSaBEzwmle70nLu51MQMIN9M_Jlic0Ao8vQPFbSUkNnKCY9zKNJQPzk_VcY-TFB6LuBRi8xWETlrMvklUEttfo8bgRvQXzvKPEdgZH_HLgN_jg3AkB10jg6N0GbIxSq3ERbKJnbj7XPdxh4Hiaeq4A0aLj-2AYBiU6yxKjwV1KjTlnufI5CFkdHpxKVqEZPlbgoAjfHsyrZCfnw7CYRU-33fUFj3p8td26JuDxlHTLeMj52bL8uAU7uHv9qyKHAi1yiPylJCMZQO7Ud12dX1zXshm5qlMGoVrgRsUakQuXJV3jiD1Gab8uAIO_B5kwj_zfvjWoxcQC9wcLeROMyA383eyrNgtirHVgcRXlTPQuBkEBFuBtdwiwa0DMohGoEXAKsXUy1mjkZWMa7gMp4gPw3hmJc2UwzB_DvB67c8N8JukGIxWnr18gW5nIEOF_Lv6Ot0YkdoLKBaGPXtCwjErpBmDMm7yyLtH5THZwD4y_xG_MtR8yuca_FOgoa08W9WH58cM3zledGbOEr52K_KI8AJZqVmo9PhUyrLhDXmcwPwMY1e1IMYIpWJn5z87OLoAwb6hS667FU-Sxf5R-z-4MLVLRj3h1H782i2GV6MKrmUtr6WIsaYDp9Np8tnaEZjvpt5DDvDwXWQysaT0Fx-aq_wQEclfH1Fg5RXPLnfnMOp0ARb_UKWvRmM-9J6sdaZa89BixC6srK97E40W3tkE7xyJlkJv6xxguUc4yb2eR1isK8oO7I-eZ4kl2QNBtQzVzvfOtfSGAuCZqXvp42A8hCefJlEaLPsrXYP9c8t5AOcIK7CHIHCcVSU2BOUqiOkSNLou8OBJJ1Sr54q2ygQLFMAEkEu_blRD5lNAmUr_Ds_cqxZsDYtpD07cggyzewnnFu6RYk-POsANNnzUd0k90rIfwYspPTzEbrtt6I2ulYokOdhkLsZ2CNrjGxRC9oQ04IbbZNC-JFUDUy64i6Al1ixbACbkEnunT4p9WjLqVyX2PalBTxj3k1eGZxYH0mrCe_ioE6UR5-mTjPdN_yMR1dAuNnTk1mDBGp3l5LooHKjq-9QBhKQuYQTdoJisGle3ihOlTuqa5jR217vi94ki9YUap7nfAbv4iMLUevnUxJP0Ia3BPN9wxhs01x2C_qeT-x07mCkyGQnwgF7UYgRcm4SxxOPMjBW5stu743LjtZI5ZvBmkCviCiGmwT2F6bjR1UZQBYz31bm1Ss4G-9YgqxMiIncRlMa8J5xz1xnm8SU0zpVusV60TS7X9SNEawwQ7QqkJ0l22h8sIn8bqo5Rx_46bftq_mQpt16Xzkry41Jbe0rFmkqO2MvqkOM8ZecCLIWbU9T4eS0IdK8A_Rvl-C-vIb3SxEMHSPdB2E604o4lEuA0Y-iZBnjmm3nim9Ad9tdVgvYTCsgaZkwKmjnNnuRBsn-HIBQbk3_OgJ-8zy38XYTa7STjCvGiKKIyYshnHzb1wk6SyVlvcfcwkNmCLFTJET-rV8o9layTJsYGtpgPOu0yeftYYmA4Sx9GsUvcpVoiwt4IDIxJvwGwkPf8k9WrmBFS4H0AJYhM7lWLoW1BbdY-WCAEM0ov32ZgXbbK0Wp182bSoYMb-mg12D_wOGIcakUwfKffAQJubGZN-zxNJ47Th1xcB3aA8pc4p6pRRn_I0fXJuOI1M8eWuXBx09Sqequb57Jm2NJYGrG9fXwNfMv0-gPYFUyS1LyY3i5RchkzFJnD0vSbS8615_5IrXw7QOTxnu6-3Ixvfm7EEkPKPQgpvPOpKozD7fp-cE-U9xBiTHdeksKUiZU0ppbC_nRUvnY7d-tcii_U34JLOOWn0EzYZ3FmiqUb2eymYCL_f9slkfdtp78UTIPQEtMepRwgvrU9myWCm6_9sb4Kw40iIVSdzb8mKaouvO6UWVvtmFyFK0K0WPvsW2j-Y9v-yymDGltWM3bpUfifq5tYRFZ9PkM9LlScYoEUtOjmGMaKKMBjfNEBWlcnsVQ_bEnYr_qY4aLq-DTWbvwaNCNSgfVD5DyymcZMn30AN8y-PoJ4j20LOc5hPJMG7_B6FkUqcDA5lJ7N3NEy3ecUsw_f0aLVZoTjZI1e5c6l1zMvV-AjiHIS5aPcBLJ6q3PKyayX7miasKvHT2ynRQlqFumzLeNnbgjYtRxsfEWoj-Y2TkbzW2bw7p3lm4vA7W9AyspHKwQrj_hsRQmwkHbjBe1w-sjfZCi25A8oXiyKWOeHnG5a_Vh8kbjB1-JYI-n3vFKbYAEsyXZx3bwd0D__308YBMoB7yxKwLyVzAg27FAvt9kfE-IfqMFiWds3vz5T_oCMMz1IyRa7E5bqCRR1EFj6yZ6jyftXgTdBqK50ox7NVXf0l3JffqjdG8zARYMpucTfZGnNp5bLzTRrtd36PmA1jogEdiokH6V07M9bFotGlPXH6z8sg-5xAQeVbA-ymrXs8kCLHGcY9TSqDgeIoIo5pXYnbL-QDMlRPqv0fUJwwCXo5sf6VfbSP3fX2hd8M5hJ9QpmNnSmGpKdEyqy9L4_qpyO2DZJX6HWBKry8BlT_Rd5B9SZb_FXh3wzOlnd8ZzMnvZHP5LmT-aoB-zP3u9_e38NW8ZGAgZs7Fe9xwaSnr6IIrtrKNmIaCTDmPgmIiM7qSCvSeQdbJzLeExwjuh07cuCVkoOhafNKmxB9XeqapbBCgDIN_hp-MSOc7XBRZ7jIo-GN8K8P6z4raPZE1IZvQy7H1J8VxvpQ14R8TPswOfL6xfvXrImyBH2Zk-pnLno3R50pbzQwKkbIx7rkYs0yrVkCbARKih4jOX45aMqVMj_3B0VsALdKXgE_ombAmUTDIeaAlO0NR53i_16KjprMk6M7gUwtR5DNu_jPaklSIMDzz4M5UGX7kPmmdkX0uCG2xGm5o3sSgZzjCCDsvqCcffS4Vps6PtHNKSk61nLZCP6UTTxecUxRwKiGoO_ZD2OBiOihpoqT0NrGptxtE5mlya14HOB9fHAfS1Jtdli6hgoMjcJDR-EX3mJRBx5fNHYLoHPUSIx2l8y2BVRNHzFelBxntT5E7JyI-l3FNg4-JcA4IuxJRzgNDRqUMpIbEyfUJSnIpfXVuL9liF_FL1NguSPecEmtb1d7xkaKYrFPXyB1q5V.Qq8mH5VJBZDH_PUUbTm5Ww"  # noqa: E501
SAMPLE_PERSON_ENCRYPTED = "eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJraWQiOiI3VGt5TWFqV0JYUlo3aVpmZ3lQUGZmMmdMMzloMlh0ZkpEemNzNXRjZXJNIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiQTVNNWVkR3pUUVFzYTlMSmNQWF9udHZGaDFHOXJ3NHExQU1Pcjl5TnRXQSIsInkiOiI1U2dIMmxZT0RtM21JSXpYSHNOSGV2NjNMSVg5UFBEX1JQRHc0cEx0US1NIn19.7n3YH3EKaPnrjFim6_tSAUl96QoHoklL_u22Ii4cEXQafCDxZ0jJ4g.ELiLkCyX-jXwB_v3.oM92GhrfA09eGVahmumIdP3I4UFABhMx8Hd4UkoI-nCU4XnDbwE2icZqJ-4jplK3Di85VnSGp0-VoqmISt0v-lbZt2N0-FdSmdYwTqlmDtPSTD869cp5_2XJPjQTqKRRKqVDb4isdEObb7fHGyt79a2T7TQRf29KLtp3T17SngEva895Co_e5jETcHgjh6Y5-gme4_o-bgny1RumbDrzVqbx9hBs37u0oG4Id0NutDhpbfQ0M5htmKv6A1IPFppsATClUDR7rkFgrRJ5XdHSeO8hD8H6jqDWKiHT8g5IMMj67OltjEd-Ql3eMnXfyN8ppBKVxWPbDlJh4B_SVfOhlrw8Zwv1mwVBigNvfIBYRHwreiKyrJaxukHQKSBbtRXtBzYyiht3DJaFs40_DTdHHEnLNvxhGE4JKvFL992xNQG-JeB9B5lbQqXIMOrNmVH7Y_mGHquK_8-Q-sFow6T38_gbKARWfSVf5geTWFoc_PdBa3pFHtrIAsUt1keU3Ti4CCfFHHXYls46wmRz91lzjb1ZAtHWfKKvthTBr1KKfVdt33zYsi4YA7e-MffJZolz6JVKbtKt-UWLBjSbAQO_SiWXNXFkyX7DdOdVmYZTvK79U81K0UXv8dOXC5ZO6lkU8ZhqEpd5w0OE2jgHCqSXEj9KZVTQDtUWswrSNCMTLmt6TWz2DHSE-XUli5PdRRebGpYqYdAq9eYm4HS9KDq29KYt4OwCV6e6rwB8-oiXZPCqZ1DHkZaceQ5D2VcQIC_nJn5myrtuEwvA4UJ2i_moAMRu8AfBr4j6C11aQjpl6mMvQ8qHEeeincpJG9Wl4DzjSJu9gneIShu_Qrzdkc3Gwq96crONbHQhXhVw83WKgwL8NMB-NnxGIYesdXkfLWDd98_hLoo30gJ2Zd6brXYBHNNupYYx8nX3EZcn3G_cNI8Wb1qyX-q94TjBB_VJX4HqW39f3aKsu7qFz03DGsYfjXe_lJf_-OU4QX8xvkrPL_nvVDeUoPkYaPDswNqKZ8wIJddjgxvgYqKbbrQDUNt1oS3Pr-tzROoWEc_3LIzwo34XiwPAICac4V8XaKfGQQ9qyg1XgUD3BmrXpk0_Q7lifgTX6qPJpOntqFTQLb613RM9AFJ1ChGWhCTxTN17Io4a0TtZM8xamo9SAT2sEFdlXFrKVEmFwcOJdH_GjgtIfVBXXHj36xdFHvYb7nE1hQ9hDxs9q0z7TFi-d9H8GoF86RyTMaC5m8XKfEAfGpavvdlIy6NUATOj_Xpqp_pN1bFNvA_kWmSvWV6m_rifJey0ViAfzY1A8TinngsPOoNIvs4IeowaQy5RhO_vJr_HQDU3O_FYwFnZzozbf4e0r8wHyclefLulTV8fhr2tSC3zyjxMI0p0scb2FnJkmW5sQ6SWoH0-Z3pKuwoZzQM-MdGtDPVIAm7vR7GvJXJYdH69Lnz0kL5F-wCdvY1vtOA1PqPhxI-S-yKRcST5hb76pUkL6L6GiGNMeM87iq1--gBS0J-LdGUqzBkYdTt0C-gOf7z4uDwBnJhM7dL0cNNle5WsyOQghLYvERuXQWAic1HiFYoAysY-mOb0rqxaMOQdIX6Ispwfie0l3Jjz_mUs1bGc2Dyz_mMEikEU_V3jOGsSxlHaywQ7atJtwOPv_nfe_OMj3HWfhbOGE9spix9cLmxqPQlsSlDk4kdy4g-AYFso0VzwGqh_HLcTswEmmCIyC-mvbPjmLOl8zvpZ1R7a0n5k_YoE0Pz2Tx7TvUsKRvq7rb0oF5IQaRb_VBy7qxG5C1eQjznd6P_e4Sph2RB-L83po7oZ4rYFBKnsIzrbjnQPBIGwBgQFoFkTeLk6i0Lb3Tg5GyasvzZs2rA1-xzKN2ETjJV347U_-vq-2kcvth257HvcrH1lX-bsSNByVFARBTiRZOO3iN40X8Bi7tZPpbpwcuPvJNJtMIB5ywUN7mUNLULU_LV9XPSpujyOlhV7Jsts2k7lU8sN3Nj5k75BQGWiK2eGX-g78edALcY_TsyEJQEB6yllJA1-DTVfE1ovnDjXmai6-pZjkzR20_zClKblVGCDxzWWkQAUkt69f1urZ6whbDxOFqEv_wItJnL_tBsrBljvRQzfcOFkA1DIHtuZikp3cvaESpqu8z-UOhp1m3vVcXemMx9jBDWZrTD1EuHHmDXhGZ7bY-tj19RL893aIvmCsZ4O_7Y0hU1CMzTi1I4___lp8-QHOM6kZ532s0vP-DVo5QtBmlVc7XZRCYI8PBl_y-6cQfQ_3k_nDk9yNlT-GqlUgGIdHS11s2ajafJ54FX_6z7G91uOGmIl3Yd7eyiUWVp4r_jk2OCYFefZHgAQf7SjzdU3VyaFw--3gQIwtqD6STERJm798Mn_ew2p9mIyUUNyPw6VswVzaH8rkL3i83W5LcxeBT1sFFBW8aYYmUTbGOgj5yBDW2SXFZl-_dn6Y_tpUGEa-I-ubYSI1a8Prbgo35L35Hom1hit4tGThOeZyRhkauWKJfeBpxCFtRGTJ3KrWxEbreAq42LzH1XRhLbqrWtY6-pRHvKu49IUM3QAj5-k8Nd77wbFT30syD7CpiSEfP8WD3kFPT20iCPAZ04rd1gWtkxWcYqrJ-TOOEJnG7UuAqFCwG5hflk1yTOBHKk48n6aoDybtSuf5PHAPpg-fxD2xXINrZ5kv3Diaq6EAxrbm6nSQnEWHbCM3dcbObs5YdAW5ZGZTW0V77thJEUeX9fFA34gn8jqw0xLcqkwbIE26k2rNVKtqJcsEKQs1FXUhgQDgKUrm7Ig2bhyCXCV2MItXXYjght-VcKc1zC_88WQfGG8acC1cMHoOe2WOVFZLINilYkltXxs2ziiNX7LY-GpVDM-o4A9P7Wthsv25mButg1P86Sd9i04QVRekcY9k8uN3rjIsNyfIk6wYzmuvcOAfYMG89uf3nRMZvkllk1oly5ys18slBRa_tPjXpMJtMgHWhVA6JcoTcZyuTF-ICln51nErrfhRwzoqeflzPEKFsgKNZjmYgs1CgjjDr4RVXfaLTbT0lSSwU-EunNi4a9TMQYcGG2jRcqGLE7al97xE7ot4n537PzIt32It25QwFpuptIPH0qJFXL58X0Vz5C2VzqC7WfHWKrTywGTEHXDplNocZs0t1JF3xOH7bK8YBDhI1foAQEnfGY0z4q5KXcQpkKiIXWj1SJo8HpTOZqYv1dF26n5bRX4wFn7tuGlpn5Vpi-4SznhBQo57i9QEsuX7teSKHidwg-el9liVDQ9BQ0ywQTmxKkGfANojphlNDXOgblYRHN8fbpGHy_rVGkrkXgddiXdvvPqAnGi1lHHcC1LmzC-8pwSGGUcDVWF5jj7lLtzAR2nMgu4Oo__JJ5Ohgr52JsXZ2qy7PHwRWTNdvMPNrYk4GFtNoShpwYOsYwsxsMBSFsMMMC81gGyt_igrrypEVb5Jes4DfJuIWhEi1dIJkv3JSQX6K9RCtRI3PRsKXEaxkjemvHc_29WL8Dd65zZNqu1n9P5YmJTveYmDr9ZXfeEH_L0nW1s1ERzxRjtUK3gURJspWvroo55r1Z5Kglsl_LOnWaFy_h3MMh8cs7axlDOL_EJjDMaMKIxVK_h73uXVl828OLeyrKyDPWn2hgsHFHz470ZQQst06SE_AlFImiFC3YLsisl2LxlrxW-wdyizNkuTdo8gaLcFH9zgqNY2rROHQYEvoUrNpf8rzXENWjfo9yWRAEy3V0uu685Pt_D0Ri4vm8NZ-Y6jtAjtJb-VLqVZSJVrZrRMxdMj9slQyqhOO599PHECcYCu7SiQqyWpDyH7M0yZrjXGXkcK1mIy39a9omCjSI1FIf0NsGGHRB3tlkT3uvG53PvERX45ebYkbpWLyCu3Tr05DqKKuWxKkG8ESObTWHyaeGHNTFLK4SYcB37zddRiYV3F5E5Mov72N28MJK2NhV_8dIccktend0iyWvK5gVqPe4QYqHD4-qG6aE6vqawxaWK_dPttTUYPt9kEHQUyfJmqBtAqpz-c13SoJ3u-OeNRRd44vyhTMJwMnVzSy8iD_c26nwwAPSEjNA6mS1d3D81lTx9YoYg9821BVAaI35dlDL2T1xDAjWGDxxXZi7cBaZHqwPj6sTyyv5s2uN9m06JyIyZBHDtKG9L1n77asF2a2NLpd485SRAEik0sMxz6TnXj9IAJZBKPtMalO7I8bNEVO30De5CVBuvWDKLapws9cZLGsTGhjjZfROEXhqj21rVzM-G9tVUNtRuoACqQAjGncVyqHvajNNMd49F5efoWC2ghzu49VctZwr3EGbFPDZQ1JpX6vI7MMDoSsO47P_Ojhc0EIWXG4Bp_OjLY_6Mw8UykPu8jOXnJb-AhQGVmDcxCsltq2BXLQH1mQqSTcUQqLYjE42cMRWQTcY06ah5aqp1oud85ag5PkZlYprAhcoylYUe6-BuRAoF_F8DScDAUQWfXi5O5g1GklU4sM_r2ftDQ9e7kSUNPDjXtgdM17f2s1OUY9vz330CVUKDv_gR99T8HqlwHYlnV05pSGyN3zYWs_XvdDDQD_uMh7YZsH8KPqYaZjMvJhsgdDWFpsdEcAMOtGwwOmamA95cZDtxlUyV0psJ9CW0enxnNjCfnOF3oMYN8GlsrAe6HHHcXsb4A5AoEKHHiiXGGkD3Mf_PYYmHM6wA3GrqwsZeW83xLT2w6yNRogovMDSbx6Un7h0vReCQBmHTyolCPmoka0aPrtOghPbtKdEVT0VWze9pn1gagIyKvaoCMT-rmxdeRe7Lp_sp9tH8dN-FAv9HUu9DQqfv7SNSGsQG8op8YUgOoUKo4bZsC1qRy6AoBzNP9ho7jfNyEpp-pZ8YZADHck5nQI7Rg1hrceW7rCNxLDMRUxPYayu4lYZeeR2A8nihoAyrhK0sEy-lCP-rlENh7ti6tO1jjSKUhIrzVWqqFWOoXDIjTZTZFir8kqV5ZpnfYr3YRR3Smi134fhUCywDh0ZGl1JUUA2Yp6b773EVgACDgz8aZ91jlDw45RBtGF9QCeOOOZOem75o0iyGBG348Lyh6dDegBX7i4e-lKYjgcnvgJki46Ix540i3QfdcwT-5VWXO_-VA1KfccdA8Mr7H2wHdIsfxO0F_k7mzUjuTyi68qADrXPFi2G2sf2tf2WALWa_UIcl3tmtW410d5AvzKHjs5BdRawIhWqlRjAJJWvhdoifz5JH2KKjRnn9lZgZjHVdM5b40Eb00Xehu4SLqjl0doxBWm1RKNR030fQiQJA6enTQ-sHHwT_qOz9dkhmwXpEQtyqOdK41wDMKp5RvPde8VxjBCqQVHN6fpxNPIJl8Mw1gyRcZm5oeMZHJ7e652kjzlxgtQytOXDBmEOsEuK4BRQZQVT9t3EtmJsvhYxjf13gQl4L5Q_7MKyvpFW5EiOBMauh4qJZncwA1w78WlOP_s42q_ib7of6T8u3UAJEj850Kzhnz_GYIm6OtMrrAXOPJU6PELeiSNAm-zixAoFGf_-EPg5qYwUkcyYUW5rjmD-OIp7IeJOvqQ1BXjfsajLqvL2ebv58tisCTV9HRjINYfE1PBKq1KcKcmsvVplqIjpE-k05ZtjvLDtaO18Zuslpei9nQRMvQzav46avzId-xFHVMCA2RKtnvdiC4gnzgn0DWg0NRSZrKm0KrfzsXtaANF5rGIhZe2edC4tdQfFyJOBkWErSeN1pPiKUtcOgn-k167XdjPHCRGCLjQjeMIwOFpjtTpF191-b7kMIMr6YwldUbEByMuMSG_riqIaqxb0yig29zw14BQkx8cLKlq026kt8DwRUdJr4WdY6iE95yBFpmBPC1B0akMI7ZOtUH8rJc87g6ewvYhPJdvF7tZCsL9zLdf9OUneBrA8Yyfv5hRtSQ_vRHbXjgJQvaNnRthGymSXWPhswm75HmrM-6tV6CjAfuQ4SjdEKGKyv2H2zNBRm2_-ta4Bn7KNK6StSxj8ga68MC8ComOxxY0M689-HReEhSTXFKXNPtY8F246EsjfHVfT_0ZbBP8aTf-krhmfCqGsGoiypM_6jA-wsrYJIbjjf8nMBIKifMGjJ2lFPDV9UrcQbbuBw2RzJ1Zm7vsTati1_C2y28SZ3w77PbA08Ny3vNSEkgpEC0hTUOpAZo3dKTEFnULtuIIexE3BNosYILm3BogHcoICA-awfmHsCUS0lZ-AUA00LU53Vnelw93p4NafmGEbiJd_-MJg7iGx3_32xVDMQWB5LaitnoH4NSuU7VMTTsU5L_NrwQULDJiBEYvdoXJ2Qq4jW5zL0N1jwJ2VdCeTCXvVdM9Cnr43LGDHbu6aJLWX2x05j5L_1CJlKfeF-i4eeI33gdSH3VgQAiAAnKSmwxQs20zhs1nV04yFyT5Ys2HsYdulOIYbE4SWheLRhPdmco5mbSfYxQMXC6rciAt1pcqiELJcyhGe0u-YZhbmpX2n6AaK9gM-sAbiyl1YqtqqlKg6sh0MGRAogYpWtb0_4NAidHy0gfx35Xk1emsKcNQ-Cf-oJQ7nVKpfKW7ZuUc58Kr6snqIOL7A1Uffa9iWjjtIpV79QrUDgIMCt3QS7BDViHzAABr1-eJR_rZqeH-9lCKcwqcyBzUU9c9bGnVmmlYIwlE1raF-wJUcdH5sjdGnkZ-gfJNIXzy_jePyfNH77uZUgL6h3LP2l-GQBGCODnwC5SSTw-3_r-iAmV8hXKGB6DsLmUhgxUxylhDYtIArXOW-gfn7h6ip9gkSqcbWoPGvoJ8R55Hp5Wnu4-_zouZX64ekHpLvT9RF1PxwSraUISkTisBpxutblLqLLE2bX3GQPx9zx04hKVGLp2BUMHMQI6jCvT7tMkVcybXiJDrcQTYQQjeFbXGH0v1gRnmpCCFsKa1cqxQ9B7fN_eZ7nTqfsMe2n6cj-uSrjDIXR2Sjf4x7O2dTDqCYDhHveiEqLX7yyI2xNaOZzWGjh5d0FDIqahgp7uXdOZ5Z2qWIoawgUdGu2mrN0vXCS7y22F_FaklMpdIWdO0-wUoVJejBcwY95kJH6gmIhWRH1LqnI3dkKZTMvl8G5FBZyMkCty6Ey7xKqlfejmvdjKiaQaIpZ6lV0I11OrODNPGX9LI_F4EhCgR4D5dK01BEx_GRTTDMQkvuAyn9FN5_ASJkcBMTfhs4U602htgpaQIoDs5lMOdsz1cVZbv8WorUh6L7KkET2lg4l8U3rO6EY1GxZf3Hn7B_Iwk3tECNOD65Yl_RutWSDvKTy1BaUfuLTZ0ZbVs8DziiLNUXENG5VrgreKDqIRoukEzp4OFekgWornKTHxjc4HFRRKPZ2s3tAg8HBqENVP2i7mHsSauYzKd4yoSiQB2xTYh5QPDuW8hxZs1aDsuBJyKWjcW6NGgAjsBDJqBnaRds8f2Nh_MyWXvDJqJ7FL0Q6AkDvUhdLb-txnHNy6tm3NWcXttNdLUE2epjESnifohadBTEDkVGpN_fTHN4WFuHT7QSR3BNG3jRk.6zQKdAVmjKqqmD15dEPiIg"
EXPECTED_PERSON_DECRYPTED = {
   "uinfin":{
      "lastupdated":"2024-01-26",
      "source":"1",
      "classification":"C",
      "value":"S0290695C"
   },
   "name":{
      "lastupdated":"2024-01-26",
      "source":"1",
      "classification":"C",
      "value":"BERNARD LI GUO HAO"
   },
   "sex":{
      "lastupdated":"2024-01-26",
      "code":"F",
      "source":"1",
      "classification":"C",
      "desc":"FEMALE"
   },
   "race":{
      "lastupdated":"2024-01-26",
      "code":"CN",
      "source":"1",
      "classification":"C",
      "desc":"CHINESE"
   },
   "nationality":{
      "lastupdated":"2024-01-26",
      "code":"MY",
      "source":"1",
      "classification":"C",
      "desc":"MALAYSIAN"
   },
   "dob":{
      "lastupdated":"2024-01-26",
      "source":"1",
      "classification":"C",
      "value":"1991-12-04"
   },
   "email":{
      "lastupdated":"2024-01-26",
      "source":"4",
      "classification":"C",
      "value":"dbstesting03@gmail.com"
   },
   "mobileno":{
      "lastupdated":"2024-01-26",
      "source":"4",
      "classification":"C",
      "areacode":{
         "value":"65"
      },
      "prefix":{
         "value":"+"
      },
      "nbr":{
         "value":"87163551"
      }
   },
   "regadd":{
      "country":{
         "code":"SG",
         "desc":"SINGAPORE"
      },
      "unit":{
         "value":"128"
      },
      "street":{
         "value":"BEDOK NORTH AVENUE 4"
      },
      "lastupdated":"2024-01-26",
      "block":{
         "value":"102"
      },
      "source":"1",
      "postal":{
         "value":"460102"
      },
      "classification":"C",
      "floor":{
         "value":"9"
      },
      "type":"SG",
      "building":{
         "value":"PEARL GARDEN"
      }
   },
   "housingtype":{
      "lastupdated":"2024-01-26",
      "code":"131",
      "source":"1",
      "classification":"C",
      "desc":"CONDOMINIUM"
   },
   "hdbtype":{
      "lastupdated":"2024-01-26",
      "code":"",
      "source":"1",
      "classification":"C",
      "desc":""
   },
   "marital":{
      "lastupdated":"2024-01-26",
      "code":"1",
      "source":"1",
      "classification":"C",
      "desc":"SINGLE"
   },
   "edulevel":{
      "lastupdated":"2024-01-26",
      "code":"",
      "source":"2",
      "classification":"C",
      "desc":""
   },
   "noa-basic":{
      "yearofassessment":{
         "value":"2023"
      },
      "lastupdated":"2024-01-26",
      "amount":{
         "value":100000
      },
      "source":"1",
      "classification":"C"
   },
   "ownerprivate":{
      "lastupdated":"2024-01-26",
      "source":"1",
      "classification":"C",
      "value": False
   },
   "cpfcontributions":{
      "lastupdated":"2024-01-26",
      "source":"1",
      "history":[
         {
            "date":{
               "value":"2022-10-08"
            },
            "employer":{
               "value":"DBS BANK LTD"
            },
            "amount":{
               "value":2035
            },
            "month":{
               "value":"2022-10"
            }
         },
         {
            "date":{
               "value":"2022-11-08"
            },
            "employer":{
               "value":"DBS BANK LTD"
            },
            "amount":{
               "value":2035
            },
            "month":{
               "value":"2022-11"
            }
         },
         {
            "date":{
               "value":"2022-12-08"
            },
            "employer":{
               "value":"DBS BANK LTD"
            },
            "amount":{
               "value":2035
            },
            "month":{
               "value":"2022-12"
            }
         },
         {
            "date":{
               "value":"2023-01-08"
            },
            "employer":{
               "value":"DBS BANK LTD"
            },
            "amount":{
               "value":2035
            },
            "month":{
               "value":"2023-01"
            }
         },
         {
            "date":{
               "value":"2023-02-08"
            },
            "employer":{
               "value":"DBS BANK LTD"
            },
            "amount":{
               "value":2035
            },
            "month":{
               "value":"2023-02"
            }
         },
         {
            "date":{
               "value":"2023-03-08"
            },
            "employer":{
               "value":"DBS BANK LTD"
            },
            "amount":{
               "value":2035
            },
            "month":{
               "value":"2023-03"
            }
         },
         {
            "date":{
               "value":"2023-04-08"
            },
            "employer":{
               "value":"DBS BANK LTD"
            },
            "amount":{
               "value":2035
            },
            "month":{
               "value":"2023-04"
            }
         },
         {
            "date":{
               "value":"2023-05-08"
            },
            "employer":{
               "value":"DBS BANK LTD"
            },
            "amount":{
               "value":2035
            },
            "month":{
               "value":"2023-05"
            }
         },
         {
            "date":{
               "value":"2023-06-08"
            },
            "employer":{
               "value":"DBS BANK LTD"
            },
            "amount":{
               "value":2035
            },
            "month":{
               "value":"2023-06"
            }
         },
         {
            "date":{
               "value":"2023-07-08"
            },
            "employer":{
               "value":"DBS BANK LTD"
            },
            "amount":{
               "value":2035
            },
            "month":{
               "value":"2023-07"
            }
         },
         {
            "date":{
               "value":"2023-08-08"
            },
            "employer":{
               "value":"DBS BANK LTD"
            },
            "amount":{
               "value":2035
            },
            "month":{
               "value":"2023-08"
            }
         },
         {
            "date":{
               "value":"2023-09-08"
            },
            "employer":{
               "value":"DBS BANK LTD"
            },
            "amount":{
               "value":2035
            },
            "month":{
               "value":"2023-09"
            }
         },
         {
            "date":{
               "value":"2023-10-08"
            },
            "employer":{
               "value":"DBS BANK LTD"
            },
            "amount":{
               "value":2035
            },
            "month":{
               "value":"2023-10"
            }
         },
         {
            "date":{
               "value":"2023-11-08"
            },
            "employer":{
               "value":"DBS BANK LTD"
            },
            "amount":{
               "value":2035
            },
            "month":{
               "value":"2023-11"
            }
         },
         {
            "date":{
               "value":"2023-12-08"
            },
            "employer":{
               "value":"DBS BANK LTD"
            },
            "amount":{
               "value":2035
            },
            "month":{
               "value":"2023-12"
            }
         }
      ],
      "classification":"C"
   },
   "cpfbalances":{
      "oa":{
         "lastupdated":"2024-01-26",
         "source":"1",
         "classification":"C",
         "value":89365.6
      },
      "ma":{
         "lastupdated":"2024-01-26",
         "source":"1",
         "classification":"C",
         "value":74584.94
      },
      "sa":{
         "lastupdated":"2024-01-26",
         "source":"1",
         "classification":"C",
         "value":66485.84
      },
      "ra":{
         "lastupdated":"2024-01-26",
         "source":"1",
         "classification":"C",
         "unavailable": True
      }
   }
}

EXPECTED_PERSON_DECRYPTEDSSS = {
    "employmentsector": {
        "lastupdated": "2024-01-26",
        "source": "3",
        "classification": "C",
        "value": "",
    },
    "uinfin": {
        "lastupdated": "2024-01-26",
        "source": "1",
        "classification": "C",
        "value": "S0290695C",
    },
    "name": {
        "lastupdated": "2024-01-26",
        "source": "1",
        "classification": "C",
        "value": "BERNARD LI GUO HAO",
    },
    "sex": {
        "lastupdated": "2024-01-26",
        "code": "F",
        "source": "1",
        "classification": "C",
        "desc": "FEMALE",
    },
    "race": {
        "lastupdated": "2024-01-26",
        "code": "CN",
        "source": "1",
        "classification": "C",
        "desc": "CHINESE",
    },
    "dob": {
        "lastupdated": "2024-01-26",
        "source": "1",
        "classification": "C",
        "value": "1991-12-04",
    },
    "residentialstatus": {
        "lastupdated": "2024-01-26",
        "code": "P",
        "source": "1",
        "classification": "C",
        "desc": "PR",
    },
    "nationality": {
        "lastupdated": "2024-01-26",
        "code": "MY",
        "source": "1",
        "classification": "C",
        "desc": "MALAYSIAN",
    },
    "birthcountry": {
        "lastupdated": "2024-01-26",
        "code": "MY",
        "source": "1",
        "classification": "C",
        "desc": "MALAYSIA",
    },
    "passtype": {
        "lastupdated": "2024-01-26",
        "code": "",
        "source": "3",
        "classification": "C",
        "desc": "",
    },
    "passstatus": {"lastupdated": "2024-01-26", "source": "3", "classification": "C", "value": ""},
    "passexpirydate": {
        "lastupdated": "2024-01-26",
        "source": "3",
        "classification": "C",
        "value": "",
    },
    "mobileno": {
        "lastupdated": "2024-01-26",
        "source": "4",
        "classification": "C",
        "areacode": {"value": "65"},
        "prefix": {"value": "+"},
        "nbr": {"value": "87163551"},
    },
    "email": {
        "lastupdated": "2024-01-26",
        "source": "4",
        "classification": "C",
        "value": "dbstesting03@gmail.com",
    },
    "regadd": {
        "country": {"code": "SG", "desc": "SINGAPORE"},
        "unit": {"value": "128"},
        "street": {"value": "BEDOK NORTH AVENUE 4"},
        "lastupdated": "2024-01-26",
        "block": {"value": "102"},
        "source": "1",
        "postal": {"value": "460102"},
        "classification": "C",
        "floor": {"value": "9"},
        "type": "SG",
        "building": {"value": "PEARL GARDEN"},
    },
    "housingtype": {
        "lastupdated": "2024-01-26",
        "code": "131",
        "source": "1",
        "classification": "C",
        "desc": "CONDOMINIUM",
    },
    "hdbtype": {
        "lastupdated": "2024-01-26",
        "code": "",
        "source": "1",
        "classification": "C",
        "desc": "",
    },
    "cpfcontributions": {
        "lastupdated": "2024-01-26",
        "source": "1",
        "history": [
            {
                "date": {"value": "2022-10-08"},
                "employer": {"value": "DBS BANK LTD"},
                "amount": {"value": 2035},
                "month": {"value": "2022-10"},
            },
            {
                "date": {"value": "2022-11-08"},
                "employer": {"value": "DBS BANK LTD"},
                "amount": {"value": 2035},
                "month": {"value": "2022-11"},
            },
            {
                "date": {"value": "2022-12-08"},
                "employer": {"value": "DBS BANK LTD"},
                "amount": {"value": 2035},
                "month": {"value": "2022-12"},
            },
            {
                "date": {"value": "2023-01-08"},
                "employer": {"value": "DBS BANK LTD"},
                "amount": {"value": 2035},
                "month": {"value": "2023-01"},
            },
            {
                "date": {"value": "2023-02-08"},
                "employer": {"value": "DBS BANK LTD"},
                "amount": {"value": 2035},
                "month": {"value": "2023-02"},
            },
            {
                "date": {"value": "2023-03-08"},
                "employer": {"value": "DBS BANK LTD"},
                "amount": {"value": 2035},
                "month": {"value": "2023-03"},
            },
            {
                "date": {"value": "2023-04-08"},
                "employer": {"value": "DBS BANK LTD"},
                "amount": {"value": 2035},
                "month": {"value": "2023-04"},
            },
            {
                "date": {"value": "2023-05-08"},
                "employer": {"value": "DBS BANK LTD"},
                "amount": {"value": 2035},
                "month": {"value": "2023-05"},
            },
            {
                "date": {"value": "2023-06-08"},
                "employer": {"value": "DBS BANK LTD"},
                "amount": {"value": 2035},
                "month": {"value": "2023-06"},
            },
            {
                "date": {"value": "2023-07-08"},
                "employer": {"value": "DBS BANK LTD"},
                "amount": {"value": 2035},
                "month": {"value": "2023-07"},
            },
            {
                "date": {"value": "2023-08-08"},
                "employer": {"value": "DBS BANK LTD"},
                "amount": {"value": 2035},
                "month": {"value": "2023-08"},
            },
            {
                "date": {"value": "2023-09-08"},
                "employer": {"value": "DBS BANK LTD"},
                "amount": {"value": 2035},
                "month": {"value": "2023-09"},
            },
            {
                "date": {"value": "2023-10-08"},
                "employer": {"value": "DBS BANK LTD"},
                "amount": {"value": 2035},
                "month": {"value": "2023-10"},
            },
            {
                "date": {"value": "2023-11-08"},
                "employer": {"value": "DBS BANK LTD"},
                "amount": {"value": 2035},
                "month": {"value": "2023-11"},
            },
            {
                "date": {"value": "2023-12-08"},
                "employer": {"value": "DBS BANK LTD"},
                "amount": {"value": 2035},
                "month": {"value": "2023-12"},
            },
        ],
        "classification": "C",
    },
    "noahistory": {
        "noas": [
            {
                "amount": {"value": 100000},
                "trade": {"value": 0},
                "interest": {"value": 0},
                "yearofassessment": {"value": "2023"},
                "taxclearance": {"value": "N"},
                "employment": {"value": 100000},
                "rent": {"value": 0},
                "category": {"value": "ORIGINAL"},
            },
            {
                "amount": {"value": 150000},
                "trade": {"value": 0},
                "interest": {"value": 0},
                "yearofassessment": {"value": "2022"},
                "taxclearance": {"value": "N"},
                "employment": {"value": 150000},
                "rent": {"value": 0},
                "category": {"value": "ORIGINAL"},
            },
        ],
        "lastupdated": "2024-01-26",
        "source": "1",
        "classification": "C",
    },
    "ownerprivate": {
        "lastupdated": "2024-01-26",
        "source": "1",
        "classification": "C",
        "value": False,
    },
    "employment": {"lastupdated": "2024-01-26", "source": "2", "classification": "C", "value": ""},
    "occupation": {"lastupdated": "2024-01-26", "source": "2", "classification": "C", "value": ""},
    "cpfemployers": {
        "lastupdated": "2024-01-26",
        "source": "1",
        "history": [
            {"month": {"value": "2022-10"}, "employer": {"value": "DBS BANK LTD"}},
            {"month": {"value": "2022-11"}, "employer": {"value": "DBS BANK LTD"}},
            {"month": {"value": "2022-12"}, "employer": {"value": "DBS BANK LTD"}},
            {"month": {"value": "2023-01"}, "employer": {"value": "DBS BANK LTD"}},
            {"month": {"value": "2023-02"}, "employer": {"value": "DBS BANK LTD"}},
            {"month": {"value": "2023-03"}, "employer": {"value": "DBS BANK LTD"}},
            {"month": {"value": "2023-04"}, "employer": {"value": "DBS BANK LTD"}},
            {"month": {"value": "2023-05"}, "employer": {"value": "DBS BANK LTD"}},
            {"month": {"value": "2023-06"}, "employer": {"value": "DBS BANK LTD"}},
            {"month": {"value": "2023-07"}, "employer": {"value": "DBS BANK LTD"}},
            {"month": {"value": "2023-08"}, "employer": {"value": "DBS BANK LTD"}},
            {"month": {"value": "2023-09"}, "employer": {"value": "DBS BANK LTD"}},
            {"month": {"value": "2023-10"}, "employer": {"value": "DBS BANK LTD"}},
            {"month": {"value": "2023-11"}, "employer": {"value": "DBS BANK LTD"}},
            {"month": {"value": "2023-12"}, "employer": {"value": "DBS BANK LTD"}},
        ],
        "classification": "C",
    },
    "marital": {
        "lastupdated": "2024-01-26",
        "code": "1",
        "source": "1",
        "classification": "C",
        "desc": "SINGLE",
    },
}

SAMP = {
    "keys": [
        {
            "alg": "RS256",
            "use": "sig",
            "kty": "RSA",
            "kid": "_RC6xwOMvbtt6ajWuZe6Glgs-j3wm5riAyCUoRasa-I",
            "x5t": "tsPLUcV212j_gO4vY-2pUI9CHhw",
            "n": "sGBNIs4nsiHNfLqoR40h06We1IvWVaGISvETHKlJATWIURd9wx1bqHZ6tesVmLYqKT776kgxXwVD8NP0Vu-Th8C-IF-9fMNOa8_TeowvcqDiIRjL7RId8kmpcmjtIS2G-MolfSbH7CRWVRko4q88LMbJUAlglSnFppfQhsEVYlwLtZlHAYy9cl8PcsxPmFUzCUH4Fefyq77BBUPMpzbZLLjlAj97rF1oSQJKHM6RBLcvI-AauRpKe34O3GR9bCCTbkhETVerWsemtFUznr9moOSaDkEMIGA5wDyt12kjKKvbbm-k2Y5TMq1IIQXfhihGAbTttVpmZLYwJda0nemL4Q",
            "e": "AQAB"
        },
        {
            "alg": "ES256",
            "use": "sig",
            "kty": "EC",
            "kid": "AFMnnKRWTaBYEhNfEB6iQ5ErC1yqGVyZchH8A7nl_yM",
            "crv": "P-256",
            "x": "L_GG9F-hIWXxUEWCB4Fco6zXJkbaU_aUMSbHVbwEwso",
            "y": "lNPEj7SHn5IFsO76Xel13d3NDlql8JyToZFylm5V-kU"
        },
        {
            "alg": "ECDH-ES+A256KW",
            "use": "enc",
            "kty": "EC",
            "kid": "M-JXqh0gh1GGUUdzNue3IUDyUiagqjHathnscUk2nS8",
            "crv": "P-256",
            "x": "qrR8PAUO6fDouV-6mVdix5IyrVMtu0PVS0nOqWBZosA",
            "y": "6xSbySYW6ke2V727TCgSOPiH4XSDgxFCUrAAMSbl9tI"
        },
        {
            "kty": "RSA",
            "kid": "DVVOeIJY9-UKVBOSfIys1FpVhtNeg2iMUCeSBuBkJZs",
            "x5t": "cKZSFGviM-dYbGHrLjn0zp6tbKg",
            "n": "5lj1EE4NMZQJxJAtBEIdJQduc72sMU_hS-GHwcflEZdPKXaaIj9FDR5GsP6EBwnci_5ACmzvKWCd60WOcMK2732mkVLSl4WV8yqA-D0jg6lJZSlrYZ2ubKvHeFYxJk9a225Zq6n6dQpMoF_3NfQGUBLO6HdsE7T9KoZ9ED3XoQJJyovKYcuebMSzomW-SJiq1eHFx2uWdzlCclsSaK78YgqauItG41zowZiyJa5k_R6KqEh1soZC6_6OTPQk73SSPUjeex-Ir3cXTWTWV8gbN1kXlIBcbAtx7JweIc3w7o8TuF9zHt3JyPpKLCNZRPKxGycog0OnQuQSwvy_W-dMUQ",
            "e": "AQAB",
            "use": "sig",
            "alg": "RS256"
        }
    ]
}

SAMP_MYINFO = json.dumps({
    "keys": [
        {
            "alg": "RS256",
            "use": "sig",
            "kty": "RSA",
            "kid": "_RC6xwOMvbtt6ajWuZe6Glgs-j3wm5riAyCUoRasa-I",
            "x5t": "tsPLUcV212j_gO4vY-2pUI9CHhw",
            "n": "sGBNIs4nsiHNfLqoR40h06We1IvWVaGISvETHKlJATWIURd9wx1bqHZ6tesVmLYqKT776kgxXwVD8NP0Vu-Th8C-IF-9fMNOa8_TeowvcqDiIRjL7RId8kmpcmjtIS2G-MolfSbH7CRWVRko4q88LMbJUAlglSnFppfQhsEVYlwLtZlHAYy9cl8PcsxPmFUzCUH4Fefyq77BBUPMpzbZLLjlAj97rF1oSQJKHM6RBLcvI-AauRpKe34O3GR9bCCTbkhETVerWsemtFUznr9moOSaDkEMIGA5wDyt12kjKKvbbm-k2Y5TMq1IIQXfhihGAbTttVpmZLYwJda0nemL4Q",
            "e": "AQAB"
        },
        {
            "alg": "ES256",
            "use": "sig",
            "kty": "EC",
            "kid": "AFMnnKRWTaBYEhNfEB6iQ5ErC1yqGVyZchH8A7nl_yM",
            "crv": "P-256",
            "x": "L_GG9F-hIWXxUEWCB4Fco6zXJkbaU_aUMSbHVbwEwso",
            "y": "lNPEj7SHn5IFsO76Xel13d3NDlql8JyToZFylm5V-kU"
        },
        {
            "alg": "ECDH-ES+A256KW",
            "use": "enc",
            "kty": "EC",
            "kid": "M-JXqh0gh1GGUUdzNue3IUDyUiagqjHathnscUk2nS8",
            "crv": "P-256",
            "x": "qrR8PAUO6fDouV-6mVdix5IyrVMtu0PVS0nOqWBZosA",
            "y": "6xSbySYW6ke2V727TCgSOPiH4XSDgxFCUrAAMSbl9tI"
        },
        {
            "kty": "RSA",
            "kid": "DVVOeIJY9-UKVBOSfIys1FpVhtNeg2iMUCeSBuBkJZs",
            "x5t": "cKZSFGviM-dYbGHrLjn0zp6tbKg",
            "n": "5lj1EE4NMZQJxJAtBEIdJQduc72sMU_hS-GHwcflEZdPKXaaIj9FDR5GsP6EBwnci_5ACmzvKWCd60WOcMK2732mkVLSl4WV8yqA-D0jg6lJZSlrYZ2ubKvHeFYxJk9a225Zq6n6dQpMoF_3NfQGUBLO6HdsE7T9KoZ9ED3XoQJJyovKYcuebMSzomW-SJiq1eHFx2uWdzlCclsSaK78YgqauItG41zowZiyJa5k_R6KqEh1soZC6_6OTPQk73SSPUjeex-Ir3cXTWTWV8gbN1kXlIBcbAtx7JweIc3w7o8TuF9zHt3JyPpKLCNZRPKxGycog0OnQuQSwvy_W-dMUQ",
            "e": "AQAB",
            "use": "sig",
            "alg": "RS256"
        }
    ]
})


class TestJWT(unittest.TestCase):
    maxDiff = None

    @patch("my_info.utils.security.get_random_string")
    @patch("my_info.utils.security.time.time", return_value=1710202991.123456)
    @patch("my_info.utils.security.generate_ephemeral_session_keypair")
    def test_generate_client_assertion(
        self, mock_generate_ephemeral_session_keypair, mock_time, mock_get_random_string
    ):
        mock_generate_ephemeral_session_keypair.return_value = jwk.JWK.from_json(
            SAMPLE_EPHEMERAL_SESSION_KEYPAIR_EXPORT
        )
        mock_get_random_string.return_value = "OWcyc0bs4Sx0iXYqb57OhT5W793zWaOguThZVDBs"

        sig = generate_client_assertion(
            "https://test.api.myinfo.gov.sg/com/v4/token",
            "ghatI5LS0CkrMHHj_MbSdHAP-18TDD6iEPOmjXO5zZE",
        )

        jwstoken = jws.JWS()
        jwstoken.deserialize(sig)
        # jwstoken.verify(jwk.JWK.from_json(myinfo_settings.MYINFO_PRIVATE_KEY_SIG))
        from my_info.utils.security import open_cert
        jwstoken.verify(jwk.JWK.from_pem(open_cert("SIGNING_PRIVATE_KEY_PATH")))
        self.assertEqual(
            json.loads(jwstoken.payload.decode()),
            {
                "sub": "STG2-MYINFO-SELF-TEST",
                "jti": "OWcyc0bs4Sx0iXYqb57OhT5W793zWaOguThZVDBs",
                "aud": "https://test.api.myinfo.gov.sg/com/v4/token",
                "iss": "STG2-MYINFO-SELF-TEST",
                "iat": 1710202991,
                "exp": 1710203291,
                "cnf": {"jkt": "ghatI5LS0CkrMHHj_MbSdHAP-18TDD6iEPOmjXO5zZE"},
            },
        )
        self.assertEqual(
            jwstoken.jose_header,
            {"alg": "ES256", "kid": "aQPyZ72NM043E4KEioaHWzixt0owV99gC9kRK388WoQ", "typ": "JWT"},
        )

    @patch("my_info.utils.security.get_random_string")
    @patch("my_info.utils.security.time.time", return_value=1710202991.123456)
    def test_generate_dpop_header(self, mock_time, mock_get_random_string):
        mock_get_random_string.return_value = "DdDB3S5I10qHmwCGgciAosejxSquL6SA944r7yGH"
        session_ephemeral_keypair = jwk.JWK.from_json(SAMPLE_EPHEMERAL_SESSION_KEYPAIR_EXPORT)

        sig = generate_dpop_header(
            "https://test.api.myinfo.gov.sg/com/v4/token", session_ephemeral_keypair
        )

        jwstoken = jws.JWS()
        jwstoken.deserialize(sig)
        jwstoken.verify(session_ephemeral_keypair)
        self.assertEqual(
            json.loads(jwstoken.payload.decode()),
            {
                "htu": "https://test.api.myinfo.gov.sg/com/v4/token",
                "htm": "POST",
                "jti": "DdDB3S5I10qHmwCGgciAosejxSquL6SA944r7yGH",
                "iat": 1710202991,
                "exp": 1710203111,
            },
        )
        self.assertEqual(
            jwstoken.jose_header,
            {
                "alg": "ES256",
                "jwk": {
                    "alg": "ES256",
                    "crv": "P-256",
                    "kid": "ghatI5LS0CkrMHHj_MbSdHAP-18TDD6iEPOmjXO5zZE",
                    "kty": "EC",
                    "use": "sig",
                    "x": "hzP7o6QSUsqoEG1_ia7uXKWUxMnLZyDsc_Q_58vX9Gg",
                    "y": "UNTaMkOSmhCcZdVbClmKNOYD3i8LJ3yYMNjFCyV8zOk",
                },
                "typ": "dpop+jwt",
            },
        )

    @responses.activate
    def test_verify_jws(self):
        responses.add(
            responses.GET,
            myinfo_settings.MYINFO_JWKS_TOKEN_VERIFICATION_URL,
            body=SAMPLE_MYINFO_JWKS_TOKEN_VERIFICATION_DATA,
            status=200,
        )

        jwkset = get_jwkset(myinfo_settings.MYINFO_JWKS_TOKEN_VERIFICATION_URL)
        result = verify_jws(SAMPLE_TOKEN_RESP["access_token"], jwkset)
        self.assertEqual(result, EXPECTED_DECODED_ACCESS_TOKEN)

    @responses.activate
    def test_decrypt_jwe(self):
        responses.add(
            responses.GET,
            # myinfo_settings.MYINFO_JWKS_DATA_VERIFICATION_URL,
            MYINFO_CONNECTOR_CONFIG.get("MYINFO_JWKS_URL"),
            body=SAMP_MYINFO,
            status=200,
        )

        result = decrypt_jwe(SAMPLE_PERSON_ENCRYPTED)
        self.assertEqual(result, EXPECTED_PERSON_DECRYPTED)
