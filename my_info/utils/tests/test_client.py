import unittest
from django.utils.crypto import get_random_string
from my_info.utils.client import MyInfoPersonalClientV4
from my_info.utils.security import generate_code_challenge


class TestMyInfoPersonalClientV4(unittest.TestCase):
    maxDiff = None

    def test_get_authorise_url(self):
        oauth_state = get_random_string(length=16)
        callback_url = "http://localhost:3001/callback"
        code_chal = generate_code_challenge(oauth_state)

        authorise_url = MyInfoPersonalClientV4().get_authorise_url(
            oauth_state, callback_url
        )
        self.assertEqual(
            authorise_url,
            f"https://test.api.myinfo.gov.sg/com/v4/authorize?client_id=STG2-MYINFO-SELF-TEST&scope=uinfin%20name%20sex%20race%20nationality%20dob%20email%20mobileno%20regadd%20housingtype%20hdbtype%20marital%20edulevel%20noa-basic%20ownerprivate%20cpfcontributions%20cpfbalances&purpose_id=None&response_type=code&code_challenge={code_chal}&code_challenge_method=S256&redirect_uri=http://localhost:3001/callback",  # noqa: E501
        )
