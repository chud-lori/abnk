# MyInfo Integration

## Setup
1. Set up virtual env and install requirements
```shell
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
```

2. Set env variable `ENV
`export ENV=test`

3. Run the server on port 3001
`python manage.py runserver 3001`

## Testing

### In Browser

1. Open the `127.0.0.1:3001`
2. Click `Retrieve My Info`
3. Click `Login`
4. Click `Agree`
5. It will load the person data

### In Shell

```python
from django.utils.crypto import get_random_string
import django
import os
os.environ['DJANGO_SETTINGS_MODULE'] = 'abnk.settings'
django.setup()

from my_info.utils.client import MyInfoPersonalClientV4

oauth_state = get_random_string(length=16)
callback_url = "http://localhost:3001/callback"

client = MyInfoPersonalClientV4()

client.get_authorise_url(oauth_state, callback_url)

# Open up this SingPass Authorise URL and follow instructions
# After clicking on the "I Agree" button, you'll be redirected back to a callback URL like this
# http://localhost:3001/callback?code=myinfo-com-NlZPurlLUH79euT2I0xT6dFnY0lbf5oNVAhNVo8U


# Getting access token and getting person data
# Note: paste the auth code from the above callback
auth_code = "myinfo-com-NlZPurlLUH79euT2I0xT6dFnY0lbf5oNVAhNVo8U"
person_data = MyInfoPersonalClientV4().retrieve_resource(auth_code, oauth_state, callback_url)
print(person_data)
```
### Unit test

Run test:
`python manage.py test`
