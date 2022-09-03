import requests
from requests.auth import HTTPBasicAuth


HOST = 'http://127.0.0.1:5000'

# response = requests.post(f'{HOST}/users/', json={'mail': 'user_1', 'password': '1234'})
# print(response.status_code)
# print(response.text)

# response = requests.patch(f'{HOST}/users/1', auth=HTTPBasicAuth('user_2', '12345'), json={'mail': 'user_2'})
# print(response.status_code)
# print(response.text)
#
# response = requests.get(f'{HOST}/users/1', auth=HTTPBasicAuth('user_2', '12345'))
# print(response.status_code)
# print(response.text)

# response = requests.post(f'{HOST}/adv/', auth=HTTPBasicAuth('user_2', '12345'), json={'header': 'adv_2', 'description': 'dawdsvdsrtbtw dfbb s', 'owner': 1})
# print(response.status_code)
# print(response.text)

# response = requests.get(f'{HOST}/adv/2', auth=HTTPBasicAuth('user_1', '1234'))
# print(response.status_code)
# print(response.text)

# response = requests.patch(f'{HOST}/adv/2', auth=HTTPBasicAuth('user_1', '1234'), json={'header': 'adv_1_v2'})
# print(response.status_code)
# print(response.text)

response = requests.delete(f'{HOST}/adv/2', auth=HTTPBasicAuth('user_2', '12345'))
print(response.status_code)
print(response.text)
