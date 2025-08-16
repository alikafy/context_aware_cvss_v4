import json

import requests


def make_request(prompt:str, system_content: str = None, model: str = 'gpt-4o'):
    url = 'https://api.gilas.io/v1/chat/completions'
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjIwNjkxMzExMjMsImp0aSI6ImE2ZjA2MWI1LWVlMDUtNDIwYS1hOWRiLWY4ZjBlMTMwY2U4NSIsImlhdCI6MTc1Mzc3MTEyMywiaXNzIjoiaHR0cHM6Ly9naWxhcy5pbyIsIm5iZiI6MTc1Mzc3MTEyMywic3ViIjoiMTExODIyMTMzMjA3NDA5MTExNzU4Iiwic2NvcGUiOiJbXCJhcGlcIl0ifQ.3kdvcDFYIdMMH3Q_J7oJm7hYmiGWfoOYjdERmvXah9Y'
    }
    payload = {
        'model': model,  # 'deepseek-chat',
        "messages": [
            {"role": "system", "content": system_content if system_content else "You are a helpful cybersecurity expert."},
            {"role": "user", "content": prompt}
        ]
    }
    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()
    return json.loads(
        response.json()['choices'][0]['message']['content'].replace('```', '').replace('json', '', 1).replace('\n', ''))
