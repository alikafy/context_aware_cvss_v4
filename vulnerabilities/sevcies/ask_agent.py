import json
import time

import requests

from context_aware.settings import GILAS_TOKEN


def make_request(prompt:str, system_content: str = None, model: str = 'gpt-4o'):
    url = 'https://api.gilas.io/v1/chat/completions'
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {GILAS_TOKEN}'
    }
    payload = {
        'model': model if model else 'gpt-4o',  # 'deepseek-chat',
        "messages": [
            {"role": "system", "content": system_content if system_content else "You are a helpful cybersecurity expert."},
            {"role": "user", "content": prompt}
        ]
    }
    attempts = 2
    for attempt in range(1, attempts + 1):
        try:
            response = requests.post(url, json=payload, headers=headers)
            response.raise_for_status()
            return json.loads(
                response.json()['choices'][0]['message']['content'].replace('```', '').replace('json', '', 1).replace('\n', ''))
        except Exception as e:
            if attempt < attempts:
                time.sleep(1.0)
                continue
            else:
                raise e
    return None