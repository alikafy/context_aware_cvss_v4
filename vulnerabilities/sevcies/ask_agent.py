import json
import time

import requests

from context_aware.settings import GILAS_TOKEN
from vulnerabilities.models import APICallLog


def make_request(prompt: str, system_content: str = None, model: str = 'gpt-4o'):
    url = 'https://api.gilas.io/v1/chat/completions'
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {GILAS_TOKEN}'
    }
    payload = {
        'model': model if model else 'gpt-4o',
        "messages": [
            {
                "role": "system",
                "content": system_content if system_content else "You are a helpful cybersecurity expert."
            },
            {"role": "user", "content": prompt}
        ]
    }

    log = APICallLog.objects.create(
        endpoint=url,
        method="POST",
        request_headers=headers,
        request_body=json.dumps(payload),
    )

    attempts = 2
    for attempt in range(1, attempts + 1):
        try:
            response = requests.post(url, json=payload, headers=headers)
            log.response_status = response.status_code
            log.response_headers = dict(response.headers)
            log.response_body = response.text

            response.raise_for_status()

            content = response.json()['choices'][0]['message']['content']
            cleaned = content.replace('```', '').replace('json', '', 1).replace('\n', '')

            log.save()
            return json.loads(cleaned)

        except Exception as e:
            log.error_message = str(e)
            log.save()
            if attempt < attempts:
                time.sleep(1.0)
                continue
            else:
                raise e
    return None
