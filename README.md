# ICAP-сервер RESPMOD

Сервис `/decrypt` принимает вложенный HTTP-ответ через ICAP/1.0. Тело с маркером `ENC1` расшифровывается с помощью AES-256-GCM и тестового ключа из задания. Для обычного тела сервер возвращает полученные HTTP-заголовки и байты тела. Некорректный контейнер и ошибка проверки тега дают `ICAP/1.0 400 Bad Request`.

## Запуск

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m icap_decrypt
```