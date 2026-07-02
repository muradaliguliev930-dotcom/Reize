FROM python:3.11-slim

WORKDIR /app

### Установка системных зависимостей для работы с BLE

RUN apt-get update && apt-get install -y  
bluez  
bluetooth  
&& rm -rf /var/lib/apt/lists/\*

### Копирование проекта

COPY . /app/

### Запуск платформы REIZE

ENTRYPOINT \["python", "main.py"\]
