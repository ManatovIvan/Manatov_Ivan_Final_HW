# Manatov_Ivan_Final_HW

Простой инструмент для мониторинга угроз безопасности. Скрипт анализирует логи Suricata, проверяет подозрительные IP-адреса через API VirusTotal и имитирует блокировку угроз.

## Возможности
- Чтение логов в формате JSON (Suricata EVE).
- Проверка IP-адресов через VirusTotal API.
- Автоматическое реагирование (вывод сообщения о блокировке).
- Генерация отчета в CSV и графика в PNG.

## Установка

1. Клонируйте репозиторий.
2. Установите зависимости:
   ```bash
   pip install requests pandas matplotlib
3. Настройка API-ключа  

   Скрипт использует переменную окружения `VirusTotal` для безопасного хранения ключа API.
   
   *   **Для Windows:**
       ```shell
       set VirusTotal=ВАШ_КЛЮЧ_API
       ```
   
   *   **Для Linux / macOS:**
       ```shell
       export VirusTotal=ВАШ_КЛЮЧ_API
       ```

4. Запуск скрипта

   ```shell
   python3 virustotal_checker.py
   ```
