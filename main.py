import os
import json
import requests
import pandas as pd
import matplotlib.pyplot as plt
import time

# Настройки
VT_API_KEY = os.environ.get('VirusTotal')
LOG_FILE = 'log.txt'
REPORT_FILE = 'report.csv'
CHART_FILE = 'threats_chart.png'

def load_logs(filepath):
    """Читаем логи Suricata и ищем уникальные внешние IP из алертов"""
    suspicious_ips = set()
    print(f"[*] Читаю логи из {filepath}...")
    
    try:
        with open(filepath, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    # Нас интересуют только алерты и внешние IP (для примера берем src_ip)
                    if entry.get('event_type') == 'alert':
                        ip = entry.get('src_ip')
                        # Игнорируем локальные IP для проверки в VT (простая фильтрация)
                        if not ip.startswith('192.168.') and not ip.startswith('10.'):
                            suspicious_ips.add(ip)
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        print("Ошибка: Файл логов не найден.")
        return []
    
    return list(suspicious_ips)

def check_virustotal(ip):
    """Проверка IP через API VirusTotal"""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            return stats['malicious']
        else:
            print(f"Ошибка API VT для {ip}: {response.status_code}")
            return 0
    except Exception as e:
        print(f"Ошибка соединения: {e}")
        return 0

def respond_to_threat(ip, score):
    """Имитация реагирования"""
    if score > 0:
        print(f"!!! УГРОЗА ОБНАРУЖЕНА [{ip}]. Malicious score: {score}. БЛОКИРОВКА IP...")
        # Здесь могла бы быть команда для iptables
    else:
        print(f"[*] IP {ip} чист.")

def main():
    if not VT_API_KEY:
        print("Ошибка: Не задана переменная окружения VirusTotal")
        return

    # 1. Сбор данных (Логи)
    ips_to_check = load_logs(LOG_FILE)
    print(f"Найдено подозрительных IP для проверки: {len(ips_to_check)}")

    results = []

    # 2. Анализ (API VirusTotal)
    for ip in ips_to_check:
        print(f"Проверяю {ip}...")
        malicious_score = check_virustotal(ip)
        
        # 3. Реагирование
        respond_to_threat(ip, malicious_score)
        
        results.append({'IP': ip, 'Malicious_Score': malicious_score})
        time.sleep(15) # Пауза, так как у бесплатного VT лимит 4 запроса в минуту

    # 4. Отчет и Визуализация
    if results:
        df = pd.DataFrame(results)
        
        # Сохраняем CSV
        df.to_csv(REPORT_FILE, index=False)
        print(f"Отчет сохранен в {REPORT_FILE}")

        # Строим график
        plt.figure(figsize=(8, 5))
        plt.bar(df['IP'], df['Malicious_Score'], color='red')
        plt.title('Уровень угрозы по IP (VirusTotal)')
        plt.xlabel('IP адрес')
        plt.ylabel('Кол-во детектов (Malicious)')
        plt.savefig(CHART_FILE)
        print(f"График сохранен в {CHART_FILE}")
    else:
        print("Нет данных для отчета.")

if __name__ == "__main__":
    main()
