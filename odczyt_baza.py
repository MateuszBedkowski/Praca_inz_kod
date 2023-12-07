import os
import json

def odczytaj_pliki_json_w_folderze(folder_path):
    for foldername, subfolders, filenames in os.walk(folder_path):
        for filename in filenames:
            pełna_ścieżka = os.path.join(foldername, filename)
            if pełna_ścieżka.endswith('.json'):
                try:
                    odczytaj_i_wyswietl_info(pełna_ścieżka)
                except Exception as e:
                    print(f'Błąd podczas przetwarzania pliku {pełna_ścieżka}: {e}')

def odczytaj_i_wyswietl_info(plik_path):
    with open(plik_path, 'r', encoding='utf-8') as plik:
        dane_json = json.load(plik)

        # Wyświetl informacje o CVE ID
        cve_id = dane_json.get('cveMetadata', {}).get('cveId', 'Brak informacji')
        print(f"CVE ID: {cve_id}")

        # Wyświetl informacje o Description
        description = dane_json.get('containers', {}).get('cna', {}).get('descriptions', [{}])[0].get('value', 'Brak informacji')
        print(f"Description: {description}")

        # Wyświetl pierwszy URL
        url = dane_json.get('containers', {}).get('cna', {}).get('references', [{}])[0].get('url', 'Brak informacji')
        print(f"URL: {url}")

        print('\n' + '-'*40 + '\n')  # Dodaj separator między wynikami

# Przykład użycia
folder_path = r'C:\Users\bedko\Downloads\cvelistV5-main'
odczytaj_pliki_json_w_folderze(folder_path)
