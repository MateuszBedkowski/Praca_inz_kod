import os
import json

def odczytaj_pliki_json_w_folderze(folder_path):
    for foldername, subfolders, filenames in os.walk(folder_path):
        for filename in filenames:
            pełna_ścieżka = os.path.join(foldername, filename)
            if pełna_ścieżka.endswith('.json'):
                with open(pełna_ścieżka, 'r', encoding='utf-8') as plik:
                    try:
                        zawartość_json = json.load(plik)
                        # Tutaj możesz przetworzyć zawartość pliku JSON według potrzeb
                        #print(f'Zawartość pliku JSON {pełna_ścieżka}:')
                        print(json.dumps(zawartość_json, indent=2))  # Wyświetla sformatowaną zawartość JSON
                        print('\n' + '-'*40 + '\n')
                    except json.JSONDecodeError as e:
                        print(f'Błąd podczas odczytu pliku JSON {pełna_ścieżka}: {e}')

# Przykład użycia
folder_path = r'C:\Users\bedko\Downloads\cvelistV5-main'
odczytaj_pliki_json_w_folderze(folder_path)
