1. Zawartość rozwiązania
Rozwiązanie składa się z następujących plików:
 - README
 - Makefile
 - raise_utils.c, raise_utils.h - pomocnicze funkcje, głównie wrappery na
    funkcje systemowe sprawdzające dodatkowo, czy wywołanie nie zakończyło
    się błędem
 - raise.c - właściwy program

2. Opis rozwiązania
Program (zlinkowany poniżej standardowego adresu ładowania) kolejno:
 - przenosi swój stos poniżej standardowego adresu ładowania
 - sprawdza, czy podany plik jest poprawnym plikiem core na x86 32bit
 - wśród nagłówków programu szuka PT_NOTE i wczytuje z niego (do zdefiniowanej
 w raise.c struktury pt_note_info_t): informacje o rejestrach, zmapowane pliki
 oraz adres segmentu TLS.
 Jeśli któraś ze struktur NT_PRSTATUS, NT_386_TLS nie została znaleziona,
 program kończy się.
 Informacje z NT_FILE przechowywane są w statycznej strukturze - rozwiązanie
 zakłada, że program będzie miał nie więcej niż 1000 zmapowanych plików
 (narzucenie ograniczenia pozwala trzymać informacje o zmapowanych plikach w
 pamięci i co za tym idzie - uniknąć wielokrotnego czytania sekcji
 NT_FILE, a 1000 wydaje się autorowi sensowną wartością).
 - mapuje fragmenty pamięci z PT_LOAD, szukając dla każdego fragmentu
 wszystkich wpisów z NT_FILE, które zawierają się w tym fragmencie
 i wykonując odpowiednie mapowania z plików
 - odtwarza adres segmentu TLS
 - uzupełnia template (tablica set_registers_template) zawierający kod
 ustawiający wartości rejestrów i skaczący do podanego adresu,
 a następnie skacze do tego kodu.

3.Instrukcja kompilacji
Kompilacja odbywa się przez wykonanie polecenia "make".
