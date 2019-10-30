# encryption-service


Encryption Service to prosta usługa służąca do szyfrowania danych. Wykorzystuje bibliotekę NSec Cryptography (https://nsec.rocks/) z funkcją szyfrującą ChaCha20Poly1305.

Serwis umożliwia enkrypcję/dekrypcję zarówno stringów, jak i plików binarnych. Dla rozróżnienia danych wejściowych serwis udostępnia 4 endpointy:

POST /api/encryptString
POST /api/encryptFile
POST /api/decryptString
POST /api/decryptFile


Uruchomienie serwisu:

Komenda: dotnet EncryptionSerice.dll "nazwa_pliku.txt", gdzie nazwa_pliku.txt to ścieżka do pliku tekstowego zawierającego wartość klucza używanego do szyfrowania.

Serwis domyślnie uruchamia się na localhost:5001

Poprawnie uruchomiany serwis pod adresem /api odpowiada komunikatem "It's working".
