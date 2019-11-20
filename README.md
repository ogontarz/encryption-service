# Encryption-Service

Encryption Service to prosta usługa służąca do szyfrowania danych. Wykorzystuje bibliotekę [NSec Cryptography](https://nsec.rocks/) z funkcją szyfrującą ChaCha20Poly1305.


Serwis umożliwia enkrypcję/dekrypcję zarówno stringów, jak i plików binarnych. Dla rozróżnienia danych wejściowych serwis udostępnia 4 endpointy:

- POST /api/encryptString
- POST /api/encryptFile
- POST /api/decryptString
- POST /api/decryptFile

Enpoint encryptString przyjmuje w body zapytania dowolny string i zwraca go w postaci zaszyfrowanej w base64. Odpowiedź wrzucona w body zapytania decryptString zwróci początkowy string. 

Analogicznie działają zapytania na plikach, ale ich wejściem i wyściem są dane binarne. Tę opcję można przetestować np. w Postmanie wybierając Body -> binary -> select file, a następnie Save response -> Save to a file i użyć pliku z odpowiedzią w zapytaniu decrypt.

Schemat działania:

![enc-service](https://i.ibb.co/TkmyDnf/enc-service.png)


Program wtkorzystuje dwie funkcje biblioteki NSec - HkdfSha256.DeriveKey() służącej do wygenerowania klucza szyfrującego na podstawie sekretu - naszego klucza wejściowego Mother Key oraz losowego wektora salt - w naszym przypadku wartości sekund, oraz ChcaCha20Poly1305.Encrypt() służącego do enkrypcji danych na podstawie wygenerowanego klucza oraz losowego wektora bajtów IV. Zaszyfowany tekst jest następnie składany w jeden wektor bajtów wraz z użytymi wcześniej wartościami wektorów sekund i IV, które są niezbędne do późniejszej dekrypcji danych.



W obenej formie po uruchomieniu w kosnoli serwis wypisuje dodatkowe informacje pozwalające na analizę poprawności działania w kolejnych krokach - wartości mother key, iv, rozmiary danych itp, które można usunąć w wersji produkcyjnej (wszystkie linie Console.WriteLine w CryptoController.cs).



Aby zbudować aplikację należy pobrać żródła i otworzyć je w Visual Studio, a następnie zbudować poprzez opcję Publish na Project Solution. W tym przypadku należy dodatkowo do folderu runtimes zbudowanej aplikacji dodać plik z biblioteką vcruntime140.dll, który można znaleźć w folderze windows\system32 - w przypadku jej braku biblioteka do enkrypcji NSec nie zadziała na platformie Windows Server.

Można również pobrać gotowy do uruchomiania zbudowany program znajduje się repozytorium w archiwum build.7z.


#### Uruchomienie serwisu:

Aby uruchomć serwis potrzebujemy przejść do folderu build i wywołać komendę:

```dotnet EncryptionSerice.dll "nazwa_pliku.txt"```, gdzie nazwa_pliku.txt to ścieżka do pliku tekstowego zawierającego wartość klucza używanego do szyfrowania.

Serwis domyślnie uruchamia się na localhost:5001. Domyślny port można zmodyfikować w kodzie programu w pliku appsettings.json. Poprawnie uruchomiany program na zapytania GET /api odpowiada komunikatem "It's working".


Usługa udostępniona jest tylko przez HTTP i wymaga postawienia dodatkowego proxy IIS z certyfikatem dla zapewnienia ruchu po HTTPS.
