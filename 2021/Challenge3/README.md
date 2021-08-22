# Bayerns Bester Hacker 2021 / Challenge 3

![Bayerns Bester Hacker 2021](../images/BBH_Logo_2021.png)


## Briefing

Du hast es geschafft! Hier ist Aufgabe 3 von Bayerns Bester Hacker.

Das Netzwerk der RAe Schmitt wurde nach dem Ransomware-Vorfall komplett neu aufgesetzt.
Der Administrator Aurelius Müller hat jedoch weiterhin Schwachstellen im neuen Netzwerk.
Finde die Schwachstellen und beweise die Ausnutzung der Schwachstellen, indem du dein Vorgehen erläuterst, ein Passwort des Administrators A. Müller und den ältesten Fall der Kanzlei angibst.
Zusätzlich gibt es noch eine Flag, die du finden und abgeben kannst.

Im Zuge der vorherigen Aufgaben hast du Hinweise gefunden, die dir kombiniert für Aufgabe 3 eine Start-Hilfe geben.
Bitte beachte, dass du auf den Systemen nicht immer alleine sein wirst.
Für Fragen und Probleme zur Aufgabe stehen wir gerne bereit.

Happy Hacking!
Dein Challenge-Team von Bayerns Bester Hacker!


## Lösung

### Vorbereitung

Das Briefing deutet auf Hinweise aus den ersten zwei Challenges hin:
* [Challenge 1](../Challenge1) lässt als Artifakt den [SSH-Key](../Challenge1/ssh.key) über
* [Challenge 2](../Challenge2) hat gleich drei Hosts zur Auswahl:
  * ```DESKTOP-BÜRO1.rae-schmitt.de``` den Desktop-PC des Users l.maier
  * ```win-horcue9m4ld.rae-schmitt.de``` den Domain-Controller des internen Netzwerks
  * ```93.90.206.205``` den Backup-Host aus der sichergestellten Datei [backup.sh](../Challenge2/277aef46-3504-4afa-ae6c-6d1c013589bc/backup.sh)


### Analyse

Zuerst werden die beiden internen Systeme auf ihre Verfügbarkeit überprüft und beide lösen sich als Webserver unter ```h02.wlh.io``` auf. Damit fallen sie vorerst aus der näheren Betrachtung.
```
$ ping DESKTOP-BÜRO1.rae-schmitt.de
PING xn--desktop-bro1-llb.rae-schmitt.de (213.190.30.57): 56 data bytes
$ ping win-horcue9m4ld.rae-schmitt.de
PING win-horcue9m4ld.rae-schmitt.de (213.190.30.57): 56 data bytes
```

Das Backup-Script nutzt einen User ```kayilvggxt``` und Host ```93.90.206.205```. Ein Ping zur Kontaktaufnahme wird blockiert, daher wurde der offene SSH-Port mit [nmap](https://nmap.org/) überprüft und sichergestellt. Ein Login mit dem [SSH-Key](../Challenge1/ssh.key) aus [Challenge 1](../Challenge1) funktioniert und gibt folgende Meldung aus:
```
$ ssh -i ../Challenge1/ssh.key kayilvggxt@93.90.206.205
Mitteilung:
Hallo Mitarbeiter und Mitarbeiterinnen,

wir haben unseren Server umgezogen.
Dieser ist unter http://fileshare.rae-schmitt.ddnss.de/ zu erreichen.
Die Nutzung ist wie gewohnt möglich.

Mit freundlichen Grüßen
A. MüllerConnection to 93.90.206.205 closed.
```



# Fazit


# Parkplatz

