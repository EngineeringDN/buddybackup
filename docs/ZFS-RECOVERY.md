# Verschlüsselte ZFS-Datasets: Einrichtung und Wiederherstellung

Restic bleibt der Standard. ZFS überträgt explizit ausgewählte, native verschlüsselte
Dateisysteme raw. TrueNAS verwaltet die Snapshot-Aufgaben; ein geschützter
Root-Runner sendet über Root-Cronjobs und prüft vor jedem Versand die Verschlüsselung. Die App erhält
keinen TrueNAS-API-Key, Docker-Socket oder `/dev/zfs`.

## Vor dem Einschalten offline sichern

**ZFS-Schlüssel oder Passphrase jeder Verschlüsselungswurzel außerhalb des NAS
sichern.** Bei geerbter Verschlüsselung ist es der Schlüssel des ursprünglichen
Encryption Root. Das Restic-Notfall-Kit enthält ausschließlich den Restic-Schlüssel.
Auch die neue ZFS-Rettungsdatei enthält KEINEN ZFS-Entschlüsselungsschlüssel.

Die ZFS-Rettungsdatei enthält den SSH-Privatschlüssel des Senders, den bestehenden
Empfangsbenutzer, Parent, gepinnten SSH-Hostschlüssel, die Einladung des Freundes
(einschließlich HTTP-Passwort) und die geordnete Zuordnung der Quellnamen zu `d0`,
`d1`, … . Sie ist Klartext und muss wie ein Passwort offline verwahrt werden.
Zusätzlich das Restic-Kit sichern, wenn auch Restic wiederhergestellt werden soll.

Bei Passphrasen liegen der **verpackte ZFS-Schlüssel und Salt ebenfalls beim
Freund**. Er kann offline Passphrasen raten. Eine starke zufällige Passphrase oder
einen zufälligen Hex-Schlüssel verwenden. Eine kurze menschlich gewählte Passphrase
schützt gegenüber dem Besitzer der Kopie nicht ausreichend.

## Einrichten

1. Compose verwenden: `extra_hosts: host.docker.internal:host-gateway`,
   `network_mode: bridge`, Port 2288 ausschließlich auf **127.0.0.1** veröffentlichen.
   Der Container muss `host.docker.internal` eindeutig auf das direkt verbundene
   Default-Route-Gateway auflösen. Bei Abweichung bleiben beide SSH-Tunnel geschlossen.
   Keine Poolwurzel, keinen Kontrollordner und keinen Docker-Socket einbinden.
2. Beide Tailscale-App-Geräte gegenseitig teilen; TCP 8787 und optional 8788
   zulassen. Die bestehende Geräteidentität wird geprüft; 8788 erreicht ausschließlich
   den SSH-Dienst des eigenen NAS. Der Empfänger schaltet ZFS-Empfang mit GiB-Limit ein.
3. Sender: genaue Datasetnamen, Uhrzeit und Aufbewahrung anbieten. Nachfahren werden
   niemals automatisch ausgewählt. Quellen müssen lokal entsperrte, verschlüsselte
   Dateisysteme sein; Zvols sind wegen der Inhaltsprobe ausgeschlossen.
4. Empfänger: generierten Empfänger-Befehl als root/Admin in der TrueNAS-Shell
   ausführen, dann Empfängerabschluss in der App bestätigen.
5. Sender: `/zfs/commands/sender` abrufen. Dabei wird der SSH-Hostschlüssel erstmals
   durch den authentifizierten, gerätegepinnten Tunnel erfasst und gespeichert.
   **Das ist First Use, keine Bestätigung des Hostschlüssels durch eine Person.**
   Spätere Änderungen werden abgewiesen; niemals ungeprüft `ssh-keyscan` übernehmen.
6. `/zfs/rescue/export` aufrufen, die **vollständige Antwort** als z.B.
   `buddy-zfs-rescue.json` offline speichern und mit `/zfs/rescue/ack` den exportierten
   Fingerabdruck plus `SAVED_OFFLINE` bestätigen. Das ist vor Senderabschluss Pflicht.
   Wiederholte Downloads vor Abschluss liefern dieselbe Datei.
7. Sender-Befehl auf dem Sender-NAS ausführen. Setup kehrt nach Installation zurück
   und startet den ersten Transfer im Hintergrund; er kann Tage dauern. Senderabschluss
   sofort bestätigen, ohne auf den Transfer zu warten. Erst dann löscht die App ihren
   SSH-Privatschlüssel. Der Runner behält ihn root-eigen mit Modus 0600 als
   `sender-ANGEBOTS_ID.key` im Kontrollordner. Danach ist kein Export mehr möglich.
   Die Datei enthält denselben Schlüssel wie die vorher exportierte Rettungsdatei.

API-Aufrufe benötigen die bestehende Admin-Session und CSRF-Token; Felder, Antworten
und Bestätigungswerte stehen vollständig in [docs/API.md](API.md#optional-encrypted-zfs-replication).

**Setup aktiviert den TrueNAS-SSH-Dienst auf allen konfigurierten bzw. standardmäßig
allen Interfaces.** LAN-/Firewall-Regeln des NAS prüfen. Der Empfangsbenutzer hat
kein Passwort, sudo oder SMB-Zugang. Sein root-eigenes `authorized_keys` enthält nur
`restrict,command="<Gate>"`. Interaktive Shell, SFTP, Weiterleitungen, beliebige
ZFS-Befehle und unverschlüsseltes `send` sind gesperrt. Der Rückweg erlaubt nur
`/usr/sbin/zfs send -w <empfangenes Dataset@Snapshot>`.

Gate, Runner, Schlüssel, Home und Journale liegen im eigenen ZFS-Dataset
`<pool>/buddy-zfs-control`, gemountet root-eigen mit 0755 unter
`/mnt/<pool>/buddy-zfs-control`, außerhalb des begrenzten Empfangsparents.
Kein App-Bind-Mount darf dieses Dataset als Quelle verwenden, auch keinen anderen
Unterordner darauf. Bestehende einfache Kontrollordner werden nicht übernommen. Der Mount
bleibt auf dem Pool bei Neustarts und Boot-Environment-Upgrades erhalten. Seine
Vorfahren müssen root gehören und dürfen nicht gruppen-/weltbeschreibbar sein.
Den Ordner nie einem Container oder NAS-Benutzer schreibbar freigeben. Nach einem
Poolverlust ist er verloren; die offline Rettungsdatei überbrückt diesen Verlust.
Unter `/data/buddy-zfs` liegen nur JSON-Berichte/Abschlussmarker, kein ausführbarer
Root-Code. Root folgt dort keinen Symlinks und arbeitet über geöffnete Ordner-Handles.

**Der Sender-Befehl enthält den privaten SSH-Schlüssel, auch wenn er base64-kodiert
ist.** Beim Einfügen in eine Shell kann er in History, Terminal-Aufzeichnungen oder
Zwischenablagen landen. History für diese Sitzung vorher abschalten (Bash:
`set +o history`), keine Sitzung aufzeichnen und Zwischenablage danach leeren.
Frühere History-Einträge und App-/NAS-Snapshots können alte Schlüssel weiter enthalten.

Bei Schlüsselverdacht: Empfang ausschalten; Sender-Aufgaben entfernen; Empfänger-
Aufgaben/Account mit Standard-Entfernungsbefehl entfernen; beide Seiten zurücksetzen;
neues Angebot mit neuem Schlüssel, neuem Parent und neuer Rettungsdatei einrichten.
Die alten Empfangsdaten bleiben dabei bestehen. Sie erst nach einer erfolgreichen
neuen Sicherung bewusst löschen. Die alte Rettungsdatei verliert mit dem alten
Empfangsaccount ihren Zugriff. Keine Wiederverwendung/Übernahme des alten Parents.

## Was der Freund sehen und verändern kann

Der Freund sieht angebotene Quellnamen und die Dataset-/Nachfahrennamen, die er
empfangen hat, Snapshotnamen und Zeiten, Größen und Blockänderungsmuster sowie
**alle mitgesendeten ZFS-Eigenschaften**, darunter Beschreibungen und User Properties.
Die Aufgaben schließen nur `mountpoint`, `sharenfs`, `sharesmb`, `xattr` aus;
Eigenschaften dürfen deshalb keine vertraulichen Klartextinformationen enthalten.
Dateiinhalte bleiben raw verschlüsselt, solange der Entschlüsselungsschlüssel bzw.
eine ausreichend starke Passphrase geheim bleibt. Bei Passphrasen sind verpackter
Schlüssel und Salt Bestandteil der empfangenen Kopie. Der Freund kann als NAS-
Eigentümer Kopien löschen, ersetzen, zurückrollen und Statusberichte fälschen.
Eine zusätzliche unabhängige Kopie bleibt sinnvoll.

Das Empfangsparent bekommt die GiB-Quota sowie **filesystem_limit=128** und
**snapshot_limit=8192** für alle darunterliegenden Objekte. Der Peer kann diese
Grenzen nicht ändern. Die Werte erlauben bis zu 32 explizite Quellen mit mehreren
Monaten täglicher Snapshots; bei längerer Aufbewahrung kann zuerst das Snapshotlimit
greifen. Dann schlägt die Replikation fehl; es werden keine Limits automatisch
aufgehoben. Freien Poolplatz weiter überwachen; eine Quota reserviert keinen Platz.

Tägliche Snapshots entstehen zur gewählten Stunde um :00. Der eigene Raw-Sender
erscheint unter **TrueNAS Cron Jobs**, nicht unter Replication Tasks. Er läuft jede
Stunde um :01; überlappende Läufe überspringt eine nicht blockierende Sperre.
Der App-Status `sender_status` zeigt Versuch, letzten Erfolg, Snapshot und Fehler;
Warnungen fließen auch in die bestehenden ntfy-Meldungen ein. Lange Transfers
können wegen des über zwei Stunden alten Status eine Alterswarnung auslösen.
Jeder Lauf prüft Dateisystemtyp, native Verschlüsselung, Entsperrung und die bei der
Einrichtung gespeicherte Verschlüsselungswurzel. Bei Abweichung stoppt der Versand.
Ein später angelegtes unverschlüsseltes Kind wird niemals ausgewählt.

Der Sender wählt die inkrementelle Basis ausschließlich aus lokalen Snapshots,
deren Name UND GUID mit dem Freund übereinstimmen. Ohne gemeinsame Basis wird
nur auf ein noch nicht vorhandenes Ziel voll gesendet. Vorhandene Empfangsdaten
werden weder zurückgerollt noch automatisch zerstört. Die Basis und der laufende
Zielsnapshot bleiben lokal durch eigene ZFS-Holds vor Retention geschützt. Erst
nach Prüfung von neuestem empfangenem Namen und GUID wandert der Basis-Hold nach
vorne. Empfangsretention benutzt lokal gespeicherte GUIDs und Erstellungszeiten;
die neueste gemeinsame Basis wird niemals gelöscht. Unbekannte Snapshots bleiben.

Nach Behebung eines Quell-/Verbindungsfehlers versucht der nächste Stundenlauf
erneut. Manuell kann der Besitzer den vorhandenen Runner starten:

```bash
sudo /usr/bin/python3 -I /mnt/tank/buddy-zfs-control/sender-ANGEBOTS_ID.py run
```

Die echte 32-stellige Angebots-ID einsetzen. `setup` kann mit dem bestehenden
root-eigenen Schlüssel wiederholt werden; geänderte Ressourcen/Wurzeln werden
nicht übernommen. Vor Entfernung eines laufenden Transfers den Root-Prozess
geordnet beenden (SIGTERM), dann Entfernung wiederholen; die Sperre verhindert
parallel laufende Änderungen. Experimentelle alte native Aufträge zuerst mit ihrem
ursprünglichen Runner entfernen; es gibt keine automatische Migration.

## Monatliche Wiederherstellungsprobe

Am ersten Monatstag um 04:17 holt der Sender den neuesten empfangenen Snapshot der
**ersten Quelle** raw zurück und vergleicht GUID sowie optional Inhalte. Der lokale
Snapshot bleibt dafür gehalten. Der temporäre Parent erhält schon bei Erstellung
eine Quota von `referenced + max(referenced/4, 1 GiB)`, gemessen am lokalen Snapshot.
Vorher muss der lokale Pool mindestens dieses Budget plus 1 GiB frei haben. Ein
bösartiger oder größerer Peer-Stream kann deshalb nur die begrenzte Probe füllen;
Platzmangel/Quotaüberschreitung ergeben einen Fehler mit anschließender Bereinigung.

Bei in TrueNAS gespeichertem Hex-/Raw-Schlüssel wird der ursprüngliche Root-Schlüssel
über stdin geladen und ein Datei-/Symlink-Inhaltsvergleich durchgeführt. Rechte,
ACLs, Anwendungskonsistenz und weitere Quellen sind damit nicht vollständig geprüft;
Spezialdateien ergeben einen Fehler. Bei Passphrase oder nicht gespeichertem Schlüssel
bedeutet `raw_only`: Der Freund hat einen Stream geliefert; Inhalt nicht geprüft.
Seine GUID-Angaben sind kein unabhängiger Nachweis.
Temporäre Datasets und lokale Holds werden auch bei Fehler/SIGINT/SIGTERM bereinigt.
SIGKILL, Stromausfall oder fehlgeschlagene Bereinigung können manuelles Entfernen
des ausdrücklich gemeldeten `buddy-probe-…` erfordern. `probe.state=error` beachten.

## Nach vollständigem Verlust des Eigentümer-NAS

**Beim Freund weder Empfangsaccount noch Empfangsdaten entfernen und kein neues
Angebot erzeugen.** Die bestehende Gate-Berechtigung für Raw-Send reicht aus.

1. Auf dem Ersatz-NAS die App mit der Compose-Konfiguration starten, Admin mit dem
   bisherigen Namen einrichten und Tailscale anmelden. Das neue App-Gerät mit dem
   überlebenden Freund gegenseitig teilen. Optional zuerst das Restic-Kit importieren;
   die darin gespeicherte Freundeseinladung muss der ZFS-Rettungsdatei entsprechen.
2. Auf dem Ersatz-NAS `/zfs/rescue/import` mit `rescue` und `fingerprint` aus der
   gesicherten Antwort sowie `confirm:"IMPORT_ZFS_RESCUE"` aufrufen. Das öffnet den
   lokalen Tunnel auf 127.0.0.1:2288 **ohne aktives Angebot**. Es erzeugt keine neuen
   Replikationsaufgaben oder Empfangsaccounts und initialisiert kein Restic-Repository.
3. `/invitation` des Ersatz-NAS abrufen. Beide Personen vergleichen dessen vollständigen
   Fingerabdruck außerhalb des Tunnels. Der Freund ruft auf seiner überlebenden App
   `/zfs/peer/repin` mit dieser Einladung, deren Fingerabdruck, der bisherigen Node-ID
   und `REPIN_REPLACED_ZFS_PEER` auf. Nur Geräte-ID/IP werden neu gepinnt; bestehender
   Empfangsaccount, dessen SSH-Schlüssel, Parent und Daten bleiben erhalten.
   Gewöhnliches `/peer`-Ersetzen ist hierfür gesperrt. Empfang muss eingeschaltet sein.
4. Aus der Rettungsdatei auf dem Eigentümer-NAS die SSH-Dateien extrahieren. Der
   Receiver-Hostschlüssel kommt aus der Datei und wird nicht neu gelernt:

```bash
sudo /usr/bin/python3 -I - <<'BUDDY_RESCUE_FILES'
import json
import os
from pathlib import Path
k = json.loads(Path('/root/buddy-zfs-rescue.json').read_text())['rescue']
# Neue Dateien erzeugen, vorhandene Dateien/Symlinks niemals überschreiben.
for path, text in (
    ('/root/buddy-zfs-ssh-key', k['private_key']),
    ('/root/buddy-zfs-known_hosts', '[127.0.0.1]:2288 ' + k['host_key'] + '\n'),
):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(text)
print('Benutzer:', k['username'], 'Parent:', k['parent'])
for i, source in enumerate(k['datasets']):
    print(source, 'liegt auf', k['parent'] + '/d' + str(i))
BUDDY_RESCUE_FILES
```

Die Rettungsdatei dazu zuvor sicher nach `/root/buddy-zfs-rescue.json` kopieren.
Mit dem eigenen Benutzer und Parent die verfügbaren Snapshotnamen abfragen:

```bash
sudo ssh -T -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=/root/buddy-zfs-known_hosts \
  -i /root/buddy-zfs-ssh-key -p 2288 bz0123456789abcdef@127.0.0.1 \
  '/usr/sbin/zfs list -H -p -t snapshot -d 1 -o name -s creation tank/buddy-zfs-0123456789abcdef/d0'
```

Im folgenden vollständigen Beispiel Benutzer, Parent, Snapshot und **neues** lokales
Ziel durch die eigenen Werte ersetzen. Vorher freien Platz prüfen und eine passende
lokale Restore-Quota setzen; das Beispiel begrenzt die temporäre Zielhierarchie auf
100 GiB. Bei größeren Sicherungen entsprechend erhöhen. Kein `-F` verwenden.

```bash
sudo bash <<'BUDDY_RESTORE'
set -euo pipefail
umask 077
if /usr/sbin/zfs list -H tank/buddy-restore >/dev/null 2>&1; then
  echo 'Ziel existiert bereits; Abbruch.' >&2
  exit 1
fi
/usr/sbin/zfs create -o mountpoint=none -o canmount=off -o volmode=none -o dedup=off -o copies=1 -o quota=100G tank/buddy-restore
ssh -T -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=/root/buddy-zfs-known_hosts \
  -i /root/buddy-zfs-ssh-key -p 2288 bz0123456789abcdef@127.0.0.1 \
  '/usr/sbin/zfs send -w tank/buddy-zfs-0123456789abcdef/d0@bz-0123456789abcdef-d0-2026-11-08_03-00' \
  | /usr/sbin/zfs recv -u -x mountpoint -x sharenfs -x sharesmb -x xattr -x volmode -x dedup -x copies -x reservation -x refreservation tank/buddy-restore/photos
/usr/sbin/zfs load-key -L file:///root/offline-zfs-key tank/buddy-restore/photos
# TrueNAS verwendet altroot=/mnt: Property /tank/... ergibt /mnt/tank/...
/usr/sbin/zfs set mountpoint=/tank/buddy-restore/photos canmount=noauto tank/buddy-restore/photos
/usr/sbin/zfs mount tank/buddy-restore/photos
BUDDY_RESTORE
```

Bei Passphrase den `load-key -L file:///…`-Schritt und die nachfolgenden Mount-Schritte
zunächst aus dem Paste weglassen; danach interaktiv
`sudo /usr/sbin/zfs load-key -L prompt tank/buddy-restore/photos` und anschließend
`set`/`mount` ausführen. Für jede weitere explizite Quelle separat wiederholen.
Dateien, Freigaben, ACLs und Anwendungskonsistenz prüfen. Nach Fehlern die teilweise
empfangene Hierarchie bewusst prüfen/bereinigen, nicht mit `-F` überschreiben.

Nach erfolgreicher Wiederherstellung `/zfs/rescue/close` mit `CLOSE_ZFS_RESCUE`
aufrufen: Tunnel und importierter SSH-Schlüssel werden aus dem App-Zustand entfernt.
Die Offline-Datei geschützt behalten; lokale SSH-Arbeitskopien sicher entfernen.
Die Rettung repariert keine verlorenen Daten oder Empfangsaccounts der Gegenrichtung.
Für neue laufende Sicherungen nach erfolgreicher Rettung die betroffenen alten
Aufgaben bewusst entfernen/zurücksetzen und neue Angebote einrichten.

## Entfernen

Zuerst Sender-Aufgaben, dann Empfänger-Aufgaben über ihre generierten
Entfernungsbefehle entfernen; erst danach jede Seite in der App zurücksetzen.
Entfernung führt ausschließlich den root-eigenen Runner aus. Der Empfängerzugang
wird zuerst über den journalisierten Account-ID entzogen, auch wenn der Parent
verschwunden, verändert oder gehalten ist. Optionales Datenlöschen prüft den
unveränderlichen Parent-GUID aus dem root-eigenen Journal, keine User Property.

Standardentfernung lässt empfangene Daten, erzeugte Snapshots, root-eigenes Home,
Journal und Runner bestehen. Der Sender entfernt seine Transportdateien und
löst ausschließlich seine eigenen Basis-/Transfer-Holds. Verbleibende Holds werden mit Namen/Tags gemeldet;
sie als Eigentümer mit `/usr/sbin/zfs holds -r <Dataset>` prüfen und gezielt mit
`/usr/sbin/zfs release <Tag> <Dataset@Snapshot>` lösen. Unbekannte Holds werden nicht
automatisch aufgehoben. Der gemeinsam genutzte SSH-Dienst bleibt eingeschaltet.

Nur zur ausdrücklich endgültigen Löschung des eigenen Empfangsparents vor dessen
Entfernungsbefehl `export BUDDY_ZFS_REMOVE_FLAG=--destroy-received-data` setzen;
danach `unset BUDDY_ZFS_REMOVE_FLAG`. Holds oder GUID-Abweichungen verhindern die
Datenlöschung, aber niemals den vorherigen Account-Entzug. Fehler sichtbar beheben
und Entfernung wiederholen. Beim Sender werden alle Quellen unabhängig bereinigt; ein verschwundenes Dataset
verhindert weder Schlüssel-/Cron-Löschung noch die Entfernung seines Abschlussmarkers.
Verschwundene Quellen gelten als bereits bereinigt; echte Fehler bei Aufgaben,
Schlüsseln oder Holds müssen behoben werden. Erst bei erfolgreicher Entfernung wird
der Abschlussmarker zuletzt gelöscht; `/zfs/reset` verweigert vorhandene Marker.

## Schutz gegen manipulierte Resume-Tokens

Auch ein Freund mit Root-Zugang auf seinem NAS ist für den Sender eine nicht
vertrauenswürdige Gegenstelle. ZFS-Resume-Tokens haben keine Authentifizierung;
ein Angreifer kann ihren Checksum neu berechnen und Raw-Flags oder GUIDs ersetzen.
Der native zettarepl-Sender wird deshalb nicht mehr benutzt. Jeder lokale Send
enthält ausdrücklich `-w`, auch der Resume-Send. Der Runner dekodiert das binäre
Tokenformat streng (OpenZFS 2.3.x, gegen 2.4.0 geprüft), akzeptiert nur Raw-Flags
und bindet Ziel sowie Basis an lokal existierende, gehaltene Schema-Snapshots und
die vor dem Transfer gespeicherte Absicht. Keine gedruckten Diagnosezeilen werden
als Beweis ausgewertet. Unbekannte Felder/Flags/Encodings werden abgelehnt.

Ungültiges Token: kein Resume-Send, Sicherheitswarnung im Status/Syslog, Remote-
Teilzustand mit dem fest begrenzten `recv -A` abbrechen und normal neu anfangen.
Scheitert der Abbruch oder fehlt bei existierendem Ziel eine gemeinsame Basis,
stoppt der Runner. Die Warnung bleibt auch nach späterem Erfolg sichtbar; nach
Untersuchung kann Entfernen/Zurücksetzen des Angebots sie beseitigen. Exakte
Formatgrenzen und Prüfregeln: [API: Resume-Tokens](API.md#hostile-receiver-resume-tokens).
Der Freund kann weiterhin Daten löschen, Empfang vortäuschen oder Sicherungen
verhindern. Schlüsselstärke, Eigenschaftsinhalte und unabhängige Kopien bleiben
entscheidend; ein Raw-Stream schützt nur, was der Sender tatsächlich raw versendet.

## Auf echtem TrueNAS prüfen

Die automatisierten Tests verwenden Middleware-/ZFS-Fakes und einen echten
OpenSSH-Dienst im isolierten Testcontainer. Auf TrueNAS 25.10.8 sind zusätzlich
Erstlauf, inkrementeller Lauf, abgebrochener/resümierter Empfang, Retention,
Quota-/Objektlimits, Benutzerlöschung mit Holds/fehlendem Parent und die komplette
Ersatz-NAS-Rettung zu prüfen. Nach Neustart und Boot-Environment-Upgrade kontrollieren,
dass Pool-Kontrollordner, Root-Eigentümer, StrictModes-Schlüsseldatei, Cron und
Delegationen erhalten bleiben. Echte Raw-Resume-Tokens aus der installierten
OpenZFS-Version mit dem Decoder abgleichen, besonders nach Updates. Ein langer
Ersttransfer muss nach Neustart fortsetzen, während Cron-Ticks übersprungen werden.
Manipulierte Tokens dürfen niemals einen Resume-Send auslösen. Hold-Bewegung,
Empfangsretention, Status/ntfy und sofortige Setup-Bestätigung separat prüfen.


## Root-Vertrauensgrenze und Restgefahren

Ein kompromittierter App-Container kann den gesamten Befehl verfassen, den ein
Admin als root einfügt. Vor Änderungen zeigt der Paste SHA-256 des dekodierten
Python-Helfers und die dekodierte Konfiguration (Benutzernamen, Datasets, Parent,
Quota, Fingerabdrücke der öffentlichen Schlüssel), danach verlangt er `RUN` am
Terminal. Private Schlüssel werden nicht ausgegeben. Auch diese Anzeige kann eine
kompromittierte App fälschen. Den Helfer ohne Ausführung dekodieren und separat
hashen, Wrapper und Konfiguration prüfen. Mit dem ersten Feld der **unabhängig aus
dem passenden Release bezogenen** [ZFS-HOST-SHA256.txt](ZFS-HOST-SHA256.txt)
vergleichen; `make zfs-host-hash` erzeugt diese Release-Datei. Der App-API-Hash allein
ist keine unabhängige Vertrauensquelle. Ein Helfer-Hash authentifiziert weder Wrapper
noch Konfiguration. Der Entfernungspaste prüft vor Aufruf des gespeicherten
Root-Runners; sein Helfer-Hash ist keine Prüfung des installierten Runner-Wrappers.
Alte experimentelle Ordner-Installationen mit ihrem ursprünglichen Runner entfernen;
keine automatische Übernahme in das neue Kontroll-Dataset.

Mit Container-Root und DAC_READ_SEARCH ermöglicht `open_by_handle_at` Zugriff auf
weitere Inodes desselben Dateisystems. Ein als einfacher Ordner eingebundener
Quellpfad exponiert damit den Rest seines Datasets. Für Quellen, `/data` und
Restore-Ziele eigene Datasets anlegen. **Das gilt ebenso für Restic-Dateisicherungen.**
`GET /sources` und `/status` warnen bei Quellen und `/data` ohne Dataset-Root.

Vor Empfängereinrichtung in TrueNAS Dienste > SSH die Passwortauthentifizierung
für alle Benutzer deaktivieren, Password Login Groups leeren und Auxiliary
Parameters entfernen; vorher eigenen Admin-Schlüsselzugang einrichten. Setup bricht
andernfalls anhand von `ssh.config` ab. Der gemeinsame SSH-Dienst bleibt nach
Entfernung aktiviert und ist auf allen konfigurierten Interfaces erreichbar.

Transfer und Probe brechen nach 30 Minuten ohne Bytes vom Sender-Pipe zum
Empfänger-Pipe ab. Jeder Fortschritt erneuert die Frist; langsame laufende Transfers
haben keine Gesamtlaufzeitgrenze. Stundenläufe melden eine seit mehr als sechs
Stunden belegte Sperre. Entfernen sendet dem journalisierten laufenden PID SIGTERM,
wartet höchstens zehn Sekunden, danach SIGKILL und fünf weitere Sekunden; ein
unkillbarer Host-Prozess erfordert Host-Administration. Höchstens zwei dauerhafte
Sender-Holds pro Dataset bleiben (drei während des Basiswechsels oder einer Probe).
Der deterministische Angebots-Probe-Hold wird beim nächsten Versuch bereinigt;
unbekannte alte experimentelle Zufalls-Holds bleiben manuell zu prüfen.

`raw_only`: **Freund hat einen Stream geliefert; Inhalt nicht geprüft. Entschlüsselung benötigt den Benutzerschlüssel.**
Nur `verified` bestätigt entschlüsselten Inhaltsvergleich. Empfang und Probe setzen
`volmode=none`, `dedup=off`, `copies=1` und schließen außerdem empfangene
Reservierungen aus. Präparierte Streams erreichen dennoch den OpenZFS-Kernelparser:
CPU-/I/O-Verbrauch und Implementierungsfehler bleiben Restgefahren. Quotas und
Objektlimits sind keine Sandbox. Ein böswilliger Freund kann Daten löschen, GUIDs
vortäuschen, drosseln oder Sicherungen verweigern; unabhängige Kopien behalten.
