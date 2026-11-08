# BuddyBackup

Du und ein Freund sichert eure TrueNAS-Daten gegenseitig. Alles wird auf dem eigenen NAS verschlüsselt, bevor es das Haus verlässt. Dein Freund speichert nur unlesbare Daten, und du seine. Die Verbindung läuft über Tailscale, jeder bleibt in seinem eigenen Konto.

Die App läuft als einzelner Container auf TrueNAS 25.10 oder neuer. Sie braucht keinen TrueNAS-API-Key. Die standardmäßigen Restic-Dateisicherungen benötigen kein SSH.

## Was du brauchst

- TrueNAS SCALE 25.10 oder neuer mit eingerichteten Apps
- Ein kostenloses Tailscale-Konto, dein Freund ein eigenes
- Etwa 10 Minuten, und einen zweiten Weg zu deinem Freund, zum Beispiel Telefon

## Installation

**1. Ordner anlegen.** In TrueNAS unter Datasets zwei neue Datasets mit der Vorlage **Generic** anlegen:

- `buddybackup` für App-Daten und die Backups deines Freundes
- `restore` für Wiederherstellungen

**2. YAML anpassen.** [`compose.example.yaml`](compose.example.yaml) öffnen und ändern:

- `host_ip` auf die LAN-IP deines NAS
- Pfade unter `source:` auf deinen Pool
- Pro Ordner, den du sichern willst, einen Eintrag nach `/sources/<name>`. Für `<name>` nur Buchstaben, Ziffern und Bindestriche.

**3. Installieren.** Unter Apps → Discover Apps → das Menü oben rechts → **Install via YAML**. YAML einfügen, Name `buddybackup`, speichern.

**4. Öffnen.** Im Browser `http://<NAS-IP>:8080`. Der Assistent führt durch alles Weitere: Passwort, Tailscale-Anmeldung, Freund verbinden, Ordner wählen, Notfall-Kit sichern. Danach mit „jetzt sichern" die erste Sicherung starten.

## Wichtig

- **Notfall-Kit:** Es enthält deinen Schlüssel. Ohne Kit sind deine Backups wertlos, wenn das NAS ausfällt. Außerhalb des NAS aufbewahren und nicht an deinen Freund geben.
- **Port 8080 nie ins Internet weiterleiten.** Die Oberfläche ist nur fürs Heimnetz gedacht.
- **Key Expiry abschalten:** In der Tailscale-Konsole für das Gerät `buddy-<name>`, sonst läuft die Anmeldung nach einigen Monaten ab.
- **ZFS-Snapshots:** Richte für das Dataset `buddybackup` eine tägliche Snapshot-Aufgabe in TrueNAS ein. Sie schützt die Backups deines Freundes, falls Daten gelöscht werden.

## Wiederherstellen

Unter „versionen" eine Version aufklappen, ganze Version oder einzelne Dateien wählen. Die Daten landen in einem neuen Ordner unter deinem `restore`-Dataset, vorhandene Dateien werden nie überschrieben. Eigentümer und Unix-Rechte kommen zurück, NFSv4-ACLs von SMB-Freigaben nicht. Die müssen danach neu gesetzt werden.

**NAS ausgefallen:** App auf dem neuen NAS installieren, bei „freund verbinden" unten „notfall-kit einspielen" wählen. Dann stehen deine Versionen sofort bereit.

## Was geschützt ist und was nicht

Bei Restic kann dein Freund deine Dateien und Dateinamen nicht lesen. Er sieht, wie viel Speicher dein Backup belegt und wann du sicherst. Er könnte dein Backup löschen, deshalb bleibt eine weitere Kopie sinnvoll.

Passwort vergessen: In der App-Konfiguration einmal die Variable `BUDDY_RESET_PASSWORD` mit dem neuen Passwort setzen, App neu starten, Variable wieder entfernen.

## Optional: verschlüsselte ZFS-Datasets

Zusätzlich zu Restic können native verschlüsselte ZFS-Dateisystem-Datasets als
Raw-Streams beim Freund liegen. Jeder Besitzer führt dafür einmal einen generierten
Bash-Befehl in der TrueNAS-Shell aus. TrueNAS verwaltet anschließend sichtbare
Snapshot-Aufgaben und Root-Cronjobs für den eigenen Raw-Sender. Übertragungen
stehen in Cron Jobs und im App-Status, nicht unter Replication Tasks. Der Container bekommt weiterhin weder API-Key,
Docker-Socket noch `/dev/zfs`; sein zusätzlicher SSH-Tunnel hat feste Endpunkte.

**ZFS-Schlüssel oder Passphrase jeder Verschlüsselungswurzel separat außerhalb des
NAS sichern. Ohne sie ist die ZFS-Kopie beim Freund unbrauchbar.** Das bisherige
Restic-Notfall-Kit enthält diese Schlüssel nicht. Der Freund sieht Datasetnamen,
Snapshotnamen/-zeiten und Größen. Einrichtung, monatliche Wiederherstellungsprobe,
Entfernung und ein genauer Befehl für die umgekehrte Raw-Replikation stehen in
[ZFS-Einrichtung und Notfall-Kit](docs/ZFS-RECOVERY.md).

Der ZFS-Empfang verwendet ein root-eigenes SSH-Befehlsgate mit festem Parent,
Speicher- und Objektlimits. Vor Senderabschluss die separate **ZFS-Rettungsdatei**
exportieren und offline bestätigen; sie ermöglicht den Rückweg nach NAS-Verlust,
ersetzt aber keinen ZFS-Schlüssel. Der Sender prüft feindliche Resume-Tokens
gegen lokal gehaltene Snapshots und erzwingt bei jedem Send `-w`; ein manipulierter
Empfänger kann dadurch keinen Klartext-Send anfordern. Der Ersttransfer läuft im
Hintergrund, Wiederholungen stündlich unter einer Sperre. Setup aktiviert TrueNAS-SSH auf allen Interfaces.
Raw-ZFS verschlüsselt Inhalte, legt beim Freund jedoch Dataset-/Nachfahrennamen,
Snapshotnamen/-zeiten, Größen, Blockänderungsmuster und mitgesendete Eigenschaften
(einschließlich Beschreibungen und User Properties) offen. Bei Passphrasen speichert
die Kopie auch den verpackten Schlüssel und Salt: eine starke zufällige Passphrase
oder einen Hex-Schlüssel verwenden. Details und Schlüsselrotation stehen in
[ZFS-Einrichtung und Wiederherstellung](docs/ZFS-RECOVERY.md).

## Stand

Version 0.2. Das Datei-Backup wurde auf zwei virtuellen TrueNAS-SCALE-25.10-Systemen über zwei getrennte Tailscale-Konten geprüft, einschließlich Neustart und Rettung aus dem Notfall-Kit.

Die ZFS-Option wurde auf denselben Systemen geprüft: Einrichtung per Einfügen in die Shell, verschlüsselter Versand in beide Richtungen, Fortsetzen nach Abbruch, Abweisen gefälschter Resume-Tokens, Rettung nach NAS-Verlust, Neustart und Entfernen. Noch nicht geprüft sind echte Hardware, mehrtägige Erstübertragungen, das Löschen abgelaufener Snapshots im Dauerbetrieb und eine Direktverbindung ohne Relay. Das Image gibt es nur für amd64. Bitte zunächst mit einem Testordner und einem Test-Dataset ausprobieren und eine Wiederherstellung durchspielen.

## Entwicklung

`make test` (Go 1.26.6, Python 3 und Bash; Shellcheck ist für die Prüfung generierter Befehle erforderlich), `make docker`, `make integration`. API-Beschreibung in [`docs/API.md`](docs/API.md), geprüfte Upstream-Quellen in [`docs/UPSTREAM.md`](docs/UPSTREAM.md).


ZFS-Root-Pastes sind eine Vertrauensgrenze: Eine kompromittierte App kann beliebigen
Root-Code liefern. Der Paste zeigt vor Änderungen Helfer-SHA-256 und dekodierte
Konfiguration und verlangt `RUN`; beides unabhängig mit dem Release prüfen.
`make zfs-host-hash` schreibt [den Release-Hash](docs/ZFS-HOST-SHA256.txt).
Runner, Journal, Gate, Schlüssel und Home liegen im eigenen Dataset
`<pool>/buddy-zfs-control` mit root-eigenem 0755-Mountpoint, nie auf einem
App-Bind-Dateisystem. Mit Root + DAC_READ_SEARCH exponiert ein Ordner-Bind den Rest
seines Datasets über Dateihandles. Quellen und `/data` als eigene Datasets anlegen;
**das gilt auch für Restic-Dateisicherungen**. `/sources` und `/status` warnen bei
abweichenden Mounts. ZFS-Empfang verlangt global deaktivierte SSH-Passwortanmeldung
und leere Password Login Groups/Auxiliary Parameters; SSH bleibt nach Entfernung an.
`raw_only` bedeutet: Freund lieferte einen Stream, Inhalt nicht geprüft. Präparierte
Streams bleiben trotz Quota, Property-Filtern und `volmode=none` ein Risiko für den
OpenZFS-Kernelparser. Details: [ZFS-Sicherheit und Rettung](docs/ZFS-RECOVERY.md).
