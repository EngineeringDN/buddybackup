# BuddyBackup

Du und ein Freund sichert eure TrueNAS-Daten gegenseitig. Alles wird auf dem eigenen NAS verschlüsselt, bevor es das Haus verlässt. Dein Freund speichert nur unlesbare Daten, und du seine. Die Verbindung läuft über Tailscale, jeder bleibt in seinem eigenen Konto.

Die App läuft als einzelner Container auf TrueNAS 25.10 oder neuer. Sie braucht keinen TrueNAS-API-Key und kein SSH im Alltag.

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

Dein Freund kann deine Dateien und Dateinamen nicht lesen. Er sieht, wie viel Speicher dein Backup belegt und wann du sicherst. Er könnte dein Backup löschen, deshalb bleibt eine weitere Kopie sinnvoll.

Passwort vergessen: In der App-Konfiguration einmal die Variable `BUDDY_RESET_PASSWORD` mit dem neuen Passwort setzen, App neu starten, Variable wieder entfernen.

## Stand

Version 0.1. Der komplette Ablauf wurde auf zwei virtuellen TrueNAS-SCALE-25.10-Systemen über zwei getrennte Tailscale-Konten geprüft, einschließlich Neustart und Rettung aus dem Notfall-Kit. Noch nicht geprüft sind echte Hardware und eine Direktverbindung ohne Relay. Das Image gibt es nur für amd64. Bitte zunächst mit einem Testordner ausprobieren und eine Wiederherstellung durchspielen.

## Entwicklung

`make test`, `make docker`, `make integration`. API-Beschreibung in [`docs/API.md`](docs/API.md), geprüfte Upstream-Quellen in [`docs/UPSTREAM.md`](docs/UPSTREAM.md).
