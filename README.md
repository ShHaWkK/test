# Honeypot SSH haute interaction

Ce projet propose un serveur SSH simulant un environnement Linux complet. Une fois connecté, un attaquant peut utiliser de nombreuses commandes usuelles ainsi que établir certaines connexions réseau factices.

## Connexions disponibles

- **FTP** : via la commande `ftp <hôte>` ouvrant une session FTP simulée.
- **MySQL** : via `mysql` ou `sql` pour accéder à un shell MySQL factice.
- **Telnet** : `telnet <hôte>` renvoie une connexion refusée.
- **SFTP** : support du sous-système SFTP de Paramiko.
- **Ping** : `ping <hôte>` pour tester la présence d'une machine.
- **Nmap** : `nmap <cible>` simule un scan de ports.
- **CURL/WGET** : `curl <url>` ou `wget <url>` pour simuler un téléchargement.
- **SCP** : `scp` affiche une erreur de connexion (simulation).

Toutes ces connexions sont entièrement simulées et enregistrées afin d'analyser le comportement d'un potentiel attaquant.
