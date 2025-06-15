# test

This honeypot now displays a colorized shell prompt.

Additional features:

- Autocompletion now learns custom commands added with `definecmd`.
- Fake FTP sessions can be launched using the `ftp` command.
- Session activity is logged to JSON files in `logs/` and each session is
  recorded under `session_logs/` then compressed at the end.

