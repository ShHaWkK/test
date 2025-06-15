# test

This honeypot now displays a colorized shell prompt.

Additional features:

- Autocompletion now learns custom commands added with `definecmd`.
- Fake FTP sessions can be launched using the `ftp` command.
- Session activity is logged to JSON files in `logs/` and each session is
  recorded under `session_logs/` then compressed at the end.
- A shared in-memory SQLite database ensures all modules see the same state.
- Console key display can be filtered or disabled using the `KEY_DISPLAY_MODE`
  setting.

