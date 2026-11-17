# Project
Legacy PHP 5.6.40 web-site engine. Goal of this branch: security audit, then staged refactoring
(PHP 5.6 -> 7.4 -> 8.x). Behaviour must not change except to fix a vulnerability or remove an
API that is removed or deprecated in the target PHP version.

# Environment
- Production runs PHP 5.6.40 with [Apache/nginx], [MySQL/MariaDB version], extensions: [list].
- Database schema: [path/to/schema.sql]. Configuration with credentials: [path/to/config.php]
  (credentials are not in the repository; never request or invent them).
- Report the installed PHP version before running any code. Do not claim that tests passed unless you ran them.

# Commands
- Install dev tools: composer install
- Tests: vendor/bin/phpunit
- Compatibility check: vendor/bin/phpcs -p --standard=PHPCompatibility --runtime-set testVersion 5.6- .
- Static analysis: vendor/bin/phpstan analyse --level=3
- (Adjust these once composer.json exists; if a command is unavailable, say so.)

# Gotchas
- [Files included dynamically, e.g. include "$page.php" in index.php.]
- [Code that looks unused but is called by cron or by the admin area.]
- [Directories holding uploaded user files or generated cache: path, and whether they are web-accessible.]
- [Third-party or vendored libraries in path/, with versions if known.]
- [Database access uses the removed mysql_* functions; replace them with PDO prepared statements.]

# Rules
- Audit tasks are read-only: write results only to docs/audit/. Do not edit application files.
- Fix tasks: change only the files for the named finding (SEC-nnn). One finding per branch.
- Record each finding as: ID, file:line, CWE, severity, exploit scenario, minimal fix, status.
- Mark uncertain findings as "unverified". List all files not examined.
- Do not add new dependencies, delete files, or modify the database schema without asking.
- Never write secrets, passwords or keys to any file or to output.
- If a test fails twice, stop and report instead of continuing to modify code.
- Use English; formal, precise wording in reports and comments.
