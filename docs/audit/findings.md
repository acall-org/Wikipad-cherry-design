# Security Audit Findings: Wikipad v2.3.0 (PHP 5.6)

- Date of audit: 2026-11-17
- Branch: `security-audit`
- Type of task: read-only audit. No application file was modified. This report is the only file written.

## 1. Scope, method and limitations

**Scope.** All 43 files tracked in the repository. The application is the directory `website/`:
13 PHP files (about 5,800 lines), one template, one JavaScript file, two style sheets, six wiki
pages stored as text, and five `.htaccess` files. The application is a flat-file wiki and blog
engine. It uses no database, no PHP sessions, no Composer packages and no third-party library.

**Method.** Manual static review. Every PHP file, the template, the JavaScript file and the
`.htaccess` files were read completely. In addition, all PHP files were searched for the functions
named in the audit request.

**Limitations.**

- The interpreter installed in the audit environment is **PHP 8.3.6**, not PHP 5.6.40. The
  application cannot run on PHP 8 without modification (`get_magic_quotes_gpc()`, `each()`,
  `set_magic_quotes_runtime()`). **No application code was executed. No exploit scenario in this
  report was reproduced at run time.** Every scenario is derived from reading the code; statements
  about run-time behaviour refer to documented PHP 5.6 behaviour.
- The commands listed in `CLAUDE.md` (`composer install`, `vendor/bin/phpunit`, `vendor/bin/phpcs`,
  `vendor/bin/phpstan`) are unavailable: the repository contains no `composer.json` and no tests.
  No test was run.
- The production web server, its virtual-host configuration and `php.ini` were not available.
  Findings that depend on them have the status `unverified`.
- The upload directory `website/files/` is not part of the repository. `README.md` instructs the
  installer to create it with mode 0777.

**Status values.** `open`: confirmed by reading the code path from input to sink.
`unverified`: plausible, but dependent on server configuration or on behaviour that could not be
confirmed without execution.
`accepted risk`: confirmed, and deliberately not fixed by decision of the project owner, under the
conditions stated in the finding (see section 7).

**Severity scale.** Critical, High, Medium, Low, Informational. Preconditions (authentication,
non-default configuration flag) are stated in each finding.

**Terminology.** "Administrator" denotes the single account defined in
`website/includes/configuration.php`. The application has no separate administration area: the
administrative functions are page editing (`pages.php?action=edit`), file upload and deletion
(`files.php?action=upload`) and export (`export.php`).

All paths below are relative to the repository root.

## 2. Summary

| ID | Title | Primary location | CWE | Severity | Status |
|---|---|---|---|---|---|
| SEC-001 | Default administrator credentials; password stored in plain text | `website/includes/configuration.php:47-48` | 1392, 798, 256 | Critical | open |
| SEC-002 | Unrestricted file upload permits remote code execution | `website/files.php:106-123` | 434 | High | open |
| SEC-003 | No CSRF protection; state-changing actions accepted through GET | `website/pages.php:300-308` | 352 | High | open |
| SEC-004 | Arbitrary file deletion through path traversal in `upload[filename]` | `website/files.php:84-87` | 22 | High | open |
| SEC-005 | Authentication token is a static, unsalted MD5 of the credentials | `website/includes/initialization.php:41-57` | 916, 613, 1004, 614, 697 | High | open |
| SEC-006 | Execution continues after redirect; access restrictions are not enforced | `website/pages.php:21-23` | 698, 284 | High (conditional) | open |
| SEC-007 | `export.php` has no authentication check | `website/export.php:22-24,997` | 306, 862 | Medium | open |
| SEC-008 | Path traversal in page identifier `id` | `website/pages.php:100,138,183,242-245` | 22 | Medium | open |
| SEC-009 | Reflected XSS through `id` and `title` (authenticated victim) | `website/includes/functions.php:171,178` | 79 | Medium | open |
| SEC-010 | Reflected XSS through search `query` in pagination links | `website/search.php:433-434` | 79 | Medium | open |
| SEC-011 | Stored XSS: page content and page title are emitted as raw HTML | `website/includes/parser.php:964-966,1364-1380` | 79 | Medium | accepted risk (content); open (title) |
| SEC-012 | XSS in file views through file name, extension and `upload[referer]` | `website/files.php:127,191-242` | 79 | Low | unverified |
| SEC-013 | Open redirect after login through `user[referer]` | `website/login.php:65` | 601 | Medium | open |
| SEC-014 | Open redirect through `id` when `rewrite_flag` is enabled | `website/includes/functions.php:458` | 601 | Low | open |
| SEC-015 | `Host` header and request URI written unescaped into cached RSS feed | `website/rss.php:72,205,222` | 644, 91, 349 | Medium | open |
| SEC-016 | File existence, size and modification-time disclosure | `website/files.php:177-224` | 22, 200 | Low | open |
| SEC-017 | No limitation of login attempts; credentials accepted through GET | `website/login.php:55-58,105-106` | 307, 598 | Low | open |
| SEC-018 | Regular-expression injection from search keywords | `website/search.php:268,274,421` | 1333, 624 | Low | open |
| SEC-019 | Directory protection depends on Apache 2.2 `.htaccess` directives | `website/includes/.htaccess:1-2` | 552, 548 | Low | unverified |
| SEC-020 | Error display is not configured by the application | `website/includes/initialization.php:14-37` | 209 | Low | unverified |
| SEC-021 | World-writable directories (mode 0777) | `website/export.php:113` | 732 | Low | open |
| SEC-022 | No security response headers | `website/includes/functions.php:59-62` | 1021, 693 | Low | open |
| SEC-023 | `unserialize()` applied to cache files | `website/search.php:122` | 502 | Informational | unverified |
| SEC-024 | Emulated magic quotes are the only input handling | `website/includes/initialization.php:26-34` | 20 | Informational | open |
| SEC-025 | End-of-life platform; no third-party libraries present | — | 1104 | Informational | open |

## 3. Findings

### SEC-001: Default administrator credentials; password stored in plain text

- **File:line:** `website/includes/configuration.php:47-48`; documented in `README.md:45-46`.
- **CWE:** CWE-1392 (Use of Default Credentials), CWE-798 (Hard-coded Credentials),
  CWE-256 (Plaintext Storage of a Password).
- **Severity:** Critical.
- **Description:** The single administrator account is defined by two literal values in the
  configuration file. The distributed default password is identical to the default login name and
  is published in `README.md`. The application does not require the installer to change it. The
  password is stored in plain text. (The literal values are deliberately not repeated in this
  report.)
- **Exploit scenario:** An attacker submits the documented default credentials to `login.php` on
  an installation whose configuration was not changed and obtains administrator rights. The
  attacker then uses SEC-002 to upload a PHP file and execute code on the server. No further
  precondition exists.
- **Minimal fix:** Remove the default password from the distributed configuration. Store only a
  `password_hash()` value (available in PHP 5.5 and later) and verify with `password_verify()`.
  Refuse login while no hash is configured. Update `README.md` accordingly.
- **Dependency:** the accepted risk in SEC-011 (a) depends on the fix of this finding.
- **Status:** open.

### SEC-002: Unrestricted file upload permits remote code execution

- **File:line:** `website/files.php:106-123` (extension taken from the client file name at line
  106; file stored at line 123).
- **CWE:** CWE-434 (Unrestricted Upload of File with Dangerous Type).
- **Severity:** High. Authentication as administrator is required; in combination with SEC-001 or
  SEC-005 the precondition is weak.
- **Description:** The base name of the uploaded file is sanitised by `calculate_ascii_string()`,
  but the extension is copied unchanged from `$_FILES["upload"]["name"]["file"]`. No allow-list of
  extensions and no content check exists. The target directory `files/` is inside the document
  root and has no `.htaccess` file. A client file name that consists only of an extension (for
  example `.htaccess`) produces an empty base name and is stored under that name.
- **Exploit scenario:** An authenticated user uploads a file with the extension `php` through
  `files.php?action=upload`. The file is stored as `files/<name>.php`. A subsequent request for
  that URL causes the web server to execute the file. Alternatively the user uploads a file named
  `.htaccess` that changes the handler configuration of the directory (Apache with
  `AllowOverride` enabled).
- **Minimal fix:** Accept only an allow-list of extensions (for example `gif`, `jpg`, `png`,
  `pdf`, `zip`, `txt`), compared in lower case; reject an empty base name. In addition, disable
  script execution in `files/` at server level.
- **Status:** open.

### SEC-003: No CSRF protection; state-changing actions accepted through GET

- **File:line:** `website/pages.php:300-308` (page create, overwrite, delete);
  `website/files.php:267-275` (file upload, file delete); `website/export.php:990-997` (export,
  deletion of the export tree); `website/logout.php:40`; input read through `$_REQUEST` in
  `website/includes/initialization.php:62-80`.
- **CWE:** CWE-352 (Cross-Site Request Forgery).
- **Severity:** High.
- **Description:** No request carries an anti-CSRF token, and no `Origin` or `Referer` check is
  performed. All parameters are read from `$_REQUEST`; therefore every state-changing action can
  be triggered by a GET request.
- **Exploit scenario:** An attacker sends the logged-in administrator a link of the form
  `pages.php?action=edit&id=index&data[text]=<markup>`. When the administrator follows the link,
  the browser sends the authentication cookies (a top-level GET navigation is not blocked by the
  `SameSite=Lax` default of current browsers), and `edit_page()` overwrites the start page with
  attacker-chosen content. Because page content is emitted as raw HTML (SEC-011), the attacker
  thereby stores script code that runs for every visitor. A link of the form
  `files.php?action=upload&upload[filename]=<path>` deletes a file (SEC-004).
- **Minimal fix:** Read state-changing input only from `$_POST`. Add a per-login random token
  (generated with `openssl_random_pseudo_bytes()` on PHP 5.6) as a hidden field to the edit,
  upload, export and logout forms, and verify it with `hash_equals()` before any write or delete.
- **Dependency:** the accepted risk in SEC-011 (a) depends on the fix of this finding.
- **Status:** open.

### SEC-004: Arbitrary file deletion through path traversal in `upload[filename]`

- **File:line:** `website/files.php:84-87`.
- **CWE:** CWE-22 (Path Traversal).
- **Severity:** High. Authentication is required, but the action is reachable through CSRF with a
  GET request (SEC-003).
- **Description:** When the upload form is submitted with a file name but without a file, the
  application deletes `files/` + `upload[filename]`. The value is not validated; `../` sequences
  are accepted.
- **Exploit scenario:** A request
  `files.php?action=upload&upload[filename]=../includes/configuration.php`, sent with the
  administrator cookies, deletes the configuration file; every subsequent request terminates with
  a fatal error in `require()`. Deleting `../pages/.htaccess` or `../temp/.htaccess` removes the
  access restriction of those directories. Any file that the web-server account may delete is
  affected.
- **Minimal fix:** Before `file_exists()` and `unlink()`, require the name to match
  `/^[a-z0-9_-]+\.[a-z0-9]+$/i` (the format produced by the upload routine), or apply `basename()`
  and reject names that begin with a dot.
- **Status:** open.

### SEC-005: Authentication token is a static, unsalted MD5 of the credentials

- **File:line:** `website/includes/initialization.php:41-57` (verification);
  `website/login.php:58-62` (issue); `website/logout.php:33-34` (logout).
- **CWE:** CWE-916 (Password Hash With Insufficient Computational Effort), CWE-613 (Insufficient
  Session Expiration), CWE-1004 and CWE-614 (cookie without `HttpOnly` and `Secure`),
  CWE-697 (Incorrect Comparison).
- **Severity:** High.
- **Description:** After login the application stores `md5(login)` and `md5(password)` in two
  cookies and treats any request that presents these two values as authenticated. No server-side
  session exists. The consequences are:
  1. The cookie values are constant for a given password. A copied cookie remains valid until the
     password is changed. Logout only clears the cookies in the browser.
  2. The cookie is an unsalted MD5 of the password; a disclosed cookie permits an inexpensive
     offline search for the password.
  3. The cookies are set without `HttpOnly`, `Secure` and `SameSite`, so they are readable by
     script (see SEC-009 to SEC-012) and are transmitted over unencrypted HTTP.
  4. The comparisons at `initialization.php:53` and `login.php:58` use `==`. In PHP 5.6 two
     strings that both have numeric form (for example an MD5 value of the form `0e` followed by
     digits) are compared as numbers and can be equal although the strings differ.
- **Exploit scenario:** An attacker obtains the two cookie values once, through cross-site
  scripting, through interception of an HTTP connection, or from a shared computer after logout.
  The attacker sets the same cookies in a browser and has permanent administrator access.
- **Minimal fix:** Replace the two cookies by a PHP session: call `session_regenerate_id(true)`
  and set a session flag on successful login; call `session_destroy()` on logout; configure the
  session cookie with `HttpOnly`, `Secure` (when HTTPS is used) and `SameSite=Lax`. Use `===` or
  `hash_equals()` for all credential comparisons.
- **Dependency:** the accepted risk in SEC-011 (a) depends on the fix of this finding.
- **Status:** open. Item 4 was not reproduced and applies only to credentials whose MD5 value has
  numeric form.

### SEC-006: Execution continues after redirect; access restrictions are not enforced

- **File:line:** `website/pages.php:21-23`; `website/files.php:21-23`; `website/search.php:21-23`;
  `website/rss.php:22-24`; `website/blog.php:21-23`; `website/export.php:22-24`. The same pattern
  without security effect: `website/login.php:20-22`, `website/logout.php:20-22`.
- **CWE:** CWE-698 (Execution After Redirect), CWE-284 (Improper Access Control).
- **Severity:** High when `hidden_flag` is enabled (non-default); Low otherwise.
- **Description:** The mode "mandatory authorisation" (`hidden_flag = 1`) and the feature switches
  `search_flag`, `rss_flag`, `blog_flag` and `export_flag` are enforced only by
  `header("Location: ./")`. No `exit` follows. The script continues and sends the complete page
  body together with the redirect header.
- **Exploit scenario:** On a site configured with `hidden_flag = 1`, an unauthenticated client
  that does not follow redirects (for example a command-line HTTP client) requests
  `pages.php?id=<page>`, `search.php?query=<word>` or `rss.php` and receives the protected content
  in the response body. On any site, a disabled feature remains reachable in the same manner.
- **Minimal fix:** Add `exit();` immediately after each of the listed `header("Location: ...")`
  calls.
- **Status:** open.

### SEC-007: `export.php` has no authentication check

- **File:line:** `website/export.php:22-24` (only check; see SEC-006), `website/export.php:997`
  (unconditional call); deletion logic at `website/export.php:40-91`.
- **CWE:** CWE-306 (Missing Authentication for Critical Function), CWE-862 (Missing
  Authorization).
- **Severity:** Medium.
- **Description:** In contrast to `pages.php:306` and `files.php:273`, `export.php` never tests
  `$globals["user_entry_flag"]`. The only condition is the redirect described in SEC-006, which
  does not stop execution. The export therefore runs for any client, also when `export_flag = 0`
  (the default).
- **Exploit scenario:** An unauthenticated client requests `export.php?data[clear]=yes`. The
  application deletes the previously exported tree, regenerates all pages and copies all uploaded
  files into `../export/`. Repeated requests cause sustained disk and processor load. If the
  directory above `website/` is served by the web server (for example when the repository root is
  the document root), the complete content, including content protected by `hidden_flag`, becomes
  retrievable from `export/website/`.
- **Minimal fix:** After the redirect block, terminate unless
  `$globals["export_flag"] && $globals["user_entry_flag"]` holds; accept the form only through
  POST with a CSRF token (SEC-003).
- **Status:** open.

### SEC-008: Path traversal in page identifier `id`

- **File:line:** read: `website/pages.php:242-245`, `website/blog.php:431-434`;
  read in edit mode: `website/pages.php:100`; delete: `website/pages.php:135-138`;
  write: `website/pages.php:183`; source of the value: `website/includes/initialization.php:69-70`.
- **CWE:** CWE-22 (Path Traversal).
- **Severity:** Medium.
- **Description:** The request parameter `id` is concatenated into `pages/` + `id` + `.txt`
  without validation. The fixed prefix prevents stream wrappers and the fixed suffix restricts the
  effect to files whose names end in `.txt` (PHP 5.6 rejects NUL bytes in paths).
- **Exploit scenario:** (a) Unauthenticated: `pages.php?id=../../<directory>/<name>` displays any
  readable `.txt` file on the server, except its first two lines. (b) Authenticated or through
  CSRF: `pages.php?action=edit&id=../<directory>/<name>` with `data[text]` creates or overwrites
  any `.txt` file writable by the web-server account; with an empty `data[text]` it deletes that
  file.
- **Minimal fix:** In `initialization.php`, accept `id` only if it matches
  `/^[a-z0-9_-]+$/i`; otherwise set it to `index`. The same pattern is already used for file
  names read from the directory (`search.php:133`).
- **Status:** open.

### SEC-009: Reflected XSS through `id` and `title` (authenticated victim)

- **File:line:** `website/includes/functions.php:171,178` (`id` in menu links);
  `website/pages.php:151,203` (`id` in link and form action); `website/pages.php:37,221` together
  with `website/includes/functions.php:434` (`title` in `<title>` and `<h1>`).
- **CWE:** CWE-79 (Cross-site Scripting).
- **Severity:** Medium. The victim must be the logged-in administrator; successful exploitation
  yields the authentication cookies (SEC-005) and all administrator functions, including SEC-002.
- **Description:** For an authenticated user, the main menu contains a link that includes the raw
  request value `id`. The edit form repeats `id` in its `action` attribute. The request value
  `title` is entity-decoded (`pages.php:34-37`) and inserted into the template placeholder
  `{TITLE}` without encoding when the page does not yet exist. The emulated magic quotes add a
  backslash before a double quote but do not prevent the termination of the attribute.
- **Exploit scenario:** The attacker sends the administrator a link to `pages.php` whose `id`
  value contains a double quote followed by an HTML element with script content, or a link to
  `pages.php?action=edit&id=<new>&title=<element with script>`. The script runs in the
  administrator's browser in the origin of the site, reads `document.cookie` and transmits it, or
  submits the upload form.
- **Minimal fix:** Validate `id` as in SEC-008 (this removes the `id` vector completely). Apply
  `htmlspecialchars($title, ENT_QUOTES, "UTF-8")` when the title is assigned to
  `$globals["page"]["title"]`.
- **Status:** open.

### SEC-010: Reflected XSS through search `query` in pagination links

- **File:line:** `website/search.php:433-434`; sink in `website/includes/functions.php:369,392,404`.
- **CWE:** CWE-79.
- **Severity:** Medium.
- **Description:** The raw value of `query` is passed to `print_navigation()` and written into the
  `href` attribute of the pagination links without HTML or URL encoding.
- **Precondition established by reading the code:** a link is emitted only for result pages other
  than the current one. The search must therefore return more than 10 results
  (`records_per_page`, `search.php:26`). The distributed installation has six pages, so the
  default installation is not affected; a site with more than ten pages that share a word is
  affected.
- **Exploit scenario:** The attacker constructs a query that consists of a frequent word, the
  operator `or`, and a third token that contains a double quote followed by an HTML element with
  an event handler and no space character. The victim opens the resulting `search.php` link. The
  first word produces the result list; the third token is written into each pagination link and
  the browser executes the script.
- **Minimal fix:** In `search.php:433`, build the value as
  `"query=".htmlspecialchars(urlencode(stripslashes($query)), ENT_QUOTES, "UTF-8")`.
- **Status:** open (not executed).

### SEC-011: Stored XSS: page content and page title are emitted as raw HTML

- **File:line:** `website/includes/parser.php:964-966` (`<nowiki>` block copied unchanged);
  `website/includes/parser.php:1364-1380` (`parse_special_characters()` reverses the earlier
  `htmlspecialchars()` encoding for all text blocks); `website/includes/parser.php:1143` (image
  caption); `website/includes/functions.php:434` (template substitution without encoding) with
  the title sources `website/pages.php:250-251,291`, `website/blog.php:323,410,439-440,522` and
  `website/export.php:655-656,732`.
- **CWE:** CWE-79.
- **Severity:** Medium while SEC-001, SEC-003 and SEC-005 are open; Low for part (a) after those
  three findings are fixed, because authorship is then restricted to the administrator.
- **Description:** The finding has two parts.
  - **(a) Page content.** Text blocks are first encoded with `htmlspecialchars()` and later
    decoded again by `parse_special_characters()`. The content of `<nowiki>` blocks is never
    encoded, and the image caption is emitted unencoded. Consequently any HTML, including script
    elements, that is stored in a page is delivered unchanged to every visitor and is also written
    into the exported static site. The help page `website/pages/help.txt` documents `<nowiki>`;
    raw HTML is an intended feature.
  - **(b) Page title.** The page title (first line of the page file, in the form `= Title =`) is
    inserted into `<title>` and `<h1>` without encoding. The title is plain text and is not a
    documented HTML feature.
- **Exploit scenario:** Only the administrator can store pages directly. An attacker without
  credentials uses CSRF (SEC-003) or the default credentials (SEC-001) to store a page that
  contains a script element. The script is then executed in the browser of every visitor of that
  page, including the administrator.
- **Minimal fix:**
  - (a) None. No change to `website/includes/parser.php` is planned (see the decision below).
  - (b) Encode the title at the point of output (`htmlspecialchars(..., ENT_QUOTES, "UTF-8")` in
    `view_page()`, `view_record()`, `view_blog()` and `export_wiki()`).
- **Decision (2026-11-17, project owner):** raw HTML in page content is retained as a feature.
  The risk of part (a) is accepted on the condition that SEC-001, SEC-003 and SEC-005 are fixed,
  so that only the administrator can store page content. Until those three findings are fixed,
  part (a) remains exploitable through default credentials, CSRF and reuse of the authentication
  cookie. The decision concerns page content only; it does not cover part (b).
- **Status:** (a) accepted risk; (b) open.

### SEC-012: XSS in file views through file name, extension and `upload[referer]`

- **File:line:** `website/files.php:127` (`$filename` and `$record["referer"]` in the upload
  result); `website/files.php:191,218` (title); `website/files.php:201,203` (`data`, `src`);
  `website/files.php:210,235,242`.
- **CWE:** CWE-79.
- **Severity:** Low.
- **Description:** (a) The upload result page writes `upload[referer]` into an `href` attribute
  without encoding. (b) The file name is written into the page title and into several attributes
  without encoding. The view is reached only if the named file exists, so a request alone cannot
  inject markup; however, the extension of an uploaded file is not sanitised (SEC-002), so a
  stored file name can contain HTML metacharacters.
- **Exploit scenario:** An authenticated user uploads a file whose extension contains a double
  quote and an HTML element. Every later view of `files.php?filename=<that name>` emits the
  element. For (a), a forged multipart request that includes a file and a crafted
  `upload[referer]` returns a page containing the injected attribute; this requires the
  administrator cookies and is therefore dependent on SEC-003.
- **Minimal fix:** Apply `htmlspecialchars(..., ENT_QUOTES, "UTF-8")` to `$filename`,
  `$image_src` and `$record["referer"]` at each listed output; restrict the extension as in
  SEC-002; validate `filename` as in SEC-004.
- **Status:** unverified (the treatment of quotation marks in multipart file names by PHP 5.6 was
  not tested).

### SEC-013: Open redirect after login through `user[referer]`

- **File:line:** `website/login.php:65`; value preserved in the form at `website/login.php:82`;
  read from the request at `website/login.php:105-106`.
- **CWE:** CWE-601 (URL Redirection to Untrusted Site).
- **Severity:** Medium.
- **Description:** The default value of the hidden field `user[referer]` is computed by
  `get_referer_link()`, which validates it. A value supplied in the request is, however, used
  without validation in `header("Location: ...")` after a successful login.
- **Exploit scenario:** The attacker distributes a link `login.php?user[referer]=<external URL>`.
  The login page reports an incomplete form and displays the form again with the attacker's value
  in the hidden field. The victim enters valid credentials and is redirected to the external site,
  which can imitate the login page and request the credentials again.
- **Minimal fix:** Before the redirect, accept `user[referer]` only if it matches the patterns
  already used in `get_referer_link()` (`includes/functions.php:493,500`); otherwise use `./`.
- **Status:** open.

### SEC-014: Open redirect through `id` when `rewrite_flag` is enabled

- **File:line:** `website/includes/functions.php:458`; callers `website/index.php:26`,
  `website/blog.php:27`, `website/pages.php:191`.
- **CWE:** CWE-601.
- **Severity:** Low (requires the non-default setting `rewrite_flag = 1`).
- **Description:** With `rewrite_flag = 1`, `get_rewrite_link()` returns `id` + `.htm`. The value
  of `id` is not validated, so it can be an absolute or scheme-relative URL. With
  `rewrite_flag = 0` the result always begins with `pages.php?id=` or `blog.php?id=` and is not
  affected.
- **Exploit scenario:** A link `index.php?id=//<external host>/<path>` causes the response header
  `Location: //<external host>/<path>.htm`, and the browser leaves the site.
- **Minimal fix:** The validation of `id` proposed in SEC-008 removes this finding.
- **Status:** open.

### SEC-015: `Host` header and request URI written unescaped into cached RSS feed

- **File:line:** `website/rss.php:72` (URL built from `HTTP_HOST` and `REQUEST_URI`);
  `website/rss.php:140` (item links); `website/rss.php:205,222` (output without encoding);
  cache write at `website/rss.php:174-183`, lifetime 600 seconds (`website/rss.php:33`).
- **CWE:** CWE-644 (Improper Neutralization of HTTP Headers), CWE-91 (XML Injection),
  CWE-349 (Acceptance of Extraneous Untrusted Data).
- **Severity:** Medium.
- **Description:** The site URL in the feed is derived from the request and is stored in the
  cache file `temp/rss_last.dat`, which is then served to all clients for ten minutes. The value
  is not XML-encoded in the `<link>` elements. The scheme is fixed to `http://`.
- **Exploit scenario:** At the moment the cache expires, the attacker requests `rss.php` with a
  forged `Host` header (possible when the server routes unknown host names to this site) or with
  a query string that contains XML markup and a slash. For the next ten minutes every subscriber
  receives a feed whose links point to the attacker's host, or a feed with injected elements.
- **Minimal fix:** Add a configuration entry for the canonical site URL and use it instead of the
  request values; apply `htmlspecialchars()` to both `<link>` values in `print_rss()`.
- **Status:** open. The `Host` variant depends on the virtual-host configuration.

### SEC-016: File existence, size and modification-time disclosure

- **File:line:** `website/files.php:177-224`; parameter read at `website/files.php:26-27`.
- **CWE:** CWE-22, CWE-200 (Exposure of Sensitive Information).
- **Severity:** Low.
- **Description:** `view_file()` tests `file_exists("files/" . $filename)` with an unvalidated
  `filename`, without authentication. The file content is not read, but the response differs for
  existing and non-existing paths and, for existing ones, states the modification time and the
  size.
- **Exploit scenario:** An unauthenticated client requests `files.php?filename=../../<path>` for
  a series of paths and learns which files and directories exist on the server, their sizes and
  their modification times (for example whether the configuration file was changed after
  installation).
- **Minimal fix:** Validate `filename` with the pattern given in SEC-004 before any file-system
  call.
- **Status:** open.

### SEC-017: No limitation of login attempts; credentials accepted through GET

- **File:line:** `website/login.php:55-58` (check); `website/login.php:105-106` (`$_REQUEST`).
- **CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts), CWE-598 (Use of
  GET Request Method With Sensitive Query Strings).
- **Severity:** Low.
- **Description:** Failed logins are neither counted, delayed nor logged. Because the form data
  are read from `$_REQUEST`, a login can be performed with a URL that contains the password; such
  URLs are recorded in server logs and browser history.
- **Exploit scenario:** An attacker submits a password list to `login.php` at full speed. With
  one account and no lockout, the search is limited only by the network.
- **Minimal fix:** Read the credentials from `$_POST` only. Record failed attempts per client
  address in a file in `temp/` and insert a delay or a temporary block after a small number of
  failures.
- **Status:** open.

### SEC-018: Regular-expression injection from search keywords

- **File:line:** `website/search.php:268,274,421`.
- **CWE:** CWE-1333 (Inefficient Regular Expression Complexity), CWE-624 (Executable Regular
  Expression Error).
- **Severity:** Low.
- **Description:** Each search keyword is inserted into a PCRE pattern without `preg_quote()`.
  The `/e` modifier cannot be injected in PHP 5.6: text after the closing delimiter is rejected as
  an unknown modifier and NUL bytes in patterns are rejected.
- **Exploit scenario:** A client sends keywords with nested quantifiers. Each keyword is matched
  against the text of every page; the cost per match is bounded by `pcre.backtrack_limit`, but
  repeated requests consume processor time. A keyword containing `/` produces a PHP warning that
  discloses the script path when error display is enabled (SEC-020).
- **Minimal fix:** Use `preg_quote($keyword, "/")` at the three locations.
- **Status:** open.

### SEC-019: Directory protection depends on Apache 2.2 `.htaccess` directives

- **File:line:** `website/includes/.htaccess:1-2`, `website/pages/.htaccess:1-2`,
  `website/temp/.htaccess:1-2`, `website/templates/.htaccess:1-2`; `website/.htaccess:1-4`.
- **CWE:** CWE-552 (Files Accessible to External Parties), CWE-548 (Directory Listing).
- **Severity:** Low in the default mode; Medium when `hidden_flag = 1`.
- **Description:** The four data directories are protected only by `Order allow,deny` /
  `Deny from all`. These directives have no effect on nginx and require `mod_access_compat` on
  Apache 2.4; they also require `AllowOverride`. Where they are ineffective, `pages/*.txt` (page
  sources) and `temp/*.dat` (search index with the text of all pages) can be downloaded directly,
  which bypasses `hidden_flag`. The root `.htaccess` does not disable directory indexes; the
  upload directory `files/` has no protection file.
- **Exploit scenario:** On a server where the directives are not applied, an unauthenticated
  client requests `temp/search_index.dat` and receives the text of all pages of a site that is
  configured as hidden.
- **Minimal fix:** Use `Require all denied` (Apache 2.4) in addition to the existing directives
  inside `<IfModule>` blocks, add `Options -Indexes`, and document the equivalent nginx `location`
  rules. Preferably move `pages/`, `temp/`, `templates/` and `includes/` outside the document
  root.
- **Status:** unverified (the production web server is not specified).

### SEC-020: Error display is not configured by the application

- **File:line:** `website/includes/initialization.php:14-37` (no `error_reporting` or
  `display_errors` setting); examples of suppression with `@`: `website/pages.php:100,245`.
- **CWE:** CWE-209 (Generation of Error Message Containing Sensitive Information).
- **Severity:** Low.
- **Description:** The application relies entirely on `php.ini`. If `display_errors` is enabled,
  warnings and notices that contain absolute file paths are sent to the client. Several inputs
  provoke such messages, for example array-valued parameters (`id[]=`, `query[]=`,
  `user[login][]=`) passed to string functions, and invalid search patterns (SEC-018).
- **Exploit scenario:** A client requests `search.php?query[]=x` and reads the installation path
  from the warning text.
- **Minimal fix:** In `initialization.php`, set `ini_set("display_errors", "0")` and
  `ini_set("log_errors", "1")`; reject non-string values of `action`, `id`, `page`, `query`,
  `filename`, `title`, `tag` and `year`.
- **Status:** unverified (depends on `php.ini`).

### SEC-021: World-writable directories (mode 0777)

- **File:line:** `website/export.php:113`; installation instruction in `README.md:34-39`.
- **CWE:** CWE-732 (Incorrect Permission Assignment for Critical Resource).
- **Severity:** Low.
- **Description:** Export directories are created with mode 0777, and the documentation instructs
  the installer to set 0777 on `files/`, `pages/` and `temp/`.
- **Exploit scenario:** On a shared host, another local account modifies page files, replaces the
  cache files that are later passed to `unserialize()` (SEC-023), or places a script in `files/`.
- **Minimal fix:** Create directories with mode 0755 (or 0750) and document that the directories
  must be owned by the web-server account instead of being world-writable.
- **Status:** open.

### SEC-022: No security response headers

- **File:line:** `website/includes/functions.php:59-62` (only cache headers are sent).
- **CWE:** CWE-1021 (Improper Restriction of Rendered UI Layers), CWE-693 (Protection Mechanism
  Failure).
- **Severity:** Low.
- **Description:** The responses contain no `X-Frame-Options` or `Content-Security-Policy:
  frame-ancestors`, no `X-Content-Type-Options` and no content security policy.
- **Exploit scenario:** An attacker embeds the edit or upload form in a frame on another site and
  induces the logged-in administrator to click on it (clickjacking). Uploaded files may be
  interpreted by the browser as a type other than the declared one.
- **Minimal fix:** In `print_page()`, send `X-Frame-Options: SAMEORIGIN` and
  `X-Content-Type-Options: nosniff`.
- **Status:** open.

### SEC-023: `unserialize()` applied to cache files

- **File:line:** `website/search.php:122`; `website/rss.php:64`; `website/blog.php:68`.
- **CWE:** CWE-502 (Deserialization of Untrusted Data).
- **Severity:** Informational.
- **Description:** The cache files in `temp/` are read with `unserialize()`. No code path was
  found by which a remote client controls the bytes of these files: they are produced by
  `serialize()` in the same scripts, and the page-write traversal (SEC-008) can create only files
  ending in `.txt`. The application defines no classes, so no gadget chain exists in its own code.
  The risk arises only if another weakness or a local account (SEC-021) permits writing to
  `temp/`.
- **Exploit scenario:** A local user on a shared host replaces `temp/search_index.dat`; the next
  search request deserialises the content.
- **Minimal fix:** Store the caches with `json_encode()` and read them with
  `json_decode(..., true)`.
- **Status:** unverified (no remote path identified).

### SEC-024: Emulated magic quotes are the only input handling

- **File:line:** `website/includes/initialization.php:26-34`;
  `website/includes/functions.php:269-284`.
- **CWE:** CWE-20 (Improper Input Validation).
- **Severity:** Informational.
- **Description:** All request data are passed through `addslashes()`. No database exists, so
  this provides no protection; it is not an output encoding and does not prevent any finding in
  this report. Array keys are not processed. The functions used here are relevant to the planned
  migration: `set_magic_quotes_runtime()` was removed in PHP 7.0, `get_magic_quotes_gpc()` was
  deprecated in PHP 7.4 and removed in PHP 8.0, and `each()` was deprecated in PHP 7.2 and removed
  in PHP 8.0.
- **Exploit scenario:** None directly. The mechanism may give maintainers the incorrect
  impression that input is sanitised.
- **Minimal fix:** Remove the emulation and the corresponding `stripslashes()` calls together, in
  a separate change, after the output-encoding fixes (SEC-009 to SEC-012) are in place.
- **Status:** open.

### SEC-025: End-of-life platform; no third-party libraries present

- **File:line:** not applicable.
- **CWE:** CWE-1104 (Use of Unmaintained Third Party Components).
- **Severity:** Informational.
- **Description:** The repository contains no third-party or vendored PHP or JavaScript library;
  `website/js/functions.js` is project code and contains no dangerous DOM operation with external
  data. The target interpreter PHP 5.6.40 has received no security updates since January 2019.
  The generated pages disclose the engine version (`website/templates/main.tpl:50`,
  `website/export.php:227`).
- **Exploit scenario:** Vulnerabilities of the interpreter itself remain unpatched on the
  production server.
- **Minimal fix:** Proceed with the planned migration to a supported PHP version.
- **Status:** open.

## 4. Coverage of the requested categories

| Category | Result |
|---|---|
| SQL injection (`mysql_*`, string-built queries) | No instance. The application uses no database function. |
| XSS | SEC-009, SEC-010, SEC-011, SEC-012 |
| CSRF | SEC-003 |
| File inclusion | No instance. All `require` statements use constant paths (`website/includes/initialization.php:17-21` and line 17 of each entry script). |
| File upload handling | SEC-002, SEC-012 |
| Path traversal | SEC-004, SEC-008, SEC-016 |
| Command execution (`exec`, `system`, `shell_exec`, `passthru`, `eval`, `preg_replace /e`, `create_function`) | No instance of these functions. Regular-expression injection without code execution: SEC-018. |
| `unserialize` | SEC-023 |
| Session handling | No PHP session is used; cookie-based authentication: SEC-005 |
| Password storage | SEC-001, SEC-005 |
| Weak random values | No instance. No random value is generated; the absence of any random token is covered by SEC-003 and SEC-005. |
| Open redirects | SEC-013, SEC-014 |
| SSRF | No instance. No outbound request function is used; all file functions operate on local paths with a fixed prefix. |
| `extract()` / variable overwriting | No instance of `extract()`, `parse_str()`, `import_request_variables()` or variable variables. Request values are assigned to named globals in `website/includes/initialization.php:62-80`. |
| Error display | SEC-020 |
| Hard-coded secrets | SEC-001 |
| Access control on administrative functions | SEC-006, SEC-007, SEC-019 |
| Outdated third-party libraries | SEC-025 (none present) |

## 5. Files examined

Read completely: `website/index.php`, `website/login.php`, `website/logout.php`,
`website/pages.php`, `website/files.php`, `website/search.php`, `website/rss.php`,
`website/blog.php`, `website/export.php`, `website/includes/configuration.php`,
`website/includes/initialization.php`, `website/includes/functions.php`,
`website/includes/parser.php`, `website/templates/main.tpl`, `website/js/functions.js`, the five
`.htaccess` files, `.gitignore`, `CLAUDE.md`.

Examined partially:

- `README.md`: installation and configuration sections read; long lines were truncated in the
  remaining text.
- `website/css/screen.css`, `website/css/print.css`: searched for `url(`, `expression`, `@import`
  and `javascript`; not read line by line.
- `website/pages/*.txt` (six wiki pages): searched for script elements, event handlers,
  `javascript:` and `<nowiki>`; only `help.txt` matches, as documentation of the `<nowiki>`
  syntax. Not read line by line.

## 6. Files not examined

- `LICENSE` (licence text).
- `export/.keep` (empty file).
- `psd/` (one Photoshop file) — binary.
- `screenshots/` (four PNG files) — binary.
- `website/pic/` (five GIF/JPG files) — binary.

Not available for examination: the production web-server configuration, `php.ini`, the list of
installed PHP extensions, the content of the upload directory `website/files/` and of the cache
directory `website/temp/` on the production system.

## 7. Decisions

| Date | Finding | Decision | Decided by | Conditions |
|---|---|---|---|---|
| 2026-11-17 | SEC-011 (a), raw HTML in page content | Retained as a feature; risk accepted; no change to the parser | Project owner | SEC-001, SEC-003 and SEC-005 must be fixed. SEC-011 (b), encoding of the page title, is not covered and remains open. |
