# Splunk queries (auto-converted from the Sigma rules with pySigma)

Field names follow the Sigma rules. Map them to your own sourcetypes and field names before use.

## PHP2Shell - Apache Worker Segmentation Fault
Source rule: `php2shell_apache_worker_segfault.yml`

```spl
message="*AH00052*" message="*Segmentation fault*"
```

## PHP2Shell - Burst of HTTP 500 Responses to POST Requests From One Source
Source rule: `php2shell_multipart_500_burst.yml`

```spl
"cs-method"="POST" "sc-status"=500

| bin _time span=1m
| stats count as event_count by _time "c-ip" "cs-host"

| search event_count >= 2
```

## PHP2Shell - Multipart Request With Session Upload Progress Field
Source rule: `php2shell_multipart_session_upload_progress.yml`

```spl
"cs-method"="POST" "cs-content-type"="*multipart/form-data*" request_body="*PHP_SESSION_UPLOAD_PROGRESS*" request_body="*PHPSESSID*"
```

## PHP2Shell - PHP Memory Exhaustion During Request Initialisation
Source rule: `php2shell_php_oom_during_request_init.yml`

```spl
message="*Allowed memory size of*" message="*exhausted*" message="*Unknown on line 0*"
```

## PHP2Shell - Upload Filename Containing PHP Code or Serialized Object
Source rule: `php2shell_upload_filename_with_php_code.yml`

```spl
"cs-method"="POST" (request_body IN ("*filename=\"<?php*", "*filename=\"<?=*") OR (request_body="*filename=\"*" request_body="*|O:*"))
```

## PHP2Shell - Shell or Download Tool Spawned by PHP Worker
Source rule: `php2shell_webserver_spawns_shell.yml`

```spl
(ParentImage IN ("*/apache2", "*/httpd", "*/lsphp", "*/frankenphp", "*/php-cgi") OR ParentImage="*/php-fpm*") (Image IN ("*/sh", "*/bash", "*/dash", "*/zsh", "*/curl", "*/wget", "*/nc", "*/ncat", "*/socat", "*/busybox"))
```
