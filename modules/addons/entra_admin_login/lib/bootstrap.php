<?php
// SPDX-License-Identifier: MIT

// No Composer autoloader on purpose: the addon has no dependencies and must
// install on shared hosting by copying one folder.
require_once __DIR__ . '/Base64Url.php';
require_once __DIR__ . '/Guid.php';
require_once __DIR__ . '/Jwks.php';
require_once __DIR__ . '/IdTokenValidator.php';
require_once __DIR__ . '/OidcClient.php';
require_once __DIR__ . '/Settings.php';
require_once __DIR__ . '/Links.php';
require_once __DIR__ . '/Roles.php';
require_once __DIR__ . '/AdminSession.php';
