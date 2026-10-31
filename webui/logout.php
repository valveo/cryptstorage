<?php
require_once __DIR__ . '/auth.php';
session_start_secure();
clear_session();
header('Location: index.php');
exit;
