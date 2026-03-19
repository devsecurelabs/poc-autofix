<?php
// CWE-89: Improper Neutralization of Special Elements used in an SQL Command
// VULNERABLE: Direct string concatenation from user-controlled $_GET parameter
// An attacker can supply id=1 OR 1=1 to dump the entire users table

$id = $_GET['id'];
$result = $mysqli->query("SELECT * FROM users WHERE id = " . $id);
?>
