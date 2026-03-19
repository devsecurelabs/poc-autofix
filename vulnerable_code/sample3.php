<?php
// Get the 'q' parameter from the URL
$search_query = $_GET['q']; 

// VULNERABILITY: Directly echoing user input into the HTML
echo "<h1>Search results for: " . $search_query . "</h1>";
?>