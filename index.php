<?php
require __DIR__ . '/vendor/autoload.php';

$dotenv = new Dotenv\Dotenv(
);
$dotenv->load();
echo getenv('ENV_VAR');

 
    
