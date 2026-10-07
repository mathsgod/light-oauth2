<?php
$loader = require dirname(__DIR__) . '/vendor/autoload.php';
// Optional local checkout for testing the unreleased Light extension points.
if ($path = getenv('LIGHT_SOURCE_PATH')) {
    $loader->addClassMap(['Light\\App' => rtrim($path, '/') . '/src/App.php']);
    $loader->addClassMap([
        'Light\\GraphQL\\ExplicitController' => rtrim($path, '/') . '/src/GraphQL/ExplicitController.php',
        'Light\\GraphQL\\ControllerDiscovery' => rtrim($path, '/') . '/src/GraphQL/ControllerDiscovery.php',
    ]);
}
