<?php
namespace Application;

function unserialize(string $value): string
{
    return "application:" . $value;
}

echo unserialize("value"), PHP_EOL;
echo \unserialize('s:6:"global";'), PHP_EOL;
