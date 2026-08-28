<?php
/**
 * evalhook callback. Logs every eval() payload.
 * SANDBOX_MODE=dump  -> do not execute the eval'd code
 * SANDBOX_MODE=observe -> execute after logging
 */
function __eval($code, $file)
{
    $dir = getenv('SANDBOX_LOGS') ?: '/logs';
    if (!is_dir($dir)) {
        @mkdir($dir, 0777, true);
    }
    static $n = 0;
    $n++;
    $dump = sprintf('%s/eval-%04d.php', $dir, $n);
    @file_put_contents($dump, $code);
    $header = sprintf("--- eval #%d @ %s ---\n", $n, $file);
    @file_put_contents($dir . '/eval.log', $header . $code . "\n\n", FILE_APPEND);
    $mode = getenv('SANDBOX_MODE') ?: 'dump';
    if ($mode === 'dump') {
        return false;
    }
}
