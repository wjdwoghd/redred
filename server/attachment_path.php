<?php

/**
 * Resolve a database attachment path against the relocated server directory.
 *
 * New rows store portable `uploads/...` paths. Existing rows may still contain
 * an absolute path from the previous repository layout, so the `uploads/`
 * suffix is remapped to this server directory when the original path no longer
 * exists.
 */
function resolve_attachment_path(string $storedPath): string
{
    $storedPath = trim($storedPath);
    if ($storedPath === '') {
        return '';
    }

    if (file_exists($storedPath)) {
        return $storedPath;
    }

    $normalized = str_replace('\\', '/', $storedPath);
    if (preg_match('~(?:^|/)uploads/(.+)$~i', $normalized, $matches)) {
        return __DIR__ . '/uploads/' . $matches[1];
    }

    return __DIR__ . '/' . ltrim($normalized, '/');
}

