<?php
/**
 * WP Secure Guard Packaging Script
 *
 * Builds a 100% specification-compliant ZIP archive with standard forward slashes (/)
 * ensuring seamless installation on WordPress on all operating systems (Linux, macOS, Windows).
 */

$source_dir = __DIR__ . '/wp-secure-guard';
$zip_file   = __DIR__ . '/wp-secure-guard.zip';

if ( file_exists( $zip_file ) ) {
    unlink( $zip_file );
    echo "Removed previous wp-secure-guard.zip\n";
}

$zip = new ZipArchive();
if ( $zip->open( $zip_file, ZipArchive::CREATE | ZipArchive::OVERWRITE ) !== true ) {
    echo "ERROR: Could not create zip archive: {$zip_file}\n";
    exit(1);
}

$files = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator( $source_dir, RecursiveDirectoryIterator::SKIP_DOTS ),
    RecursiveIteratorIterator::SELF_FIRST
);

$file_count = 0;

foreach ( $files as $file ) {
    $real_path = $file->getRealPath();
    
    // Relative path starting with 'wp-secure-guard/'
    $relative_path = 'wp-secure-guard/' . substr( $real_path, strlen( $source_dir ) + 1 );
    
    // CRITICAL: ZIP specification mandates forward slashes (/) only!
    $zip_path = str_replace( '\\', '/', $relative_path );

    if ( $file->isDir() ) {
        $zip->addEmptyDir( rtrim( $zip_path, '/' ) . '/' );
    } elseif ( $file->isFile() ) {
        $zip->addFile( $real_path, $zip_path );
        $file_count++;
    }
}

$zip->close();

$size_kb = round( filesize( $zip_file ) / 1024, 2 );

echo "=========================================================\n";
echo " WP Secure Guard ZIP Archive Created Successfully!\n";
echo " Path: {$zip_file}\n";
echo " Files Packaged: {$file_count}\n";
echo " Archive Size: {$size_kb} KB\n";
echo " Specification: 100% compliant forward-slash (/) paths\n";
echo "=========================================================\n";
