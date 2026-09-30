<?php

/*
 * Construit irundoo-index.json à partir de extensions/<id>/manifest.json, incrémente `serial`,
 * signe l'index (Ed25519) et vérifie la signature avec source.pub.
 *
 * Clé secrète (base64, 64 octets) : variable IRUNDO_INDEX_SECRET_KEY, sinon le fichier désigné
 * par IRUNDO_INDEX_SECRET_KEY_FILE (défaut : ~/.config/irundoo-extensions/secret.key).
 * La clé ne va jamais dans le dépôt.
 *
 * Usage : php scripts/publish.php [--init-key]
 *   --init-key : génère la paire de clés si le fichier de clé n'existe pas, et écrit source.pub.
 */

$root = dirname(__DIR__);
$keyFile = getenv('IRUNDO_INDEX_SECRET_KEY_FILE') ?: getenv('HOME').'/.config/irundoo-extensions/secret.key';

function fail(string $message): never
{
    fwrite(STDERR, "Erreur : {$message}\n");
    exit(1);
}

if (in_array('--init-key', $argv, true)) {
    if (file_exists($keyFile)) {
        fail("{$keyFile} existe déjà : une clé publiée ne se remplace pas (voir README).");
    }
    @mkdir(dirname($keyFile), 0700, true);
    $pair = sodium_crypto_sign_keypair();
    file_put_contents($keyFile, base64_encode(sodium_crypto_sign_secretkey($pair)).PHP_EOL);
    chmod($keyFile, 0600);
    file_put_contents("{$root}/source.pub", base64_encode(sodium_crypto_sign_publickey($pair)).PHP_EOL);
    echo "Clé générée dans {$keyFile}, source.pub écrit.\n";
}

$secret = getenv('IRUNDO_INDEX_SECRET_KEY') ?: (is_readable($keyFile) ? trim(file_get_contents($keyFile)) : '');
$secret = base64_decode($secret, true);
if ($secret === false || strlen($secret) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
    fail('clé secrète absente ou illisible (IRUNDO_INDEX_SECRET_KEY ou '.$keyFile.').');
}

$publicKey = base64_decode(trim((string) @file_get_contents("{$root}/source.pub")), true);
if ($publicKey === false || $publicKey !== sodium_crypto_sign_publickey_from_secretkey($secret)) {
    fail('source.pub ne correspond pas à la clé secrète.');
}

$extensions = [];
$paths = glob("{$root}/extensions/*/manifest.json");
sort($paths);
foreach ($paths as $path) {
    $manifest = json_decode(file_get_contents($path), true, 64, JSON_THROW_ON_ERROR);
    $dir = basename(dirname($path));
    if (($manifest['id'] ?? null) !== $dir) {
        fail("{$path} : l'id du manifeste doit être le nom du dossier ({$dir}).");
    }
    $extensions[] = $manifest;
}

$indexPath = "{$root}/irundoo-index.json";
$previous = is_readable($indexPath) ? json_decode(file_get_contents($indexPath), true) : null;
$serial = max(time(), (int) ($previous['serial'] ?? 0) + 1);

$index = [
    'format' => 'irundoo-extensions-index',
    'version' => 1,
    'serial' => $serial,
    'name' => 'Extensions IRUNDO',
    'publisher' => 'Henri Touchard',
    'extensions' => $extensions,
];

$bytes = json_encode($index, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR).PHP_EOL;
$signature = sodium_crypto_sign_detached($bytes, $secret);

if (! sodium_crypto_sign_verify_detached($signature, $bytes, $publicKey)) {
    fail('la signature produite ne vérifie pas.');
}

file_put_contents($indexPath, $bytes);
file_put_contents("{$indexPath}.sig", base64_encode($signature).PHP_EOL);

$fingerprint = implode('-', str_split(substr(hash('sha256', $publicKey), 0, 16), 4));
echo "Index publié : serial {$serial}, ".count($extensions)." extension(s), clé sha256:{$fingerprint}.\n";
