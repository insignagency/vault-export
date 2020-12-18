#!/usr/bin/env php
<?php
/**
 * Exports vault kv secrets as json file and encrypts it.
 * php version 7.*
 */

$debug = false;
$passwordFileGiven = "";
// Eclude some secret engines
$secret_engines_excluded = array("cubbyhole", "identity", "sys");
$exportFilePath = "./export.json";

if (false !== strpos(implode(" ", $argv), "-d")) {
  $debug = true;
};

if (0 !== preg_match("|-p ([^ ]+)|", implode(" ", $argv), $macthes)) {
  $passwordFileGiven = $macthes[1];
};

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin
   1 => array("pipe", "w"),  // stdout
   2 => array("pipe", "w"),  // stderr
);

/**
 * Log msg in file.
 *
 * @param string $msg string to log
 * 
 * @return null
 */ 
function logInErr($msg)
{
    file_put_contents("./out.err", "\n" . $msg, FILE_APPEND);
}

function encryptFile ()
{
    global $passwordFileGiven;
    global $exportFilePath;
    if("" != $passwordFileGiven) {
      $perm = fileperms($passwordFileGiven);
      $permOct = substr(sprintf('%o', $perm ), -4);
      if("0600" !=$permOct) {
        die($passwordFileGiven . ": file permissions are too open, should be 600, got " . $permOct);
      }
      $passwordFile = $passwordFileGiven;
    } else {
      echo "Give a password to encrypt exported file: ";
      $pwd = stream_get_line(STDIN, 1024, PHP_EOL);
      $passwordFile = "./.temp";
      file_put_contents($passwordFile, $pwd);
    }
    process("openssl enc -in export.json -aes-256-cbc -md md5 -kfile " . $passwordFile. " > " . $exportFilePath . ".encrypted");
    if ("" == $passwordFileGiven) {
      unlink($passwordFile);
    }

    printf ("%s\n", "Export file has been encrypted, to decrypt it whith prompted asking password : ");
    printf ("%s\n", "openssl enc -in " . $exportFilePath . ".encrypted -d -aes-256-cbc -md md5 -pass stdin > " . $exportFilePath);
    printf ("%s\n", "To decrypt it giving a password file : ");
    printf ("%s\n", "openssl enc -in " . $exportFilePath . ".encrypted -d -aes-256-cbc -md md5 -kfile [path-to-password-file] > " . $exportFilePath);

}
/**
 * Launch shell process.
 *
 * @param string $cmd shell command to execute
 * 
 * @return array 
 */ 
function process($cmd)
{
    global $descriptorspec;
    global $debug;
    if ($debug) {
        echo "=> Executing: " . $cmd . "\n";
    }
    
    $process = proc_open($cmd, $descriptorspec, $pipes, dirname(__FILE__), null);
    $stdout = stream_get_contents($pipes[1]); fclose($pipes[1]);
    $stderr = stream_get_contents($pipes[2]); fclose($pipes[2]);
    return array("stdout" => $stdout, "stderr" => $stderr);
}

/**
 * Launch shell process.
 *
 * @param array $proc results returned by process function
 * 
 * @return boolean 
 */ 
function valueExists($proc)
{
    if (preg_match("|No value found|", $proc["stderr"])) {
        return false;
    } elseif ($proc["stderr"] != "") {
        logInErr($proc["stderr"]);
        return false;
    } else { 
        return true;
    }
}

/**
 * Discover all paths.
 *
 * @param string $path the vault path to check
 * 
 * @return boolean 
 */ 
function recurseInPath($path)
{
    global $secrets;
    $proc = process("vault kv list " . $path . "|sed '1d;2d'");
    if (preg_match("|No value found|", $proc["stderr"])) {
        return false;
    } elseif ($proc["stderr"] != "") {
        logInErr($proc["stderr"]);
        return false;
    } else {
        foreach (explode("\n", $proc["stdout"]) as $pathFound) {
            if ($pathFound == "") { 
                continue; 
            }
            $proc = process("vault kv get -field data -format json " . $path . "/" . $pathFound);
            if (valueExists($proc)) {
                $secrets[$path . $pathFound] = ["secrets" => $proc["stdout"]];
            }
            recurseInPath($path . $pathFound);
        }
    }
}

if ($debug) {
    echo "Working with vault instance at " . getenv("VAULT_ADDR") . "\n";
}

$proc = process("vault secrets list |sed '1d;2d' |cut -d '/' -f1 |grep -v -E '".implode("|", $secret_engines_excluded)."'");
$secrets_engines = explode("\n", $proc["stdout"]);
$secrets = array();

foreach ($secrets_engines as $secrets_engine) {
    if ($secrets_engine == "") { 
        continue; 
    }
    recurseInPath($secrets_engine . "/");
}

if ($debug) {
  var_dump($secrets);
}

file_put_contents($exportFilePath, json_encode($secrets, JSON_PRETTY_PRINT));
encryptFile();
unlink($exportFilePath);

if ($proc["stderr"] != "") {
    echo "\nERR: ".$proc["stderr"];
    logInErr($proc["stderr"]);
}

