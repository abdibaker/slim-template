<?php
if ($_SERVER['REQUEST_URI'] === '/') {
  header('Location: /status');
  exit;
}
if (file_exists($_SERVER['DOCUMENT_ROOT'] . $_SERVER['REQUEST_URI'])) {
  return false;
} else {
  include_once 'index.php';
}
