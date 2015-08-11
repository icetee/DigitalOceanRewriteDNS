<?php

if ( $this->data["type"] == "json" ) {
    header('Content-Type: application/json');
    echo json_encode(  $this->data["return"] );
}

?>
