<?php
use DigitalOceanV2\Adapter\BuzzAdapter;
use DigitalOceanV2\DigitalOceanV2;

require 'vendor/autoload.php';

/*
*
* TRIVIAL METHODS
*
*/
class dnsAPI {

    protected $IP;
    protected $DB;
    protected $APP;

    function __construct() {
        $this->DB = new MysqliDb (SQL_HOST, SQL_NAME, SQL_PASS, SQL_DB);
        $this->APP = new \Slim\Slim();
        $this->IP = $this->requestIP();
    }

    private function requestIP() {
        $ip = $_SERVER['REMOTE_ADDR'];

        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $ip = $_SERVER['HTTP_CLIENT_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
        }
        return $ip;
    }

    protected function checkBOT() {
        $this->DB->where('IP', $this->IP);
        $results = $this->DB->getOne( SQL_SESSION_TABLE );

        if ( $results !== null) {
            if ( (time() - strtotime( $results["TIME"] )) <= 15 && $results["IP"] ==  $this->IP) {
                return "quota";
            } else {
                $this->DB->where('IP', $this->IP);
                $this->DB->update( "session", array('TIME' => date("Y-m-d H:i:s", time())) );
                return true;
            }
        } else {
            $this->DB->where('IP', $this->IP);
            $this->DB->insert(SQL_SESSION_TABLE, array(
                'IP'  => $this->IP,
                'TIME' => date("Y-m-d H:i:s", time())
            ));
        }

        return false;
    }

}

/*
*
* DigitalOcean METHODS
*
*/
class oceanAPI extends dnsAPI {

    protected $ADAPTER;
    protected $DIGITALOCEAN;
    protected $DOMAINRECORD;
    private   $DATA;
    private   $ID;
    public    $record_name;
    public    $record_domain;

    function __construct() {
        $this->ADAPTER      = new BuzzAdapter( DOPLET_TOKEN );
        $this->DIGITALOCEAN = new DigitalOceanV2($this->ADAPTER);
        $this->DOMAINRECORD = $this->DIGITALOCEAN->domainRecord();
        parent::__construct();
    }

    function run( $record_name, $record_domain ) {

        $return = false;
        $this->record_name = $record_name;
        $this->record_domain = $record_domain;

        if ( !$this->record_check() ) {
            $this->recordCreate();
            $return = "created";
        } else {
            $this->DOMAINRECORD->updateData( $this->record_domain , $this->ID, $this->IP);
            $return = "updated";
        }

        return $return;
    }

    /*
    *
    * METHODS
    *
    */
    private function record_check() {

        $domainRecords = $this->DOMAINRECORD->getAll( $this->record_domain );
        foreach ($domainRecords as $record) {
            if ( $record->type === DOMAIN_RECORD_TYPE && $record->name === $this->record_name ) {
                $this->ID = $record->id;
                $this->DATA = $record->data;
                return true;
            }
        }

        return false;
    }

    private function recordCreate() {
        $record = $this->DOMAINRECORD->create($this->record_domain, DOMAIN_RECORD_TYPE, $this->record_name, $this->IP);
        $this->ID = $record->id;
    }

    public function recordUpload($domain, $subdomain) {
        $return = $this->DOMAINRECORD->create($domain, DOMAIN_RECORD_TYPE, $subdomain, $this->IP);
        return $return->id;
    }

    public function getAllRecords( $filter = true ) {

        $tmp = array();
        foreach ($this->DOMAINRECORD->getAll( DOMAIN ) as $record) {
            $filter = ( $filter ? in_array($record->name, unserialize(SUBDOMAIN_DISABLE)) : false);
            if ( $record->type === DOMAIN_RECORD_TYPE && !$filter ) {
                $i = count($tmp);
                $tmp[$i]["id"]      = $record->id;
                $tmp[$i]["name"]    = $record->name;
                $tmp[$i]["data"]    = $record->data;
            }
        }

        return $tmp;
    }
}

/*
*
* ROUTE METHODS
*
*/
class slimFramwork extends oceanAPI {

    function __construct() {
        parent::__construct();
        $this->slimFramwork();
    }

    function slimFramwork() {

        // CONFIG
        $this->APP->config(array(
            'debug' => false,
            'templates.path' => __DIR__.'/views/'
        ));

        // INDEX PAGE
        $this->APP->get('/', function() {
            $this->APP->render('json.php', array("type" => "json", "return" => array("authentication" => "false")));
        });

        // 404 PAGE
        $this->APP->notFound(function () { });

        // DNS API
        $this->APP->group('/dns', function () {
            $this->APP->group('/auth', function () {

                // LOGIN
                $this->APP->get('/:user/:token', function ($user, $token) {

                    if ( $this->checkBOT() === true ) {
                        $return = array();

                        foreach ($this->DB->get( SQL_TABLE ) as $row) {
                            if ( $token === $row["token"] && $user === $row["username"] ) {
                                if ( $this->IP !== "127.0.0.1" && $this->IP !== $row["current_ip"] ) {
                                    if ($this->run( $row["subdomain"], $row["domain"] ) !== false) {
                                        $this->DB->where('token', $row["token"]);
                                        if ($this->DB->update(SQL_TABLE, array('current_ip' => $this->IP))) {
                                            $return["sql_rewrite"] = true;
                                        } else { $return["sql_rewrite"] = false; }
                                        $return["dns_rewrite"] = true;
                                    } else { $return["dns_rewrite"] = false; }
                                    $return["remote_ip"] = true;
                                } else { $return["remote_ip"] = false; }
                                $return["auth"] = true;
                            } else { $return["auth"] = false; }
                        }

                        if ( !in_array(false, $return) ) {
                            $return = array();
                            $return["successful"] = true;
                        }

                        $this->APP->render('json.php', array("type" => "json", "return" => $return));
                    } else {
                        $this->APP->render('json.php', array("type" => "json", "return" => array("quote_limit" => "true")));
                    }
                });

                // CREATE USER
                $this->APP->get('/:user/:token/create/:newuser/:subdomain(/:domain)', function ($user, $token, $newuser, $subdomain, $domain = DOMAIN) {

                    $logged = $already = false;
                    $newtoken = "";
                    $users = array();

                    foreach ($this->DB->get( SQL_TABLE ) as $row) {
                        if ( $token === $row["token"] && $user === $row["username"] && $row["admin"] === 1 ) { $logged = true; }
                        $users[] = $row;
                    }

                    if ($logged) {
                        foreach ($users as $user) {
                            foreach ($user as $key => $value) {
                                if ( $newuser ===  $user["username"] || $subdomain === $user["subdomain"] || in_array($subdomain, unserialize(SUBDOMAIN_DISABLE)) ) {
                                    $already = true;
                                }
                            }
                        }

                        if ( !$already ) {
                            $token_not_already = true;

                            do {
                                $newtoken = bin2hex(openssl_random_pseudo_bytes(16));
                                foreach ($users as $user) {
                                    foreach ($user as $key => $value) {
                                        if ( $user["token"] === $newtoken ) {
                                            $token_not_already = false;
                                        }
                                    }
                                }
                            } while ($token_not_already !== true);

                            if ($token_not_already) {
                                $record_id = $this->recordUpload($domain, $subdomain);
                                echo "<pre>"; var_dump( $record_id ); echo "</pre>";
                                $this->DB->insert(SQL_TABLE, array(
                                    'username'      => $newuser,
                                    'token'         => $newtoken,
                                    'domain'        => $domain,
                                    'subdomain'     => $subdomain,
                                    'record_id'     => $record_id,
                                    'current_ip'    => $this->IP,
                                    'modify'        => date("Y-m-d H:i:s", time()),
                                    'created'       => date("Y-m-d H:i:s", time())
                                ));
                            }

                        }
                    }

                });

                // REMOVE USER
                $this->APP->get('/:user/:token/remove/:username', function($user, $token, $looser) {

                    $logged = $already = $admin = false;

                    foreach ($this->DB->get( SQL_TABLE ) as $row) {
                        if ( $token === $row["token"] && $user === $row["username"] && $row["admin"] === 1 ) { $logged = true; }
                        if ( $row["username"] === $looser && $row["admin"] === 1 ) { $admin = true; }
                    }

                    if ( $logged && !$admin ) {
                        // GET DROPLET ID
                        $this->DB->where('username', $looser);
                        $rm = $this->DB->getOne(SQL_TABLE);

                        //REMOVE DB RECORD
                        $this->DB->where('username', $looser);
                        $this->DB->delete(SQL_TABLE, $rm["ID"]);

                        //REMOVE DO RECORD
                        $this->DOMAINRECORD->delete(DOMAIN, $rm["record_id"]);
                    }

                });
            });
        });

        $this->APP->run();
    }

}

?>
