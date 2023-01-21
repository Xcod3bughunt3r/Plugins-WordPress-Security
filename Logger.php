<?php


class Logger {

    private static $LOG_FILE = 'vulners-debug.log';

    private static $instances = [];

    protected function __construct() { }

    protected function __clone() { }

    public function __wakeup()
    {
        throw new \Exception("Cannot unserialize a singleton.");
    }

    public static function getInstance(): Logger
    {
        $cls = static::class;
        if (!isset(self::$instances[$cls])) {
            self::$instances[$cls] = new static();

            try {
                if (getenv("_system_type") ===  "Darwin") { // for running tests on Mac
                    self::$LOG_FILE = getcwd().'/'.self::$LOG_FILE;
                } else {
                    self::$LOG_FILE = '/tmp/'.self::$LOG_FILE;
                }
            } catch (Exception $e) {

            }
        }

        return self::$instances[$cls];
    }

    public function debug($message) {
        $message = array_map(function ($i) {
            if (gettype($i)=== "array" or gettype($i) ==="object") {
                return json_encode($i);
            }
            return $i;
        }, func_get_args());

        $message = '['. date("Y-m-d H:i:s") .']  '.implode(" - ", $message). PHP_EOL;
        error_log($message, 3, self::$LOG_FILE);
//        print_r($message);
    }

    public function log($message='') {
        error_log($message.PHP_EOL, 3, self::$LOG_FILE);
    }
}

?>
