<?php
/**
 * @package vulners-scanner
 * @version 1.2
 */
/*
Plugin Name: Vulners Scanner
Plugin URI: http://vulners.com
Description: Vulners WordPress and OS Security Scanner. Finds vulnerabilities in OS packages and installed WP-plugins using Vulners scanner API. To get started: activate the Vulners plugin and then go to Vulners Settings page to set up your API key.
Author: Vulners.com team
Version: 1.2
Author URI: https://profiles.wordpress.org/vulnersdevelopers/
*/

if ( !function_exists( 'add_action' ) ) {
    echo 'Hi there!  I\'m just a plugin, not much I can do when called directly.';
    exit;
}

if (defined('VULNERS_PLUGIN_VERSION'))
{
    // already included for some reason
    exit;
}

define('VULNERS_PLUGIN_VERSION', '1.2');


class VulnersConfig
{
    const AUDIT_CMD = [
        'rpm' => "rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n'",
        'deb' => <<<'XML'
    dpkg-query -W -f='${Status} ${Package} ${Version} ${Architecture}\n'|awk '($1 == "install") && ($2 == "ok") {print   $4" "$5" "$6}'
    XML
    ];
    const AUDIT_URL = "https://vulners.com/api/v3/audit/audit/";
    const PLUGIN_AUDIT_URL = "https://vulners.com/api/v3/burp/packages/";
    const CVE_URL = "https://vulners.com/api/v3/search/id/";
    const SUPPORTED_OS_URL = "https://vulners.com/api/v3/agent/supported/";

    public static function getSupportedOS()
    {
        try
        {
            $resp = wp_remote_get(self::SUPPORTED_OS_URL);
        } catch(Exception $e)
        {
            exit;
        }

        if(wp_remote_retrieve_response_code($resp) !== 200)
        {
            exit;
        }

        $body = json_decode(wp_remote_retrieve_body($resp), true);
        if ($body && $body['result'] === "OK") {
            return $body['data']['supported'] ?? [];
        }
        else
        {
            return [];
        }

    }
}

include 'Cron.php';
include 'Logger.php';

//----------------------------get CVE info------------
//----------------------------------------------------
function vulners_get_cve_info($cvelist = [])
{
    $body = json_encode([
            "id" => $cvelist,
            "apiKey" => get_option("VULNERS_API_KEY")
    ]);

    $headers = array(
            'Content-type' => 'application/json',
            'User-agent' => 'vulners-wordpress/' . VULNERS_PLUGIN_VERSION
    );
    $args = array(
        'body'        => $body,
        'timeout'     => '5',
        'redirection' => '5',
        'httpversion' => '1.1',
        'blocking'    => true,
        'headers'     => $headers,
        'cookies'     => array(),
    );
    try {
        $res = wp_remote_post(VulnersConfig::CVE_URL, $args);
    } catch (Exception $e) {
        throw $e;
    }
    if(wp_remote_retrieve_response_code($res) !== 200)
    {
        throw new Exception("Error Processing Request", 1);
    }
    $cve_info = vulners_parse_cve_response(wp_remote_retrieve_body($res));

    return $cve_info;
}

function vulners_parse_cve_response($resp = '')
{
    $resp = json_decode($resp, true);
    if(!$resp || $resp["result"] != "OK")
    {
        throw new Exception("Error Processing Request", 1);
    }
    $cve_info = array();
    foreach ($resp['data']['documents'] ?? [] as $cve => $info) {
        $score = ($info['cvss'] ?? [])['score'];
        $vulnersScore = ($info['enchantments'] ?? [])['vulnersScore'];
        $title = $info['title'];
        $severity = $info['cvss2'] ? $info['cvss2']['severity'] : [];

        $cve_info[$cve] = [
            "score" => $score,
            "vulnersScore" => $vulnersScore,
            "title" => $title,
            "severityText" => $severity
        ];
    }

    return $cve_info;
}
//-------------------end of get CVE info--------------
//----------------------------------------------------


//--------------------audit OS packages---------------
//----------------------------------------------------
function vulners_audit_os_request($osname = '', $osversion = '', $packages = array())
{
    $body = json_encode(array(
        'os' => $osname,
        'version' => $osversion,
        'package' => $packages,
        'apiKey' => get_option("VULNERS_API_KEY")
    ));
    $headers = array(
            'Content-type' => 'application/json',
            'User-agent' => 'vulners-wordpress/' . VULNERS_PLUGIN_VERSION
    );
    $args = array(
        'body'        => $body,
        'timeout'     => '5',
        'redirection' => '5',
        'httpversion' => '1.1',
        'blocking'    => true,
        'headers'     => $headers,
        'cookies'     => array(),
    );

    $res = wp_remote_post(VulnersConfig::AUDIT_URL, $args);
    if(wp_remote_retrieve_response_code($res) !== 200)
    {
        throw new Exception("Error Processing Request", 1);
    }
    $result = vulners_parse_audit_response(wp_remote_retrieve_body($res));

    $invuln_pkgs = array_filter($packages, function($pkg){return !isset($result['audit_res'][$pkg]);});
    $result['safe_packages'] = $invuln_pkgs;

    return $result;
}

function vulners_parse_audit_response($resp = '')
{
    $resp = json_decode($resp, true);
    if(!$resp || $resp["result"] != "OK")
    {
        throw new Exception("Error Processing Request", 1);
    }
    $vuln_info = array();
    $all_cve = [];
    foreach (($resp['data']['packages'] ?? []) as $pkg_name => $pkg_info) {
        $cvelist = [];
        foreach ($pkg_info as $vuln_name => $desc) {
            array_push($cvelist, array_merge(...array_map(function($x){return $x['cvelist']??[];}, $desc)));
        }
        $cvelist = array_unique(array_merge(...$cvelist));
        if(count($cvelist))
        {
            $vuln_info[$pkg_name] = [
                "cve" => $cvelist
            ];
            $all_cve = array_merge($all_cve, $cvelist);
        }
    }

    // because of array_unique array_unique([1,2,2,4]) would turn into {"0":1,"1":2,"3":4}
    // but we need a flat pure list here
    $vuln_info['all_cve'] = array_values($all_cve);

    return ["audit_res"=>$vuln_info, "cumulativeFix"=>$resp['data']['cumulativeFix'] ?? ''];
}

function vulners_get_os_release()
{
    if(defined(PHP_OS) && substr(PHP_OS, 0, 3) === "WIN")
    {
        return ["win", null];
    }
    // else we will hope it is Linux
    if(is_readable("/etc/os-release"))
    {
        $release = file_get_contents("/etc/os-release");
        $info = array_merge(...array_map(
            function($s){$t = explode('=', $s); return [$t[0]=>$t[1]];},
            explode("\n", trim($release))
        ));
        return ['os' => $info["ID"], 'version' => trim($info["VERSION_ID"], '"')];
    }
}

function vulners_audit_os($update = true)
{
    $vuln_audit_result = get_option('vulners_os_audit_result') ?? [];
    if(!$update && isset($vuln_audit_result['res']))
    {
        $result = $vuln_audit_result['res'];
        $audit_res = $result['audit_res'];
        $cve_info = $result['cve_info'];
        $cumulativeFix = $result["cumulativeFix"];
        $invuln_pkgs = $result['safe_packages'];
    }
    else
    {
        $os_info = vulners_get_os_release();
        $supported = VulnersConfig::getSupportedOS();
        if(!$supported[$os_info['os']])
        {
            return [];
        }

        $cmd = VulnersConfig::AUDIT_CMD[$supported[$os_info['os']]['packager']];
        $out = null;

        # TODO[gmedian]: add logging

        try {
            exec($cmd, $out);
            $result = vulners_audit_os_request($os_info['os'], $os_info['version'], $out);
        } catch (Exception $e) {
            return [];
        }

        $audit_res = $result["audit_res"];
        $cumulativeFix = $result["cumulativeFix"];
        $invuln_pkgs = $result['safe_packages'];

        try {
            $cve_info = vulners_get_cve_info($audit_res['all_cve']);
        } catch (Exception $e) {
            return [];
        }

        $vuln_audit_result['res'] = ['audit_res'=>$audit_res, 'cve_info'=>$cve_info, "cumulativeFix"=>$cumulativeFix, "safe_packages"=>$invuln_pkgs];
        $vuln_audit_result['os_last_scan'] = date('Y-m-d H:i:s');
        update_option('vulners_os_audit_result', $vuln_audit_result);
    }

    return ["audit_res"=>$audit_res, "cve_info"=>$cve_info, "cumulativeFix"=>$cumulativeFix, "safe_packages"=>$invuln_pkgs];
}

function vulners_audit_req_os()
{
    check_ajax_referer( 'vulners_run_audit', 'nonce' );

    $is_update = strval($_POST['update'])=='true' ? true : false ;

    $API_KEY = get_option("VULNERS_API_KEY");
    if (!$API_KEY) {
        return wp_send_json(['error' => 'Vulners API key not found', 'key' => get_option('VULNERS_API_KEY')], 403);
    }

    $result = vulners_audit_os($is_update);

    wp_send_json(["pkg_res"=>$result["audit_res"] ?? [], "cve_info"=>$result["cve_info"] ?? [], "cumulativeFix"=>$result["cumulativeFix"] ?? "", "safe_packages"=>$result['safe_packages'] ?? []], 200);
}

//------------------end of audit OS packages----------
//----------------------------------------------------

//------------------audit plugins---------------------
//----------------------------------------------------
function vulners_audit_plugins_request($plugins_info = [])
{

    $packages = [];
    foreach ($plugins_info as $p_info) {
        $version = $p_info["version"] ?? "";
        $name = $p_info["name"] ?? "";
        $text = $p_info["TextDomain"] ?? "";
        $packages[] = [
            "software" => $text ?? $name,
            "version" => $version
        ];
    }

    $body = json_encode(array(
        'os' => "",
        'osVersion' => "",
        'packages' => $packages,
        'apiKey' => get_option("VULNERS_API_KEY")
    ));
    $headers = array(
            'Content-type' => 'application/json',
            'User-agent' => 'vulners-wordpress/' . VULNERS_PLUGIN_VERSION
    );
    $args = array(
        'body'        => $body,
        'timeout'     => '5',
        'redirection' => '5',
        'httpversion' => '1.1',
        'blocking'    => true,
        'headers'     => $headers,
        'cookies'     => array(),
    );

    $resp = wp_remote_post(VulnersConfig::PLUGIN_AUDIT_URL, $args);
    if(wp_remote_retrieve_response_code($resp) !== 200)
    {
        throw new Exception("Error Processing Request", 1);
    }

    $resp = json_decode(wp_remote_retrieve_body($resp), true);
    if(!$resp || $resp["result"] != "OK")
    {
        throw new Exception("Error Processing Request", 1);
    }

    $vulns = $resp["data"]["vulnerabilities"] ?? [];
    $vulns_map = [];
    foreach ($vulns as $vuln) {
        $vulns_map[$vuln['package']] = $vuln;
    }

    $vulns_and_packages = array_map(function($plugin) use ($vulns_map){
        return [
            'id'=> $vulns_map[$plugin['TextDomain']]['id'] ?? [],
            'package'=> $plugin['TextDomain'],
            'version'=> $plugin['version'],
            'name'=> $plugin['name'],
        ];
    }, $plugins_info);

    $cvelist = array_unique(array_merge(...array_map(function($x){return $x["id"];}, $vulns_and_packages)));

    try {
        $cve_info = vulners_get_cve_info($cvelist);
    } catch (Exception $e) {
        throw $e;
    }

    return ["plugin_res"=>$vulns_and_packages, "vuln_info"=>$cve_info];

}


// TODO[gmedian]: do not send empty responses
function vulners_audit_plugins($update = true)
{   
    $vuln_audit_result = get_option('vulners_plugins_audit_result') ?? [];
    if(!$update && isset($vuln_audit_result['res']))
    {
        $result = $vuln_audit_result['res'];
    }
    else
    {
        if ( ! function_exists( 'get_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $all_plugins = get_plugins();

        $plugins_info = [];
        foreach ($all_plugins as $name => $p_info) {
            $plugins_info[] = ["name" => $p_info["Name"], "version" => $p_info["Version"], "TextDomain" => $p_info["TextDomain"]];
        }


        # TODO[gmedian]: divide into active and not
        # TODO[gmedian]: add logging

        try {
            $result = vulners_audit_plugins_request($plugins_info);
        } catch (Exception $e) {
            Logger::getInstance() -> debug('[AUDIT]', $e);
            return [];
        }

        $vuln_audit_result['res'] = $result;
        $vuln_audit_result['plugins_last_scan'] = date('Y-m-d H:i:s');
        update_option('vulners_plugins_audit_result', $vuln_audit_result);
    }

    return $result;

}

function vulners_audit_req_plugins()
{
    check_ajax_referer( 'vulners_run_audit', 'nonce' );

    $is_update = strval($_POST['update'])=='true' ? true : false ;

    $API_KEY = get_option("VULNERS_API_KEY");
    if (!$API_KEY) {
        return wp_send_json(['error' => 'Vulners API key not found', 'key' => get_option('VULNERS_API_KEY')], 403);
    }

    $result = vulners_audit_plugins($is_update);

    wp_send_json($result, 200);
}
//-----------------end of audit plugins---------------
//----------------------------------------------------

//-----------------get the last scan time-------------
//----------------------------------------------------
function vulners_get_last_scan_time()
{
    check_ajax_referer( 'vulners_run_audit', 'nonce' );

    $vuln_os_audit_result = get_option('vulners_os_audit_result') ?? [];
    $vuln_plugins_audit_result = get_option('vulners_plugins_audit_result') ?? [];

    $result = ["os"=>$vuln_os_audit_result['os_last_scan']??'', "plugins"=>$vuln_plugins_audit_result['plugins_last_scan']??''];

    wp_send_json($result, 200);
}
//-----------------end of last scan time--------------
//----------------------------------------------------

add_action("wp_ajax_vulners_audit_os", "vulners_audit_req_os");
add_action("wp_ajax_vulners_audit_plugins", "vulners_audit_req_plugins");
add_action("wp_ajax_vulners_get_last_scans", "vulners_get_last_scan_time");


//----------------setting section---------------------
//----------------------------------------------------

function vulners_settings_init() {
    register_setting('vulners-settings', 'VULNERS_API_KEY', ["type"=>"string", "default"=>'']);
    register_setting('vulners-settings', 'VULNERS_EMAIL', ["type"=>"string", "default"=>'']);



    add_settings_section(
        'vulners_settings_section',
        '', 'vulners_settings_section_callback',
        'vulners-settings'
    );


    add_settings_field(
        'VULNERS_API_KEY',
        'Vulners Api Key', 'vulners_settings_key_callback',
        'vulners-settings',
        'vulners_settings_section'
    );

    add_settings_field(
        'VULNERS_EMAIL',
        'Email for updates', 'vulners_settings_email_callback',
        'vulners-settings',
        'vulners_settings_section'
    );

}


add_action('admin_init', 'vulners_settings_init');

/**
 * callback functions
 */

// section content callback
function vulners_settings_section_callback($args) {
    echo '<p>
        Vulners scanner finds vulnerabilities in your OS and installed plugins. <br/>
        Current plugin requires API key that you can find at vulners.com in user-profile section <a href="https://vulners.com/api-keys" target="_blank">Get API Key</a>  <br/>
        It also requires an email to notify you about new findings.
    </p>';
    if (get_option('VULNERS_API_KEY')) {
        echo '<p>To see and manage scan results follow <a href="/wp-admin/admin.php?page=vulners-plugin/scanner.php">Scanner page</a></p>';
    }
}

// field content cb
function vulners_settings_key_callback($args) {
    // get the value of the setting we've registered with register_setting()
    $setting = get_option('VULNERS_API_KEY');
    ?>
    <input type="text" name="VULNERS_API_KEY" value="<?php echo isset( $setting ) ? esc_attr( $setting ) : ''; ?>">
    <?php
}

function vulners_settings_email_callback($args) {
    // get the value of the setting we've registered with register_setting()
    $setting = get_option('VULNERS_EMAIL');
    ?>
    <input type="text" name="VULNERS_EMAIL" value="<?php echo isset( $setting ) ? esc_attr( get_option('admin_email') ) : ''; ?>">
    <?php
}


// Add main menu page
add_action( 'admin_menu', 'vulners_page' );

function vulners_page() {
    add_menu_page(
        'Vulners Scanner',
        'Vulners Scanner',
        'manage_options',
        plugin_dir_path(__FILE__) . 'scanner.php',
        null,
        plugin_dir_url(__FILE__) . 'static/icon-20x20.svg',
        30
    );
//    add_menu_page(  // For Debugging report Page
//        'Vulners TEST',
//        'Vulners TEST',
//        'manage_options',
//        plugin_dir_path(__FILE__) . 'templates/report.php',
//        null,
//        plugin_dir_url(__FILE__) . 'static/icon-20x20.svg',
//        30
//    );

    add_action( 'admin_enqueue_scripts', 'vulners_enqueue_script');
}


function vulners_enqueue_script($hook='') {

    wp_enqueue_script( 'vulners-js', plugin_dir_url(__FILE__) .'/frontend/dist/main.js' );

    wp_localize_script(
        'vulners-js',
        'vulners_js_obj',
        array(
            'ajax_url' => admin_url( 'admin-ajax.php' ),
            'nonce'    => wp_create_nonce( 'vulners_run_audit' ),
        )
    );
}


add_action( 'admin_menu', 'vulners_options_page' );

function vulners_options_page() {
    add_submenu_page(
        plugin_dir_path(__FILE__) . 'scanner.php',
        'Vulners Scanner - settings',
        'Vulners Settings',
        'manage_options',
        'vulners-settings',
        'vulners_options_page_html'
    );
}

function vulners_options_page_html() {
    ?>
    <div class="wrap">
        <h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
        <form action="options.php" method="post">
            <?php
            settings_fields( 'vulners-settings' );
            // output setting sections and their fields
            do_settings_sections( 'vulners-settings' );
            // output save settings button
            submit_button( __( 'Save Settings', 'textdomain' ) );
            ?>
        </form>
    </div>
    <?php
}


//-----------------end settings section------------
//-------------------------------------------------


//------------------vulners admin page-------------
//-------------------------------------------------
// Shows attention if Vulners API key not set
add_action( 'admin_notices', 'hello_vulners' );

function hello_vulners() {
    $lang = '';
    if ( 'en_' !== substr( get_user_locale(), 0, 3 ) ) {
        $lang = ' lang="en"';
    }

    if (!get_option('VULNERS_API_KEY')) {
        echo '<div class="update-nag notice notice-error inline">In order to use <b>Vulners WP Scanner</b> please add your API key in <a href="/wp-admin/admin.php?page=vulners-settings">plugin settings</a></div>';
    }

    # TODO: check for failed starts due to lack of API key
    if ( ! wp_next_scheduled( 'vulners_cron_hook' ) && get_option('VULNERS_API_KEY') !== '') {
        wp_schedule_event( time(), 'four_hours', 'vulners_cron_hook' );
    }
}

//------------------end vulners admin page---------
//-------------------------------------------------


add_filter( 'cron_schedules', 'vulners_add_cron_interval' );
function vulners_add_cron_interval( $schedules ) {
    $schedules['four_hours'] = array(
        'interval' => 4*60*60,
//        'interval' => 4*60,
        'display'  => esc_html__( 'Every Four Hours' ), );
    return $schedules;
}

add_action('vulners_cron_hook', 'vulners_cron_exec');
function vulners_cron_exec() {
    $cron = new Cron();
    $cron -> run();
}

//--------------plugin (de-)activation-------------
//-------------------------------------------------
register_activation_hook( __FILE__, 'vulners_activate');
function vulners_activate() {
    add_action('admin_init', 'vulners_settings_init');
    add_option('vulners_os_audit_result', array());
    add_option('vulners_plugins_audit_result', array());

    add_option('vulners_os_audit_last_changes', array());
    add_option('vulners_plugins_audit_last_changes', array());
}

register_deactivation_hook( __FILE__, 'vulners_deactivate');
function vulners_deactivate() {
    unregister_setting('vulners-settings', 'VULNERS_API_KEY');
    unregister_setting('vulners-settings', 'VULNERS_EMAIL');
    delete_option('VULNERS_API_KEY');
    delete_option('VULNERS_EMAIL');
    delete_option('vulners_os_audit_result');
    delete_option('vulners_plugins_audit_result');
    delete_option('vulners_audit_result');
    delete_option('vulners_os_audit_last_changes');
    delete_option('vulners_plugins_audit_last_changes');

    $timestamp = wp_next_scheduled( 'vulners_cron_hook' );
    wp_unschedule_event( $timestamp, 'vulners_cron_hook' );
}
//---------------end plugin activation-------------
//-------------------------------------------------
