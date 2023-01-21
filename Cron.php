<?php


class Cron {

    public function run() {
        $logger = Logger::getInstance();

        $old_plugin_results = get_option('vulners_plugins_audit_result');
        $plugin_results = vulners_audit_plugins(true);

        $old_os_results = get_option('vulners_os_audit_result');
        $os_results = vulners_audit_os(true);


        // OS Packages
        $new_packages = [];
        try {
            $new_packages = $this -> get_new_packages_cve($os_results, $old_os_results);
        } catch (Exception $exception) {
            $logger->debug($exception);
        }
        $logger->debug('New Vulnerable Packages:');
        $logger->debug($new_packages);
        update_option('vulners_os_audit_last_changes', $new_packages);

        // Plugins
        $new_plugins = [];
        try {
            $new_plugins = $this -> get_new_plugins_cve($plugin_results, $old_plugin_results);
        } catch (Exception $exception) {
            $logger->debug($exception);
        }
        $logger->debug('New Vulnerable Plugins:');
        $logger->debug($new_plugins);
        update_option('vulners_plugins_audit_last_changes', $new_plugins);

        // TODO: send updates only for new findings, implement comparison
        if (count($new_plugins) or count($new_packages)) {
            $this->send_email_update();
        }
    }

    /**
     * @param $os_results
     * @param $old_os_results
     * @return array
     */
    function get_new_packages_cve($os_results, $old_os_results) {

        $logger = Logger::getInstance();
        $new_os_results = [];

        $os_results = json_decode(json_encode($os_results), FALSE);
        $old_os_results = json_decode(json_encode($old_os_results), FALSE) -> res;

        if (!$old_os_results -> audit_res) {
            $new_os_results = $os_results;
            return $new_os_results;
        }
        foreach($os_results -> audit_res as $new_package => $new_package_value) {
            if ($new_package === 'all_cve') {
                continue;
            }
            if (!count($new_package_value -> cve)) {
                $logger->debug('[New Package] not vulnerable: '.$new_package);
                continue;
            }
            if (!property_exists( $old_os_results -> audit_res, $new_package)) {
                $logger->debug('[New Package] with vulnerabilities: '.$new_package);
                array_push($new_os_results, $this->cve_to_flat_data($new_package, $new_package_value->cve, $os_results -> cve_info));
            }

            $old_package_value = $old_os_results -> audit_res -> $new_package;
            $new_cve = [];
            foreach ($new_package_value -> cve as $cve) {
                if (!array_search($cve, $old_package_value -> cve ?? [])) {
                    $logger->debug('[New Package] vulnerabilities in package: '.$new_package.' - '.$cve);
                    array_push($new_cve, $cve);
                    continue;
                }
            }
            if (count($new_cve)) {
                array_push(
                    $new_os_results,
                    $this->cve_to_flat_data($new_package, $new_cve, $os_results -> cve_info));
            }
        }

        usort($new_os_results, array('Cron', 'sort_by_score'));
        return $new_os_results;
    }

    /**
     * @param $plugin_results
     * @param $old_plugin_results
     * @return mixed
     */
    function get_new_plugins_cve($plugin_results, $old_plugin_results) {
        $logger = Logger::getInstance();
        $new_plugin_results = [];

        $plugin_results = json_decode(json_encode($plugin_results), FALSE);
        $old_plugin_results = json_decode(json_encode($old_plugin_results), FALSE) -> res;

        if (!$old_plugin_results -> plugin_res) {
            $new_plugin_results = $plugin_results;
            return $new_plugin_results;
        }
        foreach($plugin_results -> plugin_res as $plugin) {

            if (!count($plugin -> id)) {
                $logger->debug('[New Plugin] not vulnerable: '.$plugin -> package);
                continue;
            }

            $find_plugin = function ($p) use(&$plugin) { return $plugin -> package === $p->package; };
            $old_plugin = array_filter($old_plugin_results -> plugin_res, $find_plugin);

            if (!$old_plugin and count($plugin->id)){
                $logger->debug('[New Plugin] with vulnerabilities: ' . json_encode($plugin));
                array_push($new_plugin_results, $this->cve_to_flat_data($plugin->package.'-'.$plugin->version, $plugin->id, $plugin_results->vuln_info));
                continue;
            }

            $new_cve = [];
            foreach ($plugin -> id as $cve) {
                if (!array_search($cve, $old_plugin -> id)) {
                    $logger->debug('[New Plugin] vulnerabilities in package: ' . json_encode($plugin));
                    array_push($new_cve, $cve);
                    continue;
                }

            }
            if (count($new_cve)) {
                array_push($new_plugin_results, $this->cve_to_flat_data($plugin->package.'-'.$plugin->version, $new_cve, $plugin_results->vuln_info));
            }
        }

        usort($new_plugin_results, array('Cron', 'sort_by_score'));
        return $new_plugin_results;
    }

    /**
     * @param $package
     * @param $cve_list
     * @param $cve_info
     * @return object
     */
    function cve_to_flat_data($package, $cve_list, $cve_info) {
        $max_severity_cve = null;
        foreach ($cve_list as $cve) {
            $cve = $cve_info -> $cve;
            if (!$max_severity_cve) {
                $max_severity_cve = $cve;
            } elseif ($max_severity_cve -> score < $cve -> score ) {
                $max_severity_cve = $cve;
            }
        }
        return (object)[
            'name' => $package,
            'cve'  => $cve_list,
            'max_cve' => $max_severity_cve
        ];
    }

    /**
     * @param $packageA
     * @param $packageB
     * @return int
     */
    static function sort_by_score($packageA, $packageB) {
        if ($packageA->max_cve->score == $packageB->max_cve->score) {
            return 0;
        }
        return ($packageA->max_cve->score > $packageB->max_cve->score) ? -1 : 1;
    }

    /**
     *
     */
    function send_email_update()
    {
        $template_path = '';
        if (getenv("_system_type") === "Darwin") {
            $template_path = getcwd().'/templates/report.php';
        } else {
            $email = !get_option('VULNERS_EMAIL') ? get_option('admin_email') : get_option('VULNERS_EMAIL') ;
            $template_path = plugin_dir_path(__FILE__).'/templates/report.php';
        }

        $message = include $template_path;

        apply_filters( 'wp_mail_content_type', 'text/html' );
        wp_mail($email, "[Vulners WP Scanner] New vulnerabilities found", $message);
        apply_filters( 'wp_mail_content_type', 'text/plain');
    }

}