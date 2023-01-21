=== Vulners Scanner ===
Contributors: vulnersdevelopers
Donate link: https://example.com/
Tags: vulnerability assessment, external
Tested up to: 5.8
Stable tag: 1.2
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

This is a WordPress plugin using Vulners service. It helps one to find vulnerabilities in OS packages and installed WP-plugins using Vulners scanner API. To get started: activate the Vulners plugin and go to Vulners Settings page to set up your API key.

#### Please Check [My API Key](vulners.com.md) For You.

== Description ==

Automatically check your vulnerabilities in your WP plugins, web server and get a fix which can be installed using one bash command. This plugin helps you dramatically improve the security of your website and save time on security updates.

This plugin is based on [Vulners.com](https://vulners.com/?utm_campaign=Wordpress%20plugin&utm_source=wordpress%20&utm_medium=plugin%20page%20desc)  Database and [Scanner API](https://docs.vulners.com/api/?utm_campaign=Wordpress%20plugin&utm_source=wordpress%20&utm_medium=plugin%20page%20desc).

**NOTE:** To use the plugin it is required to have a valid Vulners API key. To obtain one, please signup at [Vulners.com](https://vulners.com/?utm_campaign=Wordpress%20plugin&utm_source=wordpress%20&utm_medium=plugin%20page%20desc) and follow the guide at [docs.vulners.com](https://docs.vulners.com/api/?utm_campaign=Wordpress%20plugin&utm_source=wordpress%20&utm_medium=plugin%20page%20desc). You can also read the Vulners [EULA](https://vulners.com/static/docs/eula.pdf).

### Features
 * OS scanner – get information about vulnerabilities in OS packages with a simple command to fix themhem
 * Cumulative fix – generate bash command to fix vulnerable OS packages
 * WP plugin scanner – get information about vulnerabilities in installed plugins
 * Email notifications about new vulnerabilities based on your OS Environment and plugins
 * Scheduled scans keep you up to date with new vulnerabilities and are run every 4 hours


### Usage notes 
 * Install the plugin and activate it as usual
 * Add your vulners API key at the settings page (a warning will be visible at the top of admin menu until you do so) so)
 * Your first scan would be scheduled to run immediately. Others would be scheduled every 4 hours from now on
 * Go to Vulners Scanner page to see the results about OS packages and WP plugins separately
 * Visiting the Scaner page loads the saved results of the previous scan (no scans are performed on each and every visit so that your license would not deplete)y visit so that your license would not deplete)
 * To run a manual scan click Scan Now button. This should perform an immediate update (and cost several requests from your license)ts from your license)
 * You can use the How to Fix button to see the shell command you need to run to fix the found vulnerabilities


== Frequently Asked Questions ==

= No scheduled scans are performed =

One of the main problems met during development was the one that scheduled scans were not running properly. Note that the plugin makes use of **wp-cron** for scheduled scans rather than system-specific cron. That means no scheduled events would fire unless someone visits your site from time to time. And if scheduled scans do not run, make sure **wp-cron** runs correctly (for instance using **ALTERNATE_CRON** made the trick during the development phase). Or you can simply set system cron yourself.

= Everything else =

Pretty much everything else should have been accounted for (either fixed or appended to the list of future developments). However, if you do run into something you believe to be a problem in the plugin itself, you can send your question to **support@vulners.com**.


== Screenshots == 

 1. This is an example of OS Packages scan results.
 2. This is an example of WP Plugins scan results.
 3. This is an interface of Plugin Settings.
 4. This is an example of email notification about new vulnerabilities.


== Changelog ==

= 1.2 =
 * Fix several warnings.
 * Restrict direct access to email template.
 * Show safe OS packages as well.

= 1.1 =
 * Add email template: include report with the found vulnerabilities
 * Refactoring.

= 1.0 =
 * Initial release
 * currently only Linux is scanned (only basic OS detection mechanism is implemented for now)
 * emails are sent at the end of every scheduled scan and do not contain vulnerability descriptions
 * schedule for wp-cron is hard-coded: the scans would run every 4 hours.
----
