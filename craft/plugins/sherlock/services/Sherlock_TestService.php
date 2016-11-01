<?php
namespace Craft;

/**
 * Sherlock Test Service
 */
class Sherlock_TestService extends BaseApplicationComponent
{
    private $_settings;
    private $_headers;

    private $_tests = array(
        'pluginVulnerabilities' => array(
            'name' => 'Plugin Vulnerabilities',
            'type' => 'plugin',
            'typeName' => 'Plugins',
            'forceFail' => true,
            'details' => array(
                'pass' => 'No known plugin vulnerabilities',
                'warning' => 'Missing or invalid JSON feed URL',
                'fail' => 'Fix known plugin vulnerabilities:',
            ),
            'info' => 'Plugins with known vulnerabilities that are installed on your site and that have been reported in the JSON feed URL setting will be shown here.',
            'url' => 'https://github.com/putyourlightson/craft-plugin-vulnerabilities',
        ),
        'httpsControlPanel' => array(
            'name' => 'HTTPS In Control Panel',
            'type' => 'secure',
            'typeName' => 'Security',
            'forceFail' => true,
            'details' => array(
                'pass' => 'Control panel is using an encrypted HTTPS connection',
                'warning' => 'Use an encrypted HTTPS connection in control panel',
            ),
            'info' => 'Using an SSL certificate and an encrypted HTTPS connection in your control panel ensures secure authentication of users and protects your site data.',
            'url' => 'https://craftcms.com/support/force-ssl',
        ),
        'httpsFrontEnd' => array(
            'name' => 'HTTPS On Front-End',
            'type' => 'secure',
            'typeName' => 'Security',
            'canFail' => true,
            'details' => array(
                'pass' => 'Front-end site is forcing an encrypted HTTPS connection',
                'warning' => 'Force an encrypted HTTPS connection on front-end site',
            ),
            'info' => 'Using an SSL certificate and forcing your front-end site to use an encrypted HTTPS connection protects your site and user data. This is especially important if public user registration is allowed.',
            'url' => 'https://craftcms.com/support/force-ssl',
        ),
        'cors' => array(
            'name' => 'Cross-Origin Resource Sharing (CORS)',
            'type' => 'header',
            'typeName' => 'HTTP Header',
            'forceFail' => true,
            'details' => array(
                'pass' => 'Access to other sites is not granted',
                'warning' => 'Access is granted to',
                'fail' => 'Remove CORS access to all sites',
            ),
            'info' => 'Cross-origin resource sharing (CORS) allows sites from other domains to access resources on your site\'s domain. If you must use CORS then be sure to limit it to specific domains rather than granting access to all domains using a wildcard.',
            'url' => 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS',
        ),
        'xFrameOptions' => array(
            'name' => 'X-Frame-Options Header',
            'type' => 'header',
            'typeName' => 'HTTP Header',
            'canFail' => true,
            'details' => array(
                'pass' => 'X-Frame-Options header is set to',
                'warning' => 'Set X-Frame-Options header to "DENY" or "SAMEORIGIN"',
            ),
            'info' => 'The X-Frame-Options header protects your visitors against clickjacking attacks. Setting it to DENY means your site cannot be framed, setting it to SAMEORIGIN allows your site to be framed on your domain only. The ALLOW-FROM value is not supported in all browsers and therefore should be avoided.',
            'url' => 'https://scotthelme.co.uk/hardening-your-http-response-headers/#x-frame-options',
        ),
        'xContentTypeOptions' => array(
            'name' => 'X-Content-Type-Options Header',
            'type' => 'header',
            'typeName' => 'HTTP Header',
            'canFail' => true,
            'details' => array(
                'pass' => 'X-Content-Type-Options header is set to',
                'warning' => 'Set X-Content-Type-Options header to "nosniff"',
            ),
            'info' => 'The X-Content-Type-Options header prevents Google Chrome and Internet Explorer from trying to mime-sniff the content-type of a response away from the one being declared by the server. It reduces exposure to drive-by downloads and the risks of user uploaded content that could be treated as a different content-type, like an executable.',
            'url' => 'https://scotthelme.co.uk/hardening-your-http-response-headers/#x-content-type-options',
        ),
        'xXssProtection' => array(
            'name' => 'X-Xss-Protection Header',
            'type' => 'header',
            'typeName' => 'HTTP Header',
            'canFail' => true,
            'details' => array(
                'pass' => 'X-Xss-Protection header is set to',
                'warning' => 'Set X-Xss-Protection header to "1; mode=block"',
            ),
            'info' => 'The X-Xss-Protection header is used to configure the built in reflective XSS protection found in browsers. Setting  the header to "1; mode=block" tells the browser to block the response if it detects an attack rather than sanitising the script.',
            'url' => 'https://scotthelme.co.uk/hardening-your-http-response-headers/#x-xss-protection',
        ),
        'strictTransportSecurity' => array(
            'name' => 'Strict-Transport-Security Header',
            'type' => 'header',
            'typeName' => 'HTTP Header',
            'canFail' => true,
            'details' => array(
                'pass' => 'Strict-Transport-Security header not required',
                'warning' => 'Set Strict-Transport-Security header to "max-age=31536000"',
            ),
            'info' => 'The Strict-Transport-Security header allows a web server to enforce the use of TLS in a web browser. It allows for a more effective implementation of TLS by ensuring all communication takes place over a secure transport layer on the client side. It should be set for communication over HTTPS connections only.',
            'url' => 'https://scotthelme.co.uk/hsts-the-missing-link-in-tls/',
        ),
        'purifyHtml' => array(
            'name' => 'Purify HTML For Rich Text Fields',
            'type' => 'field',
            'typeName' => 'Fields',
            'canFail' => true,
            'details' => array(
                'pass' => 'Purify HTML is enabled for all Rich Text fields',
                'warning' => 'Enable purify HTML for the following fields:',
            ),
            'info' => 'Enabling the purify HTML setting for all Rich Text fields ensures that any potentially malicious code is removed before saving to the database.',
            'url' => 'https://craftcms.com/docs/rich-text-fields',
        ),
        'craftFoldersAboveWebRoot' => array(
            'name' => 'Craft Folders Above Web Root',
            'typeName' => 'File/Folder System',
            'type' => 'folder',
            'canFail' => true,
            'details' => array(
                'pass' => 'Craft folders are located above the web root',
                'warning' => 'Craft folders not located above the web root',
            ),
            'info' => 'Keeping the Craft folders above the web root ensures that no one can access any of their files directly.',
            'url' => 'https://craftcms.com/docs/installing#step-1-upload-the-files',
        ),
        'craftFolderPermissions' => array(
            'name' => 'Craft Folder Permissions',
            'typeName' => 'File/Folder System',
            'type' => 'folder',
            'canFail' => true,
            'details' => array(
                'pass' => 'Craft folder permissions are correctly set',
                'warning' => 'Craft folder permissions are not correctly set',
            ),
            'info' => 'The folder permissions of Craft\'s writeable folders. Set these to at most 0775, which will grant everything for the owner and group, read and execute for everyone else.',
            'url' => 'https://craftcms.com/docs/installing#step-2-set-the-permissions',
        ),
        'craftFilePermissions' => array(
            'name' => 'Craft File Permissions',
            'typeName' => 'File/Folder System',
            'type' => 'files',
            'canFail' => true,
            'details' => array(
                'pass' => 'Craft file permissions are correctly set',
                'warning' => 'Craft file permissions are not correctly set',
            ),
            'info' => 'The file permissions of Craft\'s writable files. Set these to at most 0664, which will grant read and write for the owner and group, read for everyone else.',
            'url' => 'https://craftcms.com/docs/installing#step-2-set-the-permissions',
        ),
        'phpVersion' => array(
            'name' => 'PHP Version',
            'type' => 'code',
            'typeName' => 'Server Language',
            'canFail' => true,
            'thresholds' => array(
                '5.0' => '2005-09-05',
                '5.1' => '2006-07-24',
                '5.2' => '2011-01-06',
                '5.3' => '2014-07-14',
                '5.4' => '2015-09-03',
                '5.5' => '2016-07-10',
                '5.6' => '2018-12-31',
                '7.0' => '2018-12-03',
            ),
            'details' => array(
                'pass' => 'Site is running on a supported PHP version',
                'warning' => 'Site is running on an unsupported PHP version',
            ),
            'info' => 'Each release branch of PHP is fully supported for two years from its initial stable release, followed by an additional year for critical security issues only. After this time the branch reaches its end of life and is no longer supported.',
            'url' => 'http://php.net/supported-versions.php',
        ),
        'craftUpdated' => array(
            'name' => 'Craft Updated',
            'type' => 'upload',
            'typeName' => 'Software Update',
            'canFail' => true,
            'details' => array(
                'pass' => 'No Craft updates available',
                'warning' => 'Your version of Craft is behind the latest version',
            ),
            'info' => 'Craft updates can contain security enhancements and bug fixes so it is recommended to keep it updated whenever possible.',
            'url' => 'https://craftcms.com/changelog',
        ),
        'requireEmailVerification' => array(
            'name' => 'Require Email Verification',
            'type' => 'users',
            'typeName' => 'User Setting',
            'canFail' => true,
            'details' => array(
                'pass' => 'Require email verification is enabled',
                'warning' => 'Require email verification is disabled',
            ),
            'info' => 'Requiring that new email addresses are verified before getting saved to user accounts ensures that they are genuine and active email addresses.',
        ),
        'allowPublicRegistration' => array(
            'name' => 'Allow Public Registration',
            'type' => 'users',
            'typeName' => 'User Setting',
            'details' => array(
                'pass' => 'Public registration is disabled',
                'warning' => 'Public registration is enabled but not protected by Snaptcha',
            ),
            'info' => 'Enabling public registration allows unauthenticated registration of user accounts on the front-end of your site. If you enable this then ensure that you are protecting your user registration forms with a spam blocker such as <a href="https://www.putyourlightson.net/craft-snaptcha" target="_blank">Snaptcha</a>.',
            'url' => 'https://craftcms.com/docs/users#public-registration',
        ),
        'devMode' => array(
            'name' => 'Dev Mode',
            'canFail' => true,
            'details' => array(
                'pass' => 'Dev mode is disabled',
                'warning' => 'Disable dev mode',
            ),
            'info' => 'Dev mode is intended for testing and debugging your site and outputs performance related data on the front-end. It should never be enabled in live production environments.',
            'url' => 'https://craftcms.com/docs/config-settings#devMode',
        ),
        'translationDebugOutput' => array(
            'name' => 'Translation Debug Output',
            'canFail' => true,
            'details' => array(
                'pass' => 'Translation debug output is disabled',
                'warning' => 'Set translation debug output to false',
            ),
            'info' => 'If enabled, this setting will wrap all strings that are ran through Craft::t() or the |translate filter with "@" symbols. It is intended for debugging and should be disabled in live production environments.',
            'url' => 'https://craftcms.com/docs/config-settings#translationDebugOutput',
        ),
        'defaultFilePermissions' => array(
            'name' => 'Default File Permissions',
            'canFail' => true,
            'threshold' => 0664,
            'details' => array(
                'pass' => 'Default file permissions are set to ',
                'warning' => 'Set default file permissions to 0664',
            ),
            'info' => 'The permissions Craft will use when creating a new file on the file system. Set this to at most 0664, which will grant read and write for the owner and group, read for everyone else.',
            'url' => 'https://craftcms.com/docs/config-settings#defaultFilePermissions',
        ),
        'defaultFolderPermissions' => array(
            'name' => 'Default Folder Permissions',
            'canFail' => true,
            'threshold' => 0775,
            'details' => array(
                'pass' => 'Default folder permissions are set to ',
                'warning' => 'Set default folder permissions to 0775',
            ),
            'info' => 'The permissions Craft will use when creating a new folder on the file system. Set this to at most 0775, which will grant everything for the owner and group, read and execute for everyone else.',
            'url' => 'https://craftcms.com/docs/config-settings#defaultFolderPermissions',
        ),
        'defaultTokenDuration' => array(
            'name' => 'Default Token Duration',
            'canFail' => true,
            'threshold' => 1,
            'format' => '%d',
            'details' => array(
                'pass' => 'Default token duration is set to',
                'warning' => 'Set default token duration to P1D or less',
            ),
            'info' => 'The duration that system tokens should last for. Setting this to P1D or less will ensure that system tokens expire after at most 1 day.',
            'url' => 'https://craftcms.com/docs/config-settings#defaultTokenDuration',
        ),
        'enableCsrfProtection' => array(
            'name' => 'CSRF Protection',
            'canFail' => true,
            'details' => array(
                'pass' => 'CSRF protection is enabled',
                'warning' => 'Enable CSRF protection',
            ),
            'info' => 'Cross-Site Request Forgery (CSRF) protection ensures that all POST requests to Craft must be accompanied by a CSRF token, otherwise the request will be rejected with a 400 error. This helps to prevent attacks that force unwanted actions to be executed on behalf of a user that is authenticated and logged in to Craft.',
            'url' => 'https://craftcms.com/docs/config-settings#enableCsrfProtection',
        ),
        'useSecureCookies' => array(
            'name' => 'Use Secure Cookies',
            'canFail' => true,
            'details' => array(
                'pass' => 'Site is using secure cookies',
                'warning' => 'Set secure cookies to "on" or "auto"',
            ),
            'info' => 'Whether Craft should set the secure flag on its cookies, limiting them to only be sent on secure (SSL) requests. Setting this to "on" or "auto" will ensure that the secure flag is set.',
            'url' => 'https://craftcms.com/docs/config-settings#useSecureCookies',
        ),
        'validationKey' => array(
            'name' => 'Validation Key',
            'canFail' => true,
            'details' => array(
                'pass' => 'Validation key is secure',
                'warning' => 'Set secure validation key',
            ),
            'info' => 'This setting will override the auto-generated secure validation key used to verify that hashed values have not been tampered with. If set, ensure that it is a private, random, cryptographically secure key.',
            'url' => 'https://craftcms.com/docs/config-settings#validationKey',
        ),
        'cpTrigger' => array(
            'name' => 'Control Panel Trigger',
            'details' => array(
                'pass' => 'Control panel trigger is not "admin"',
                'warning' => 'Change control panel trigger to something other than "admin"',
            ),
            'info' => 'This is the URI segment that triggers Craft to load the control panel rather than the front-end website. Changing this to something other than the default "admin" can help prevent people from guessing the access point to your site\'s control panel.',
            'url' => 'https://craftcms.com/docs/config-settings#cpTrigger',
        ),
        'blowfishHashCost' => array(
            'name' => 'Blowfish Hash Cost',
            'threshold' => 13,
            'details' => array(
                'pass' => 'Blowfish hash cost is set to',
                'warning' => 'Set blowfish hash cost to at least 13',
            ),
            'info' => 'The higher the cost value, the longer it takes to generate a password hash and to verify against it. For best protection against brute force attacks, set it to the highest value that is tolerable on your server.',
            'url' => 'https://craftcms.com/docs/config-settings#blowfishHashCost',
        ),
        'cooldownDuration' => array(
            'name' => 'Cooldown Duration',
            'threshold' => 5,
            'format' => '%i',
            'details' => array(
                'pass' => 'Cooldown duration is set to',
                'warning' => 'Set cooldown duration to false or at least PT5M',
            ),
            'info' => 'The amount of time a user must wait before re-attempting to log in after their account is locked due to too many failed login attempts. Setting this to false will keep the account locked indefinitely. Setting this to PT5M will keep the account locked for 5 minutes.',
            'url' => 'https://craftcms.com/docs/config-settings#cooldownDuration',
        ),
        'invalidLoginWindowDuration' => array(
            'name' => 'Invalid Login Window Duration',
            'threshold' => 1,
            'format' => '%h',
            'details' => array(
                'pass' => 'Invalid login window duration is set to',
                'warning' => 'Set invalid login window duration to at least PT1H',
            ),
            'info' => 'The amount of time to track invalid login attempts for a user, for determining if Craft should lock an account. Setting this to at least PT1H will ensure that invalid login attempts are tracked for at least 1 hour.',
            'url' => 'https://craftcms.com/docs/config-settings#invalidLoginWindowDuration',
        ),
        'maxInvalidLogins' => array(
            'name' => 'Max Invalid Logins',
            'canFail' => true,
            'threshold' => 5,
            'details' => array(
                'pass' => 'Max invalid logins is set to',
                'warning' => 'Set max invalid logins to 5 or less',
            ),
            'info' => 'The number of invalid login attempts Craft will allow within the specified duration before the account gets locked. Set this to 5 or less to help prevent a brute force attack.',
            'url' => 'https://craftcms.com/docs/config-settings#maxInvalidLogins',
        ),
        'rememberedUserSessionDuration' => array(
            'name' => 'Remembered User Session Duration',
            'threshold' => 14,
            'format' => '%d',
            'details' => array(
                'pass' => 'Remembered user session duration is set to',
                'warning' => 'Set remembered user session duration to P2W or less',
            ),
            'info' => 'The amount of time a user stays logged in if "Remember Me" is checked on the login page. Setting this to P2W or less will ensure that users are remembered for at most 2 weeks.',
            'url' => 'https://craftcms.com/docs/config-settings#rememberedUserSessionDuration',
        ),
        'requireMatchingUserAgentForSession' => array(
            'name' => 'Require Matching User Agent For Session',
            'details' => array(
                'pass' => 'Require matching user agent for session is enabled',
                'warning' => 'Set require matching user agent for session to true',
            ),
            'info' => 'Whether Craft should require a matching user agent string when restoring a user session from a cookie. Keeping this enabled will prevent users switching to different browsers/devices while remaining logged in.',
            'url' => 'https://craftcms.com/docs/config-settings#requireMatchingUserAgentForSession',
        ),
        'requireUserAgentAndIpForSession' => array(
            'name' => 'Require User Agent And IP For Session',
            'details' => array(
                'pass' => 'Require user agent and IP for session is enabled',
                'warning' => 'Set require user agent and IP for session to true',
            ),
            'info' => 'Whether Craft should require the existence of a user agent string and IP address when creating a new user session. Keeping this enabled will help prevent user sessions being created for bots.',
            'url' => 'https://craftcms.com/docs/config-settings#requireUserAgentAndIpForSession',
        ),
        'testToEmailAddress' => array(
            'name' => 'Test Email Address',
            'canFail' => true,
            'details' => array(
                'pass' => 'Test email address is disabled',
                'warning' => 'Remove test email address',
            ),
            'info' => 'If set, all system emails will be sent to this email address. It is intended for testing and should be disabled in live production environments.',
            'url' => 'https://craftcms.com/docs/config-settings#testToEmailAddress',
        ),
        'userSessionDuration' => array(
            'name' => 'Remembered User Session Duration',
            'canFail' => true,
            'threshold' => 1,
            'format' => '%h',
            'details' => array(
                'pass' => 'Remembered user session duration is set to',
                'warning' => 'Set user session duration to PT1H or less',
            ),
            'info' => 'The amount of time a user stays logged in. Setting this to false will allow users to stay logged in as long as their browser is open. Setting this to PT1H or less will allow users to stay logged in for at most 1 hour.',
            'url' => 'https://craftcms.com/docs/config-settings#userSessionDuration',
        ),
        'verificationCodeDuration' => array(
            'name' => 'Verification Code Duration',
            'canFail' => true,
            'threshold' => 1,
            'format' => '%d',
            'details' => array(
                'pass' => 'Verification code duration is set to',
                'warning' => 'Set verification code duration to P1D or less',
            ),
            'info' => 'The amount of time a user verification code can be used before expiring. Setting this to P1D or less will ensure that the user verification code expires after at most 1 day.',
            'url' => 'https://craftcms.com/docs/config-settings#verificationCodeDuration',
        )
    );

    /**
    * Init
    */
    public function init()
    {
        parent::init();

        // get settings
        $this->_settings = craft()->plugins->getPlugin('sherlock')->getSettings();

        // get site headers of insecure front-end site url
        $this->_headers = get_headers(str_replace('https://', 'http://', UrlHelper::getSiteUrl()), 1);

        // check if the pluginVulnerabilities test should be removed
        if (!isset($this->_settings->pluginVulnerabilitiesFeedUrl))
        {
            unset($this->_tests['pluginVulnerabilities']);
        }
    }

    /**
     * Get test names
     *
	 * @return array
     */
    public function getTestNames()
    {
        return array_keys($this->_tests);
    }

    /**
     * Run test
     *
	 * @return Sherlock_TestModel
     */
    public function runTest($test)
    {
        if (!isset($this->_tests[$test]))
        {
            return false;
        }

        $sherlockTestModel = new Sherlock_TestModel($this->_tests[$test]);
        $sherlockTestModel->highSecurityLevel = $this->_settings->highSecurityLevel;

        switch ($test)
        {
            case 'pluginVulnerabilities':
                if (!empty($this->_settings->pluginVulnerabilitiesFeedUrl) AND stripos($this->_settings->pluginVulnerabilitiesFeedUrl, 'https://') === 0)
                {
                    $pluginVulnerabilities = array();

                    // create new guzzle client
                    $client = new \Guzzle\Http\Client();

                    try
                    {
                        $request = $client->get($this->_settings->pluginVulnerabilitiesFeedUrl, array(
                            'timeout' => 3,
                            'connect_timeout' => 3,
                        ));

                        $response = $request->send();
                        $responseBody = $response->getBody();
                        $vulnerabilities = JsonHelper::decode($responseBody);

                        if ($vulnerabilities)
                        {
                            $installedPlugins = craft()->plugins->getPlugins();

                            foreach ($vulnerabilities as $vulnerability)
                            {
                                if (isset($installedPlugins[$vulnerability['handle']]))
                                {
                                    $plugin = craft()->plugins->getPlugin($vulnerability['handle']);

                                    if (empty($vulnerability['fixedVersion']) OR version_compare($plugin->getVersion(), $vulnerability['fixedVersion'], '<'))
                                    {
                                        $pluginVulnerabilities[] = '<a href="'.$vulnerability['url'].'" target="_blank">'.$plugin->getName().' '.$vulnerability['version'].'</a> <span class="info">'.$vulnerability['description'].(isset($vulnerability['fixedVersion']) ? ' (fixed in version '.$vulnerability['fixedVersion'].')' : '').'</span>';
                                    }
                                }
                            }
                        }

                        else
                        {
                            $sherlockTestModel->warning = true;
                        }
                    }
                    catch (\Guzzle\Http\Exception\BadResponseException $e) { $sherlockTestModel->warning = true; }
                    catch (\Guzzle\Http\Exception\CurlException $e) { $sherlockTestModel->warning = true; }

                    if (!empty($pluginVulnerabilities))
                    {
                        $sherlockTestModel->info = '';
                        $sherlockTestModel->failTest();
                        $sherlockTestModel->value = join(' , ', $pluginVulnerabilities);
                    }
                }

                else
                {
                    $sherlockTestModel->warning = true;
                }

                break;

            case 'httpsControlPanel':
                if (!craft()->request->isSecureConnection())
                {
                    $sherlockTestModel->failTest();
                }

                break;

            case 'httpsFrontEnd':
                if (empty($this->_headers['Location']) OR strpos($this->_headers['Location'], 'https') !== 0)
                {
                    // if public registration is allowed then force fail
                    if (craft()->systemSettings->getSetting('users', 'allowPublicRegistration'))
                    {
                        $sherlockTestModel->forceFail = true;
                    }

                    $sherlockTestModel->failTest();
                }

                break;

            case 'cors':
                if (isset($this->_headers['Access-Control-Allow-Origin']))
                {
                    if ($this->_headers['Access-Control-Allow-Origin'] == '*')
                    {
                        $sherlockTestModel->failTest();
                    }

                    else if ($this->_headers['Access-Control-Allow-Origin'])
                    {
                        $sherlockTestModel->warning = true;
                        $sherlockTestModel->value = $this->_headers['Access-Control-Allow-Origin'];
                    }
                }

                break;

            case 'xFrameOptions':
                if (empty($this->_headers['X-Frame-Options']) OR ($this->_headers['X-Frame-Options'] != 'DENY' AND $this->_headers['X-Frame-Options'] != 'SAMEORIGIN'))
                {
                    $sherlockTestModel->failTest();
                }

                else
                {
                    $sherlockTestModel->value = '"'.$this->_headers['X-Frame-Options'].'"';
                }

                break;

            case 'xContentTypeOptions':
                if (empty($this->_headers['X-Content-Type-Options']) OR $this->_headers['X-Content-Type-Options'] != 'nosniff')
                {
                    $sherlockTestModel->failTest();
                }

                else
                {
                    $sherlockTestModel->value = '"'.$this->_headers['X-Content-Type-Options'].'"';
                }

                break;

            case 'xXssProtection':
                if (empty($this->_headers['X-Xss-Protection']) OR $this->_headers['X-Xss-Protection'] != '1; mode=block')
                {
                    $sherlockTestModel->failTest();
                }

                else
                {
                    $sherlockTestModel->value = '"'.$this->_headers['X-Xss-Protection'].'"';
                }

                break;

            case 'strictTransportSecurity':
                if (isset($this->_headers['Location']) AND strpos($this->_headers['Location'], 'https') === 0)
                {
                    if (empty($this->_headers['Strict-Transport-Security']))
                    {
                        $sherlockTestModel->failTest();
                    }

                    else
                    {
                        $sherlockTestModel->value = '"'.$this->_headers['Strict-Transport-Security'].'"';

                        $details = $sherlockTestModel->details;
                        $details['warning'] = 'Strict-Transport-Security header is set to:';
                        $sherlockTestModel->details = $details;
                    }
                }

                break;

            case 'purifyHtml':
                $fields = craft()->fields->getAllFields();
                $fieldsFailed = array();

            	foreach ($fields as $field)
            	{
                    if ($field->getFieldType()->model->type == 'RichText' AND !$field->getFieldType()->getSettings()->purifyHtml)
                    {
                        $fieldsFailed[] = '<a href="'.UrlHelper::getUrl('settings/fields/edit/'.$field->id).'" target="_blank">'.$field->name.'</a>';
                    }
                }

                if (count($fieldsFailed))
                {
                    $sherlockTestModel->failTest();

                    $sherlockTestModel->value = join(', ', $fieldsFailed);
                }

                break;

            case 'craftFoldersAboveWebRoot':
                $paths = array(
                    'app' => CRAFT_APP_PATH,
                    'config' => CRAFT_CONFIG_PATH,
                    'plugins' => CRAFT_PLUGINS_PATH,
                    'storage' => CRAFT_STORAGE_PATH,
                    'templates' => CRAFT_TEMPLATES_PATH,
                    'translations' => CRAFT_TRANSLATIONS_PATH,
                );
                $pathsFailed = array();
                $cwd = getcwd();

                if (strpos(CRAFT_BASE_PATH, $cwd) !== false)
                {
                    $sherlockTestModel->failTest();
                }

                else
                {
                    foreach ($paths as $key => $path)
                    {
                        // if the current working directory is a substring of the path
                        if (strpos($path, $cwd) !== false)
                        {
                            $pathsFailed[] = $key;
                        }
                    }

                    if (count($pathsFailed))
                    {
                        $sherlockTestModel->failTest();

                        $sherlockTestModel->value = join(', ', $pathsFailed);

                        $details = $sherlockTestModel->details;
                        $details['warning'] .= ':';
                        $sherlockTestModel->details = $details;
                    }

                }

                break;

            case 'craftFolderPermissions':
                $paths = array(
                    'app' => CRAFT_APP_PATH,
                    'config' => CRAFT_CONFIG_PATH,
                    'storage' => CRAFT_STORAGE_PATH,
                );
                $pathsFailed = array();

                foreach ($paths as $key => $path)
                {
                    // if the path is writable by everyone
                    if (substr(IOHelper::getPermissions($path), -1) >= 6)
                    {
                        $pathsFailed[] = $key;
                    }
                }

                if (count($pathsFailed))
                {
                    $sherlockTestModel->failTest();

                    $sherlockTestModel->value = join(', ', $pathsFailed);

                    $details = $sherlockTestModel->details;
                    $details['warning'] .= ':';
                    $sherlockTestModel->details = $details;
                }

                break;

            case 'craftFilePermissions':
                $files = array(
                    'app/Info.php' => CRAFT_APP_PATH.'Info.php',
                    'config/db.php' => CRAFT_CONFIG_PATH.'db.php',
                    'config/general.php' => CRAFT_CONFIG_PATH.'general.php',
                    'config/license.key.php' => CRAFT_CONFIG_PATH.'license.key.php',
                );
                $filesFailed = array();

                foreach ($files as $key => $file)
                {
                    // if the file is writable by everyone
                    if (substr(IOHelper::getPermissions($file), -1) >= 6)
                    {
                        $filesFailed[] = $key;
                    }
                }

                if (count($filesFailed))
                {
                    $sherlockTestModel->failTest();

                    $sherlockTestModel->value = join(', ', $filesFailed);

                    $details = $sherlockTestModel->details;
                    $details['warning'] .= ':';
                    $sherlockTestModel->details = $details;
                }

                break;

            case 'phpVersion':
                $version = phpversion();
                $value = substr($version, 0, 3);
                $eolDate = '';

                if (isset($sherlockTestModel->thresholds[$value]))
                {
                    if (strtotime($sherlockTestModel->thresholds[$value]) < time())
                    {
                        $sherlockTestModel->failTest();
                    }

                    $eolDate = $sherlockTestModel->thresholds[$value];
                }

                $sherlockTestModel->value = $version.' (until '.$eolDate.')';

                break;

            case 'craftUpdated':
                if (craft()->updates->getTotalAvailableUpdates())
                {
                    $sherlockTestModel->failTest();
                }

                break;

            case 'requireEmailVerification':
                if (!craft()->systemSettings->getSetting('users', 'requireEmailVerification'))
                {
                    $sherlockTestModel->failTest();
                }

                break;

            case 'allowPublicRegistration':
                if (craft()->systemSettings->getSetting('users', 'allowPublicRegistration'))
                {
                    $installedPlugins = craft()->plugins->getPlugins();

                    // if not installed or not enabled
                    if (empty($installedPlugins['snaptcha']) OR !craft()->plugins->getPlugin('snaptcha')->getSettings()->enabled)
                    {
                        $sherlockTestModel->failTest();
                    }

                    else
                    {
                        $details = $sherlockTestModel->details;
                        $details['pass'] = 'Public registration is enabled and protected by Snaptcha';
                        $sherlockTestModel->details = $details;
                    }
                }

                break;

            case 'devMode':
                if (craft()->config->get($test))
                {
                    $sherlockTestModel->pass = $sherlockTestModel->forceFail ? false : ($sherlockTestModel->canFail AND $this->_settings->liveMode ? false : true);
                    $sherlockTestModel->warning = true;
                }

                break;

            case 'enableCsrfProtection':
            case 'useSecureCookies':
            case 'requireMatchingUserAgentForSession':
            case 'requireUserAgentAndIpForSession':
                if (!craft()->config->get($test))
                {
                    $sherlockTestModel->failTest();
                }

                break;

            case 'translationDebugOutput':
            case 'testToEmailAddress':
                if (craft()->config->get($test))
                {
                    $sherlockTestModel->failTest();
                }

                break;

            case 'defaultFilePermissions':
            case 'defaultFolderPermissions':
                $value = craft()->config->get($test);

                if ($value > $sherlockTestModel->threshold)
                {
                    $sherlockTestModel->failTest();
                }

                else
                {
                    $sherlockTestModel->value = '0'.decoct($value);
                }

                break;

            case 'defaultTokenDuration':
            case 'verificationCodeDuration':
                $value = craft()->config->get($test);

                $interval = new DateInterval($value);

                if ($interval->format($sherlockTestModel->format) > $sherlockTestModel->threshold)
                {
                    $sherlockTestModel->failTest();
                }

                else
                {
                    $sherlockTestModel->value = $value;
                }

                break;

            case 'validationKey':
                $value = craft()->config->get($test);

                if ($value AND (strlen($value) < 10 OR $value == '6#AYD6jW6nUJ3GMfreeXcPTGmBu.V*3Fi?f'))
                {
                    $sherlockTestModel->failTest();
                }

                break;

            case 'cpTrigger':
                $value = craft()->config->get($test);

                if ($value == 'admin')
                {
                    $sherlockTestModel->failTest();
                }

                break;

            case 'blowfishHashCost':
                $value = craft()->config->get($test);

                if ($value < $sherlockTestModel->threshold)
                {
                    $sherlockTestModel->failTest();
                }

                else
                {
                    $sherlockTestModel->value = $value;
                }

                break;

            case 'cooldownDuration':
                $value = craft()->config->get($test);
                $interval = new DateInterval($value);

                if ($interval->format($sherlockTestModel->format) < $sherlockTestModel->threshold)
                {
                    $sherlockTestModel->failTest();
                }

                else
                {
                    $sherlockTestModel->value = $value;
                }

                break;

            case 'invalidLoginWindowDuration':
                $value = craft()->config->get($test);

                $interval = new DateInterval($value);

                if ($interval->format($sherlockTestModel->format) < $sherlockTestModel->threshold)
                {
                    $sherlockTestModel->failTest();
                }

                else
                {
                    $sherlockTestModel->value = $value;
                }

                break;

            case 'maxInvalidLogins':
                $value = craft()->config->get($test);

                if (!$value)
                {
                    $sherlockTestModel->failTest();
                }

                else if ($value > $sherlockTestModel->threshold)
                {
                    $sherlockTestModel->warning = true;
                }

                else
                {
                    $sherlockTestModel->value = $value;
                }

                break;

            case 'rememberedUserSessionDuration':
                $value = craft()->config->get($test);

                if ($value)
                {
                    $interval = new DateInterval($value);

                    if ($interval->format($sherlockTestModel->format) > $sherlockTestModel->threshold)
                    {
                        $sherlockTestModel->failTest();
                    }

                    else
                    {
                        $sherlockTestModel->value = $value;
                    }
                }

                break;

            case 'userSessionDuration':
                $value = craft()->config->get($test);

                if (!$value)
                {
                    $sherlockTestModel->failTest();
                }

                else
                {
                    $interval = new DateInterval($value);

                    if ($interval->format($sherlockTestModel->format) > $sherlockTestModel->threshold)
                    {
                        $sherlockTestModel->warning = true;
                    }

                    else
                    {
                        $sherlockTestModel->value = $value;
                    }
                }

                break;
        }

        return $sherlockTestModel;
    }
}
