<?php
namespace Craft;

/**
 * Sherlock Service
 */
class SherlockService extends BaseApplicationComponent
{
    private $_settings;

    /**
    * Init
    */
    public function init()
    {
        parent::init();

        // get settings
        $this->_settings = craft()->plugins->getPlugin('sherlock')->getSettings();
    }

    /**
     * Check Header Protection
     */
    public function checkHeaderProtection()
    {
        if (!empty($this->_settings->headerProtection) AND $this->_settings->headerProtection)
        {
			HeaderHelper::setHeader(array('X-Frame-Options' => 'SAMEORIGIN'));
			HeaderHelper::setHeader(array('X-Content-Type-Options' => 'nosniff'));
			HeaderHelper::setHeader(array('X-Xss-Protection' => '1; mode=block'));

            if (craft()->request->isSecureConnection())
            {
                HeaderHelper::setHeader(array('Strict-Transport-Security' => 'max-age=31536000'));
            }
        }
    }

    /**
     * Check Restrictions
     */
    public function checkRestrictions()
    {
        if (!empty($this->_settings->restrictControlPanelIpAddresses) AND craft()->request->isCpRequest() AND !craft()->userSession->isAdmin() AND !in_array(craft()->request->getIpAddress(), explode("\n", $this->_settings->restrictControlPanelIpAddresses)))
        {
            throw new HttpException(503);
        }

        if (!empty($this->_settings->restrictFrontEndIpAddresses) AND craft()->request->isSiteRequest() AND !craft()->userSession->isAdmin() AND !in_array(craft()->request->getIpAddress(), explode("\n", $this->_settings->restrictFrontEndIpAddresses)))
        {
            throw new HttpException(503);
        }
    }

    /**
     * Get CP Alerts
     *
	 * @return array
     */
    public function getCpAlerts()
    {
        $alerts = array();

        if (!isset($this->_settings->notificationEmailAddresses) AND craft()->getEdition() != Craft::Personal)
        {
            $alerts[] = 'You are running a free unlicensed version of Sherlock on a Craft '.craft()->getEditionName().' license. <a href="https://craftpl.us/plugins/sherlock" class="go" target="_blank">Buy Plugin License</a>';
        }

        if ($this->_settings->liveMode)
        {
            if (craft()->getEdition() == Craft::Personal OR craft()->userSession->isAdmin() OR in_array('accessplugin-sherlock', craft()->userPermissions->getPermissionsByUserId(craft()->userSession->user->id)))
            {
                $lastScan = $this->getLastScan();

                if ($lastScan AND !$lastScan->pass)
                {
                    $alerts[] = 'Your site has failed the Sherlock '.($lastScan->highSecurityLevel ? 'high' : 'standard').' security scan. <a href="'.UrlHelper::getUrl('sherlock').'" class="go">Run Scan Again</a>';
                }
            }
        }

        return $alerts;
    }

    /**
     * Get last scan
     *
	 * @return Sherlock_ScanModel|null
     */
    public function getLastScan()
    {
        // get record
        $sherlockScanRecord = Sherlock_ScanRecord::model()->find(
            array('order'=>'dateCreated desc')
        );

        $sherlockScanModel = null;

        if ($sherlockScanRecord)
        {
            // populate model
            $sherlockScanModel = Sherlock_ScanModel::populateModel($sherlockScanRecord);
        }

        return $sherlockScanModel;
    }

    /**
     * Run scan
     *
	 * @return Sherlock_ScanModel
     */
    public function runScan()
    {
        // create model
        $sherlockScanModel = new Sherlock_ScanModel(array(
            'highSecurityLevel' => $this->_settings->highSecurityLevel,
        ));

        $results = $sherlockScanModel->results;
        $tests = craft()->sherlock_test->getTestNames();

        foreach ($tests as $test)
        {
            $sherlockTestModel = craft()->sherlock_test->runTest($test);

            if (!$sherlockTestModel->pass)
            {
                $sherlockScanModel->pass = false;
            }

            if ($sherlockTestModel->warning)
            {
                $sherlockScanModel->warning = true;
            }

            $status = (!$sherlockTestModel->pass ? 'fail' : ($sherlockTestModel->warning ? 'warning' : 'pass'));
            $results[$status][$test] = $sherlockTestModel;
        }

        $sherlockScanModel->results = $results;

        // log scan
        $user = craft()->userSession->getUser();
        SherlockPlugin::log(
            'Scan run by '.($user ? $user->username : craft()->request->ipAddress).' with result: '.($sherlockScanModel->pass ? 'pass'.($sherlockScanModel->warning ? ' with warnings' : '') : 'fail'),
            LogLevel::Info,
            $this->_settings->logAllEvents
        );

        // check failed scan against last scan
        if (!$sherlockScanModel->pass)
        {
            $lastScan = $this->getLastScan();

            // if last scan exists
            if ($lastScan)
            {
                if ($lastScan->pass)
                {
                    // send and log notification email
                    $this->_sendLogNotificationEmail(
                        'Security Scan Failed',
                        'Sherlock security scan failed at the following site: ',
                        'Sent email about failed scan to '
                    );
                }

                // check plugin vulnerabilities against last scan
                else if (isset($sherlockScanModel->results['fail']['pluginVulnerabilities']) AND !isset($lastScan->results['fail']['pluginVulnerabilities']))
                {
                    // send and log notification email
                    $this->_sendLogNotificationEmail(
                        'Security Scan Plugin Vulnerabilities',
                        'Sherlock security scan detected plugin vulnerabilities at the following site: ',
                        'Sent email about plugin vulnerabilities to '
                    );
                }

            }
        }

        // populate and save record
        $sherlockScanRecord = new Sherlock_ScanRecord;
        $sherlockScanRecord->setAttributes($sherlockScanModel->getAttributes(), false);

        // simlplify results
        $results = array();
        foreach ($sherlockScanRecord->results as $key => $result)
        {
            foreach ($result as $test => $sherlockTestModel)
            {
                $results[$key][$test] = array('value' => strip_tags($sherlockTestModel->value));
            }
        }

        $sherlockScanRecord->results = $results;
        $sherlockScanRecord->save();

        return $sherlockScanModel;
    }

    /**
     * Send and Log Notification Email
     */
    private function _sendLogNotificationEmail($subject, $message, $log)
    {
        // if live mode and notification email addresses exist
        if ($this->_settings->liveMode AND !empty($this->_settings->notificationEmailAddresses))
        {
            $emailModel = new EmailModel();
            $emailModel->toEmail = $this->_settings->notificationEmailAddresses;
            $emailModel->subject = craft()->getSiteName().' – '.$subject;
            $emailModel->body = $message.UrlHelper::getUrl('sherlock');

            craft()->email->sendEmail($emailModel);

            // log notification email
            $user = craft()->userSession->getUser();
            SherlockPlugin::log(
                $log.$this->_settings->notificationEmailAddresses,
                LogLevel::Info,
                true
            );
        }
    }
}
