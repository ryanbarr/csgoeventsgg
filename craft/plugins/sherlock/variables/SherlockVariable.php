<?php
namespace Craft;

/**
 * Sherlock Variable
 */
class SherlockVariable
{
    /**
     * Get plugin name
     *
	 * @return string
     */
    public function getPluginName()
    {
        return craft()->plugins->getPlugin('sherlock')->getName();
    }

    /**
     * Get random string
     *
	 * @return string
     */
    public function getRandomString()
    {
        return StringHelper::randomString();
    }

    /**
     * Get last scan
     *
	 * @return Sherlock_ScanModel
     */
    public function getLastScan()
    {
        return craft()->sherlock->getLastScan();
    }

    /**
     * Check High Security Level
     *
	 * @return string
     */
    public function checkHighSecurityLevel()
    {
        return craft()->plugins->getPlugin('sherlock')->getSettings()->highSecurityLevel;
    }

    /**
     * Run scan
     *
	 * @return Sherlock_ScanModel
     */
    public function runScan()
    {
        return craft()->sherlock->runScan();
    }
}
