<?php
namespace Craft;

/**
 * Sherlock Controller
 */
class SherlockController extends BaseController
{
    protected $allowAnonymous = array('actionRunScan');

    /**
     * Run scan
     */
    public function actionRunScan()
    {
        // get api key from settings
        $apiKey = craft()->plugins->getPlugin('sherlock')->getSettings()->apiKey;

        // verify key
        if (!$apiKey OR $apiKey != craft()->request->getParam('key'))
        {
            die('Unauthorised API key');
        }

        $scan = craft()->sherlock->runScan();

        die('Success');
    }
}
