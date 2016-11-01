<?php
namespace Craft;

/**
 * Sherlock Plugin
 */
class SherlockPlugin extends BasePlugin
{
    public function init()
    {
        parent::init();

        // check for header protection
        craft()->sherlock->checkHeaderProtection();

        // check for site resrictions
        craft()->sherlock->checkRestrictions();
    }

    public function getName()
    {
        return 'Sherlock Free';
    }

    public function getVersion()
    {
        return '1.1.0';
    }

    public function getSchemaVersion()
    {
        return '1.0.0';
    }

    public function getDeveloper()
    {
        return 'PutYourLightsOn';
    }

    public function getDeveloperUrl()
    {
        return 'https://www.putyourlightson.net';
    }

    public function getDescription()
    {
        return Craft::t('Security scanner to keep your site and CMS secure.');
    }

    public function getDocumentationUrl()
    {
        return 'https://www.putyourlightson.net/craft-sherlock/docs';
    }

    public function getReleaseFeedUrl()
    {
        return 'https://www.putyourlightson.net/releases/craft-sherlock';
    }

    public function hasCpSection()
    {
        return true;
    }

    protected function defineSettings()
    {
        return array(
            'liveMode' => array(AttributeType::Bool, 'default' => true),
            'highSecurityLevel' => array(AttributeType::Bool, 'default' => true),
            'logAllEvents' => array(AttributeType::Bool, 'default' => true),
            'headerProtection' => array(AttributeType::Bool, 'default' => true),
        );
    }

    public function getSettingsHtml()
    {
        return craft()->templates->render('sherlock/settings', array(
            'settings' => $this->getSettings()
        ));
    }

    public function getCpAlerts($path, $fetch)
    {
        return craft()->sherlock->getCpAlerts();
    }

    public function onAfterInstall()
    {
		craft()->request->redirect(UrlHelper::getCpUrl('settings/plugins/sherlock'));
    }
}
