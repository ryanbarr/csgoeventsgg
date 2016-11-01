<?php

/**
 * General Configuration
 *
 * All of your system's general configuration settings go in here.
 * You can see a list of the default settings in craft/app/etc/config/defaults/general.php
 */

return array(
    '*' => array(
        'omitScriptNameInUrls' => true,
        'enableCsrfProtection' => true,
        'sendPoweredByHeader' => false,
        'cpTrigger' => 'a',
        'devMode' => true,
    ),

    'craft.local' => array(
        'environmentVariables' => array(
            'basePath' => '/Users/ericboyer/Sites/craft/',
            'baseUrl'  => 'http://craft.local/',
        )
    ),

    'csgoevents.gg' => array(
        'environmentVariables' => array(
            'basePath' => '/home/ejboyer/csgoeventsgg/craft',
            'baseUrl'  => 'http://csgoevents.gg/',
        )
    )
);
