<?php
namespace Craft;

/**
 * Sherlock Scan Model
 */
class Sherlock_ScanModel extends BaseModel
{
    /**
     * Define model attributes
     *
     * @return array
     */
    public function defineAttributes()
    {
        return array(
            'highSecurityLevel' => array(AttributeType::Bool, 'default' => false),
            'pass' => array(AttributeType::Bool, 'default' => true),
            'warning' => array(AttributeType::Bool, 'default' => false),
            'results' => array(AttributeType::Mixed, 'default' => array(
                'fail' => array(),
                'warning' => array(),
                'pass' => array(),
            )),
            'dateCreated' => AttributeType::DateTime,
            'dateUpdated' => AttributeType::DateTime,
        );
    }
}
