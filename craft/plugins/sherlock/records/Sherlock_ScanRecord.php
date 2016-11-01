<?php

namespace Craft;

/**
* Sherlock Scan Record
*
*/
class Sherlock_ScanRecord extends BaseRecord
{
    /**
    * Gets the database table name
    *
    * @return string
    */
    public function getTableName()
    {
        return 'sherlock';
    }

    /**
    * Define columns for our database table
    *
    * @return array
    */
    public function defineAttributes()
    {
        return array(
            'highSecurityLevel' => AttributeType::Bool,
            'pass' => AttributeType::Bool,
            'warning' => AttributeType::Bool,
            'results' => AttributeType::Mixed,
        );
    }
}
