<?php
namespace Craft;

/**
 * Sherlock Test Model
 */
class Sherlock_TestModel extends BaseModel
{
    /**
     * Define model attributes
     *
     * @return array
     */
    public function defineAttributes()
    {
        return array(
            'name' => AttributeType::String,
            'type' => array(AttributeType::String, 'default' => 'settings'),
            'typeName' => array(AttributeType::String, 'default' => 'Config Setting'),
            'canFail' => array(AttributeType::Bool, 'default' => false),
            'forceFail' => array(AttributeType::Bool, 'default' => false),
            'threshold' => array(AttributeType::Number, 'default' => 0),
            'thresholds' => AttributeType::Mixed,
            'format' => AttributeType::String,
            'details' => AttributeType::String,
            'info' => AttributeType::String,
            'url' => AttributeType::String,
            'pass' => array(AttributeType::Bool, 'default' => true),
            'warning' => array(AttributeType::Bool, 'default' => false),
            'value' => AttributeType::String,
            'highSecurityLevel' => array(AttributeType::Bool, 'default' => false),
        );
    }

    /**
     * Fail test
     */
    public function failTest()
    {
        $this->pass = $this->forceFail ? false : (($this->canFail AND $this->highSecurityLevel) ? false : true);
        $this->warning = true;
    }
}
