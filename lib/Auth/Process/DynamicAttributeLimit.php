<?php

namespace SimpleSAML\Module\attributelimit\Auth\Process;

use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Configuration;
use SimpleSAML\Error\Exception;
use SimpleSAML\Logger;

/**
 * A filter for limiting which attributes are passed on.
 *
 * Example config
 * XX => [
 *     'class' => 'attributelimit:DynamicAttributeLimit',
 *     'allowedAttributes' => [
 *         'displayName',
 *         'eduPersonEntitlement' => [
 *             'regex' => true,
 *             '/^urn:mace:egi.eu:/i',
 *         ],
 *     ],
 *     'eppnFromIdp' => [
 *         'idpEntityId01',
 *         'idpEntityId02',
 *     ],
 *     'eppnToSp' => [
 *         'spEntityId01',
 *         'spEntityId02',
 *         'spEntityId03',
 *     ],
 * ],
 *
 * @author Olav Morken, UNINETT AS.
 * @author Nicolas Liampotis <nicolas.liampotis@gmail.com>
 * @author Nick Evangelou <nikos.ev@hotmail.com>
 * @package SimpleSAMLphp
 */
class DynamicAttributeLimit extends ProcessingFilter
{

    /**
     * List of attributes which this filter will allow through.
     */
    private $allowedAttributes = [];

    /**
     * List of IdP entityIDs that release ePPN
     */
    private $eppnFromIdp = [];

    /**
     * List of SP entityIDs that require ePPN
     */
    private $eppnToSp = [];

    /**
     * Associative array with the mappings of attribute names.
     */
    private $map = [];

    private $duplicate = false;

    /**
     * Initialize this filter.
     *
     * @param array $config  Configuration information about this filter.
     * @param mixed $reserved  For future use
     * @throws Exception If invalid configuration is found.
     */
    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);

        assert('is_array($config)');

        if (array_key_exists('allowedAttributes', $config)) {
            if (!is_array($config['allowedAttributes'])) {
                Logger::error("[DynamicAttributeLimit] Configuration error: 'allowedAttributes' not an array");
                throw new Exception(
                    "DynamicAttributeLimit configuration error: 'allowedAttributes' not an array"
                );
            }
            $this->allowedAttributes = $config['allowedAttributes'];
        }
        if (array_key_exists('eppnFromIdp', $config)) {
            if (!is_array($config['eppnFromIdp'])) {
                Logger::error("[DynamicAttributeLimit] Configuration error: 'eppnFromIdp' not an array");
                throw new Exception(
                    "DynamicAttributeLimit configuration error: 'eppnFromIdp' not an array"
                );
            }
            $this->eppnFromIdp = $config['eppnFromIdp'];
        }
        if (array_key_exists('eppnToSp', $config)) {
            if (!is_array($config['eppnToSp'])) {
                Logger::error("[DynamicAttributeLimit] Configuration error: 'eppnToSp' not an array");
                throw new Exception(
                    "DynamicAttributeLimit configuration error: 'eppnToSp' not an array"
                );
            }
            $this->eppnToSp = $config['eppnToSp'];
        }
    }


    /**
     * Get list of allowed from the SP/IdP config.
     *
     * @param array &$request  The current request.
     * @return array|null  Array with attribute names, or null if no limit is placed.
     */
    private static function getSPIdPAllowed(array &$request)
    {

        if (array_key_exists('attributes', $request['Destination'])) {
            // SP Config
            return $request['Destination']['attributes'];
        }
        if (array_key_exists('attributes', $request['Source'])) {
            // IdP Config
            return $request['Source']['attributes'];
        }
        return [];
    }


    /**
     * Apply filter to remove attributes.
     *
     * Removes all attributes which aren't one of the allowed attributes.
     *
     * @param array &$request  The current request
     * @throws Exception If invalid configuration is found.
     */
    public function process(&$request)
    {
        assert('is_array($request)');
        assert('array_key_exists("Attributes", $request)');

        if (
            isset($request['SPMetadata']['entityid'])
            && in_array($request['SPMetadata']['entityid'], $this->eppnToSp)
        ) {
            Logger::debug(
                "[DynamicAttributeLimit] process: SP="
                . var_export($request['SPMetadata']['entityid'], true)
            );
            $idpEntityId = [];
            if (!empty($request['Attributes']['idpEntityId'])) {
                $idpEntityId = $request['Attributes']['idpEntityId'];
            }
            if (!empty(array_intersect($idpEntityId, $this->eppnFromIdp))) {
                $this->allowedAttributes[] = "eduPersonPrincipalName";
                Logger::debug(
                    "[DynamicAttributeLimit] process: allowed attrs= "
                    . var_export($this->allowedAttributes, true)
                );
            }
        }
        $metadataAllowedAttributes = array_merge([], self::getSPIdPAllowed($request));
        $this->loadMapFile('oid2name');
        foreach ($metadataAllowedAttributes as $key => $name) {
            if (array_key_exists($name, $this->map)) {
                if (!is_array($this->map[$name])) {
                    if (!$this->duplicate) {
                        Logger::debug(
                            "[DynamicAttributeLimit] process: unset mdAllowedAttributes["
                            . var_export($name, true) . "]"
                        );
                        unset($metadataAllowedAttributes[$key]);
                    }
                    $metadataAllowedAttributes[] = $this->map[$name];
                } else {
                    foreach ($this->map[$name] as $toMap) {
                        $metadataAllowedAttributes[] = $toMap;
                    }
                    if (!$this->duplicate && !in_array($name, $this->map[$name], true)) {
                        unset($metadataAllowedAttributes[$key]);
                    }
                }
            }
        }
        Logger::debug(
            "[DynamicAttributeLimit] process: mdAllowedAttributes=" . var_export($metadataAllowedAttributes, true)
        );
        if (empty($this->allowedAttributes) && empty($metadataAllowedAttributes)) {
            Logger::debug("[DynamicAttributeLimit] process: No limit on attributes");
            return; /* No limit on attributes. */
        }
        if (!empty($this->allowedAttributes)) {
            if (empty($metadataAllowedAttributes)) {
                $allowedAttributes = $this->allowedAttributes;
            } else {
                $allowedAttributes = $this->flattenAllowedAttributes($this->allowedAttributes);
                $allowedAttributes = array_intersect($allowedAttributes, $metadataAllowedAttributes);
            }
        } else {
            $allowedAttributes = $metadataAllowedAttributes;
        }
        Logger::debug("[DynamicAttributeLimit] process: allowedAttributes=" . var_export($allowedAttributes, true));

        $attributes = &$request['Attributes'];

        foreach ($attributes as $name => $values) {
            if (!in_array($name, $allowedAttributes, true)) {
                // the attribute name is not in the array of allowed attributes
                if (array_key_exists($name, $allowedAttributes)) {
                    // but it is an index of the array
                    if (!is_array($allowedAttributes[$name])) {
                        throw new Exception(
                            '[DynamicAttributeLimit]: process: Values for ' . var_export($name, true)
                            . ' must be specified in an array.'
                        );
                    }
                    $attributes[$name] = $this->filterAttributeValues($attributes[$name], $allowedAttributes[$name]);
                    if (!empty($attributes[$name])) {
                        continue;
                    }
                }
                unset($attributes[$name]);
            }
        }
    }

    /**
     * Loads and merges in a file with a attribute map.
     *
     * @param string $fileName  Name of attribute map file. Expected to be in the attributenamemapdir.
     */
    private function loadMapFile($fileName)
    {
        $config = Configuration::getInstance();
        $filePath = $config->getPathValue('attributenamemapdir', 'attributemap/') . $fileName . '.php';

        if (!file_exists($filePath)) {
            throw new Exception('Could not find attributemap file: ' . $filePath);
        }

        // Reminder: Don't change the case of this variable (as described in PSR-12)
        // this is how the array is defined in the attribute map file
        $attributemap = null;
        include($filePath);
        if (!is_array($attributemap)) {
            throw new Exception('Attribute map file "' . $filePath . '" didn\'t define an attribute map.');
        }

        if ($this->duplicate) {
            $this->map = array_merge_recursive($this->map, $attributemap);
        } else {
            $this->map = array_merge($this->map, $attributemap);
        }
    }

    /**
     * Perform the filtering of attributes
     * @param array $values The current values for a given attribute
     * @param array $allowedConfigValues The allowed values, and possibly configuration options.
     * @return array The filtered values
     */
    private function filterAttributeValues(array $values, array $allowedConfigValues)
    {
        if (array_key_exists('regex', $allowedConfigValues) && $allowedConfigValues['regex'] === true) {
            $matchedValues = [];
            foreach ($allowedConfigValues as $option => $pattern) {
                if (!is_int($option)) {
                    // Ignore any configuration options in $allowedConfig. e.g. regex=>true
                    continue;
                }
                foreach ($values as $index => $attributeValue) {
                    // Suppress errors in preg_match since phpunit is set to fail on warnings, which
                    // prevents us from testing with invalid regex.
                    $regexResult = @preg_match($pattern, $attributeValue);
                    if ($regexResult === false) {
                        Logger::warning(
                            "[DynamicAttributeLimit] filterAttributeValues: "
                            . "Error processing regex '$pattern' on value '$attributeValue'"
                        );
                        break;
                    } elseif ($regexResult === 1) {
                        $matchedValues[] = $attributeValue;
                        // Remove matched value incase a subsequent regex also matches it.
                        unset($values[$index]);
                    }
                }
            }
            return $matchedValues;
        } elseif (array_key_exists('ignoreCase', $allowedConfigValues) && $allowedConfigValues['ignoreCase'] === true) {
            unset($allowedConfigValues['ignoreCase']);
            return array_uintersect($values, $allowedConfigValues, "strcasecmp");
        }
        // The not true values for these options shouldn't leak through to array_intersect
        unset($allowedConfigValues['ignoreCase']);
        unset($allowedConfigValues['regex']);

        return array_intersect($values, $allowedConfigValues);
    }

    /**
     * @param array $allowedAttributes
     *
     * @return array  Flattened array list of allowed Attributes
     */
    private function flattenAllowedAttributes($allowedAttributes)
    {
        if (empty($allowedAttributes)) {
            return array();
        }

        return array_map(
            static function ($key, $value) {
                if (is_array($value) && is_string($key)) {
                    return $key;
                }
                return $value;
            },
            array_keys($allowedAttributes),
            $allowedAttributes
        );
    }
}
