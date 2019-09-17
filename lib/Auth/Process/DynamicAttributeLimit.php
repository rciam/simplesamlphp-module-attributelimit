<?php

/**
 * A filter for limiting which attributes are passed on.
 *
 * @author Olav Morken, UNINETT AS.
 * @package SimpleSAMLphp
 */
class sspmod_attributelimit_Auth_Process_DynamicAttributeLimit extends SimpleSAML_Auth_ProcessingFilter
{

	/**
	 * List of attributes which this filter will allow through.
	 */
	private $allowedAttributes = array();

	/**
	 * Assosiative array with the mappings of attribute names.
	 */
	private $map = array();

	private $duplicate = false;

	/**
	 * Initialize this filter.
	 *
	 * @param array $config  Configuration information about this filter.
	 * @param mixed $reserved  For future use
	 * @throws SimpleSAML_Error_Exception If invalid configuration is found.
	 */
	public function __construct($config, $reserved)
	{
		parent::__construct($config, $reserved);

		assert('is_array($config)');

		foreach ($config as $index => $value) {
			if ($index === 'default') {
				$this->isDefault = (bool) $value;
			} elseif (is_int($index)) {
				if (!is_string($value)) {
					throw new SimpleSAML_Error_Exception('DynamicAttributeLimit: Invalid attribute name: ' .
						var_export($value, TRUE));
				}
				$this->allowedAttributes[] = $value;
			} elseif (is_string($index)) {
				if (!is_array($value)) {
					throw new SimpleSAML_Error_Exception('DynamicAttributeLimit: Values for ' . var_export($index, TRUE) .
						' must be specified in an array.');
				}
				$this->allowedAttributes[$index] = $value;
			} else {
				throw new SimpleSAML_Error_Exception('DynamicAttributeLimit: Invalid option: ' . var_export($index, TRUE));
			}
		}
	}


	/**
	 * Get list of allowed from the SP/IdP config.
	 *
	 * @param array &$request  The current request.
	 * @return array|NULL  Array with attribute names, or NULL if no limit is placed.
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
		return array();
	}


	/**
	 * Apply filter to remove attributes.
	 *
	 * Removes all attributes which aren't one of the allowed attributes.
	 *
	 * @param array &$request  The current request
	 * @throws SimpleSAML_Error_Exception If invalid configuration is found.
	 */
	public function process(&$request)
	{
		assert('is_array($request)');
		assert('array_key_exists("Attributes", $request)');

		$metadataAllowedAttributes = array_merge(array(), self::getSPIdPAllowed($request));
		$this->loadMapFile('oid2name');
		foreach ($metadataAllowedAttributes as $key => $name) {
			if (array_key_exists($name, $this->map)) {
				if (!is_array($this->map[$name])) {
					if (!$this->duplicate) {
						SimpleSAML_Logger::debug("[DynamicAttributeLimit] unset mdAllowedAttributes[" . var_export($name, true) . "]");
						unset($metadataAllowedAttributes[$key]);
					}
					$metadataAllowedAttributes[] = $this->map[$name];
				} else {
					foreach ($this->map[$name] as $to_map) {
						$metadataAllowedAttributes[] = $to_map;
					}
					if (!$this->duplicate && !in_array($name, $this->map[$name], TRUE)) {
						unset($metadataAllowedAttributes[$key]);
					}
				}
			}
		}
		SimpleSAML_Logger::debug("[DynamicAttributeLimit] mdAllowedAttributes=" . var_export($metadataAllowedAttributes, true));
		if (empty($this->allowedAttributes) && empty($metadataAllowedAttributes)) {
			SimpleSAML_Logger::debug("[DynamicAttributeLimit] No limit on attributes");
			return; /* No limit on attributes. */
		}
		if (!empty($this->allowedAttributes)) {
			if (empty($metadataAllowedAttributes)) {
				$allowedAttributes = $this->allowedAttributes;
			} else {
				$allowedAttributes = array_intersect($this->allowedAttributes, $metadataAllowedAttributes);
			}
		} else {
			$allowedAttributes = $metadataAllowedAttributes;
		}
		SimpleSAML_Logger::debug("[DynamicAttributeLimit] allowedAttributes=" . var_export($allowedAttributes, true));

		$attributes = &$request['Attributes'];

		foreach ($attributes as $name => $values) {
			if (!in_array($name, $allowedAttributes, TRUE)) {
				// the attribute name is not in the array of allowed attributes
				if (array_key_exists($name, $allowedAttributes)) {
					// but it is an index of the array
					if (!is_array($allowedAttributes[$name])) {
						throw new SimpleSAML_Error_Exception('AttributeLimit: Values for ' . var_export($name, TRUE) . ' must be specified in an array.');
					}
					$attributes[$name] = array_intersect($attributes[$name], $allowedAttributes[$name]);
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
		$config = SimpleSAML_Configuration::getInstance();
		$filePath = $config->getPathValue('attributenamemapdir', 'attributemap/') . $fileName . '.php';

		if (!file_exists($filePath)) {
			throw new Exception('Could not find attributemap file: ' . $filePath);
		}

		$attributemap = NULL;
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
}
