<?php

function patch_function($oldFunc, $newFunc, $prefix = 'original') {

    if (!extension_loaded('runkit')) {
        die('Patching functions needs the runkit extension');
    }

    // Rebuild the signature of the new function as string
    $funcSig = $callSig = '';
    $refFunc = new ReflectionFunction($newFunc);

    if ($refFunc->getNumberOfParameters() > 0) {
        $params = $callParams = array();
        $refParams = $refFunc->getParameters();
        foreach ($refParams as $refParam) {
            $param = ($refParam->isPassedByReference() ? '&' : '') . '$' . $refParam->name;

            if($refParam->isOptional() && $refParam->isDefaultValueAvailable()) {
                $defValue = $refParam->getDefaultValue();
                $param .= '=' . var_export($defValue, true);
            }
            $params[] = $param;
            $callParams[] = '$' . $refParam->name;
        }
        $funcSig = implode(', ', $params);
        $callSig = implode(', ', $callParams);
    }

    // Make anonymous function available via a unique global var
    $overrideFunc = uniqid('patched_') . '_' . $oldFunc;
    global $$overrideFunc;
    $$overrideFunc = $newFunc;
    $overrideCode = 'global $' . $overrideFunc . '; return $' . $overrideFunc . '(' . $callSig . ');';

    /*
    echo "override func: $overrideFunc\n";
    echo "signature: $funcSig\n";
    echo "call params: $callSig\n";
    */
    runkit_function_rename($oldFunc, $prefix . '_' . $oldFunc);
    runkit_function_add($oldFunc, $funcSig, $overrideCode);
}

patch_function('phpinfo', function($what = INFO_LICENSE) {
    echo "Default output changed! :-)\n";
    return original_phpinfo($what);
});

phpinfo();
