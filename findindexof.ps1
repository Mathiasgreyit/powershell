function _findindexof {
    param (
        $array, # A array to search in
        $property, # Propertie to look for
        $item # Value of property
    )
    $ind = 0 # Starting at 0
    $oind = "X" # If we dont find anything use "X" to Throw exception
    foreach ($i in $array) {
        if ($i.$property -eq $item) {$oind = $ind} # Set $oind to matching item. If there are multiple items only last item will be returned.
        $ind++ # Increasing $ind
    }
    if ($oind -eq "X") {Throw "Coudnt find any match in array of item $item in property $property!"}
    $oind # Return
}
