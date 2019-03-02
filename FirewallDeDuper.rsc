{
  /ip firewall filter

  :global fwRules [find];
  :put [:len $fwRules ]; 
  :put $fwRules;
  :global dupes {""};
  :for i from=0 to=([:len $fwRules ]-2) do={
    :put "test 1";
    :for j from=($i+1) to=([:len $fwRules ]-1) do={ 
        :put "test 2";
      :if ([get [:pick $fwRules $i] address ] = [get [:pick $fwRules $j] address ]) do={
        :local bAdd 1;
          :put "test 3";
        :for k from=0 to=([:len $dupes]-1) do={
              :put "test 4";
          :if ( [:pick $fwRules $j] = [:pick $dupes $k]) do={
             :set bAdd 0;
          }
        }
        :if ($bAdd = 1) do={
          :set dupes ($dupes , [:pick $fwRules $j]);
        }
          
      }
    }
  }
  :remove $dupes;
}