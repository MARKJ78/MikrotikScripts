:global checkDNS do={
	########################################## Enter URL's Here
	:global weburl [:toarray value="eu.wifiportal.io, bbc.co.uk,itv.co.uk,movenpick.com,galaxy.execloud.net,mbr.co.uk,live.com,microsoft.com,airangel.com,apple.com,samsung.com,bmw.com,ford.com,sony.com,facebook.com,twitter.com,instagram.com"];
	########################################## Enter URL's Here
    :global i 0;
    :global sum 0;
    :global method {""}
    :global retry 0;
	:global results {","};
	:global thisMany [:len $weburl];
    :global underRun 0;
    :global overRun 0;
    :put "###### Getting remote DNS servers for performance testing ######";
    :global manDnsServers [/ ip dns get servers];
    :global dynDnsServers [/ ip dns get dynamic-servers];
    :global dnsServers ($manDnsServers , $dynDnsServers);
    ########################################## Resolver
    :global resolver do={
        :foreach element in=$weburl do={
		    :global result {""};
            :set $method [resolve $element server $svr];
            :put "Trying $element";
            :do {:set result [$method];} on-error={  
                :put "###### DNS Timeout.... Trying once more before aborting test"; :do {
                    :set result [$method];
                    :return (:set retry ($retry + 1));
                };
            };
             put "Success $result";
        };
    };
    ########################################## Resolver
    ########################################## results Formatting
    :global formatResult do={
        :put "this is start time: $startTime";
        :put "this is end time: $endTime";
        :local finalTime ( $endTime - $startTime );
        :set $sum ( $sum + ( [ :pick $finalTime 0 2 ] * 60 * 60 ));
        :set sum ( $sum + ( [ :pick $finalTime 3 5 ] * 60 ));
        :set sum ( $sum + [ :pick $finalTime 6 8 ] );
        :set sum ($sum);
        :put $sum;
        :set overRun ($sum - 1);
		:set underRun (1 - $sum);
        if ($sum <= 1) do={
            :global result "###### Test #$i OO-PASSED: Retries = $retry, Resolved $thisMany URL's in $sum seconds using $svr";
            :set ($results->i) $result;
        };
        if ($sum > 1) do={
            :global result "###### Test #$i XX-FAILED: Retries = $retry, Resolved $thisMany URL's in $sum seconds using $svr - That is $overRun more than it should be.";
            :set ($results->i) $result;
        };
		#################################### Remote Results
    };
    ########################################## Time Formatting
	########################################## Remote Tests
	:put "###### OKAY, Lets go...";
	:foreach svr in=$dnsServers do={
        :set retry 0;
		:set i ($i + 1);
		:put [:ip dns cache flush];
        /delay 1;
		:put "###### Test #$i. Testing directly with $svr ######";
		:global startTime [/system clock get time];
		:put "Start time: $startTime";
        :put [$resolver svr=$svr weburl=$weburl retry=$retry method=$method];
        :global endTime [/system clock get time];
        :put [$formatResult sum=$sum startTime=$startTime endTime=$endTime svr=$svr];
        :put "This is the returned sum $sum";
        :put $sum

	    ##################################### Remote Resolver
	};
	####################################### Remote Tests
	###################################### Print Final Results
	:put "#############################################";
	:put "Each test should take <1s in a healthy system.";
	:put "There should be 0 retries.";
	:put "#############################################";
	:foreach i in=$results do={
		:put $i;
	};
	###################################### Print Final Results
};
$checkDNS;
