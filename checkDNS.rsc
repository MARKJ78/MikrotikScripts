:global checkDNS do={
	########################################## Enter URL's Here
	:global weburl [:toarray value="eu.wifiportal.io, bbc.co.uk,itv.co.uk,movenpick.com,galaxy.execloud.net,mbr.co.uk,live.com,microsoft.com,airangel.com,apple.com,samsung.com,bmw.com,ford.com,sony.com,facebook.com,twitter.com,instagram.com"];
	########################################## Enter URL's Here
	:global i 0;
	:global results {""};
	:global thisMany [:len $weburl];
    :put "###### Getting remote DNS servers for performance testing ######";
    :global manDnsServers [/ ip dns get servers];
    :global dynDnsServers [/ ip dns get dynamic-servers];
    :global dnsServers ($manDnsServers , $dynDnsServers);
	########################################## Remote Tests
	:put "###### OKAY, Lets go...";
	:foreach svr in=$dnsServers do={
		:global retry 0;
		:global result {""};
		:set i ($i + 1);
		:put [:ip dns cache flush];
		:put "###### Test #$i. Testing directly with $svr ######";
		:global startTime [/system clock get time];
		:put "Start time: $startTime";
		###################################### Remote Resolver
	    :foreach element in=$weburl do={
			:put "Trying $element";
			:do { :set result [resolve $element server $svr];} on-error={ 
				:put "###### DNS Timeout.... Trying once more before aborting test"; :do {
					:set result [resolve $element server $svr];;
					:set retry ($retry + 1);
				};
			};
			:put "Success $result";
	    };

		##################################### Time formatting
		:global sum 0;
		:global endTime [/system clock get time];
		:global finalTime ( $endTime - $startTime );
		:set sum ( $sum + ( [ :pick $finalTime 0 2 ] * 60 * 60 ));
		:set sum ( $sum + ( [ :pick $finalTime 3 5 ] * 60 ));
		:set sum ( $sum + [ :pick $finalTime 6 8 ] );
		#################################### Time formatting
		:put "End time: $endTime";
		#################################### Remote Results
		:global overRun 0;
		:set overRun ($sum - 1);
		:global underRun 0;
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
	    ##################################### Remote Resolver

		##################################### Time formatting
		:global sum 0;
		:global endTime [/system clock get time];
		:global finalTime ( $endTime - $startTime );
		:set sum ( $sum + ( [ :pick $finalTime 0 2 ] * 60 * 60 ));
		:set sum ( $sum + ( [ :pick $finalTime 3 5 ] * 60 ));
		:set sum ( $sum + [ :pick $finalTime 6 8 ] );
		#################################### Time formatting
		:put "End time: $endTime";
		#################################### Dynamic Results
		:global overRun 0;
		:set overRun ($sum - 1);
		:global underRun 0;
		:set underRun (1 - $sum);
		  if ($sum <= 1) do={
		    :global result "###### Test #$i OO-PASSED: Retries = $retry, Resolved $thisMany URL's in $sum seconds using $svr";
		   	:set ($results->i) $result;
		  };
		    if ($sum > 1) do={
		    :global result "###### Test #$i XX-FAILED: Retries = $retry, Resolved $thisMany URL's in $sum seconds using $svr - That is $overRun more than it should be.";
		    :set ($results->i) $result;
		  };

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
